from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import random
import string
from PIL import Image
import io
import base64
from datetime import datetime, timedelta
from landing.routes import landing_bp
from admin.routes import admin_bp
from teacher.routes import teacher_bp

app = Flask(__name__)
app.secret_key = 'app_secret_123'

# Email config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'rosalestrinity0625@gmail.com'
app.config['MAIL_PASSWORD'] = 'lkaa rgsy ywtj tpjz'
mail = Mail(app)

# Registers
app.register_blueprint(landing_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(teacher_bp)

# --- Helper Functions ---
def get_db_connection():
    conn = sqlite3.connect('balikwika.db')
    conn.row_factory = sqlite3.Row
    return conn

def create_users_table():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            otp TEXT,
            otp_expiry TEXT,
            is_verified INTEGER DEFAULT 0,
            reset_token TEXT,
            reset_token_expiry TEXT,
            role TEXT DEFAULT 'student',
            user_profile BLOB,
            is_temp_password INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

def create_lessons_table():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS lessons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            subject TEXT NOT NULL,
            content TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

def migrate_database():
    """Add missing columns to existing database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if columns exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'reset_token' not in columns:
            print("Adding reset_token column...")
            cursor.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
            
        if 'reset_token_expiry' not in columns:
            print("Adding reset_token_expiry column...")
            cursor.execute("ALTER TABLE users ADD COLUMN reset_token_expiry TEXT")
            
        if 'role' not in columns:
            print("Adding role column...")
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'student'")
            
        if 'is_temp_password' not in columns:
            print("Adding is_temp_password column...")
            cursor.execute("ALTER TABLE users ADD COLUMN is_temp_password INTEGER DEFAULT 0")
            
        if 'first_name' not in columns:
            print("Adding first_name column...")
            cursor.execute("ALTER TABLE users ADD COLUMN first_name TEXT")
            
        if 'last_name' not in columns:
            print("Adding last_name column...")
            cursor.execute("ALTER TABLE users ADD COLUMN last_name TEXT")
        
        conn.commit()
        print("Database migration completed!")
    except Exception as e:
        print(f"Migration error: {e}")
    finally:
        conn.close()

# Initialize database
create_users_table()
create_lessons_table()
migrate_database()

def validate_password(password):
    """Validate password meets all requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"

def generate_reset_token():
    """Generate a secure reset token"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def require_role(role):
    """Decorator to require specific role"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            conn = get_db_connection()
            user = conn.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],)).fetchone()
            conn.close()
            
            if not user or user['role'] != role:
                flash("Access denied. You don't have permission to access this page.", "error")
                # Redirect to correct dashboard if possible
                return redirect(url_for(f"{session.get('user_role')}_dashboard"))

            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


def require_login():
    """Decorator to require login"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

# --- Routes ---

# @app.route('/')
# def index():
    # return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        
        # Validate password
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, "error")
            return redirect(url_for('signup'))
        
        # Hash password
        password_hash = generate_password_hash(password)

        otp = ''.join(random.choices(string.digits, k=6))
        otp_expiry = (datetime.now() + timedelta(minutes=1)).strftime('%Y-%m-%d %H:%M:%S')

         # ✅ Generate current timestamp
        registered_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        conn = get_db_connection()
        try:
            # Students register with 'student' role by default
            conn.execute(
                "INSERT INTO users (email, password, first_name, last_name, otp, otp_expiry, is_verified, role, registered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (email, password_hash, first_name, last_name, otp, otp_expiry, 0, 'student', registered_at)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Email already registered.", "error")
            return redirect(url_for('signup'))
        finally:
            conn.close()

        print(f"[DEBUG] OTP for {email}: {otp} (expires at {otp_expiry})")

        msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = (
    f"Hello {first_name or 'User'},\n\n"
    f"Thank you for signing up for Balik-Wika!\n\n"
    f"Your One-Time Password (OTP) is: {otp}\n"
    f"This code is valid for 1 minute.\n\n"
    "Please enter it on the verification page to activate your account.\n\n"
    "If you did not sign up for this account, you can ignore this email.\n\n"
    "Salamat!\n"
    "— The Balik-Wika Team"
)
        try:
            mail.send(msg)
            print(f"[INFO] OTP email sent to {email}")
        except Exception as e:
            print(f"[ERROR] Failed to send OTP email: {e}")
            flash("Failed to send OTP email. Try again later.", "error")
            return redirect(url_for('signup'))

        session['otp_email'] = email
        return redirect(url_for('verify_otp'))
    return render_template('signup.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('otp_email')
    if not email:
        return redirect(url_for('signup'))

    if request.method == 'POST':
        user_input_otp = request.form.get('otp')

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if not user:
            conn.close()
            flash("Walang user na may email na iyon.", "error")
            return redirect(url_for('signup'))

        db_otp = user['otp']
        otp_expiry = datetime.strptime(user['otp_expiry'], '%Y-%m-%d %H:%M:%S')

        if datetime.now() > otp_expiry:
            conn.close()
            flash("Nag-expire na ang OTP. I-send ulit.", "error")
            return redirect(url_for('verify_otp'))

        if user_input_otp != db_otp:
            conn.close()
            flash("Maling OTP. Pakisubukang muli.", "error")
            return redirect(url_for('verify_otp'))

        # Mark user as verified
        conn.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
        conn.commit()
        conn.close()

        flash("Matagumpay ang pagrerehistro! Maaari ka nang mag-login.", "success")
        return redirect(url_for('login'))

    return render_template('verify_otp.html')

@app.route('/resend_otp')
def resend_otp():
    email = session.get('otp_email')
    if not email:
        return redirect(url_for('signup'))

    # Generate new OTP and update in DB
    otp = ''.join(random.choices(string.digits, k=6))
    otp_expiry = (datetime.now() + timedelta(minutes=1)).strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db_connection()
    conn.execute("UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?", (otp, otp_expiry, email))
    conn.commit()
    conn.close()

    # Send email
    msg = Message('Your New OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f"Your new OTP code is: {otp}. It will expire in 1 minute."

    try:
        mail.send(msg)
        flash("Naipadala muli ang OTP!", "success")
    except Exception as e:
        flash("Hindi naipadala ang OTP. Pakisubukang muli.", "error")

    return redirect(url_for('verify_otp'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        print(f"[DEBUG] Login attempt - Email: {email}, Password: {'*' * len(password) if password else 'None'}")

        if not email or not password:
            flash("Please enter both email and password.", "error")
            return redirect(url_for('login'))

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if user:
            print(f"[DEBUG] User found - ID: {user['id']}, Role: {user['role']}, Verified: {user['is_verified']}, Temp Password: {user['is_temp_password']}")
        else:
            print(f"[DEBUG] No user found with email: {email}")
        
        conn.close()

        if user and check_password_hash(user['password'], password):
            print(f"[DEBUG] Password verification successful for {email}")
            
            # Check verification status first
            if not user['is_verified']:
                print(f"[DEBUG] User not verified, redirecting to OTP verification")
                flash("Kumpirmahin muna ang inyong email gamit ang OTP bago mag-login.", "error")
                session['otp_email'] = email
                return redirect(url_for('verify_otp'))
            
            # Check if user has temporary password (teachers)
            if user['is_temp_password'] == 1:  # Explicit check for 1
                print(f"[DEBUG] User has temporary password, redirecting to force password change")
                session['temp_user_id'] = user['id']
                session['temp_user_email'] = user['email']  # Store email for convenience
                flash("Kailangan ninyong i-update ang temporary password bago makapag-login.", "info")
                return redirect(url_for('force_password_change'))
            
            # Log user in normally
            print(f"[DEBUG] Logging in user successfully")
            session['user_id'] = user['id']
            session['user_role'] = user['role']
            session['user_email'] = user['email']
            flash("Maligayang pagbalik!", "success")

            # Role-based redirection
            role = user['role']
            if role == 'student':
                return redirect(url_for('student_dashboard'))
            elif role == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            elif role == 'admin':
                return redirect(url_for('admin.index'))
            else:
                flash("Unknown role. Please contact support.", "error")
                return redirect(url_for('login'))

        print(f"[DEBUG] Login failed - Invalid credentials")
        flash("Maling email o password.", "error")
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/admin_dashboard')
@require_role('admin')  # Use your existing decorator if it's defined
def admin_dashboard():
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()

    if not user:
        return redirect(url_for('login'))

    return render_template('admin_dashboard.html', user=user)


@app.route('/force_password_change', methods=['GET', 'POST'])
def force_password_change():
    temp_user_id = session.get('temp_user_id')
    if not temp_user_id:
        flash("Session expired. Please login again.", "error")
        return redirect(url_for('login'))
    
    # Get user info to display email
    conn = get_db_connection()
    user = conn.execute("SELECT email, role FROM users WHERE id = ?", (temp_user_id,)).fetchone()
    conn.close()
    
    if not user:
        flash("User not found. Please login again.", "error")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate required fields
        if not new_password or not confirm_password:
            flash("Kailangan ang lahat ng field.", "error")
            return redirect(url_for('force_password_change'))
        
        # Validate passwords match
        if new_password != confirm_password:
            flash("Ang mga password ay hindi pareho.", "error")
            return redirect(url_for('force_password_change'))
        
        # Validate password strength
        is_valid, message = validate_password(new_password)
        if not is_valid:
            flash(message, "error")
            return redirect(url_for('force_password_change'))
        
        # Update password and remove temp password flag
        password_hash = generate_password_hash(new_password)
        conn = get_db_connection()
        
        # Update password and clear temp password flag
        conn.execute("""
            UPDATE users 
            SET password = ?, is_temp_password = 0 
            WHERE id = ?
        """, (password_hash, temp_user_id))
        conn.commit()
        conn.close()
        
        # Clear temp session variables
        session.pop('temp_user_id', None)
        session.pop('temp_user_email', None)
        
        flash("Password na-update! Pakisubukang mag-login ulit gamit ang bagong password.", "success")
        return redirect(url_for('login'))
    
    return render_template('force_password_change.html', user=user)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if not user:
            flash("Walang account na may email na iyon.", "error")
            conn.close()
            return redirect(url_for('forgot_password'))
        
        # Generate OTP for password reset
        otp = ''.join(random.choices(string.digits, k=6))
        otp_expiry = (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')
        
        # Update user with OTP
        conn.execute("UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?", (otp, otp_expiry, email))
        conn.commit()
        conn.close()
        
        print(f"[DEBUG] Password reset OTP for {email}: {otp} (expires at {otp_expiry})")
        
        # Send OTP email
        msg = Message('Password Reset OTP - BalikWika', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"""
Kumusta!

Nakatanggap kami ng request para i-reset ang password ng inyong BalikWika account.

Ang inyong OTP code ay: {otp}

Ang OTP na ito ay mag-expire sa loob ng 10 minuto.

Kung hindi kayo nag-request ng password reset, pakiignore lang ang email na ito.

Salamat,
BalikWika Team
        """
        
        try:
            mail.send(msg)
            flash("Naipadala na ang OTP sa inyong email. Pakicheck ang inbox.", "success")
            session['reset_email'] = email
            return redirect(url_for('verify_reset_otp'))
        except Exception as e:
            print(f"[ERROR] Failed to send password reset email: {e}")
            flash("Hindi naipadala ang OTP. Pakisubukang muli.", "error")
            return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')

@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    email = session.get('reset_email')
    if not email:
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        user_input_otp = request.form.get('otp')
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if not user:
            conn.close()
            flash("Walang user na may email na iyon.", "error")
            return redirect(url_for('forgot_password'))
        
        db_otp = user['otp']
        otp_expiry = datetime.strptime(user['otp_expiry'], '%Y-%m-%d %H:%M:%S')
        
        if datetime.now() > otp_expiry:
            conn.close()
            flash("Nag-expire na ang OTP. Pakisubukang muli.", "error")
            return redirect(url_for('forgot_password'))
        
        if user_input_otp != db_otp:
            conn.close()
            flash("Maling OTP. Pakisubukang muli.", "error")
            return redirect(url_for('verify_reset_otp'))
        
        # Generate reset token for secure password reset
        reset_token = generate_reset_token()
        reset_token_expiry = (datetime.now() + timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S')
        
        conn.execute("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?", 
                    (reset_token, reset_token_expiry, email))
        conn.commit()
        conn.close()
        
        session['reset_token'] = reset_token
        
        flash("OTP na-verify! Maaari na kayong mag-set ng bagong password.", "success")
        return redirect(url_for('reset_password'))
    
    return render_template('verify_reset_otp.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    reset_token = session.get('reset_token')
    
    if not reset_token:
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Validate passwords match
        if new_password != confirm_password:
            flash("Ang mga password ay hindi pareho.", "error")
            return redirect(url_for('reset_password'))
        
        # Validate password strength
        is_valid, message = validate_password(new_password)
        if not is_valid:
            flash(message, "error")
            return redirect(url_for('reset_password'))
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE reset_token = ?", (reset_token,)).fetchone()
        
        if not user:
            conn.close()
            flash("Invalid reset token.", "error")
            return redirect(url_for('forgot_password'))
        
        # Check if reset token has expired
        if user['reset_token_expiry']:
            reset_token_expiry = datetime.strptime(user['reset_token_expiry'], '%Y-%m-%d %H:%M:%S')
            if datetime.now() > reset_token_expiry:
                conn.close()
                flash("Nag-expire na ang reset token. Pakisubukang muli.", "error")
                return redirect(url_for('forgot_password'))
        
        # Update password and clear reset token
        password_hash = generate_password_hash(new_password)
        conn.execute("""
            UPDATE users 
            SET password = ?, reset_token = NULL, reset_token_expiry = NULL, otp = NULL, otp_expiry = NULL, is_temp_password = 0
            WHERE reset_token = ?
        """, (password_hash, reset_token))
        conn.commit()
        conn.close()
        
        # Clear session
        session.pop('reset_token', None)
        session.pop('reset_email', None)
        
        flash("Matagumpay na na-reset ang password! Maaari na kayong mag-login.", "success")
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/resend_reset_otp')
def resend_reset_otp():
    email = session.get('reset_email')
    if not email:
        return redirect(url_for('forgot_password'))
    
    # Generate new OTP and update in DB
    otp = ''.join(random.choices(string.digits, k=6))
    otp_expiry = (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')
    
    conn = get_db_connection()
    conn.execute("UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?", (otp, otp_expiry, email))
    conn.commit()
    conn.close()
    
    print(f"[DEBUG] New password reset OTP for {email}: {otp} (expires at {otp_expiry})")
    
    # Send email
    msg = Message('New Password Reset OTP - BalikWika', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f"""
Kumusta!

Narito ang bagong OTP code para sa password reset:

{otp}

Ang OTP na ito ay mag-expire sa loob ng 10 minuto.

Salamat,
BalikWika Team
    """
    
    try:
        mail.send(msg)
        flash("Naipadala muli ang OTP sa inyong email!", "success")
    except Exception as e:
        print(f"[ERROR] Failed to resend password reset OTP: {e}")
        flash("Hindi naipadala ang OTP. Pakisubukang muli.", "error")
    
    return redirect(url_for('verify_reset_otp'))

@app.route('/check_temp_password')
def check_temp_password():
    """Check if logged-in user has temporary password"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute("SELECT is_temp_password FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()
    
    if user and user['is_temp_password'] == 1:
        session['temp_user_id'] = session['user_id']
        flash("Kailangan ninyong i-update ang temporary password.", "info")
        return redirect(url_for('force_password_change'))
    
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()
    
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Additional check for temporary password (security measure)
    if user['is_temp_password'] == 1:
        session['temp_user_id'] = user['id']
        flash("Kailangan ninyong i-update ang temporary password.", "info")
        return redirect(url_for('force_password_change'))
    
    # Role-based dashboard content
    if user['role'] == 'teacher':
        return render_template('teacher_dashboard.html', user=user)
    else:
        return render_template('student_dashboard.html', user=user)

@app.route('/student_dashboard')
@require_role('student')
def student_dashboard():
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()

    if not user:
        return redirect(url_for('login'))

    profile_picture = user['user_profile'] if user['user_profile'] else None

    return render_template('student_dashboard.html', user=user, profile_picture=profile_picture)


@app.route('/mga_pagsusulit')
@require_role('student')  # Assuming you want only students to access this
def mga_pagsusulit():
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()

    if not user:
        flash("User not found.", "error")
        return redirect(url_for('login'))

    return render_template('mga_pagsusulit.html', user=user)

@app.route('/teacher_dashboard')
@require_role('teacher')
def teacher_dashboard():
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()
    return render_template('teacher_dashboard.html', user=user)

# --- User Profile Routes ---

@app.route('/profile')
@require_role('student')
def profile():
    """User profile page - accessible by all logged-in users"""
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()
    
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('login'))
    
    # Since you're storing as base64 string, just use it directly
    profile_picture = user['user_profile'] if user['user_profile'] else None
    
    return render_template('profile.html', user=user, profile_picture=profile_picture)

# Replace your existing /edit_profile route with this enhanced version
@app.route('/edit_profile', methods=['GET', 'POST'])
@require_role('student')
def edit_profile():
    """Edit user profile information"""
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    
    if not user:
        flash("User not found.", "error")
        conn.close()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        
        # Validate required fields
        if not email:
            flash("Email is required.", "error")
            return redirect(url_for('edit_profile'))
        
        # Check if email is already taken by another user
        existing_user = conn.execute("SELECT id FROM users WHERE email = ? AND id != ?", 
                                   (email, session['user_id'])).fetchone()
        
        if existing_user:
            flash("Email already taken by another user.", "error")
            conn.close()
            return redirect(url_for('edit_profile'))
        
        # Update user information
        conn.execute("""
            UPDATE users 
            SET first_name = ?, last_name = ?, email = ?
            WHERE id = ?
        """, (first_name, last_name, email, session['user_id']))
        conn.commit()
        conn.close()
        
        # Update session email if it changed
        session['user_email'] = email
        
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))
    
    conn.close()
    return render_template('edit_profile.html', user=user)

# Add this new route for AJAX profile updates
@app.route('/update_profile', methods=['POST'])
@require_role('student')
def update_profile():
    """Update profile via AJAX"""
    user_id = session['user_id']
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()
    email = request.form.get('email', '').strip()
    
    # Validate input
    if not first_name or not last_name or not email:
        return jsonify({'success': False, 'message': 'All fields are required'})
    
    # Check if email is already taken by another user
    conn = get_db_connection()
    existing_user = conn.execute(
        'SELECT id FROM users WHERE email = ? AND id != ?',
        (email, user_id)
    ).fetchone()
    
    if existing_user:
        conn.close()
        return jsonify({'success': False, 'message': 'Email already exists'})
    
    # Update user information
    try:
        conn.execute(
            'UPDATE users SET first_name = ?, last_name = ?, email = ? WHERE id = ?',
            (first_name, last_name, email, user_id)
        )
        conn.commit()
        conn.close()
        
        # Update session email
        session['user_email'] = email
        
        return jsonify({'success': True, 'message': 'Profile updated successfully'})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to update profile'})

# Add this new route for AJAX password change
@app.route('/change_password_ajax', methods=['POST'])
@require_role('student')
def change_password_ajax():
    """Change password via AJAX"""
    user_id = session['user_id']
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    # Validate input
    if not current_password or not new_password or not confirm_password:
        return jsonify({'success': False, 'message': 'All password fields are required'})
    
    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'New passwords do not match'})
    
    # Validate password strength
    is_valid, message = validate_password(new_password)
    if not is_valid:
        return jsonify({'success': False, 'message': message})
    
    # Verify current password
    conn = get_db_connection()
    user = conn.execute('SELECT password FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user or not check_password_hash(user['password'], current_password):
        conn.close()
        return jsonify({'success': False, 'message': 'Current password is incorrect'})
    
    # Update password
    try:
        hashed_password = generate_password_hash(new_password)
        conn.execute(
            'UPDATE users SET password = ?, is_temp_password = 0 WHERE id = ?',
            (hashed_password, user_id)
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Password changed successfully'})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to change password'})

# Add this new route for profile picture upload
@app.route('/upload_profile_picture', methods=['POST'])
@require_role('student')
def upload_profile_picture():
    """Upload profile picture"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'})
    
    if 'profile_picture' not in request.files:
        return jsonify({'success': False, 'message': 'No file selected'})
    
    file = request.files['profile_picture']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'})
    
    # Check file type
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    if not ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
        return jsonify({'success': False, 'message': 'Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed'})
    
    try:
        # Process the image
        image = Image.open(file.stream)

        # Convert to RGB if transparent
        if image.mode in ('RGBA', 'LA'):
            background = Image.new('RGB', image.size, (255, 255, 255))
            background.paste(image, mask=image.split()[-1])
            image = background

        # Resize to max 400x400
        max_size = (400, 400)
        image.thumbnail(max_size, Image.Resampling.LANCZOS)

        # Save to BytesIO as JPEG
        img_bytes = io.BytesIO()
        image.save(img_bytes, format='JPEG', quality=85)
        img_data = img_bytes.getvalue()

        # Encode image as base64
        img_base64 = base64.b64encode(img_data).decode('utf-8')

        # Save to database (as base64 string)
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'message': 'Database connection failed'})
        
        conn.execute(
            'UPDATE users SET user_profile = ? WHERE id = ?',
            (img_base64, session['user_id'])
        )
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Profile picture updated successfully',
            'profile_picture': img_base64
        })

    except ImportError:
        return jsonify({'success': False, 'message': 'Pillow library not installed. Please install it with: pip install Pillow'})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Failed to process image: {str(e)}'})

# Add this new route for removing profile picture
@app.route('/remove_profile_picture', methods=['POST'])
@require_role('student')
def remove_profile_picture():
   """Remove profile picture"""
   if 'user_id' not in session:
       return jsonify({'success': False, 'message': 'User not logged in'})
   
   try:
       conn = get_db_connection()
       if not conn:
           return jsonify({'success': False, 'message': 'Database connection failed'})
       
       conn.execute(
           'UPDATE users SET user_profile = NULL WHERE id = ?',
           (session['user_id'],)
       )
       conn.commit()
       conn.close()

       return jsonify({
           'success': True,
           'message': 'Profile picture removed successfully'
       })

   except Exception as e:
       import traceback
       traceback.print_exc()
       return jsonify({'success': False, 'message': f'Failed to remove profile picture: {str(e)}'})
   
   
# Add this function to update your database schema
def add_profile_picture_column():
    """Add user_profile column to users table if it doesn't exist"""
    conn = get_db_connection()
    if not conn:
        print("Failed to connect to database")
        return
    
    cursor = conn.cursor()
    
    try:
        # Check if column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'user_profile' not in columns:
            print("Adding user_profile column...")
            cursor.execute("ALTER TABLE users ADD COLUMN user_profile BLOB")
            conn.commit()
            print("user_profile column added successfully!")
        else:
            print("user_profile column already exists")
        
    except Exception as e:
        print(f"Error adding user_profile column: {e}")
    finally:
        conn.close()

# --- Lessons Routes ---

@app.route('/mga_aralin')
def mga_aralin():
    """View all lessons (accessible by students)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    # Get all lessons with teacher information
    lessons = conn.execute("""
        SELECT l.*, u.email as teacher_email 
        FROM lessons l 
        JOIN users u ON l.user_id = u.id 
        ORDER BY l.created_at DESC
    """).fetchall()
    conn.close()
    
    return render_template('mga_aralin.html', lessons=lessons)

@app.route('/generate_hash/<password>')
def generate_hash(password):
    """Temporary route to generate password hash for manual teacher account creation"""
    hashed = generate_password_hash(password)
    return f"Password: {password}<br>Hashed: {hashed}"

@app.route('/logout')
def logout():
    session.clear()
    flash("Na-logout na kayo.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)