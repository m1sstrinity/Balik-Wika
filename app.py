from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import os
import psycopg2
from database_config import get_db_connection, create_tables, db_config
import random
import string
from PIL import Image
import io
import base64
from datetime import datetime, timedelta
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from landing.routes import landing_bp
from admin.routes import admin_bp
from teacher.routes import teacher_bp

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

# Registers
app.register_blueprint(landing_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(teacher_bp)

# --- Helper Functions ---

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
    def decorator(f):
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            if db_config.is_production:
                cursor.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
                user = cursor.fetchone()
            else:
                user = conn.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],)).fetchone()
            
            conn.close()
            
            if not user or (user['role'] if hasattr(user, '__getitem__') else user[0]) != role:
                flash("Access denied. You don't have permission to access this page.", "error")
                return redirect(url_for(f"{session.get('user_role', 'student')}_dashboard"))

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
        registered_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Students register with 'student' role by default
            if db_config.is_production:
                # PostgreSQL uses %s placeholders
                cursor.execute(
                    "INSERT INTO users (email, password, first_name, last_name, otp, otp_expiry, is_verified, role, registered_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (email, password_hash, first_name, last_name, otp, otp_expiry, 0, 'student', registered_at)
                )
            else:
                # SQLite uses ? placeholders
                conn.execute(
                    "INSERT INTO users (email, password, first_name, last_name, otp, otp_expiry, is_verified, role, registered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (email, password_hash, first_name, last_name, otp, otp_expiry, 0, 'student', registered_at)
                )
            conn.commit()
        except Exception as e:
            conn.close()
            flash("Email already registered.", "error")
            return redirect(url_for('signup'))
        
        conn.close()

        print(f"[DEBUG] OTP for {email}: {otp} (expires at {otp_expiry})")

        # Send OTP email via SendGrid
        message = Mail(
            from_email='rosales_trinitycamille@plpasig.edu.ph',
            to_emails=email,
            subject='Your OTP Code - BalikWika',
            html_content=f"""
            <html>
                <body style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>Welcome to BalikWika!</h2>
                    <p>Hello {first_name or 'User'},</p>
                    <p>Thank you for signing up for Balik-Wika!</p>
                    <p style="font-size: 18px; font-weight: bold; color: #ef4444;">
                        Your One-Time Password (OTP) is: {otp}
                    </p>
                    <p>This code is valid for 1 minute.</p>
                    <p>Please enter it on the verification page to activate your account.</p>
                    <p>If you did not sign up for this account, you can ignore this email.</p>
                    <br>
                    <p>Salamat!<br>— The Balik-Wika Team</p>
                </body>
            </html>
            """
        )
        
        try:
            print(f"[DEBUG] Attempting to send OTP email via SendGrid to {email}")
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            response = sg.send(message)
            print(f"[SUCCESS] OTP email sent via SendGrid to {email}. Status: {response.status_code}")
        except Exception as e:
            print(f"[ERROR] Failed to send OTP email: {e}")
            import traceback
            traceback.print_exc()
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
        cursor = conn.cursor()
        
        try:
            if db_config.is_production:
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()
            else:
                user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

            if not user:
                cursor.close()  # ✅ ADDED
                conn.close()
                flash("Walang user na may email na iyon.", "error")
                return redirect(url_for('signup'))

            db_otp = user['otp']
            otp_expiry_raw = user['otp_expiry']
            
            # ✅ FIXED: Handle both string (SQLite) and datetime (PostgreSQL) formats
            if isinstance(otp_expiry_raw, str):
                otp_expiry = datetime.strptime(otp_expiry_raw, '%Y-%m-%d %H:%M:%S')
            else:
                otp_expiry = otp_expiry_raw  # Already a datetime object

            if datetime.now() > otp_expiry:
                cursor.close()  # ✅ ADDED
                conn.close()
                flash("Nag-expire na ang OTP. I-send ulit.", "error")
                return redirect(url_for('verify_otp'))

            if user_input_otp != db_otp:
                cursor.close()  # ✅ ADDED
                conn.close()
                flash("Maling OTP. Pakisubukang muli.", "error")
                return redirect(url_for('verify_otp'))

            # Mark user as verified
            if db_config.is_production:
                cursor.execute("UPDATE users SET is_verified = 1 WHERE email = %s", (email,))
            else:
                cursor.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))  # ✅ FIXED: Use cursor instead of conn
            
            conn.commit()
            cursor.close()  # ✅ ADDED
            conn.close()

            flash("Matagumpay ang pagrerehistro! Maaari ka nang mag-login.", "success")
            return redirect(url_for('login'))
        
        except Exception as e:  # ✅ ADDED
            cursor.close()
            conn.close()
            print(f"[ERROR] verify_otp error: {e}")
            import traceback
            traceback.print_exc()
            flash("May error na nangyari. Pakisubukang muli.", "error")
            return redirect(url_for('signup'))

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
    cursor = conn.cursor()
    
    try:
        if db_config.is_production:
            cursor.execute("UPDATE users SET otp = %s, otp_expiry = %s WHERE email = %s", 
                          (otp, otp_expiry, email))
        else:
            cursor.execute("UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?", 
                          (otp, otp_expiry, email))  # ✅ FIXED: Use cursor
        
        conn.commit()
        cursor.close()  # ✅ ADDED
        conn.close()
        
        print(f"[DEBUG] Resending OTP to {email}: {otp} (expires at {otp_expiry})")
        
        # ✅ FIXED: Send email via SendGrid (not Flask-Mail)
        message = Mail(
            from_email='rosales_trinitycamille@plpasig.edu.ph',
            to_emails=email,
            subject='Your New OTP Code - BalikWika',
            html_content=f"""
            <html>
                <body style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>New OTP Request</h2>
                    <p>Hello!</p>
                    <p>You requested a new OTP code for your BalikWika account.</p>
                    <p style="font-size: 18px; font-weight: bold; color: #ef4444;">
                        Your new OTP code is: {otp}
                    </p>
                    <p>This code is valid for 1 minute.</p>
                    <p>If you did not request this code, you can ignore this email.</p>
                    <br>
                    <p>Salamat!<br>— The Balik-Wika Team</p>
                </body>
            </html>
            """
        )
        
        try:
            print(f"[DEBUG] Attempting to resend OTP via SendGrid to {email}")
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            response = sg.send(message)
            print(f"[SUCCESS] OTP resent via SendGrid. Status: {response.status_code}")
            flash("Naipadala muli ang OTP sa inyong email!", "success")
        except Exception as e:
            print(f"[ERROR] Failed to resend OTP email: {e}")
            import traceback
            traceback.print_exc()
            flash("Hindi naipadala ang OTP. Pakisubukang muli.", "error")
    
    except Exception as e:
        cursor.close()
        conn.close()
        print(f"[ERROR] Database error in resend_otp: {e}")
        import traceback
        traceback.print_exc()
        flash("May error na nangyari. Pakisubukang muli.", "error")

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
        cursor = conn.cursor()
        
        if db_config.is_production:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
        else:
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
@require_role('admin')
def admin_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if db_config.is_production:
        cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()
    else:
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
    cursor = conn.cursor()
    
    if db_config.is_production:
        cursor.execute("SELECT email, role FROM users WHERE id = %s", (temp_user_id,))
        user = cursor.fetchone()
    else:
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
        cursor = conn.cursor()
        
        # Update password and clear temp password flag
        if db_config.is_production:
            cursor.execute("""
                UPDATE users 
                SET password = %s, is_temp_password = 0 
                WHERE id = %s
            """, (password_hash, temp_user_id))
        else:
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
        
        print(f"[DEBUG] Password reset requested for: {email}")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if db_config.is_production:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
        else:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if not user:
            flash("Walang account na may email na iyon.", "error")
            conn.close()
            return redirect(url_for('forgot_password'))
        
        # Generate OTP for password reset
        otp = ''.join(random.choices(string.digits, k=6))
        otp_expiry = (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')
        
        print(f"[DEBUG] Generated OTP: {otp}, Expiry: {otp_expiry}")
        
        # Update user with OTP
        if db_config.is_production:
            cursor.execute("UPDATE users SET otp = %s, otp_expiry = %s WHERE email = %s", 
                          (otp, otp_expiry, email))
        else:
            conn.execute("UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?", 
                        (otp, otp_expiry, email))
        
        conn.commit()
        conn.close()
        
        print(f"[DEBUG] OTP saved to database for {email}")
        
        # Send OTP email via SendGrid
        message = Mail(
            from_email='rosales_trinitycamille@plpasig.edu.ph',
            to_emails=email,
            subject='Password Reset OTP - BalikWika',
            html_content=f"""
            <html>
                <body style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>Password Reset Request</h2>
                    <p>Kumusta!</p>
                    <p>Nakatanggap kami ng request para i-reset ang password ng inyong BalikWika account.</p>
                    <p style="font-size: 18px; font-weight: bold; color: #ef4444;">
                        Ang inyong OTP code ay: {otp}
                    </p>
                    <p>Ang OTP na ito ay mag-expire sa loob ng 10 minuto.</p>
                    <p>Kung hindi kayo nag-request ng password reset, pakiignore lang ang email na ito.</p>
                    <br>
                    <p>Salamat,<br>BalikWika Team</p>
                </body>
            </html>
            """
        )
        
        try:
            print(f"[DEBUG] Attempting to send email via SendGrid to {email}")
            
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            response = sg.send(message)
            
            print(f"[SUCCESS] Email sent successfully via SendGrid. Status: {response.status_code}")
            flash("Naipadala na ang OTP sa inyong email. Pakicheck ang inbox.", "success")
            session['reset_email'] = email
            return redirect(url_for('verify_reset_otp'))
            
        except Exception as e:
            print(f"[ERROR] SendGrid error: {e}")
            import traceback
            traceback.print_exc()
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
        cursor = conn.cursor()
        
        try:
            if db_config.is_production:
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()
            else:
                user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            
            if not user:
                cursor.close()
                conn.close()
                flash("Walang user na may email na iyon.", "error")
                return redirect(url_for('forgot_password'))
            
            db_otp = user['otp']
            otp_expiry_raw = user['otp_expiry']
            
            # Handle both string (SQLite) and datetime (PostgreSQL) formats
            if isinstance(otp_expiry_raw, str):
                otp_expiry = datetime.strptime(otp_expiry_raw, '%Y-%m-%d %H:%M:%S')
            else:
                otp_expiry = otp_expiry_raw  # Already a datetime object
            
            if datetime.now() > otp_expiry:
                cursor.close()
                conn.close()
                flash("Nag-expire na ang OTP. Pakisubukang muli.", "error")
                return redirect(url_for('forgot_password'))
            
            if user_input_otp != db_otp:
                cursor.close()
                conn.close()
                flash("Maling OTP. Pakisubukang muli.", "error")
                return redirect(url_for('verify_reset_otp'))
            
            # Generate reset token for secure password reset
            reset_token = generate_reset_token()
            reset_token_expiry = (datetime.now() + timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S')
            
            if db_config.is_production:
                cursor.execute("UPDATE users SET reset_token = %s, reset_token_expiry = %s WHERE email = %s", 
                              (reset_token, reset_token_expiry, email))
            else:
                cursor.execute("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?", 
                            (reset_token, reset_token_expiry, email))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            session['reset_token'] = reset_token
            
            flash("OTP na-verify! Maaari na kayong mag-set ng bagong password.", "success")
            return redirect(url_for('reset_password'))
            
        except Exception as e:
            cursor.close()
            conn.close()
            print(f"[ERROR] verify_reset_otp error: {e}")
            import traceback
            traceback.print_exc()
            flash("May error na nangyari. Pakisubukang muli.", "error")
            return redirect(url_for('forgot_password'))
    
    return render_template('verify_reset_otp.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    reset_token = session.get('reset_token')
    
    if not reset_token:
        print("[DEBUG] No reset token in session")
        flash("Session expired. Please start password reset again.", "error")
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
        cursor = conn.cursor()
        
        try:
            # STEP 1: Get user with reset_token
            if db_config.is_production:
                cursor.execute("SELECT * FROM users WHERE reset_token = %s", (reset_token,))
                user = cursor.fetchone()
            else:
                user = conn.execute("SELECT * FROM users WHERE reset_token = ?", (reset_token,)).fetchone()
            
            # Check if user exists
            if not user:
                cursor.close()
                conn.close()
                flash("Invalid reset token.", "error")
                return redirect(url_for('forgot_password'))
            
            # STEP 2: Check if reset token has expired
            if user['reset_token_expiry']:
                reset_token_expiry_raw = user['reset_token_expiry']
                
                # ✅ FIXED: Handle both string (SQLite) and datetime (PostgreSQL) formats
                if isinstance(reset_token_expiry_raw, str):
                    reset_token_expiry = datetime.strptime(reset_token_expiry_raw, '%Y-%m-%d %H:%M:%S')
                else:
                    reset_token_expiry = reset_token_expiry_raw  # Already a datetime object
                
                if datetime.now() > reset_token_expiry:
                    cursor.close()
                    conn.close()
                    flash("Nag-expire na ang reset token. Pakisubukang muli.", "error")
                    return redirect(url_for('forgot_password'))
            
            # STEP 3: Hash the new password
            password_hash = generate_password_hash(new_password)
            
            # STEP 4: Update password and clear reset token
            if db_config.is_production:
                cursor.execute("""
                    UPDATE users 
                    SET password = %s, reset_token = NULL, reset_token_expiry = NULL, 
                        otp = NULL, otp_expiry = NULL, is_temp_password = FALSE
                    WHERE reset_token = %s
                """, (password_hash, reset_token))
            else:
                # ✅ FIXED: Use cursor.execute() instead of conn.execute()
                cursor.execute("""
                    UPDATE users 
                    SET password = ?, reset_token = NULL, reset_token_expiry = NULL, 
                        otp = NULL, otp_expiry = NULL, is_temp_password = 0
                    WHERE reset_token = ?
                """, (password_hash, reset_token))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            # Clear session
            session.pop('reset_token', None)
            session.pop('reset_email', None)
            
            flash("Matagumpay na na-reset ang password! Maaari na kayong mag-login.", "success")
            return redirect(url_for('login'))
        
        except Exception as e:
            cursor.close()
            conn.close()
            print(f"[ERROR] reset_password error: {e}")
            import traceback
            traceback.print_exc()
            flash("May error na nangyari. Pakisubukang muli.", "error")
            return redirect(url_for('forgot_password'))
    
    return render_template('reset_password.html')

@app.route('/resend_reset_otp')
def resend_reset_otp():
    email = session.get('reset_email')
    if not email:
        return redirect(url_for('forgot_password'))
    
    # Generate new OTP
    otp = ''.join(random.choices(string.digits, k=6))
    otp_expiry = (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # ✅ FIXED: Added database conditionals for both PostgreSQL and SQLite
        if db_config.is_production:
            cursor.execute("UPDATE users SET otp = %s, otp_expiry = %s WHERE email = %s", 
                          (otp, otp_expiry, email))
        else:
            cursor.execute("UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?", 
                          (otp, otp_expiry, email))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print(f"[DEBUG] Resending password reset OTP to {email}: {otp} (expires at {otp_expiry})")
        
        # ✅ FIXED: Send OTP email via SendGrid (not Flask-Mail)
        message = Mail(
            from_email='rosales_trinitycamille@plpasig.edu.ph',
            to_emails=email,
            subject='New Password Reset OTP - BalikWika',
            html_content=f"""
            <html>
                <body style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>New Password Reset OTP</h2>
                    <p>Kumusta!</p>
                    <p>Nakatanggap kami ng request para sa bagong OTP code para sa password reset.</p>
                    <p style="font-size: 18px; font-weight: bold; color: #ef4444;">
                        Ang inyong bagong OTP code ay: {otp}
                    </p>
                    <p>Ang OTP na ito ay mag-expire sa loob ng 10 minuto.</p>
                    <p>Kung hindi kayo nag-request ng password reset, pakiignore lang ang email na ito.</p>
                    <br>
                    <p>Salamat,<br>BalikWika Team</p>
                </body>
            </html>
            """
        )
        
        try:
            print(f"[DEBUG] Attempting to resend password reset OTP via SendGrid to {email}")
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            response = sg.send(message)
            print(f"[SUCCESS] Password reset OTP resent via SendGrid. Status: {response.status_code}")
            flash("Naipadala muli ang OTP sa inyong email!", "success")
        except Exception as e:
            print(f"[ERROR] Failed to resend password reset OTP via SendGrid: {e}")
            import traceback
            traceback.print_exc()
            flash("Hindi naipadala ang OTP. Pakisubukang muli.", "error")
    
    except Exception as e:
        cursor.close()
        conn.close()
        print(f"[ERROR] Database error in resend_reset_otp: {e}")
        import traceback
        traceback.print_exc()
        flash("May error na nangyari. Pakisubukang muli.", "error")
    
    return redirect(url_for('verify_reset_otp'))

@app.route('/check_temp_password')
def check_temp_password():
    """Check if logged-in user has temporary password"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Changed ? to %s for PostgreSQL
    cursor.execute("SELECT is_temp_password FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    # Changed == 1 to check for True (PostgreSQL boolean)
    if user and user['is_temp_password'] is True:
        session['temp_user_id'] = session['user_id']
        flash("Kailangan ninyong i-update ang temporary password.", "info")
        return redirect(url_for('force_password_change'))
    
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Changed ? to %s for PostgreSQL
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Additional check for temporary password (security measure)
    # Changed == 1 to check for True (PostgreSQL boolean)
    if user['is_temp_password'] is True:
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
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()
        
        if not user:
            cursor.close()
            conn.close()
            return redirect(url_for('login'))

        # ✅ FIX: Add data URI prefix for profile picture
        profile_picture = None
        if user['user_profile']:
            if isinstance(user['user_profile'], (bytes, memoryview)):
                img_data = bytes(user['user_profile']) if isinstance(user['user_profile'], memoryview) else user['user_profile']
                profile_picture = f"data:image/jpeg;base64,{base64.b64encode(img_data).decode('utf-8')}"
            elif isinstance(user['user_profile'], str):
                profile_picture = f"data:image/jpeg;base64,{user['user_profile']}"

        cursor.execute('''
            SELECT s.subject_id, s.name, s.description, s.icon, s.color,
                   COUNT(l.lesson_id) AS lesson_count
            FROM subjects s
            LEFT JOIN lessons l ON s.subject_id = l.subject_id
            GROUP BY s.subject_id, s.name, s.description, s.icon, s.color
            ORDER BY s.subject_id
            LIMIT 2
        ''')
        suggested_subjects = cursor.fetchall()

        suggested_topics = [{
            'id': s['subject_id'],
            'name': s['name'],
            'description': s['description'],
            'icon': s['icon'],
            'color': s['color'],
            'lesson_count': s['lesson_count']
        } for s in suggested_subjects]

        cursor.close()
        conn.close()

        return render_template('student_dashboard.html', 
                             user=user, 
                             profile_picture=profile_picture,
                             suggested_topics=suggested_topics)
    
    except Exception as e:
        cursor.close()
        conn.close()
        return render_template('student_dashboard.html', 
                             user=user if 'user' in locals() else None, 
                             profile_picture=None,
                             suggested_topics=[],
                             error=f'Error loading dashboard: {str(e)}')
    
@app.route('/mga_pagsusulit')
@require_role('student')  # Assuming you want only students to access this
def mga_pagsusulit():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Changed ? to %s for PostgreSQL
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        flash("User not found.", "error")
        return redirect(url_for('login'))

    return render_template('mga_pagsusulit.html', user=user)

@app.route('/teacher_dashboard')
@require_role('teacher')
def teacher_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Changed ? to %s for PostgreSQL
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    return render_template('teacher_dashboard.html', user=user)

# --- User Profile Routes ---

@app.route('/profile')
@require_role('student')
def profile():
    """User profile page - accessible by all logged-in users"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('login'))
    
    # ✅ FIX: Add data URI prefix for profile picture
    profile_picture = None
    if user['user_profile']:
        if isinstance(user['user_profile'], (bytes, memoryview)):
            img_data = bytes(user['user_profile']) if isinstance(user['user_profile'], memoryview) else user['user_profile']
            profile_picture = f"data:image/jpeg;base64,{base64.b64encode(img_data).decode('utf-8')}"
        elif isinstance(user['user_profile'], str):
            profile_picture = f"data:image/jpeg;base64,{user['user_profile']}"
    
    return render_template('profile.html', user=user, profile_picture=profile_picture)

# Replace your existing /edit_profile route with this enhanced version
@app.route('/edit_profile', methods=['GET', 'POST'])
@require_role('student')
def edit_profile():
    """Edit user profile information"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Changed ? to %s for PostgreSQL
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    
    if not user:
        flash("User not found.", "error")
        cursor.close()
        conn.close()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        
        # Validate required fields
        if not email:
            flash("Email is required.", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('edit_profile'))
        
        # Check if email is already taken by another user
        # Changed ? to %s for PostgreSQL
        cursor.execute("SELECT id FROM users WHERE email = %s AND id != %s", 
                      (email, session['user_id']))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash("Email already taken by another user.", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('edit_profile'))
        
        # Update user information
        # Changed ? to %s for PostgreSQL
        cursor.execute("""
            UPDATE users 
            SET first_name = %s, last_name = %s, email = %s
            WHERE id = %s
        """, (first_name, last_name, email, session['user_id']))
        conn.commit()
        cursor.close()
        conn.close()
        
        # Update session email if it changed
        session['user_email'] = email
        
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))
    
    cursor.close()
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
    cursor = conn.cursor()
    
    # Changed ? to %s for PostgreSQL
    cursor.execute(
        'SELECT id FROM users WHERE email = %s AND id != %s',
        (email, user_id)
    )
    existing_user = cursor.fetchone()
    
    if existing_user:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Email already exists'})
    
    # Update user information
    try:
        # Changed ? to %s for PostgreSQL
        cursor.execute(
            'UPDATE users SET first_name = %s, last_name = %s, email = %s WHERE id = %s',
            (first_name, last_name, email, user_id)
        )
        conn.commit()
        cursor.close()
        conn.close()
        
        # Update session email
        session['user_email'] = email
        
        return jsonify({'success': True, 'message': 'Profile updated successfully'})
    except Exception as e:
        cursor.close()
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
    cursor = conn.cursor()
    
    # Changed ? to %s for PostgreSQL
    cursor.execute('SELECT password FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    
    if not user or not check_password_hash(user['password'], current_password):
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Current password is incorrect'})
    
    # Update password
    try:
        hashed_password = generate_password_hash(new_password)
        # Changed ? to %s and 0 to FALSE for PostgreSQL
        cursor.execute(
            'UPDATE users SET password = %s, is_temp_password = FALSE WHERE id = %s',
            (hashed_password, user_id)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Password changed successfully'})
    except Exception as e:
        cursor.close()
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
    
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    if not ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
        return jsonify({'success': False, 'message': 'Invalid file type'})
    
    try:
        import psycopg2
        
        image = Image.open(file.stream)
        if image.mode in ('RGBA', 'LA'):
            background = Image.new('RGB', image.size, (255, 255, 255))
            background.paste(image, mask=image.split()[-1])
            image = background
        
        max_size = (400, 400)
        image.thumbnail(max_size, Image.Resampling.LANCZOS)
        
        img_bytes = io.BytesIO()
        image.save(img_bytes, format='JPEG', quality=85)
        img_data = img_bytes.getvalue()
        img_base64 = base64.b64encode(img_data).decode('utf-8')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Store as binary (BYTEA) in PostgreSQL
        cursor.execute(
            'UPDATE users SET user_profile = %s WHERE id = %s',
            (psycopg2.Binary(img_data), session['user_id'])
        )
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Profile picture updated successfully',
            'profile_picture': f"data:image/jpeg;base64,{img_base64}"
        })
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Upload failed: {str(e)}'})

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
       
       cursor = conn.cursor()
       
       # Changed ? to %s for PostgreSQL
       cursor.execute(
           'UPDATE users SET user_profile = NULL WHERE id = %s',
           (session['user_id'],)
       )
       conn.commit()
       cursor.close()
       conn.close()

       return jsonify({
           'success': True,
           'message': 'Profile picture removed successfully'
       })

   except Exception as e:
       import traceback
       traceback.print_exc()
       return jsonify({'success': False, 'message': f'Failed to remove profile picture: {str(e)}'})
   
   

# --- Lessons Routes ---
@app.route('/mga_aralin')
@require_role('student')
def mga_aralin():
    """Student dashboard for viewing lessons by subject."""
    return render_template('mga_aralin.html')


@app.route('/get_subjects')
@require_role('student')
def get_subjects():
    """Fetch all subjects and their lesson counts for students."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Added all non-aggregated columns to GROUP BY for PostgreSQL
        cursor.execute('''
            SELECT s.subject_id, s.name, s.description, s.icon, s.color,
                   COUNT(l.lesson_id) AS lesson_count
            FROM subjects s
            LEFT JOIN lessons l ON s.subject_id = l.subject_id
            GROUP BY s.subject_id, s.name, s.description, s.icon, s.color
            ORDER BY s.subject_id
        ''')
        subjects = cursor.fetchall()

        result = [{
            'id': s['subject_id'],
            'name': s['name'],
            'description': s['description'],
            'icon': s['icon'],
            'color': s['color'],
            'lesson_count': s['lesson_count']
        } for s in subjects]

        cursor.close()
        conn.close()
        return jsonify(result)
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({'error': f'Error fetching subjects: {str(e)}'}), 500


@app.route('/get_lessons')
@require_role('student')
def get_lessons():
    """Fetch lessons grouped by subject for student view."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Prepare dictionary for all subjects
        cursor.execute('SELECT name FROM subjects')
        subjects = cursor.fetchall()
        data = {subject['name']: [] for subject in subjects}

        # Get lessons with subject + teacher info
        cursor.execute('''
            SELECT l.lesson_id, l.title, l.content, l.created_at,
                   s.name AS subject_name,
                   u.first_name, u.last_name
            FROM lessons l
            JOIN subjects s ON l.subject_id = s.subject_id
            JOIN users u ON l.teacher_id = u.id
            ORDER BY l.created_at DESC
        ''')
        lessons = cursor.fetchall()

        # Build JSON response
        for lesson in lessons:
            subject_name = lesson['subject_name']
            teacher_name = f"{lesson['first_name'] or ''} {lesson['last_name'] or ''}".strip() or "Guro"

            if subject_name in data:
                data[subject_name].append({
                    "id": lesson['lesson_id'],
                    "title": lesson['title'],
                    "content": lesson['content'],
                    "teacher": teacher_name,
                    "date": lesson['created_at']
                })

        cursor.close()
        conn.close()
        return jsonify(data)
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({'error': f'Error fetching lessons: {str(e)}'}), 500
    
@app.route('/get_lesson_videos/<int:lesson_id>')
@require_role('student')
def get_lesson_videos(lesson_id):
    """Fetch videos for a specific lesson (student view)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Changed ? to %s for PostgreSQL
        cursor.execute('''
            SELECT id, video_filename, original_filename, file_size, uploaded_at
            FROM lesson_videos
            WHERE lesson_id = %s
            ORDER BY uploaded_at DESC
        ''', (lesson_id,))
        videos = cursor.fetchall()
        
        videos_list = []
        for video in videos:
            videos_list.append({
                'id': video['id'],
                'filename': video['video_filename'],
                'original_filename': video['original_filename'],
                'file_size': video['file_size'],
                'uploaded_at': video['uploaded_at'],
                'video_url': f'/static/uploads/videos/{video["video_filename"]}'
            })
        
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'videos': videos_list}), 200
        
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500


# Quiz route

@app.route('/get_all_quizzes', methods=['GET'])
def get_all_quizzes():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT id, title, created_at FROM quizzes ORDER BY title')
        quizzes = cursor.fetchall()
        
        result = []
        for quiz in quizzes:
            # Changed ? to %s for PostgreSQL
            cursor.execute('''
                SELECT 
                    id,
                    question_text, 
                    choice_a, 
                    choice_b, 
                    choice_c, 
                    choice_d, 
                    correct_answer, 
                    image,
                    trivia
                FROM questions
                WHERE quiz_id = %s
                ORDER BY id
            ''', (quiz['id'],))
            questions = cursor.fetchall()
            
            result.append({
                'id': quiz['id'],
                'title': quiz['title'],
                'created_at': quiz['created_at'],
                'questions': [dict(q) for q in questions]
            })
        
        cursor.close()
        conn.close()
        
        # Prevent caching
        response = make_response(jsonify(result))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
        
    except Exception as e:
        cursor.close()
        conn.close()
        print(f"Error getting quizzes: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Add this route for STUDENTS (around line 1200, before the teacher route)
@app.route('/student/api/quizzes/mastery', methods=['GET'])
def get_student_quizzes_by_mastery():
    """Get quizzes organized by mastery level - FOR STUDENTS"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    # Students only
    if session.get('user_role') != 'student':
        return jsonify({'success': False, 'message': 'Students only'}), 403
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all quizzes with their mastery levels
        # Added all non-aggregated columns to GROUP BY for PostgreSQL
        cursor.execute('''
            SELECT 
                q.id,
                q.title,
                q.mastery_level,
                COUNT(qs.id) as question_count
            FROM quizzes q
            LEFT JOIN questions qs ON q.id = qs.quiz_id
            GROUP BY q.id, q.title, q.mastery_level
            ORDER BY q.mastery_level, q.title
        ''')
        quizzes = cursor.fetchall()
        
        print(f"[DEBUG] Found {len(quizzes)} quizzes for student")
        
        # Organize quizzes by mastery level
        quizzes_by_mastery = {
            'baguhan': [],
            'katamtaman': [],
            'dalubhasa': []
        }
        
        for quiz in quizzes:
            # Handle NULL mastery_level safely
            mastery_raw = quiz['mastery_level']
            
            if not mastery_raw:
                mastery_key = 'baguhan'
            else:
                mastery_key = mastery_raw.lower().strip()
            
            # Map English to Filipino terms
            mastery_map = {
                'beginner': 'baguhan',
                'intermediate': 'katamtaman',
                'advanced': 'dalubhasa',
                'baguhan': 'baguhan',
                'katamtaman': 'katamtaman',
                'dalubhasa': 'dalubhasa'
            }
            
            mastery_key = mastery_map.get(mastery_key, 'baguhan')
            
            print(f"[DEBUG] Quiz '{quiz['title']}' -> '{mastery_key}' ({quiz['question_count']} questions)")
            
            # Only include quizzes that have questions
            if quiz['question_count'] > 0:
                quizzes_by_mastery[mastery_key].append({
                    'id': quiz['id'],
                    'title': quiz['title'],
                    'mastery_level': mastery_key,
                    'question_count': quiz['question_count']
                })
        
        cursor.close()
        conn.close()
        
        print(f"[DEBUG] Returning quizzes: {quizzes_by_mastery}")
        
        return jsonify({
            'success': True,
            'quizzes': quizzes_by_mastery
        })
        
    except Exception as e:
        print(f"[ERROR] Error getting quizzes: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# Also add the student quiz details route
@app.route('/student/api/quiz/<int:quiz_id>/details', methods=['GET'])
def get_student_quiz_details(quiz_id):
    """Get quiz details - FOR STUDENTS"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    # Students only
    if session.get('user_role') != 'student':
        return jsonify({'success': False, 'message': 'Students only'}), 403
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get quiz info
        cursor.execute('SELECT * FROM quizzes WHERE id = %s', (quiz_id,))
        quiz = cursor.fetchone()
        
        if not quiz:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Quiz not found'}), 404
        
        # Get questions with image
        cursor.execute('''
            SELECT 
                id,
                question_text,
                choice_a,
                choice_b,
                choice_c,
                choice_d,
                correct_answer,
                image,
                trivia
            FROM questions
            WHERE quiz_id = %s
            ORDER BY id
        ''', (quiz_id,))
        questions = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        print(f"[DEBUG] Quiz {quiz_id} has {len(questions)} questions")
        
        # Convert questions to list of dicts with proper image handling
        questions_list = []
        for q in questions:
            # Handle image field
            image_data = None
            if q['image']:
                try:
                    if isinstance(q['image'], memoryview):
                        # Convert memoryview to bytes then to base64
                        import base64
                        img_bytes = q['image'].tobytes()
                        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
                        image_data = f'data:image/jpeg;base64,{img_base64}'
                    elif isinstance(q['image'], bytes):
                        # Convert bytes to base64
                        import base64
                        img_base64 = base64.b64encode(q['image']).decode('utf-8')
                        image_data = f'data:image/jpeg;base64,{img_base64}'
                    elif isinstance(q['image'], str):
                        # Already a string (base64 or URL)
                        if q['image'].startswith('data:'):
                            image_data = q['image']
                        else:
                            image_data = f'data:image/jpeg;base64,{q["image"]}'
                except Exception as img_err:
                    print(f"[ERROR] Failed to process image for question {q['id']}: {img_err}")
                    image_data = None
            
            questions_list.append({
                'id': q['id'],
                'question_text': q['question_text'],
                'choice_a': q['choice_a'],
                'choice_b': q['choice_b'],
                'choice_c': q['choice_c'],
                'choice_d': q['choice_d'],
                'correct_answer': q['correct_answer'],
                'trivia': q['trivia'],
                'image': image_data
            })
        
        return jsonify({
            'success': True,
            'quiz': {
                'id': quiz['id'],
                'title': quiz['title'],
                'mastery_level': quiz['mastery_level'],
                'questions': questions_list
            }
        })
        
    except Exception as e:
        print(f"[ERROR] Error getting quiz details: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/get_student_mastery_level')
def get_student_mastery_level():
    if 'user_id' not in session or session.get('user_role') != 'student':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        conn = get_db_connection()
        from teacher.ml_classifier_sklearn import calculate_student_metrics
        
        metrics = calculate_student_metrics(session['user_id'], conn)
        mastery_level = metrics['mastery_level']  # 'Beginner', 'Intermediate', 'Advanced'
        
        # Convert to lowercase for consistency
        mastery_level = mastery_level.lower()
        
        conn.close()
        
        return jsonify({
            'success': True,
            'mastery_level': mastery_level  # Returns: 'beginner', 'intermediate', or 'advanced'
        })
    except Exception as e:
        print(f"Error getting student mastery level: {e}")
        return jsonify({
            'success': False,
            'mastery_level': 'beginner'  # Default fallback (lowercase)
        })
    
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

@app.route('/teacher/submit_quiz_result', methods=['POST'])
def submit_quiz_result():
    """Record student quiz attempt and result in database"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    try:
        data = request.get_json()
        quiz_id = data.get('quiz_id')
        score = data.get('score')
        total_questions = data.get('total_questions')
        
        if not quiz_id or score is None or not total_questions:
            return jsonify({'success': False, 'message': 'Missing required data'}), 400
        
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Calculate current attempt number
        # Changed ? to %s for PostgreSQL
        cursor.execute(
            'SELECT COUNT(*) as count FROM quiz_attempts WHERE user_id = %s AND quiz_id = %s',
            (user_id, quiz_id)
        )
        attempt_count = cursor.fetchone()
        
        attempt_number = attempt_count['count'] + 1 if attempt_count else 1
        
        # Insert into quiz_attempts table
        # Changed ? to %s and CURRENT_TIMESTAMP to NOW() for PostgreSQL
        cursor.execute('''
            INSERT INTO quiz_attempts (user_id, quiz_id, score, attempt_number, attempted_at)
            VALUES (%s, %s, %s, %s, NOW())
        ''', (user_id, quiz_id, score, attempt_number))
        
        # Check if user has previous result for this quiz
        # Changed ? to %s for PostgreSQL
        cursor.execute(
            'SELECT * FROM quiz_results WHERE user_id = %s AND quiz_id = %s',
            (user_id, quiz_id)
        )
        existing_result = cursor.fetchone()
        
        if existing_result:
            # Update if new score is better, or just increment attempt count
            if score > existing_result['score']:
                # Changed ? to %s and CURRENT_TIMESTAMP to NOW() for PostgreSQL
                cursor.execute('''
                    UPDATE quiz_results 
                    SET score = %s, attempt_count = %s, date_taken = NOW()
                    WHERE user_id = %s AND quiz_id = %s
                ''', (score, attempt_number, user_id, quiz_id))
            else:
                # Changed ? to %s for PostgreSQL
                cursor.execute('''
                    UPDATE quiz_results 
                    SET attempt_count = %s
                    WHERE user_id = %s AND quiz_id = %s
                ''', (attempt_number, user_id, quiz_id))
        else:
            # Insert new result
            # Changed ? to %s and CURRENT_TIMESTAMP to NOW() for PostgreSQL
            cursor.execute('''
                INSERT INTO quiz_results (user_id, quiz_id, score, date_taken, attempt_count)
                VALUES (%s, %s, %s, NOW(), %s)
            ''', (user_id, quiz_id, score, attempt_number))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Quiz result saved successfully',
            'attempt_number': attempt_number,
            'score': score,
            'total': total_questions
        })
        
    except Exception as e:
        print(f"Error saving quiz result: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500
    

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)