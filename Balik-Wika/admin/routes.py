from flask import Blueprint, render_template, url_for, request, jsonify, redirect, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
from functools import wraps

admin_bp = Blueprint('admin', __name__, template_folder='templates', static_folder='static', url_prefix='/admin')

def get_db():
    return sqlite3.connect('balikwika.db', check_same_thread=False)

@admin_bp.route('/')
def index():
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'student'")
    total_students = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'teacher'")
    total_teachers = cursor.fetchone()[0]

    total_registered = total_students + total_teachers

    cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active' AND role = 'student'")
    active_students = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active' AND role = 'teacher'")
    active_teachers = cursor.fetchone()[0]

    total_active = active_students + active_teachers

    cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'pending' AND role = 'student'")
    pending_students = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'pending' AND role = 'teacher'")
    pending_teachers = cursor.fetchone()[0]

    pending_accounts = pending_students + pending_teachers

    cursor.execute("SELECT DATE(registered_at), COUNT(*) FROM users WHERE role = 'student' GROUP BY DATE(registered_at)")
    student_dates = dict(cursor.fetchall())

    cursor.execute("SELECT DATE(registered_at), COUNT(*) FROM users WHERE role = 'teacher' GROUP BY DATE(registered_at)")
    teacher_dates = dict(cursor.fetchall())

    conn.close()

    all_dates = sorted(
    d for d in set(student_dates.keys()) | set(teacher_dates.keys()) if d is not None
)

    registration_data = [
        {
            "date": date,
            "users": student_dates.get(date, 0),
            "teachers": teacher_dates.get(date, 0)
        }
        for date in all_dates
    ]

    return render_template(
        'index.html',
        total_users=total_registered,
        active_users=total_active,
        total_users_only=total_students,
        total_teachers=total_teachers,
        registration_data=registration_data,
        pending_accounts=pending_accounts
    )

@admin_bp.route('/students')
def students():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, first_name, last_name, registered_at, status FROM users WHERE role = 'student'")
    rows = cursor.fetchall()
    conn.close()

    students_data = [
        {
            'id': row[0],
            'email': row[1],
            'first_name': row[2] or '',
            'last_name': row[3] or '',
            'registered_at': row[4] or 'N/A',
            'status': row[5] if row[5] in ['active', 'inactive'] else 'pending'
        } for row in rows
    ]

    return render_template('students.html', students=students_data)


@admin_bp.route('/update-status', methods=['POST'])
def update_status():
    data = request.get_json()
    user_id = data.get('id')
    new_status = data.get('status', '').lower()
    user_type = data.get('type')  # 'student' or 'teacher'

    if new_status not in ['active', 'inactive'] or not user_id or user_type not in ['student', 'teacher']:
        return jsonify({'message': 'Invalid input'}), 400

    try:
        conn = get_db()
        cursor = conn.cursor()
        # Update in users table and filter by role
        cursor.execute("UPDATE users SET status = ? WHERE id = ? AND role = ?", (new_status, user_id, user_type))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Status updated successfully'})
    except Exception as e:
        print("Error updating status:", e)
        return jsonify({'message': 'Failed to update status'}), 500



@admin_bp.route('/delete-users', methods=['POST'])
def delete_users():
    data = request.get_json()
    ids = data.get('ids', [])
    user_type = data.get('type')  # 'student' or 'teacher'

    # Validate input
    if not ids or user_type not in ['student', 'teacher']:
        return jsonify({'message': 'Invalid input'}), 400

    try:
        ids = list(map(int, ids))  # Ensure all IDs are integers
        placeholders = ','.join(['?'] * len(ids))
        query = f"DELETE FROM users WHERE id IN ({placeholders}) AND role = ?"

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(query, (*ids, user_type))
        conn.commit()
        conn.close()

        return jsonify({'message': 'Users deleted successfully'})
    except Exception as e:
        print("Error deleting users:", e)
        return jsonify({'message': 'Failed to delete users'}), 500


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route('/teachers', methods=['GET', 'POST'])
@login_required
def teachers():
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        registered_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        status = 'pending'
        role = 'teacher'
        is_temp_password = 1  # ✅ Set to 1 for newly added teachers

        # ✅ Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        existing = cursor.fetchone()
        if existing:
            conn.close()
            flash('Email already exists.', 'error')
            return redirect(url_for('admin.teachers'))

        # ✅ Insert into unified users table
        cursor.execute(
            "INSERT INTO users (first_name, last_name, email, password, registered_at, status, role, is_temp_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (first_name, last_name, email, hashed_password, registered_at, status, role, is_temp_password)
        )
        conn.commit()
        conn.close()

        flash('Teacher added successfully.', 'success')
        return redirect(url_for('admin.teachers'))

    # GET: Display existing teachers
    cursor.execute("SELECT id, email, first_name, last_name, registered_at, status FROM users WHERE role = 'teacher'")
    rows = cursor.fetchall()
    conn.close()

    teachers_data = [
        {
            'id': row[0],
            'email': row[1],
            'first_name': row[2] or '',
            'last_name': row[3] or '',
            'registered_at': row[4] or 'N/A',
            'status': row[5] or 'pending'
        } for row in rows
    ]

    return render_template('teachers.html', teachers=teachers_data)


@admin_bp.route('/update-teacher-status', methods=['POST'])
def update_teacher_status():
    data = request.get_json()
    teacher_id = data['id']
    new_status = data['status']

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status = ? WHERE id = ? AND role = 'teacher'", (new_status, teacher_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Teacher status updated successfully'})
    except Exception as e:
        print("Error updating teacher status:", e)
        return jsonify({'message': 'Failed to update teacher status'}), 500



@admin_bp.route('/print-teachers')
def print_teachers():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, first_name, last_name, email, registered_at, status 
        FROM users 
        WHERE role = 'teacher'
    """)
    rows = cursor.fetchall()
    conn.close()

    teachers_data = [
        {
            'id': row[0],
            'first_name': row[1],
            'last_name': row[2],
            'email': row[3],
            'registered_at': row[4] or 'N/A',
            'status': row[5] or 'inactive'
        } for row in rows
    ]

    return render_template('print_teachers.html', teachers=teachers_data)

@admin_bp.route('/print-students')
def print_students():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, first_name, last_name, email, registered_at, status 
        FROM users 
        WHERE role = 'student'
    """)
    students = cursor.fetchall()
    conn.close()
    return render_template('print_students.html', students=students)


@admin_bp.route('/account')
def account():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        flash("Unauthorized", "error")
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, first_name, last_name, email FROM users WHERE id = ?", (session['user_id'],))
    row = cursor.fetchone()
    conn.close()

    admin_info = {
        'id': row[0],
        'first_name': row[1],
        'last_name': row[2],
        'email': row[3]
    } if row else {}

    return render_template('account_management.html', admin=admin_info)


@admin_bp.route('/change-password', methods=['POST'])
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        return redirect(url_for('admin.account', message='mismatch'))

    # Get the currently logged-in admin's ID from session
    admin_id = session.get('user_id')

    if not admin_id:
        return redirect(url_for('admin.account', message='unauthorized'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE id = ? AND role = 'admin'", (admin_id,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return redirect(url_for('admin.account', message='notfound'))

    stored_password = result[0]

    if not check_password_hash(stored_password, current_password):
        conn.close()
        return redirect(url_for('admin.account', message='incorrect'))

    hashed_password = generate_password_hash(new_password)
    cursor.execute("UPDATE users SET password = ? WHERE id = ? AND role = 'admin'", (hashed_password, admin_id))
    conn.commit()
    conn.close()

    return redirect(url_for('admin.account', message='success'))


@admin_bp.route('/reports')
def reports():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, first_name, last_name, email, registered_at, status 
        FROM users 
        WHERE role = 'teacher'
    """)
    teachers = cursor.fetchall()

    cursor.execute("""
        SELECT id, email, first_name, last_name, registered_at, status 
        FROM users 
        WHERE role = 'student'
    """)
    students = cursor.fetchall()

    cursor.execute("""
        SELECT id, first_name, last_name, email 
        FROM users 
        WHERE role = 'admin'
    """)
    admins = cursor.fetchall()

    conn.close()

    return render_template('reports.html', teachers=teachers, users=students, admins=admins)

@admin_bp.route('/logout')
def logout():
    session.pop('admin_id', None)  # Remove only admin session
    flash("Admin successfully logged out.", "info")
    return redirect(url_for('login'))  # Assuming main app login route is still 'login'
