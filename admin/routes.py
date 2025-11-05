from flask import Blueprint, render_template, url_for, request, jsonify, redirect, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import csv
from io import StringIO
from flask import request, jsonify, send_file, Response

# Import database configuration
from database_config import get_db_connection, db_config

admin_bp = Blueprint('admin', __name__, template_folder='templates', static_folder='static', url_prefix='/admin')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route('/')
def index():
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    if db_config.is_production:
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'student'")
        total_students = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'teacher'")
        total_teachers = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active' AND role = 'student'")
        active_students = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active' AND role = 'teacher'")
        active_teachers = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'pending' AND role = 'student'")
        pending_students = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'pending' AND role = 'teacher'")
        pending_teachers = cursor.fetchone()['count']

        cursor.execute("SELECT DATE(registered_at), COUNT(*) FROM users WHERE role = 'student' GROUP BY DATE(registered_at)")
        student_dates_rows = cursor.fetchall()
        student_dates = {row['date']: row['count'] for row in student_dates_rows}

        cursor.execute("SELECT DATE(registered_at), COUNT(*) FROM users WHERE role = 'teacher' GROUP BY DATE(registered_at)")
        teacher_dates_rows = cursor.fetchall()
        teacher_dates = {row['date']: row['count'] for row in teacher_dates_rows}

    else:
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'student'")
        total_students = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'teacher'")
        total_teachers = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active' AND role = 'student'")
        active_students = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active' AND role = 'teacher'")
        active_teachers = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'pending' AND role = 'student'")
        pending_students = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'pending' AND role = 'teacher'")
        pending_teachers = cursor.fetchone()[0]

        cursor.execute("SELECT DATE(registered_at), COUNT(*) FROM users WHERE role = 'student' GROUP BY DATE(registered_at)")
        student_dates = dict(cursor.fetchall())

        cursor.execute("SELECT DATE(registered_at), COUNT(*) FROM users WHERE role = 'teacher' GROUP BY DATE(registered_at)")
        teacher_dates = dict(cursor.fetchall())

    conn.close()

    total_registered = total_students + total_teachers
    total_active = active_students + active_teachers
    pending_accounts = pending_students + pending_teachers

    all_dates = sorted(
        d for d in set(student_dates.keys()) | set(teacher_dates.keys()) if d is not None
    )

    registration_data = [
        {
            "date": str(date),
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
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if db_config.is_production:
        cursor.execute("SELECT id, email, first_name, last_name, registered_at, status FROM users WHERE role = 'student'")
        rows = cursor.fetchall()
    else:
        cursor.execute("SELECT id, email, first_name, last_name, registered_at, status FROM users WHERE role = 'student'")
        rows = cursor.fetchall()
    
    conn.close()

    students_data = [
        {
            'id': row[0] if isinstance(row, tuple) else row['id'],
            'email': row[1] if isinstance(row, tuple) else row['email'],
            'first_name': (row[2] if isinstance(row, tuple) else row['first_name']) or '',
            'last_name': (row[3] if isinstance(row, tuple) else row['last_name']) or '',
            'registered_at': (row[4] if isinstance(row, tuple) else row['registered_at']) or 'N/A',
            'status': (row[5] if isinstance(row, tuple) else row['status']) if (row[5] if isinstance(row, tuple) else row['status']) in ['active', 'inactive'] else 'pending'
        } for row in rows
    ]

    return render_template('students.html', students=students_data)


@admin_bp.route('/bulk-upload-students', methods=['POST'])
def bulk_upload_students():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not file.filename.endswith('.csv'):
        return jsonify({'success': False, 'message': 'Only CSV files are allowed'}), 400
    
    try:
        stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.DictReader(stream)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        added_count = 0
        errors = []
        
        for row in csv_reader:
            try:
                # Validate required fields
                if not all(key in row for key in ['first_name', 'last_name', 'email', 'password']):
                    errors.append(f"Missing required fields in row")
                    continue
                
                # Check if email already exists
                if db_config.is_production:
                    cursor.execute("SELECT id FROM users WHERE email = %s", (row['email'],))
                    existing = cursor.fetchone()
                else:
                    cursor.execute("SELECT id FROM users WHERE email = ?", (row['email'],))
                    existing = cursor.fetchone()
                
                if existing:
                    errors.append(f"Email {row['email']} already exists")
                    continue
                
                # Add student to database with temporary password
                registered_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                hashed_password = generate_password_hash(row['password'])
                
                if db_config.is_production:
                    cursor.execute(
                        "INSERT INTO users (first_name, last_name, email, password, registered_at, status, role, is_temp_password) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (row['first_name'], row['last_name'], row['email'], hashed_password, registered_at, 'active', 'student', 1)
                    )
                else:
                    cursor.execute(
                        "INSERT INTO users (first_name, last_name, email, password, registered_at, status, role, is_temp_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (row['first_name'], row['last_name'], row['email'], hashed_password, registered_at, 'active', 'student', 1)
                    )
                
                added_count += 1
                
            except Exception as e:
                errors.append(f"Error adding student {row.get('email', 'unknown')}: {str(e)}")
        
        conn.commit()
        conn.close()
        
        message = f"Successfully added {added_count} students."
        if errors:
            message += f" {len(errors)} errors occurred."
        
        return jsonify({'success': True, 'message': message, 'added': added_count, 'errors': errors})
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/download-template')
def download_template():
    # Create a CSV template
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['first_name', 'last_name', 'email', 'password'])
    writer.writerow(['Juan', 'Dela Cruz', 'juan.delacruz@example.com', 'TempPass123'])
    writer.writerow(['Maria', 'Santos', 'maria.santos@example.com', 'TempPass456'])
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=student_template.csv'}
    )


@admin_bp.route('/update-status', methods=['POST'])
def update_status():
    data = request.get_json()
    user_id = data.get('id')
    new_status = data.get('status', '').lower()
    user_type = data.get('type')  # 'student' or 'teacher'

    if new_status not in ['active', 'inactive'] or not user_id or user_type not in ['student', 'teacher']:
        return jsonify({'message': 'Invalid input'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if db_config.is_production:
            cursor.execute("UPDATE users SET status = %s WHERE id = %s AND role = %s", (new_status, user_id, user_type))
        else:
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
        placeholders = ','.join(['%s' if db_config.is_production else '?'] * len(ids))
        query = f"DELETE FROM users WHERE id IN ({placeholders}) AND role = {'%s' if db_config.is_production else '?'}"

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, (*ids, user_type))
        conn.commit()
        conn.close()

        return jsonify({'message': 'Users deleted successfully'})
    except Exception as e:
        print("Error deleting users:", e)
        return jsonify({'message': 'Failed to delete users'}), 500


@admin_bp.route('/teachers', methods=['GET', 'POST'])
@login_required
def teachers():
    conn = get_db_connection()
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
        is_temp_password = 1

        # Check if email already exists
        if db_config.is_production:
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            existing = cursor.fetchone()
        else:
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            existing = cursor.fetchone()
        
        if existing:
            conn.close()
            flash('Email already exists.', 'error')
            return redirect(url_for('admin.teachers'))

        # Insert into unified users table
        if db_config.is_production:
            cursor.execute(
                "INSERT INTO users (first_name, last_name, email, password, registered_at, status, role, is_temp_password) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (first_name, last_name, email, hashed_password, registered_at, status, role, is_temp_password)
            )
        else:
            cursor.execute(
                "INSERT INTO users (first_name, last_name, email, password, registered_at, status, role, is_temp_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (first_name, last_name, email, hashed_password, registered_at, status, role, is_temp_password)
            )
        
        conn.commit()
        conn.close()

        flash('Teacher added successfully.', 'success')
        return redirect(url_for('admin.teachers'))

    # GET: Display existing teachers
    if db_config.is_production:
        cursor.execute("SELECT id, email, first_name, last_name, registered_at, status FROM users WHERE role = 'teacher'")
        rows = cursor.fetchall()
    else:
        cursor.execute("SELECT id, email, first_name, last_name, registered_at, status FROM users WHERE role = 'teacher'")
        rows = cursor.fetchall()
    
    conn.close()

    teachers_data = [
        {
            'id': row[0] if isinstance(row, tuple) else row['id'],
            'email': row[1] if isinstance(row, tuple) else row['email'],
            'first_name': (row[2] if isinstance(row, tuple) else row['first_name']) or '',
            'last_name': (row[3] if isinstance(row, tuple) else row['last_name']) or '',
            'registered_at': (row[4] if isinstance(row, tuple) else row['registered_at']) or 'N/A',
            'status': (row[5] if isinstance(row, tuple) else row['status']) or 'pending'
        } for row in rows
    ]

    return render_template('teachers.html', teachers=teachers_data)


@admin_bp.route('/update-teacher-status', methods=['POST'])
def update_teacher_status():
    data = request.get_json()
    teacher_id = data['id']
    new_status = data['status']

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if db_config.is_production:
            cursor.execute("UPDATE users SET status = %s WHERE id = %s AND role = 'teacher'", (new_status, teacher_id))
        else:
            cursor.execute("UPDATE users SET status = ? WHERE id = ? AND role = 'teacher'", (new_status, teacher_id))
        
        conn.commit()
        conn.close()
        return jsonify({'message': 'Teacher status updated successfully'})
    except Exception as e:
        print("Error updating teacher status:", e)
        return jsonify({'message': 'Failed to update teacher status'}), 500


@admin_bp.route('/print-teachers')
def print_teachers():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if db_config.is_production:
        cursor.execute("""
            SELECT id, first_name, last_name, email, registered_at, status 
            FROM users 
            WHERE role = 'teacher'
        """)
        rows = cursor.fetchall()
    else:
        cursor.execute("""
            SELECT id, first_name, last_name, email, registered_at, status 
            FROM users 
            WHERE role = 'teacher'
        """)
        rows = cursor.fetchall()
    
    conn.close()

    teachers_data = [
        {
            'id': row[0] if isinstance(row, tuple) else row['id'],
            'first_name': row[1] if isinstance(row, tuple) else row['first_name'],
            'last_name': row[2] if isinstance(row, tuple) else row['last_name'],
            'email': row[3] if isinstance(row, tuple) else row['email'],
            'registered_at': (row[4] if isinstance(row, tuple) else row['registered_at']) or 'N/A',
            'status': (row[5] if isinstance(row, tuple) else row['status']) or 'inactive'
        } for row in rows
    ]

    return render_template('print_teachers.html', teachers=teachers_data)


@admin_bp.route('/print-students')
def print_students():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if db_config.is_production:
        cursor.execute("""
            SELECT id, first_name, last_name, email, registered_at, status 
            FROM users 
            WHERE role = 'student'
        """)
        students = cursor.fetchall()
    else:
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

    conn = get_db_connection()
    cursor = conn.cursor()
    
    if db_config.is_production:
        cursor.execute("SELECT id, first_name, last_name, email FROM users WHERE id = %s", (session['user_id'],))
        row = cursor.fetchone()
    else:
        cursor.execute("SELECT id, first_name, last_name, email FROM users WHERE id = ?", (session['user_id'],))
        row = cursor.fetchone()
    
    conn.close()

    admin_info = {
        'id': row[0] if isinstance(row, tuple) else row['id'],
        'first_name': row[1] if isinstance(row, tuple) else row['first_name'],
        'last_name': row[2] if isinstance(row, tuple) else row['last_name'],
        'email': row[3] if isinstance(row, tuple) else row['email']
    } if row else {}

    return render_template('account_management.html', admin=admin_info)


@admin_bp.route('/change-password', methods=['POST'])
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        return redirect(url_for('admin.account', message='mismatch'))

    admin_id = session.get('user_id')

    if not admin_id:
        return redirect(url_for('admin.account', message='unauthorized'))

    conn = get_db_connection()
    cursor = conn.cursor()
    
    if db_config.is_production:
        cursor.execute("SELECT password FROM users WHERE id = %s AND role = 'admin'", (admin_id,))
        result = cursor.fetchone()
    else:
        cursor.execute("SELECT password FROM users WHERE id = ? AND role = 'admin'", (admin_id,))
        result = cursor.fetchone()

    if not result:
        conn.close()
        return redirect(url_for('admin.account', message='notfound'))

    stored_password = result[0] if isinstance(result, tuple) else result['password']

    if not check_password_hash(stored_password, current_password):
        conn.close()
        return redirect(url_for('admin.account', message='incorrect'))

    hashed_password = generate_password_hash(new_password)
    
    if db_config.is_production:
        cursor.execute("UPDATE users SET password = %s WHERE id = %s AND role = 'admin'", (hashed_password, admin_id))
    else:
        cursor.execute("UPDATE users SET password = ? WHERE id = ? AND role = 'admin'", (hashed_password, admin_id))
    
    conn.commit()
    conn.close()

    return redirect(url_for('admin.account', message='success'))


@admin_bp.route('/reports')
def reports():
    conn = get_db_connection()
    cursor = conn.cursor()

    if db_config.is_production:
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
    else:
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


@admin_bp.route('/prc')
def prc():
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('login'))

    return render_template('prc.html')


@admin_bp.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_role', None)
    flash("Admin successfully logged out.", "info")
    return redirect(url_for('login'))