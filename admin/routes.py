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

# ============================================
# HELPER FUNCTIONS FOR ACTIVITY TRACKING
# ============================================

def log_activity(user_id, activity_type, content_id, content_type):
    """Log student activity to database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
        INSERT INTO student_activity_log 
        (user_id, activity_type, content_id, content_type, visited_at)
        VALUES (%s, %s, %s, %s, NOW())
    """
    
    try:
        cursor.execute(query, (user_id, activity_type, content_id, content_type))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error logging activity: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


def generate_admin_report(start_date=None, end_date=None, user_id=None):
    """Generate admin engagement report with optional filters"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT 
            u.id,
            CONCAT(u.first_name, ' ', u.last_name) as name,
            u.first_name,
            u.last_name,
            u.email,
            COALESCE(COUNT(CASE WHEN sal.content_type = 'lesson' THEN 1 END), 0) as lesson_views,
            COALESCE(COUNT(CASE WHEN sal.content_type = 'quiz' THEN 1 END), 0) as quiz_attempts,
            COALESCE(COUNT(sal.id), 0) as total_activities,
            MIN(sal.visited_at) as first_activity,
            MAX(sal.visited_at) as last_activity
        FROM users u
        LEFT JOIN student_activity_log sal ON u.id = sal.user_id
        WHERE u.role = 'student'
    """
    
    params = []
    
    if start_date:
        query += " AND sal.visited_at >= %s"
        params.append(start_date)
    
    if end_date:
        query += " AND sal.visited_at <= %s"
        params.append(end_date)
    
    if user_id:
        query += " AND u.id = %s"
        params.append(user_id)
    
    query += """
        GROUP BY u.id, u.first_name, u.last_name, u.email
        ORDER BY total_activities DESC, u.last_name, u.first_name
    """
    
    try:
        cursor.execute(query, tuple(params) if params else None)
        
        if db_config.is_production:
            # Production (Railway) - returns dict-like rows
            results = cursor.fetchall()
        else:
            # Local SQLite - returns tuples, need to convert
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            results = [dict(zip(columns, row)) for row in rows]
        
        return results
    except Exception as e:
        print(f"Error generating report: {e}")
        return []
    finally:
        cursor.close()
        conn.close()


def get_student_activities(user_id):
    """Get all activities for a specific student"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT 
            sal.id,
            sal.activity_type,
            sal.content_id,
            sal.content_type,
            sal.visited_at,
            CASE 
                WHEN sal.content_type = 'lesson' THEN l.title
                WHEN sal.content_type = 'quiz' THEN q.title
                ELSE 'Unknown'
            END as content_title
        FROM student_activity_log sal
        LEFT JOIN lessons l ON sal.content_type = 'lesson' AND sal.content_id = l.id
        LEFT JOIN quizzes q ON sal.content_type = 'quiz' AND sal.content_id = q.id
        WHERE sal.user_id = %s
        ORDER BY sal.visited_at DESC
    """
    
    try:
        cursor.execute(query, (user_id,))
        
        if db_config.is_production:
            results = cursor.fetchall()
        else:
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            results = [dict(zip(columns, row)) for row in rows]
        
        return results
    except Exception as e:
        print(f"Error getting student activities: {e}")
        return []
    finally:
        cursor.close()
        conn.close()


def get_content_stats(content_id, content_type):
    """Get statistics for a specific lesson or quiz"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT 
            COUNT(DISTINCT user_id) as unique_students,
            COUNT(*) as total_views,
            MIN(visited_at) as first_view,
            MAX(visited_at) as last_view
        FROM student_activity_log
        WHERE content_id = %s AND content_type = %s
    """
    
    try:
        cursor.execute(query, (content_id, content_type))
        
        if db_config.is_production:
            result = cursor.fetchone()
        else:
            columns = [desc[0] for desc in cursor.description]
            row = cursor.fetchone()
            result = dict(zip(columns, row)) if row else None
        
        return result
    except Exception as e:
        print(f"Error getting content stats: {e}")
        return None
    finally:
        cursor.close()
        conn.close()


def get_teacher_report(teacher_id):
    """Generate engagement report for a specific teacher's content"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT 
            'lesson' as content_type,
            l.id as content_id,
            l.title as content_title,
            COUNT(DISTINCT sal.user_id) as unique_students,
            COUNT(sal.id) as total_views,
            MAX(sal.visited_at) as last_viewed
        FROM lessons l
        LEFT JOIN student_activity_log sal ON l.id = sal.content_id AND sal.content_type = 'lesson'
        WHERE l.teacher_id = %s
        GROUP BY l.id, l.title
        
        UNION ALL
        
        SELECT 
            'quiz' as content_type,
            q.id as content_id,
            q.title as content_title,
            COUNT(DISTINCT sal.user_id) as unique_students,
            COUNT(sal.id) as total_attempts,
            MAX(sal.visited_at) as last_attempted
        FROM quizzes q
        LEFT JOIN student_activity_log sal ON q.id = sal.content_id AND sal.content_type = 'quiz'
        WHERE q.teacher_id = %s
        GROUP BY q.id, q.title
        
        ORDER BY last_viewed DESC NULLS LAST
    """
    
    try:
        cursor.execute(query, (teacher_id, teacher_id))
        
        if db_config.is_production:
            results = cursor.fetchall()
        else:
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            results = [dict(zip(columns, row)) for row in rows]
        
        return results
    except Exception as e:
        print(f"Error getting teacher report: {e}")
        return []
    finally:
        cursor.close()
        conn.close()



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

# ============================================
# NEW ACTIVITY TRACKING ROUTES
# ============================================

@admin_bp.route('/print-student-engagement')
def print_student_engagement():
    """Generate printable student engagement report"""
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('login'))
    
    # Get engagement data using helper function
    students = generate_admin_report()
    
    # Get summary statistics
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Count only users with role='student'
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'student'")
        if db_config.is_production:
            total_students = cursor.fetchone()['count']
        else:
            total_students = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM lessons")
        if db_config.is_production:
            total_lessons = cursor.fetchone()['count']
        else:
            total_lessons = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM quizzes")
        if db_config.is_production:
            total_quizzes = cursor.fetchone()['count']
        else:
            total_quizzes = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM student_activity_log")
        if db_config.is_production:
            total_activities = cursor.fetchone()['count']
        else:
            total_activities = cursor.fetchone()[0]
        
    except Exception as e:
        print(f"Error getting summary stats: {e}")
        total_students = 0
        total_lessons = 0
        total_quizzes = 0
        total_activities = 0
    finally:
        cursor.close()
        conn.close()
    
    return render_template('print_student_engagement.html',
                         students=students,
                         current_date=datetime.now().strftime('%B %d, %Y at %I:%M %p'),
                         total_students=total_students,
                         total_lessons=total_lessons or 0,
                         total_quizzes=total_quizzes or 0,
                         total_activities=total_activities or 0)


@admin_bp.route('/reports/engagement')
def admin_engagement_report():
    """API endpoint for engagement report with filters"""
    if 'user_role' not in session or session['user_role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    user_id = request.args.get('user_id')
    
    report_data = generate_admin_report(start_date, end_date, user_id)
    
    return jsonify({
        'success': True,
        'data': report_data
    })


@admin_bp.route('/reports/student/<int:user_id>')
def student_activity_report(user_id):
    """Get detailed activity report for a specific student"""
    if 'user_role' not in session or session['user_role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    # Verify user is a student
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    result = cursor.fetchone()
    
    if db_config.is_production:
        role = result['role'] if result else None
    else:
        role = result[0] if result else None
    
    cursor.close()
    conn.close()
    
    if not role or role != 'student':
        return jsonify({
            'success': False,
            'message': 'User is not a student'
        }), 404
    
    activities = get_student_activities(user_id)
    
    return jsonify({
        'success': True,
        'user_id': user_id,
        'activities': activities
    })


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

    if new_status not in ['active', 'inactive', 'pending'] or not user_id or user_type not in ['student', 'teacher']:
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
        cursor.execute("SELECT id, email, first_name, last_name, registered_at, status FROM users WHERE role = 'teacher' ORDER BY id")
        rows = cursor.fetchall()
    else:
        cursor.execute("SELECT id, email, first_name, last_name, registered_at, status FROM users WHERE role = 'teacher' ORDER BY id")
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
@login_required
def print_teachers():
    """Print all teachers"""
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if db_config.is_production:
            cursor.execute("""
                SELECT id, first_name, last_name, email, registered_at, status 
                FROM users 
                WHERE role = 'teacher'
                ORDER BY id
            """)
            teachers_raw = cursor.fetchall()
        else:
            cursor.execute("""
                SELECT id, first_name, last_name, email, registered_at, status 
                FROM users 
                WHERE role = 'teacher'
                ORDER BY id
            """)
            teachers_raw = cursor.fetchall()
        
        conn.close()
        
        # Convert to list of dicts for consistent template access
        teachers = []
        for row in teachers_raw:
            teachers.append({
                'id': row['id'] if isinstance(row, dict) else row[0],
                'first_name': row['first_name'] if isinstance(row, dict) else row[1],
                'last_name': row['last_name'] if isinstance(row, dict) else row[2],
                'email': row['email'] if isinstance(row, dict) else row[3],
                'registered_at': row['registered_at'] if isinstance(row, dict) else row[4],
                'status': row['status'] if isinstance(row, dict) else row[5]
            })
        
        return render_template('print_teachers.html', teachers=teachers)
    
    except Exception as e:
        conn.close()
        print(f"[ERROR] print_teachers error: {e}")
        import traceback
        traceback.print_exc()
        flash("Error loading teachers for printing.", "error")
        return redirect(url_for('admin.teachers'))

@admin_bp.route('/print-subjects')
@login_required
def print_subjects():
    """Print all subjects"""
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if db_config.is_production:
            cursor.execute("""
                SELECT subject_id, name, description, icon, color 
                FROM subjects 
                ORDER BY subject_id
            """)
            subjects_raw = cursor.fetchall()
        else:
            cursor.execute("""
                SELECT subject_id, name, description, icon, color 
                FROM subjects 
                ORDER BY subject_id
            """)
            subjects_raw = cursor.fetchall()
        
        conn.close()
        
        # Convert to list of dicts for consistent template access
        subjects = []
        for row in subjects_raw:
            subjects.append({
                'subject_id': row['subject_id'] if isinstance(row, dict) else row[0],
                'name': row['name'] if isinstance(row, dict) else row[1],
                'description': row['description'] if isinstance(row, dict) else row[2],
                'icon': row['icon'] if isinstance(row, dict) else row[3],
                'color': row['color'] if isinstance(row, dict) else row[4]
            })
        
        return render_template('print_subjects.html', subjects=subjects)
    
    except Exception as e:
        conn.close()
        print(f"[ERROR] print_subjects error: {e}")
        import traceback
        traceback.print_exc()
        flash("Error loading subjects for printing.", "error")
        return redirect(url_for('admin.teachers'))


@admin_bp.route('/print-lessons')
@login_required
def print_lessons():
    """Print all lessons"""
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if db_config.is_production:
            cursor.execute("""
                SELECT lesson_id, title, content, teacher_id, subject_id, 
                       created_at, updated_at, user_id 
                FROM lessons 
                ORDER BY lesson_id
            """)
            lessons_raw = cursor.fetchall()
        else:
            cursor.execute("""
                SELECT lesson_id, title, content, teacher_id, subject_id, 
                       created_at, updated_at, user_id 
                FROM lessons 
                ORDER BY lesson_id
            """)
            lessons_raw = cursor.fetchall()
        
        conn.close()
        
        # Convert to list of dicts for consistent template access
        lessons = []
        for row in lessons_raw:
            lessons.append({
                'lesson_id': row['lesson_id'] if isinstance(row, dict) else row[0],
                'title': row['title'] if isinstance(row, dict) else row[1],
                'content': row['content'] if isinstance(row, dict) else row[2],
                'teacher_id': row['teacher_id'] if isinstance(row, dict) else row[3],
                'subject_id': row['subject_id'] if isinstance(row, dict) else row[4],
                'created_at': row['created_at'] if isinstance(row, dict) else row[5],
                'updated_at': row['updated_at'] if isinstance(row, dict) else row[6],
                'user_id': row['user_id'] if isinstance(row, dict) else row[7]
            })
        
        return render_template('print_lessons.html', lessons=lessons)
    
    except Exception as e:
        conn.close()
        print(f"[ERROR] print_lessons error: {e}")
        import traceback
        traceback.print_exc()
        flash("Error loading lessons for printing.", "error")
        return redirect(url_for('admin.teachers'))


@admin_bp.route('/print-students')
def print_students():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if db_config.is_production:
            cursor.execute("""
                SELECT id, first_name, last_name, email, registered_at, status 
                FROM users 
                WHERE role = 'student'
                ORDER BY id
            """)
            students_raw = cursor.fetchall()
        else:
            cursor.execute("""
                SELECT id, first_name, last_name, email, registered_at, status 
                FROM users 
                WHERE role = 'student'
                ORDER BY id
            """)
            students_raw = cursor.fetchall()
        
        conn.close()
        
        # Convert to list of dicts for consistent template access
        students = []
        for row in students_raw:
            students.append({
                'id': row['id'] if isinstance(row, dict) else row[0],
                'first_name': row['first_name'] if isinstance(row, dict) else row[1],
                'last_name': row['last_name'] if isinstance(row, dict) else row[2],
                'email': row['email'] if isinstance(row, dict) else row[3],
                'registered_at': row['registered_at'] if isinstance(row, dict) else row[4],
                'status': row['status'] if isinstance(row, dict) else row[5]
            })
        
        return render_template('admin_print_students.html', students=students)
    
    except Exception as e:
        conn.close()
        print(f"[ERROR] print_students error: {e}")
        import traceback
        traceback.print_exc()
        flash("Error loading students for printing.", "error")
        return redirect(url_for('admin.students'))


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

@admin_bp.route('/print-student-progress/<int:student_id>')
def print_student_progress(student_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get student info
        if db_config.is_production:
            cursor.execute("""
                SELECT id, first_name, last_name, email 
                FROM users 
                WHERE id = %s AND role = 'student'
            """, (student_id,))
            student_raw = cursor.fetchone()
        else:
            cursor.execute("""
                SELECT id, first_name, last_name, email 
                FROM users 
                WHERE id = ? AND role = 'student'
            """, (student_id,))
            student_raw = cursor.fetchone()
        
        if not student_raw:
            conn.close()
            flash("Student not found.", "error")
            return redirect(url_for('admin.students'))
        
        student = {
            'id': student_raw['id'] if isinstance(student_raw, dict) else student_raw[0],
            'first_name': student_raw['first_name'] if isinstance(student_raw, dict) else student_raw[1],
            'last_name': student_raw['last_name'] if isinstance(student_raw, dict) else student_raw[2],
            'email': student_raw['email'] if isinstance(student_raw, dict) else student_raw[3]
        }
        
        # Get quiz attempts
        if db_config.is_production:
            cursor.execute("""
                SELECT id, quiz_id, score, attempt_number, attempted_at 
                FROM quiz_attempts 
                WHERE user_id = %s 
                ORDER BY attempted_at DESC
            """, (student_id,))
            quiz_attempts_raw = cursor.fetchall()
        else:
            cursor.execute("""
                SELECT id, quiz_id, score, attempt_number, attempted_at 
                FROM quiz_attempts 
                WHERE user_id = ? 
                ORDER BY attempted_at DESC
            """, (student_id,))
            quiz_attempts_raw = cursor.fetchall()
        
        quiz_attempts = []
        for row in quiz_attempts_raw:
            quiz_attempts.append({
                'id': row['id'] if isinstance(row, dict) else row[0],
                'quiz_id': row['quiz_id'] if isinstance(row, dict) else row[1],
                'score': row['score'] if isinstance(row, dict) else row[2],
                'attempt_number': row['attempt_number'] if isinstance(row, dict) else row[3],
                'attempted_at': row['attempted_at'] if isinstance(row, dict) else row[4]
            })
        
        # Get student metrics with correct column names
        if db_config.is_production:
            cursor.execute("""
                SELECT metric_id, avg_score, score_trend, total_attempts, 
                       failed_quizzes_count, consecutive_fails, 
                       days_inactive, last_updated 
                FROM student_metrics 
                WHERE user_id = %s
            """, (student_id,))
            metrics_raw = cursor.fetchone()
        else:
            cursor.execute("""
                SELECT metric_id, avg_score, score_trend, total_attempts, 
                       failed_quizzes_count, consecutive_fails, 
                       days_inactive, last_updated 
                FROM student_metrics 
                WHERE user_id = ?
            """, (student_id,))
            metrics_raw = cursor.fetchone()
        
        metrics = None
        if metrics_raw:
            metrics = {
                'metric_id': metrics_raw['metric_id'] if isinstance(metrics_raw, dict) else metrics_raw[0],
                'avg_score': metrics_raw['avg_score'] if isinstance(metrics_raw, dict) else metrics_raw[1],
                'score_trend': metrics_raw['score_trend'] if isinstance(metrics_raw, dict) else metrics_raw[2],
                'total_attempts': metrics_raw['total_attempts'] if isinstance(metrics_raw, dict) else metrics_raw[3],
                'failed_quizzes_count': metrics_raw['failed_quizzes_count'] if isinstance(metrics_raw, dict) else metrics_raw[4],
                'consecutive_fails': metrics_raw['consecutive_fails'] if isinstance(metrics_raw, dict) else metrics_raw[5],
                'days_inactive': metrics_raw['days_inactive'] if isinstance(metrics_raw, dict) else metrics_raw[6],
                'last_updated': metrics_raw['last_updated'] if isinstance(metrics_raw, dict) else metrics_raw[7]
            }
        
        conn.close()
        
        return render_template('print_student_progress.html', 
                             student=student, 
                             quiz_attempts=quiz_attempts, 
                             metrics=metrics)
    
    except Exception as e:
        conn.close()
        print(f"[ERROR] print_student_progress error: {e}")
        import traceback
        traceback.print_exc()
        flash("Error loading student progress for printing.", "error")
        return redirect(url_for('admin.students'))

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