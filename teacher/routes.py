from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash
import psycopg2
from psycopg2.extras import RealDictCursor
import base64
import io
import os
from PIL import Image
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from teacher.ml_classifier_sklearn import get_all_students_with_classification, get_classification_summary, calculate_student_metrics
from werkzeug.utils import secure_filename 

# Video upload configuration
UPLOAD_FOLDER = 'static/uploads/videos'
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'avi', 'mov', 'wmv', 'webm'}
MAX_VIDEO_SIZE = 500 * 1024 * 1024  # 500MB

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_video_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS

teacher_bp = Blueprint('teacher', __name__, template_folder='templates', static_folder='static', url_prefix='/teacher')

def get_db_connection():
    conn = psycopg2.connect(
        os.environ.get('DATABASE_URL'),
        cursor_factory=RealDictCursor
    )
    return conn

def require_teacher_login():
    """Check if user is logged in and is a teacher"""
    if 'user_id' not in session:
        return False, "Please log in to access this page."
    
    if session.get('user_role') != 'teacher':
        return False, "Access denied. Teachers only."
    
    return True, None

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


@teacher_bp.route('/')
def home():
    return redirect(url_for('teacher.teacher_dashboard'))

@teacher_bp.route('/teacher_dashboard')
def teacher_dashboard():
    # Check authentication
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        flash(error_msg, "error")
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get teacher information
    cursor.execute(
        "SELECT first_name, last_name, email, user_profile AS profile_picture FROM users WHERE id = %s AND role = 'teacher'",
        (user_id,)
    )
    user = cursor.fetchone()

    if not user:
        flash("Teacher account not found.", "error")
        cursor.close()
        conn.close()
        return redirect(url_for('login'))
    
    # Handle profile picture
    print(f"DEBUG: profile_picture type: {type(user['profile_picture'])}")
    print(f"DEBUG: profile_picture value: {user['profile_picture'][:50] if user['profile_picture'] else None}")
    
    profile_picture = None
    if user['profile_picture']:
        try:
            if isinstance(user['profile_picture'], bytes):
                profile_picture = base64.b64encode(user['profile_picture']).decode('utf-8')
            elif isinstance(user['profile_picture'], str):
                profile_picture = user['profile_picture']
            elif isinstance(user['profile_picture'], memoryview):
                profile_picture = base64.b64encode(bytes(user['profile_picture'])).decode('utf-8')
            else:
                profile_picture = base64.b64encode(bytes(user['profile_picture'])).decode('utf-8')
        except Exception as e:
            print(f"Profile picture encoding error: {e}")
            profile_picture = None

    teacher_name = user['first_name'] if user['first_name'] else "Guro"
    
    # Count lessons and quizzes
    try:
        cursor.execute("SELECT COUNT(*) FROM lessons")
        lesson_count = cursor.fetchone()['count']
    except:
        lesson_count = 0
    
    try:
        cursor.execute("SELECT COUNT(*) FROM quizzes")
        quiz_count = cursor.fetchone()['count']
    except:
        quiz_count = 0

    cursor.close()
    conn.close()

    return render_template("teacher_dashboard.html",
                           user=user,
                           teacher_name=teacher_name,
                           lesson_count=lesson_count,
                           quiz_count=quiz_count,
                           profile_picture=profile_picture)

@teacher_bp.route('/logout')
def logout():
    session.clear()
    flash("Na-logout na kayo.", "info")
    return redirect(url_for('login'))

@teacher_bp.route('/mga_aralin')
def mga_aralin():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        flash(error_msg, "error")
        return redirect(url_for('login'))
    
    return render_template('teacher_mga_aralin.html')

@teacher_bp.route('/mga_pagsusulit')
def mga_pagsusulit():
    print(f"[DEBUG] Accessing mga_pagsusulit route")
    print(f"[DEBUG] Session user_id: {session.get('user_id')}")
    print(f"[DEBUG] Session user_role: {session.get('user_role')}")
    
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        print(f"[DEBUG] Authentication failed: {error_msg}")
        flash(error_msg, "error")
        return redirect(url_for('login'))
    
    print(f"[DEBUG] Authentication successful, rendering template")
    try:
        return render_template('teacher_mga_pagsusulit.html')
    except Exception as e:
        print(f"[DEBUG] Template error: {e}")
        flash("Template not found", "error")
        return redirect(url_for('teacher.teacher_dashboard'))
    

# ============================================================================
# NEW MASTERY LEVEL QUIZ ROUTES
# ============================================================================

@teacher_bp.route('/api/quizzes/mastery', methods=['GET'])
def get_quizzes_by_mastery():
    """Get all quizzes grouped by mastery level"""
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get all quizzes with their mastery levels
        cursor.execute("""
            SELECT id, title, mastery_level, created_at,
                   (SELECT COUNT(*) FROM questions WHERE quiz_id = quizzes.id) as question_count
            FROM quizzes
            ORDER BY 
                CASE mastery_level
                    WHEN 'baguhan' THEN 1
                    WHEN 'katamtaman' THEN 2
                    WHEN 'dalubhasa' THEN 3
                    ELSE 4
                END,
                created_at DESC
        """)
        quizzes = cursor.fetchall()
        
        # Group by mastery level
        grouped = {
            'baguhan': [],
            'katamtaman': [],
            'dalubhasa': []
        }
        
        for quiz in quizzes:
            quiz_data = {
                'id': quiz['id'],
                'title': quiz['title'],
                'mastery_level': quiz['mastery_level'],
                'question_count': quiz['question_count'],
                'created_at': quiz['created_at']
            }
            
            level = quiz['mastery_level']
            if level in grouped:
                grouped[level].append(quiz_data)
        
        cursor.close()
        conn.close()
        return jsonify({
            'success': True,
            'quizzes': grouped
        })
    
    except Exception as e:
        cursor.close()
        conn.close()
        print(f"Error fetching quizzes: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@teacher_bp.route('/api/quiz/create_with_level', methods=['POST'])
def create_quiz_with_mastery_level():
    """Create a new quiz with mastery level"""
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401
    
    data = request.get_json()
    title = data.get('title', '').strip()
    mastery_level = data.get('mastery_level', '').strip().lower()
    
    if not title:
        return jsonify({'success': False, 'message': 'Quiz title is required'}), 400
    
    if mastery_level not in ['baguhan', 'katamtaman', 'dalubhasa']:
        return jsonify({'success': False, 'message': 'Invalid mastery level'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO quizzes (title, mastery_level)
            VALUES (%s, %s)
            RETURNING id
        """, (title, mastery_level))
        
        quiz_id = cursor.fetchone()['id']
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Quiz created successfully',
            'quiz_id': quiz_id
        })
    
    except Exception as e:
        cursor.close()
        conn.close()
        print(f"Error creating quiz: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@teacher_bp.route('/api/quiz/<int:quiz_id>/update_level', methods=['PUT'])
def update_quiz_mastery_level(quiz_id):
    """Update mastery level of an existing quiz"""
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401
    
    data = request.get_json()
    mastery_level = data.get('mastery_level', '').strip().lower()
    
    if mastery_level not in ['baguhan', 'katamtaman', 'dalubhasa']:
        return jsonify({'success': False, 'message': 'Invalid mastery level'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE quizzes
            SET mastery_level = %s
            WHERE id = %s
        """, (mastery_level, quiz_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Quiz level updated successfully'
        })
    
    except Exception as e:
        cursor.close()
        conn.close()
        print(f"Error updating quiz level: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@teacher_bp.route('/api/student/<int:student_id>/unlocked_levels', methods=['GET'])
def get_student_unlocked_levels(student_id):
    """Get which mastery levels are unlocked for a specific student"""
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401
    
    conn = get_db_connection()
    
    try:
        # Get student's mastery level from ML classifier
        from teacher.ml_classifier_sklearn import calculate_student_metrics
        
        metrics = calculate_student_metrics(student_id, conn)
        mastery_level = metrics['mastery_level']
        
        # Determine unlocked levels based on mastery
        unlocked = ['baguhan']  # Baguhan is always unlocked
        
        if mastery_level in ['Intermediate', 'Advanced']:
            unlocked.append('katamtaman')
        
        if mastery_level == 'Advanced':
            unlocked.append('dalubhasa')
        
        conn.close()
        
        return jsonify({
            'success': True,
            'student_id': student_id,
            'current_mastery': mastery_level.lower(),
            'unlocked_levels': unlocked
        })
    
    except Exception as e:
        conn.close()
        print(f"Error getting student unlocked levels: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

import base64

@teacher_bp.route('/api/quiz/<int:quiz_id>/details', methods=['GET'])
def get_quiz_details_with_level(quiz_id):
    """Get quiz details including mastery level and questions"""
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get quiz details
        cursor.execute("""
            SELECT id, title, mastery_level, created_at
            FROM quizzes
            WHERE id = %s
        """, (quiz_id,))
        quiz = cursor.fetchone()
        
        if not quiz:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Quiz not found'}), 404
        
        # Get questions for this quiz
        cursor.execute("""
            SELECT id, question_text, choice_a, choice_b, choice_c, choice_d,
                   correct_answer, image, trivia
            FROM questions
            WHERE quiz_id = %s
            ORDER BY id
        """, (quiz_id,))
        questions = cursor.fetchall()
        
        questions_list = []
        for q in questions:
            # Handle the image field - convert memoryview/bytes to base64 OR keep as string
            image_data = q['image']
            
            if image_data:
                # If it's memoryview or bytes, convert to base64
                if isinstance(image_data, (memoryview, bytes)):
                    image_data = base64.b64encode(bytes(image_data)).decode('utf-8')
                # If it's already a string, keep it as is
                elif isinstance(image_data, str):
                    # If it already has data: prefix, keep it
                    # Otherwise it's just the base64 string
                    pass
            else:
                image_data = ''
            
            questions_list.append({
                'id': q['id'],
                'question_text': q['question_text'],
                'choice_a': q['choice_a'],
                'choice_b': q['choice_b'],
                'choice_c': q['choice_c'],
                'choice_d': q['choice_d'],
                'correct_answer': q['correct_answer'],
                'image': image_data,
                'trivia': q['trivia']
            })
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'quiz': {
                'id': quiz['id'],
                'title': quiz['title'],
                'mastery_level': quiz['mastery_level'],
                'created_at': quiz['created_at'],
                'questions': questions_list
            }
        })
    
    except Exception as e:
        cursor.close()
        conn.close()
        print(f"Error getting quiz details: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@teacher_bp.route('/kasanayan_mag_aral')
def kasanayan_mag_aral():
    """Display student mastery levels page with ML classification"""
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        flash(error_msg, "error")
        return redirect(url_for('login'))
    
    user_id = session.get('user_id')
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get teacher information
        cursor.execute(
            "SELECT first_name, last_name, email, user_profile FROM users WHERE id = %s AND role = 'teacher'",
            (user_id,)
        )
        user = cursor.fetchone()
        
        if not user:
            flash("Teacher account not found.", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
        
        # Handle profile picture
        profile_picture = None
        if user['user_profile']:
            try:
                if isinstance(user['user_profile'], bytes):
                    profile_picture = base64.b64encode(user['user_profile']).decode('utf-8')
                elif isinstance(user['user_profile'], str):
                    profile_picture = user['user_profile']
                elif isinstance(user['user_profile'], memoryview):
                    profile_picture = base64.b64encode(bytes(user['user_profile'])).decode('utf-8')
                else:
                    profile_picture = base64.b64encode(bytes(user['user_profile'])).decode('utf-8')
            except Exception as e:
                print(f"Profile picture encoding error: {e}")
                profile_picture = None
        
        # Get teacher name
        teacher_name = user['first_name'] if user['first_name'] else "Guro"
        
        # ML CLASSIFICATION: Get all students with their mastery levels
        print("Running ML classification...")
        students_data = get_all_students_with_classification(conn)
        summary = get_classification_summary(conn)
        print(f"Classified {len(students_data)} students")
        print(f"Summary: {summary}")
        
        cursor.close()
        conn.close()
        
        # Pass data to template
        return render_template(
            'teacher_kasanayan.html',
            user=user,
            students=students_data,
            summary=summary,
            profile_picture=profile_picture,
            teacher_name=teacher_name
        )
    
    except Exception as e:
        print(f"Error in kasanayan route: {e}")
        import traceback
        traceback.print_exc()
        flash(f"Error loading student data: {str(e)}", "error")
        return redirect(url_for('teacher.teacher_dashboard'))
    

@teacher_bp.route('/student/<int:student_id>')
def student_detail(student_id):
    """Display detailed information about a specific student"""
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        flash(error_msg, "error")
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get student information
        cursor.execute("""
            SELECT id, first_name, last_name, email, mastery_level
            FROM users 
            WHERE id = %s AND role = 'student'
        """, (student_id,))
        student = cursor.fetchone()
        
        if not student:
            flash("Student not found.", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('teacher.kasanayan_mag_aral'))
        
        # Calculate comprehensive metrics for this student
        metrics = calculate_student_metrics(student_id, conn)
        
        cursor.close()
        conn.close()
        
        # Pass data to template
        return render_template(
            'student_detail.html',
            student=student,
            metrics=metrics
        )
    
    except Exception as e:
        print(f"Error loading student details: {e}")
        import traceback
        traceback.print_exc()
        flash("Error loading student details.", "error")
        return redirect(url_for('teacher.kasanayan_mag_aral'))
    
@teacher_bp.route('/api/students-classification')
def api_students_classification():
    """API endpoint to get student classifications (for AJAX refresh)"""
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        conn = get_db_connection()
        students_data = get_all_students_with_classification(conn)
        summary = get_classification_summary(conn)
        conn.close()
        
        return jsonify({
            'success': True,
            'students': students_data,
            'summary': summary
        })
    
    except Exception as e:
        print(f"API Error: {e}")
        return jsonify({'error': str(e)}), 500
    
@teacher_bp.route('/add_question', methods=['POST'])
def add_question():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    data = request.get_json()
    
    print("Received question data:", data)
    
    question = data.get('question_text')
    choice_a = data.get('choice_a')
    choice_b = data.get('choice_b')
    choice_c = data.get('choice_c')
    choice_d = data.get('choice_d')
    correct = data.get('correct_answer')
    image = data.get('image')
    trivia = data.get('trivia')
    quiz_title = data.get('quiz_title')
    quiz_id_from_request = data.get('quiz_id')
    subject = data.get('subject')
    user_id = session.get('user_id')

    # FIX: Strip the data URI prefix from image if present
    if image and image.startswith('data:image'):
        # Remove "data:image/jpeg;base64," or similar prefix
        image = image.split(',', 1)[1] if ',' in image else image
    
    print(f"Image data length: {len(image) if image else 0}")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get quiz_id
    quiz_id = quiz_id_from_request
    
    if not quiz_id:
        cursor.execute("SELECT id FROM quizzes WHERE title = %s", (quiz_title,))
        quiz_row = cursor.fetchone()
        if quiz_row:
            quiz_id = quiz_row['id']
        else:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False, 
                'message': f'Quiz "{quiz_title}" not found in database'
            }), 404

    print(f"Using quiz_id: {quiz_id}")

    # Check if subject_id is valid or make it optional
    subject_id = None
    if subject:
        subject_map = {
            "Pangngalan": 1,
            "Pandiwa": 2,
            "Pang-uri": 3,
            "Panghalip": 4
        }
        subject_id = subject_map.get(subject)
        
        # Verify the subject exists
        if subject_id:
            cursor.execute("SELECT subject_id FROM subjects WHERE subject_id = %s", (subject_id,))
            if not cursor.fetchone():
                print(f"Subject ID {subject_id} doesn't exist, setting to NULL")
                subject_id = None

    print(f"Using subject_id: {subject_id}")

    # Validate required fields
    if not all([question, choice_a, choice_b, choice_c, choice_d, correct, quiz_id, user_id]):
        cursor.close()
        conn.close()
        missing = []
        if not question: missing.append('question_text')
        if not choice_a: missing.append('choice_a')
        if not choice_b: missing.append('choice_b')
        if not choice_c: missing.append('choice_c')
        if not choice_d: missing.append('choice_d')
        if not correct: missing.append('correct_answer')
        if not quiz_id: missing.append('quiz_id')
        if not user_id: missing.append('user_id')
        
        return jsonify({
            'success': False, 
            'message': f'Missing required fields: {", ".join(missing)}'
        }), 400

    try:
        cursor.execute('''
            INSERT INTO questions (
                quiz_id, subject_id, user_id, question_text,
                choice_a, choice_b, choice_c, choice_d, correct_answer, image, trivia
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            quiz_id, subject_id, user_id, question,
            choice_a, choice_b, choice_c, choice_d, correct, image, trivia
        ))
        conn.commit()
        cursor.close()
        conn.close()
        
        print("Question added successfully")
        return jsonify({'success': True, 'message': 'Question added successfully'})
    except Exception as e:
        cursor.close()
        conn.close()
        print(f"Error adding question: {str(e)}")
        return jsonify({'success': False, 'message': f'Error adding question: {str(e)}'}), 500

@teacher_bp.route('/add_quiz', methods=['POST'])
def add_quiz():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'error': error_msg}), 401

    data = request.get_json()
    title = data.get('title')

    if not title:
        return jsonify({'error': 'Missing title'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if quiz title already exists
    cursor.execute('SELECT id FROM quizzes WHERE title = %s', (title,))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({'error': 'Duplicate title'}), 409

    # Insert new quiz
    cursor.execute('INSERT INTO quizzes (title) VALUES (%s) RETURNING id', (title,))
    quiz_id = cursor.fetchone()['id']
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'message': 'Quiz added successfully', 'quiz_id': quiz_id}), 200

@teacher_bp.route('/mga-marka')
def mga_marka():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        flash(error_msg, "error")
        return redirect(url_for('login'))
    
    return render_template('mga-marka.html')

@teacher_bp.route('/add_subject', methods=['POST'])
def add_subject():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    name = request.form.get('name')
    description = request.form.get('description')
    icon = request.form.get('icon', 'fa-book')
    color = request.form.get('color', 'pangngalan')

    if not all([name, description]):
        return jsonify({'success': False, 'message': 'Name and description are required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if subject already exists
        cursor.execute('SELECT * FROM subjects WHERE name = %s', (name,))
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Subject already exists'}), 400

        cursor.execute('''
            INSERT INTO subjects (name, description, icon, color)
            VALUES (%s, %s, %s, %s)
        ''', (name, description, icon, color))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Subject added successfully'})
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': f'Error adding subject: {str(e)}'}), 500

@teacher_bp.route('/get_subjects')
def get_subjects():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'error': error_msg}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT s.subject_id, s.name, s.description, s.icon, s.color,
                   COUNT(l.lesson_id) as lesson_count
            FROM subjects s
            LEFT JOIN lessons l ON s.subject_id = l.subject_id
            GROUP BY s.subject_id, s.name, s.description, s.icon, s.color
            ORDER BY s.subject_id
        ''')
        subjects = cursor.fetchall()
        
        subjects_list = []
        for subject in subjects:
            subjects_list.append({
                'id': subject['subject_id'],
                'name': subject['name'],
                'description': subject['description'],
                'icon': subject['icon'],
                'color': subject['color'],
                'lesson_count': subject['lesson_count']
            })
        
        cursor.close()
        conn.close()
        return jsonify(subjects_list)
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({'error': f'Error fetching subjects: {str(e)}'}), 500

@teacher_bp.route('/add_lesson', methods=['POST'])
def add_lesson():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    title = request.form.get('title')
    content = request.form.get('content')
    subject_id = request.form.get('subject_id')
    user_id = session.get('user_id')

    if not all([title, content, subject_id]):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        created_at = datetime.now()
        
        cursor.execute('''
            INSERT INTO lessons (teacher_id, subject_id, title, content, created_at, user_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING lesson_id
        ''', (user_id, subject_id, title, content, created_at, user_id))
        
        lesson_id = cursor.fetchone()['lesson_id']
        print(f"DEBUG: lesson_id = {lesson_id}")
        
        conn.commit()
        print(f"DEBUG: Commit successful")
        
        # Verify the lesson exists
        cursor.execute('SELECT lesson_id FROM lessons WHERE lesson_id = %s', (lesson_id,))
        verify = cursor.fetchone()
        print(f"DEBUG: Verification query result = {verify}")
        
        cursor.close()
        conn.close()
        
        if not verify or verify['lesson_id'] is None:
            print("ERROR: Lesson not found after insert!")
            return jsonify({'success': False, 'message': 'Failed to create lesson'}), 500
        
        print(f"DEBUG: Successfully created lesson with ID: {lesson_id}")
        
        return jsonify({
            'success': True, 
            'message': 'Lesson added successfully',
            'lesson_id': lesson_id
        })
    except Exception as e:
        cursor.close()
        conn.close()
        print(f"ERROR in add_lesson: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error adding lesson: {str(e)}'}), 500

@teacher_bp.route('/get_lessons')
def get_lessons():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'error': error_msg}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Get all subjects first
        cursor.execute('SELECT name FROM subjects')
        subjects = cursor.fetchall()
        data = {subject['name']: [] for subject in subjects}

        # Join lessons with subjects table to get subject names
        cursor.execute('''
            SELECT l.lesson_id, l.title, l.content, l.created_at, 
                   s.name as subject_name,
                   u.first_name, u.last_name
            FROM lessons l
            JOIN subjects s ON l.subject_id = s.subject_id
            JOIN users u ON l.teacher_id = u.id
            ORDER BY l.created_at DESC
        ''')
        lessons = cursor.fetchall()

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
    
# Edit and Delete Lesson/Subjects

@teacher_bp.route('/edit_subject', methods=['POST'])
def edit_subject():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    subject_id = request.form.get('id')
    name = request.form.get('name')
    description = request.form.get('description')

    if not all([subject_id, name, description]):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if subject exists
        cursor.execute('SELECT * FROM subjects WHERE subject_id = %s', (subject_id,))
        existing = cursor.fetchone()
        if not existing:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Subject not found'}), 404

        # Check if new name conflicts with another subject
        cursor.execute(
            'SELECT * FROM subjects WHERE name = %s AND subject_id != %s', 
            (name, subject_id)
        )
        name_conflict = cursor.fetchone()
        if name_conflict:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Subject name already exists'}), 400

        cursor.execute('''
            UPDATE subjects 
            SET name = %s, description = %s
            WHERE subject_id = %s
        ''', (name, description, subject_id))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Subject updated successfully'})
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': f'Error updating subject: {str(e)}'}), 500

@teacher_bp.route('/delete_subject', methods=['POST'])
def delete_subject():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    data = request.get_json()
    subject_id = data.get('id')

    if not subject_id:
        return jsonify({'success': False, 'message': 'Subject ID is required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if subject exists
        cursor.execute('SELECT * FROM subjects WHERE subject_id = %s', (subject_id,))
        existing = cursor.fetchone()
        if not existing:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Subject not found'}), 404

        # Delete all lessons associated with this subject first
        cursor.execute('DELETE FROM lessons WHERE subject_id = %s', (subject_id,))
        
        # Then delete the subject
        cursor.execute('DELETE FROM subjects WHERE subject_id = %s', (subject_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Subject and associated lessons deleted successfully'})
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': f'Error deleting subject: {str(e)}'}), 500

@teacher_bp.route('/edit_lesson', methods=['POST'])
def edit_lesson():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    lesson_id = request.form.get('id')
    title = request.form.get('title')
    content = request.form.get('content')

    if not all([lesson_id, title, content]):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if lesson exists
        cursor.execute('SELECT * FROM lessons WHERE lesson_id = %s', (lesson_id,))
        existing = cursor.fetchone()
        if not existing:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Lesson not found'}), 404

        # Verify that the teacher owns this lesson
        user_id = session.get('user_id')
        if existing['teacher_id'] != user_id:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized to edit this lesson'}), 403

        cursor.execute('''
            UPDATE lessons 
            SET title = %s, content = %s
            WHERE lesson_id = %s
        ''', (title, content, lesson_id))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Lesson updated successfully'})
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': f'Error updating lesson: {str(e)}'}), 500

@teacher_bp.route('/delete_lesson', methods=['POST'])
def delete_lesson():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    data = request.get_json()
    lesson_id = data.get('id')

    if not lesson_id:
        return jsonify({'success': False, 'message': 'Lesson ID is required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if lesson exists
        cursor.execute('SELECT * FROM lessons WHERE lesson_id = %s', (lesson_id,))
        existing = cursor.fetchone()
        if not existing:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Lesson not found'}), 404

        # Verify that the teacher owns this lesson
        user_id = session.get('user_id')
        if existing['teacher_id'] != user_id:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Unauthorized to delete this lesson'}), 403

        cursor.execute('DELETE FROM lessons WHERE lesson_id = %s', (lesson_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Lesson deleted successfully'})
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': f'Error deleting lesson: {str(e)}'}), 500
    

@teacher_bp.route('/upload_lesson_video', methods=['POST'])
def upload_lesson_video():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    print("DEBUG: Upload video route called")
    
    if 'video' not in request.files:
        print("DEBUG: No video in request.files")
        return jsonify({'success': False, 'message': 'No video file provided'}), 400
    
    video_file = request.files['video']
    lesson_id = request.form.get('lesson_id')
    
    print(f"DEBUG: Lesson ID received: {lesson_id}")
    print(f"DEBUG: Video filename: {video_file.filename}")
    
    if not lesson_id:
        print("DEBUG: Lesson ID is missing")
        return jsonify({'success': False, 'message': 'Lesson ID is required'}), 400
    
    if video_file.filename == '':
        print("DEBUG: Empty filename")
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not allowed_video_file(video_file.filename):
        print("DEBUG: Invalid file type")
        return jsonify({'success': False, 'message': 'Invalid file type. Allowed: mp4, avi, mov, wmv, webm'}), 400
    
    try:
        # Generate unique filename
        original_filename = secure_filename(video_file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"lesson_{lesson_id}_{timestamp}_{original_filename}"
        
        print(f"DEBUG: Generated filename: {filename}")
        
        # Save file
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        print(f"DEBUG: Saving to path: {file_path}")
        
        video_file.save(file_path)
        print("DEBUG: File saved successfully")
        
        # Get file size
        file_size = os.path.getsize(file_path)
        print(f"DEBUG: File size: {file_size}")
        
        # Save to database
        conn = get_db_connection()
        cursor = conn.cursor()
        print("DEBUG: Database connection established")
        
        cursor.execute('''
            INSERT INTO lesson_videos (lesson_id, video_filename, video_path, 
                                      original_filename, file_size, uploaded_by)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (lesson_id, filename, file_path, original_filename, 
              file_size, session['user_id']))
        
        print("DEBUG: Insert query executed")
        video_id = cursor.fetchone()['id']
        conn.commit()
        print("DEBUG: Commit successful")
        
        print(f"DEBUG: Video ID: {video_id}")
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Video uploaded successfully',
            'video_id': video_id,
            'filename': filename
        }), 200
        
    except Exception as e:
        print(f"DEBUG ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error uploading video: {str(e)}'}), 500

@teacher_bp.route('/get_lesson_videos/<int:lesson_id>')
def get_lesson_videos(lesson_id):
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'error': error_msg}), 401
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, video_filename, original_filename, file_size, 
                   uploaded_at as upload_date, uploaded_by
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
                'upload_date': video['upload_date'],
                'uploaded_by': video['uploaded_by'],
                'video_url': f'/static/uploads/videos/{video["video_filename"]}'
            })
        
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'videos': videos_list}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@teacher_bp.route('/delete_lesson_video/<int:video_id>', methods=['POST'])
def delete_lesson_video(video_id):
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get video info
        cursor.execute(
            'SELECT video_filename, video_path FROM lesson_videos WHERE id = %s', 
            (video_id,)
        )
        video = cursor.fetchone()
        
        if not video:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Video not found'}), 404
        
        # Delete file from filesystem
        file_path = video['video_path']
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete from database
        cursor.execute('DELETE FROM lesson_videos WHERE id = %s', (video_id,))
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Video deleted successfully'}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    
# QUIZ

@teacher_bp.route('/get_quizzes')
def get_quizzes():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, title, created_at FROM quizzes')
    quizzes = cursor.fetchall()

    quiz_data = []
    for quiz in quizzes:
        quiz_id = quiz['id']
        cursor.execute('''
            SELECT question_text, choice_a, choice_b, choice_c, choice_d, correct_answer, image, trivia
            FROM questions
            WHERE quiz_id = %s
        ''', (quiz_id,))
        questions = cursor.fetchall()

        question_list = []
        for q in questions:
            # Handle the image field - convert memoryview to base64 or empty string
            image_data = q['image']
            if image_data:
                if isinstance(image_data, memoryview):
                    # Convert memoryview to base64 string
                    image_data = base64.b64encode(image_data).decode('utf-8')
                elif isinstance(image_data, bytes):
                    # Convert bytes to base64 string
                    image_data = base64.b64encode(image_data).decode('utf-8')
            else:
                image_data = ''
            
            question_list.append({
                'question_text': q['question_text'],
                'choice_a': q['choice_a'],
                'choice_b': q['choice_b'],
                'choice_c': q['choice_c'],
                'choice_d': q['choice_d'],
                'correct_answer': q['correct_answer'],
                'image': image_data,  # Use the converted image data
                'trivia': q['trivia']
            })

        quiz_data.append({
            'id': quiz['id'],
            'title': quiz['title'],
            'created_at': quiz['created_at'],
            'questions': question_list
        })

    cursor.close()
    conn.close()
    return jsonify(quiz_data)

#Edit and Delete QUIZ

@teacher_bp.route('/delete_quiz/<int:quiz_id>', methods=['DELETE'])
def delete_quiz(quiz_id):
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Verify the quiz exists
        cursor.execute(
            'SELECT id FROM quizzes WHERE id = %s', 
            (quiz_id,)
        )
        quiz = cursor.fetchone()

        if not quiz:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Quiz not found'}), 404

        # Delete all questions associated with this quiz first
        cursor.execute('DELETE FROM questions WHERE quiz_id = %s', (quiz_id,))
        
        # Delete the quiz
        cursor.execute('DELETE FROM quizzes WHERE id = %s', (quiz_id,))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Quiz deleted successfully'}), 200

    except Exception as e:
        cursor.close()
        conn.close()
        print(f"Error deleting quiz: {str(e)}")
        return jsonify({'success': False, 'message': f'Error deleting quiz: {str(e)}'}), 500


@teacher_bp.route('/delete_question/<int:question_id>', methods=['DELETE'])
def delete_question(question_id):
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Verify the question exists
        cursor.execute(
            'SELECT id, quiz_id FROM questions WHERE id = %s', 
            (question_id,)
        )
        question = cursor.fetchone()

        if not question:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Question not found'}), 404

        quiz_id = question['quiz_id']

        # Delete the question
        cursor.execute('DELETE FROM questions WHERE id = %s', (question_id,))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True, 
            'message': 'Question deleted successfully',
            'quiz_id': quiz_id
        }), 200

    except Exception as e:
        cursor.close()
        conn.close()
        print(f"Error deleting question: {str(e)}")
        return jsonify({'success': False, 'message': f'Error deleting question: {str(e)}'}), 500


@teacher_bp.route('/update_quiz/<int:quiz_id>', methods=['PUT'])
def update_quiz(quiz_id):
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    data = request.get_json()
    new_title = data.get('title')

    if not new_title:
        return jsonify({'success': False, 'message': 'Missing title'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if quiz exists
        cursor.execute(
            'SELECT id FROM quizzes WHERE id = %s', 
            (quiz_id,)
        )
        quiz = cursor.fetchone()

        if not quiz:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Quiz not found'}), 404

        # Check if new title already exists (excluding current quiz)
        cursor.execute(
            'SELECT id FROM quizzes WHERE title = %s AND id != %s', 
            (new_title, quiz_id)
        )
        existing = cursor.fetchone()

        if existing:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Quiz title already exists'}), 409

        # Update the quiz
        cursor.execute('UPDATE quizzes SET title = %s WHERE id = %s', (new_title, quiz_id))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Quiz updated successfully'}), 200

    except Exception as e:
        cursor.close()
        conn.close()
        print(f"Error updating quiz: {str(e)}")
        return jsonify({'success': False, 'message': f'Error updating quiz: {str(e)}'}), 500


@teacher_bp.route('/update_question/<int:question_id>', methods=['PUT'])
def update_question(question_id):
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    data = request.get_json()
    
    # Extract fields
    question_text = data.get('question_text')
    choice_a = data.get('choice_a')
    choice_b = data.get('choice_b')
    choice_c = data.get('choice_c')
    choice_d = data.get('choice_d')
    correct_answer = data.get('correct_answer')
    image = data.get('image')
    trivia = data.get('trivia')

    # FIX: Strip the data URI prefix from image if present
    if image and isinstance(image, str) and image.startswith('data:image'):
        # Remove "data:image/jpeg;base64," or similar prefix
        image = image.split(',', 1)[1] if ',' in image else image
    
    print(f"Updating question {question_id}, image data length: {len(image) if image else 0}")

    # Validate required fields
    if not all([question_text, choice_a, choice_b, choice_c, choice_d, correct_answer]):
        return jsonify({
            'success': False, 
            'message': 'Missing required fields'
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if question exists
        cursor.execute(
            'SELECT id FROM questions WHERE id = %s', 
            (question_id,)
        )
        question = cursor.fetchone()

        if not question:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'Question not found'}), 404

        # Update the question
        cursor.execute('''
            UPDATE questions SET 
                question_text = %s, 
                choice_a = %s, 
                choice_b = %s, 
                choice_c = %s, 
                choice_d = %s, 
                correct_answer = %s, 
                image = %s, 
                trivia = %s
            WHERE id = %s
        ''', (
            question_text, choice_a, choice_b, choice_c, choice_d, 
            correct_answer, image, trivia, question_id
        ))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Question updated successfully'}), 200

    except Exception as e:
        cursor.close()
        conn.close()
        print(f"Error updating question: {str(e)}")
        return jsonify({'success': False, 'message': f'Error updating question: {str(e)}'}), 500


@teacher_bp.route('/get_question/<int:question_id>', methods=['GET'])
def get_question(question_id):
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            'SELECT * FROM questions WHERE id = %s', 
            (question_id,)
        )
        question = cursor.fetchone()

        cursor.close()
        conn.close()

        if not question:
            return jsonify({'success': False, 'message': 'Question not found'}), 404

        # Handle the image field
        image_data = question['image']
        if image_data:
            if isinstance(image_data, memoryview):
                image_data = base64.b64encode(image_data).decode('utf-8')
            elif isinstance(image_data, bytes):
                image_data = base64.b64encode(image_data).decode('utf-8')
        else:
            image_data = ''

        return jsonify({
            'success': True,
            'question': {
                'id': question['id'],
                'question_text': question['question_text'],
                'choice_a': question['choice_a'],
                'choice_b': question['choice_b'],
                'choice_c': question['choice_c'],
                'choice_d': question['choice_d'],
                'correct_answer': question['correct_answer'],
                'image': image_data,  # Use converted image data
                'trivia': question['trivia'],
                'quiz_id': question['quiz_id']
            }
        }), 200

    except Exception as e:
        cursor.close()
        conn.close()
        print(f"Error fetching question: {str(e)}")
        return jsonify({'success': False, 'message': f'Error fetching question: {str(e)}'}), 500


# Profile Routes

@teacher_bp.route('/profile')
def profile():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        flash(error_msg, "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        flash("User not found.", "error")
        return redirect(url_for('login'))

    # Handle profile picture
    profile_picture = None
    if user['user_profile']:
        try:
            if isinstance(user['user_profile'], bytes):
                profile_picture = base64.b64encode(user['user_profile']).decode('utf-8')
            elif isinstance(user['user_profile'], str):
                profile_picture = user['user_profile']
            elif isinstance(user['user_profile'], memoryview):
                profile_picture = base64.b64encode(bytes(user['user_profile'])).decode('utf-8')
            else:
                profile_picture = base64.b64encode(bytes(user['user_profile'])).decode('utf-8')
        except Exception as e:
            print(f"Profile picture encoding error: {e}")
            profile_picture = None
    
    return render_template('teacher_profile.html', user=user, profile_picture=profile_picture)

@teacher_bp.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        flash(error_msg, "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
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

        if not email:
            flash("Email is required.", "error")
            return redirect(url_for('teacher.edit_profile'))

        cursor.execute(
            "SELECT id FROM users WHERE email = %s AND id != %s", 
            (email, session['user_id'])
        )
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Email already taken by another user.", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('teacher.edit_profile'))

        cursor.execute("""
            UPDATE users 
            SET first_name = %s, last_name = %s, email = %s
            WHERE id = %s
        """, (first_name, last_name, email, session['user_id']))
        conn.commit()
        cursor.close()
        conn.close()

        session['user_email'] = email
        flash("Profile updated successfully!", "success")
        return redirect(url_for('teacher.profile'))

    cursor.close()
    conn.close()
    return render_template('teacher/edit_profile.html', user=user)

@teacher_bp.route('/update_profile', methods=['POST'])
def update_profile():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': 'Access denied'})

    user_id = session['user_id']
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()
    email = request.form.get('email', '').strip()

    if not first_name or not last_name or not email:
        return jsonify({'success': False, 'message': 'All fields are required'})

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id FROM users WHERE email = %s AND id != %s',
        (email, user_id)
    )
    existing_user = cursor.fetchone()

    if existing_user:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Email already exists'})

    try:
        cursor.execute(
            'UPDATE users SET first_name = %s, last_name = %s, email = %s WHERE id = %s',
            (first_name, last_name, email, user_id)
        )
        conn.commit()
        cursor.close()
        conn.close()

        session['user_email'] = email
        return jsonify({'success': True, 'message': 'Profile updated successfully'})
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to update profile'})

@teacher_bp.route('/change_password_ajax', methods=['POST'])
def change_password_ajax():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': 'Access denied'})

    user_id = session['user_id']
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not current_password or not new_password or not confirm_password:
        return jsonify({'success': False, 'message': 'All password fields are required'})

    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'New passwords do not match'})

    is_valid, message = validate_password(new_password)
    if not is_valid:
        return jsonify({'success': False, 'message': message})

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()

    if not user or not check_password_hash(user['password'], current_password):
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Current password is incorrect'})

    try:
        hashed_password = generate_password_hash(new_password)
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

@teacher_bp.route('/upload_profile_picture', methods=['POST'])
def upload_profile_picture():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': 'Access denied'})

    if 'profile_picture' not in request.files:
        return jsonify({'success': False, 'message': 'No file selected'})

    file = request.files['profile_picture']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'})

    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    if not ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
        return jsonify({'success': False, 'message': 'Invalid file type'})

    try:
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
        # Store as BYTEA (bytes) in PostgreSQL
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
            'profile_picture': img_base64
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Image processing failed: {str(e)}'})

@teacher_bp.route('/remove_profile_picture', methods=['POST'])
def remove_profile_picture():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': 'Access denied'})

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET user_profile = NULL WHERE id = %s',
            (session['user_id'],)
        )
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Profile picture removed successfully'})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Failed to remove picture: {str(e)}'})