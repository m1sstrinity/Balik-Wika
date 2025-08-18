from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash
import sqlite3
import base64
import io
from PIL import Image
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

teacher_bp = Blueprint('teacher', __name__, template_folder='templates', static_folder='static', url_prefix='/teacher')

def get_db_connection():
    """Helper function to get database connection"""
    conn = sqlite3.connect('balikwika.db')
    conn.row_factory = sqlite3.Row
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
    
    # Get teacher information
    user = conn.execute(
        "SELECT first_name, last_name, email, user_profile AS profile_picture FROM users WHERE id = ? AND role = 'teacher'",
        (user_id,)
    ).fetchone()

    if not user:
        flash("Teacher account not found.", "error")
        conn.close()
        return redirect(url_for('login'))
    
    # ✅ DEBUG: Let's see what type of data we're getting
    print(f"DEBUG: profile_picture type: {type(user['profile_picture'])}")
    print(f"DEBUG: profile_picture value: {user['profile_picture'][:50] if user['profile_picture'] else None}")
    
    # ✅ FIXED: Handle BLOB profile picture properly
    profile_picture = None
    if user['profile_picture']:
        try:
            # For BLOB data, it should be bytes - encode to base64
            if isinstance(user['profile_picture'], bytes):
                profile_picture = base64.b64encode(user['profile_picture']).decode('utf-8')
            elif isinstance(user['profile_picture'], str):
                # If somehow it's already a string, use it directly
                profile_picture = user['profile_picture']
            else:
                # Handle any other type by converting to bytes first
                profile_picture = base64.b64encode(bytes(user['profile_picture'])).decode('utf-8')
        except Exception as e:
            print(f"Profile picture encoding error: {e}")
            profile_picture = None

    teacher_name = user['first_name'] if user['first_name'] else "Guro"
    
    # Count lessons and quizzes - add error handling
    try:
        lesson_count = conn.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]
    except:
        lesson_count = 0
    
    try:
        quiz_count = conn.execute("SELECT COUNT(*) FROM quizzes").fetchone()[0]
    except:
        quiz_count = 0

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

@teacher_bp.route('/add_question', methods=['POST'])
def add_question():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    data = request.get_json()
    question = data.get('question_text')
    choice_a = data.get('choice_a')
    choice_b = data.get('choice_b')
    choice_c = data.get('choice_c')
    choice_d = data.get('choice_d')
    correct = data.get('correct_answer')
    image = data.get('image')
    quiz_title = data.get('quiz_title')
    subject = data.get('subject')
    user_id = session.get('user_id')

    conn = get_db_connection()

    # Check if quiz exists
    quiz_row = conn.execute("SELECT id FROM quizzes WHERE title = ?", (quiz_title,)).fetchone()
    quiz_id = quiz_row['id'] if quiz_row else None

    subject_map = {
        "Pangngalan": 1,
        "Pandiwa": 2,
        "Pang-uri": 3,
        "Panghalip": 4
    }
    subject_id = subject_map.get(subject)

    if not all([question, choice_a, choice_b, choice_c, choice_d, correct, subject_id, quiz_id, user_id]):
        conn.close()
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400

    try:
        conn.execute('''
            INSERT INTO questions (
                quiz_id, subject_id, user_id, question_text,
                choice_a, choice_b, choice_c, choice_d, correct_answer, image
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            quiz_id, subject_id, user_id, question,
            choice_a, choice_b, choice_c, choice_d, correct, image
        ))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Question added successfully'})
    except Exception as e:
        conn.close()
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
    cursor.execute('SELECT id FROM quizzes WHERE title = ?', (title,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Duplicate title'}), 409

    # Insert new quiz
    cursor.execute('INSERT INTO quizzes (title) VALUES (?)', (title,))
    conn.commit()
    quiz_id = cursor.lastrowid
    conn.close()

    return jsonify({'message': 'Quiz added successfully', 'quiz_id': quiz_id}), 200

@teacher_bp.route('/mga-marka')
def mga_marka():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        flash(error_msg, "error")
        return redirect(url_for('login'))
    
    return render_template('mga-marka.html')

@teacher_bp.route('/add_lesson', methods=['POST'])
def add_lesson():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'success': False, 'message': error_msg}), 401

    title = request.form.get('title')
    content = request.form.get('content')
    subject = request.form.get('subject')
    user_id = session.get('user_id')

    if not all([title, content, subject]):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    # Map subject names to subject_id from subjects table
    subject_map = {
        "Pangngalan": 1,
        "Pandiwa": 2,
        "Pang-uri": 3,
        "Panghalip": 4
    }
    subject_id = subject_map.get(subject)

    if not subject_id:
        return jsonify({'success': False, 'message': 'Invalid subject'}), 400

    conn = get_db_connection()
    try:
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute('''
            INSERT INTO lessons (teacher_id, subject_id, title, content, created_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, subject_id, title, content, created_at, user_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Lesson added successfully'})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': f'Error adding lesson: {str(e)}'}), 500

@teacher_bp.route('/get_lessons')
def get_lessons():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        return jsonify({'error': error_msg}), 401

    # Create the data structure with subject names as keys
    data = {
        "Pangngalan": [],
        "Pandiwa": [], 
        "Pang-uri": [],
        "Panghalip": []
    }

    conn = get_db_connection()
    try:
        # Join lessons with subjects table to get subject names
        lessons = conn.execute('''
            SELECT l.title, l.content, l.created_at, 
                   s.name as subject_name,
                   u.first_name, u.last_name
            FROM lessons l
            JOIN subjects s ON l.subject_id = s.subject_id
            JOIN users u ON l.teacher_id = u.id
            ORDER BY l.created_at DESC
        ''').fetchall()

        for lesson in lessons:
            subject_name = lesson['subject_name']
            teacher_name = f"{lesson['first_name'] or ''} {lesson['last_name'] or ''}".strip() or "Guro"
            
            if subject_name in data:
                data[subject_name].append({
                    "title": lesson['title'],
                    "content": lesson['content'],
                    "teacher": teacher_name,
                    "date": lesson['created_at']
                })

        conn.close()
        return jsonify(data)
    except Exception as e:
        conn.close()
        return jsonify({'error': f'Error fetching lessons: {str(e)}'}), 500

@teacher_bp.route('/get_quizzes')
def get_quizzes():
    conn = sqlite3.connect('balikwika.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, title, created_at FROM quizzes')
    quizzes = cursor.fetchall()

    quiz_data = []
    for quiz in quizzes:
        quiz_id = quiz[0]
        cursor.execute('''
            SELECT question_text, choice_a, choice_b, choice_c, choice_d, correct_answer, image
            FROM questions
            WHERE quiz_id = ?
        ''', (quiz_id,))
        questions = cursor.fetchall()

        question_list = []
        for q in questions:
            question_list.append({
                'question_text': q[0],
                'choice_a': q[1],
                'choice_b': q[2],
                'choice_c': q[3],
                'choice_d': q[4],
                'correct_answer': q[5],
                'image': q[6]
            })

        quiz_data.append({
            'id': quiz[0],
            'title': quiz[1],
            'created_at': quiz[2],
            'questions': question_list
        })

    conn.close()
    return jsonify(quiz_data)

# Profile Routes

@teacher_bp.route('/profile')
def profile():
    is_valid, error_msg = require_teacher_login()
    if not is_valid:
        flash(error_msg, "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()

    if not user:
        flash("User not found.", "error")
        return redirect(url_for('login'))

    # ✅ FIXED: Handle BLOB profile picture properly
    profile_picture = None
    if user['user_profile']:
        try:
            # For BLOB data, it should be bytes - encode to base64
            if isinstance(user['user_profile'], bytes):
                profile_picture = base64.b64encode(user['user_profile']).decode('utf-8')
            elif isinstance(user['user_profile'], str):
                # If somehow it's already a string, use it directly
                profile_picture = user['user_profile']
            else:
                # Handle any other type by converting to bytes first
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
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()

    if not user:
        flash("User not found.", "error")
        conn.close()
        return redirect(url_for('login'))

    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()

        if not email:
            flash("Email is required.", "error")
            return redirect(url_for('teacher.edit_profile'))

        existing_user = conn.execute(
            "SELECT id FROM users WHERE email = ? AND id != ?", 
            (email, session['user_id'])
        ).fetchone()

        if existing_user:
            flash("Email already taken by another user.", "error")
            conn.close()
            return redirect(url_for('teacher.edit_profile'))

        conn.execute("""
            UPDATE users 
            SET first_name = ?, last_name = ?, email = ?
            WHERE id = ?
        """, (first_name, last_name, email, session['user_id']))
        conn.commit()
        conn.close()

        session['user_email'] = email
        flash("Profile updated successfully!", "success")
        return redirect(url_for('teacher.profile'))

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
    existing_user = conn.execute(
        'SELECT id FROM users WHERE email = ? AND id != ?',
        (email, user_id)
    ).fetchone()

    if existing_user:
        conn.close()
        return jsonify({'success': False, 'message': 'Email already exists'})

    try:
        conn.execute(
            'UPDATE users SET first_name = ?, last_name = ?, email = ? WHERE id = ?',
            (first_name, last_name, email, user_id)
        )
        conn.commit()
        conn.close()

        session['user_email'] = email
        return jsonify({'success': True, 'message': 'Profile updated successfully'})
    except Exception as e:
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
    user = conn.execute('SELECT password FROM users WHERE id = ?', (user_id,)).fetchone()

    if not user or not check_password_hash(user['password'], current_password):
        conn.close()
        return jsonify({'success': False, 'message': 'Current password is incorrect'})

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
        # ✅ FIXED: Store as BLOB (bytes) in database
        conn.execute(
            'UPDATE users SET user_profile = ? WHERE id = ?',
            (img_data, session['user_id'])  # Store as bytes, not base64 string
        )
        conn.commit()
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
        conn.execute(
            'UPDATE users SET user_profile = NULL WHERE id = ?',
            (session['user_id'],)
        )
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'Profile picture removed successfully'})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Failed to remove picture: {str(e)}'})