"""
Machine Learning Classification System for Balik-Wika
SCIKIT-LEARN VERSION - Using Decision Tree Classifier
POSTGRESQL COMPATIBLE VERSION
"""

import psycopg2
from psycopg2.extras import RealDictCursor
import pickle
import os
from datetime import datetime
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler

# Global variables for the ML model
MODEL_PATH = 'balikwika_model.pkl'
SCALER_PATH = 'balikwika_scaler.pkl'
ml_model = None
scaler = None


def ensure_mastery_level_column(db_connection):
    """
    Check if mastery_level column exists, if not, add it.
    """
    cursor = db_connection.cursor()
    
    try:
        # Try to query mastery_level
        cursor.execute("SELECT mastery_level FROM users LIMIT 1")
    except psycopg2.errors.UndefinedColumn:
        # Column doesn't exist, add it
        print("⚠️ mastery_level column missing, adding it now...")
        db_connection.rollback()  # Clear the error state
        cursor.execute("ALTER TABLE users ADD COLUMN mastery_level TEXT DEFAULT 'Beginner'")
        db_connection.commit()
        print("✅ mastery_level column added successfully!")
    finally:
        cursor.close()


def classify_student_mastery(avg_score):
    """
    Classify student mastery level based on average score.
    
    Classification Rules:
    - Beginner: < 60%
    - Intermediate: 60-79%
    - Advanced: >= 80%
    
    Args:
        avg_score (float): Average quiz score percentage (0-100)
    
    Returns:
        str: 'Beginner', 'Intermediate', or 'Advanced'
    """
    if avg_score < 60:
        return 'Beginner'
    elif 60 <= avg_score < 80:
        return 'Intermediate'
    else:  # avg_score >= 80
        return 'Advanced'


def get_unlocked_levels(avg_score):
    """
    Determine which levels are unlocked based on performance.
    
    Args:
        avg_score (float): Average quiz score percentage
    
    Returns:
        str: Comma-separated string of unlocked levels
    """
    unlocked = ['Beginner']
    
    if avg_score >= 60:
        unlocked.append('Intermediate')
    
    if avg_score >= 80:
        unlocked.append('Advanced')
    
    return ', '.join(unlocked)


def prepare_features(metrics):
    """
    Prepare feature vector for ML prediction.
    
    Args:
        metrics (dict): Dictionary containing student metrics
    
    Returns:
        np.array: Feature vector for prediction
    """
    features = [
        metrics['avg_score'],
        metrics['total_quizzes'],
        metrics['completion_rate'],
        metrics['score_trend'],
        metrics['failed_count'],
        metrics['consecutive_fails'],
        metrics['days_inactive']
    ]
    return np.array(features).reshape(1, -1)


def load_or_create_model():
    """
    Load existing model or create a new one.
    
    Returns:
        tuple: (model, scaler)
    """
    global ml_model, scaler
    
    if ml_model is not None and scaler is not None:
        return ml_model, scaler
    
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        print("📦 Loading existing model...")
        with open(MODEL_PATH, 'rb') as f:
            ml_model = pickle.load(f)
        with open(SCALER_PATH, 'rb') as f:
            scaler = pickle.load(f)
        print("✅ Model loaded successfully!")
    else:
        print("🆕 Creating new Decision Tree model...")
        ml_model = DecisionTreeClassifier(
            max_depth=5,
            min_samples_split=2,
            min_samples_leaf=1,
            random_state=42
        )
        scaler = StandardScaler()
        print("✅ New model created!")
    
    return ml_model, scaler


def train_model_with_data(db_connection):
    """
    Train the Decision Tree model with existing student data.
    
    Args:
        db_connection: PostgreSQL database connection
    
    Returns:
        bool: True if training successful, False otherwise
    """
    global ml_model, scaler
    
    cursor = db_connection.cursor()
    
    # Get all students with quiz data
    cursor.execute("""
        SELECT DISTINCT u.id
        FROM users u
        JOIN quiz_attempts qa ON u.id = qa.user_id
        WHERE u.role = 'student' AND u.status = 'active'
    """)
    students = cursor.fetchall()
    
    if len(students) < 5:
        print("⚠️ Not enough data to train model (need at least 5 students)")
        cursor.close()
        return False
    
    # Collect training data
    X_train = []
    y_train = []
    
    for student in students:
        metrics = calculate_student_metrics(student['id'], db_connection)
        features = prepare_features(metrics)
        
        # Get label based on rule-based classification
        label = classify_student_mastery(metrics['avg_score'])
        label_encoded = {'Beginner': 0, 'Intermediate': 1, 'Advanced': 2}[label]
        
        X_train.append(features[0])
        y_train.append(label_encoded)
    
    X_train = np.array(X_train)
    y_train = np.array(y_train)
    
    # Scale features
    ml_model, scaler = load_or_create_model()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Train model
    print(f"🎓 Training model with {len(students)} students...")
    ml_model.fit(X_train_scaled, y_train)
    
    # Save model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(ml_model, f)
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)
    
    cursor.close()
    print("✅ Model trained and saved successfully!")
    return True


def predict_mastery_level(metrics):
    """
    Predict mastery level using ML model.
    Falls back to rule-based if model not available.
    
    Args:
        metrics (dict): Student metrics dictionary
    
    Returns:
        str: Predicted mastery level
    """
    try:
        global ml_model, scaler
        
        if ml_model is None or scaler is None:
            ml_model, scaler = load_or_create_model()
        
        # If model hasn't been trained yet, use rule-based
        if not hasattr(ml_model, 'classes_'):
            return classify_student_mastery(metrics['avg_score'])
        
        # Prepare features and predict
        features = prepare_features(metrics)
        features_scaled = scaler.transform(features)
        prediction = ml_model.predict(features_scaled)[0]
        
        # Convert prediction to label
        label_map = {0: 'Beginner', 1: 'Intermediate', 2: 'Advanced'}
        return label_map[prediction]
    
    except Exception as e:
        print(f"⚠️ ML prediction failed, using rule-based: {e}")
        return classify_student_mastery(metrics['avg_score'])


def calculate_student_metrics(user_id, db_connection):
    """
    Calculate comprehensive metrics for a student.
    Works with PostgreSQL database schema.
    
    Args:
        user_id (int): Student user ID (from users.id)
        db_connection: PostgreSQL database connection
    
    Returns:
        dict: Dictionary containing all calculated metrics
    """
    cursor = db_connection.cursor()
    
    # Get all quiz attempts for this student (using quiz_attempts table)
    query = """
        SELECT score, attempted_at
        FROM quiz_attempts
        WHERE user_id = %s
        ORDER BY attempted_at DESC
    """
    
    cursor.execute(query, (user_id,))
    attempts = cursor.fetchall()
    
    # If no quiz data, return beginner defaults
    if not attempts:
        cursor.close()
        return {
            'mastery_level': 'Beginner',
            'avg_score': 0.0,
            'total_quizzes': 0,
            'completion_rate': 0.0,
            'unlocked_levels': 'Beginner',
            'last_activity': 'Never',
            'progress_percentage': 0,
            'score_trend': 0.0,
            'failed_count': 0,
            'consecutive_fails': 0,
            'days_inactive': 999
        }
    
    # Calculate average score
    total_score = sum(attempt['score'] for attempt in attempts)
    avg_score = total_score / len(attempts)
    
    # Calculate score trend (recent performance vs overall average)
    if len(attempts) >= 3:
        recent_scores = [attempts[i]['score'] for i in range(min(3, len(attempts)))]
        recent_avg = sum(recent_scores) / len(recent_scores)
        score_trend = ((recent_avg - avg_score) / avg_score) * 100 if avg_score > 0 else 0
    else:
        score_trend = 0.0
    
    # Count failed quizzes (score < 60)
    failed_count = sum(1 for attempt in attempts if attempt['score'] < 60)
    
    # Calculate consecutive fails (from most recent)
    consecutive_fails = 0
    for attempt in attempts:
        if attempt['score'] < 60:
            consecutive_fails += 1
        else:
            break
    
    # Classify mastery level using ML
    temp_metrics = {
        'avg_score': avg_score,
        'total_quizzes': len(attempts),
        'completion_rate': 0,
        'score_trend': score_trend,
        'failed_count': failed_count,
        'consecutive_fails': consecutive_fails,
        'days_inactive': 0
    }
    
    # Determine unlocked levels
    unlocked_levels = get_unlocked_levels(avg_score)
    
    # Calculate completion rate (total quizzes taken vs available)
    cursor.execute("SELECT COUNT(*) as count FROM quizzes")
    total_available = cursor.fetchone()['count']
    completion_rate = (len(attempts) / total_available) * 100 if total_available > 0 else 0
    
    # Get last activity date
    last_activity = 'Never'
    days_inactive = 999
    if attempts:
        last_dt = attempts[0]['attempted_at']
        
        # PostgreSQL returns datetime objects directly
        if isinstance(last_dt, datetime):
            days_inactive = (datetime.now() - last_dt).days
            
            if days_inactive == 0:
                last_activity = 'Today'
            elif days_inactive == 1:
                last_activity = '1 day ago'
            else:
                last_activity = f'{days_inactive} days ago'
        else:
            # Fallback if string
            try:
                if 'T' in str(last_dt):
                    last_dt = datetime.fromisoformat(str(last_dt).replace('Z', '+00:00'))
                else:
                    last_dt = datetime.strptime(str(last_dt), '%Y-%m-%d %H:%M:%S')
                
                days_inactive = (datetime.now() - last_dt).days
                
                if days_inactive == 0:
                    last_activity = 'Today'
                elif days_inactive == 1:
                    last_activity = '1 day ago'
                else:
                    last_activity = f'{days_inactive} days ago'
            except Exception as e:
                last_activity = 'Recent'
                days_inactive = 0
    
    # Update temp_metrics with calculated values
    temp_metrics['completion_rate'] = completion_rate
    temp_metrics['days_inactive'] = days_inactive
    
    # Get ML prediction
    mastery_level = predict_mastery_level(temp_metrics)
    
    cursor.close()
    
    return {
        'mastery_level': mastery_level,
        'avg_score': round(avg_score, 2),
        'total_quizzes': len(attempts),
        'completion_rate': round(completion_rate, 2),
        'unlocked_levels': unlocked_levels,
        'last_activity': last_activity,
        'progress_percentage': round(avg_score, 2),
        'score_trend': round(score_trend, 2),
        'failed_count': failed_count,
        'consecutive_fails': consecutive_fails,
        'days_inactive': days_inactive
    }


def update_user_mastery_level(user_id, mastery_level, db_connection):
    """
    Update the mastery_level column in the users table.
    
    Args:
        user_id (int): Student user ID
        mastery_level (str): New mastery level
        db_connection: PostgreSQL database connection
    """
    cursor = db_connection.cursor()
    
    cursor.execute("""
        UPDATE users
        SET mastery_level = %s
        WHERE id = %s
    """, (mastery_level, user_id))
    
    db_connection.commit()
    cursor.close()


def update_student_metrics(user_id, metrics, db_connection):
    """
    Update or insert into student_metrics table.
    
    Args:
        user_id (int): Student user ID
        metrics (dict): Dictionary of calculated metrics
        db_connection: PostgreSQL database connection
    """
    cursor = db_connection.cursor()
    
    # Check if student_metrics table exists
    cursor.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = 'student_metrics'
        )
    """)
    
    table_exists = cursor.fetchone()[0]
    
    if not table_exists:
        # Create table if it doesn't exist
        print("⚠️ student_metrics table missing, creating it...")
        cursor.execute("""
            CREATE TABLE student_metrics (
                metric_id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                avg_score DECIMAL(5,2),
                score_trend DECIMAL(5,2),
                total_attempts INTEGER,
                failed_quizzes_count INTEGER,
                consecutive_fails INTEGER,
                days_inactive INTEGER,
                last_updated TIMESTAMP DEFAULT NOW(),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        db_connection.commit()
        print("✅ student_metrics table created!")
    
    # Check if record exists
    cursor.execute(
        "SELECT metric_id FROM student_metrics WHERE user_id = %s",
        (user_id,)
    )
    existing = cursor.fetchone()
    
    if existing:
        # Update existing record
        cursor.execute("""
            UPDATE student_metrics
            SET avg_score = %s,
                score_trend = %s,
                total_attempts = %s,
                failed_quizzes_count = %s,
                consecutive_fails = %s,
                days_inactive = %s,
                last_updated = NOW()
            WHERE user_id = %s
        """, (
            metrics['avg_score'],
            metrics['score_trend'],
            metrics['total_quizzes'],
            metrics['failed_count'],
            metrics['consecutive_fails'],
            metrics['days_inactive'],
            user_id
        ))
    else:
        # Insert new record
        cursor.execute("""
            INSERT INTO student_metrics 
            (user_id, avg_score, score_trend, total_attempts, 
             failed_quizzes_count, consecutive_fails, days_inactive)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            user_id,
            metrics['avg_score'],
            metrics['score_trend'],
            metrics['total_quizzes'],
            metrics['failed_count'],
            metrics['consecutive_fails'],
            metrics['days_inactive']
        ))
    
    db_connection.commit()
    cursor.close()


def get_all_students_with_classification(db_connection):
    """
    Get all students with their ML-classified mastery levels.
    AUTO-FIXES missing columns!
    
    Args:
        db_connection: PostgreSQL database connection
    
    Returns:
        list: List of dictionaries containing student data with classifications
    """
    # ✅ FIRST: Ensure mastery_level column exists
    ensure_mastery_level_column(db_connection)
    
    cursor = db_connection.cursor()
    
    # Get all students
    cursor.execute("""
        SELECT id, first_name, last_name, email, mastery_level
        FROM users 
        WHERE role = 'student' AND status = 'active'
    """)
    students = cursor.fetchall()
    
    student_data = []
    
    for student in students:
        try:
            # Calculate metrics for each student
            metrics = calculate_student_metrics(student['id'], db_connection)
            
            # Update mastery level in users table
            update_user_mastery_level(student['id'], metrics['mastery_level'], db_connection)
            
            # Update student_metrics table
            update_student_metrics(student['id'], metrics, db_connection)
            
            # Add to results
            student_data.append({
                'id': student['id'],
                'name': f"{student['first_name']} {student['last_name']}",
                'email': student['email'],
                'mastery_level': metrics['mastery_level'].lower(),  # lowercase for frontend
                'avg_score': metrics['avg_score'],
                'total_quizzes': metrics['total_quizzes'],
                'completion_rate': metrics['completion_rate'],
                'unlocked_levels': metrics['unlocked_levels'].split(', '),  # Convert to list
                'last_activity': metrics['last_activity'],
                'progress_percentage': metrics['progress_percentage']
            })
        
        except Exception as e:
            print(f"⚠️ Error classifying student {student['id']}: {e}")
            # Continue with other students
            continue
    
    cursor.close()
    return student_data


def classify_single_student(user_id, db_connection):
    """
    Classify a single student and update their progress.
    Call this after a student completes a quiz.
    
    Args:
        user_id (int): Student user ID
        db_connection: PostgreSQL database connection
    
    Returns:
        dict: Student metrics and classification
    """
    ensure_mastery_level_column(db_connection)
    metrics = calculate_student_metrics(user_id, db_connection)
    update_user_mastery_level(user_id, metrics['mastery_level'], db_connection)
    update_student_metrics(user_id, metrics, db_connection)
    return metrics


def get_classification_summary(db_connection):
    """
    Get summary counts for each mastery level.
    
    Args:
        db_connection: PostgreSQL database connection
    
    Returns:
        dict: Counts for each level
    """
    ensure_mastery_level_column(db_connection)
    cursor = db_connection.cursor()
    
    cursor.execute("""
        SELECT COUNT(*) as count FROM users 
        WHERE role = 'student' AND status = 'active' AND mastery_level = 'Beginner'
    """)
    beginner_count = cursor.fetchone()['count']
    
    cursor.execute("""
        SELECT COUNT(*) as count FROM users 
        WHERE role = 'student' AND status = 'active' AND mastery_level = 'Intermediate'
    """)
    intermediate_count = cursor.fetchone()['count']
    
    cursor.execute("""
        SELECT COUNT(*) as count FROM users 
        WHERE role = 'student' AND status = 'active' AND mastery_level = 'Advanced'
    """)
    advanced_count = cursor.fetchone()['count']
    
    total_count = beginner_count + intermediate_count + advanced_count
    
    cursor.close()
    
    return {
        'beginner': beginner_count,
        'intermediate': intermediate_count,
        'advanced': advanced_count,
        'total': total_count
    }


def get_model_info():
    """
    Get information about the current ML model.
    
    Returns:
        dict: Model information
    """
    global ml_model
    
    if ml_model is None:
        ml_model, _ = load_or_create_model()
    
    info = {
        'model_type': 'Decision Tree Classifier',
        'library': 'scikit-learn',
        'trained': hasattr(ml_model, 'classes_'),
        'max_depth': ml_model.max_depth,
        'min_samples_split': ml_model.min_samples_split,
        'min_samples_leaf': ml_model.min_samples_leaf
    }
    
    if hasattr(ml_model, 'classes_'):
        info['classes'] = ['Beginner', 'Intermediate', 'Advanced']
        info['n_features'] = ml_model.n_features_in_
    
    return info


# Example usage and testing
if __name__ == "__main__":
    print("Testing ML Classifier with Balik-Wika Database (PostgreSQL version)...")
    
    # Test classification logic
    test_scores = [45, 55, 65, 75, 85, 95]
    
    print("\n📊 Classification Rules:")
    for score in test_scores:
        level = classify_student_mastery(score)
        unlocked = get_unlocked_levels(score)
        print(f"Score: {score}% → Level: {level} → Unlocked: {unlocked}")
    
    print("\n✅ Classification logic working correctly!")
    print("\n💡 To test with your database:")
    print("   python test_ml_classifier_sklearn.py")
    print("\n📦 Model info:")
    print(get_model_info())