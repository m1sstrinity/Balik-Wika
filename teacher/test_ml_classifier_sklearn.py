"""
Test script for ML classification system - Scikit-learn Version
"""

import sqlite3
import sys
import os

# Add parent directory to path to import ml_classifier
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def get_db_connection():
    """Get database connection - UPDATE THIS PATH"""
    try:
        # Try common database names
        possible_paths = [
            'balikwika.db',
            'database.db',
            'instance/balikwika.db',
            '../balikwika.db'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                print(f"✅ Found database at: {path}")
                conn = sqlite3.connect(path)
                conn.row_factory = sqlite3.Row
                return conn
        
        print("❌ Database not found. Please update the path in this script.")
        print("   Current directory:", os.getcwd())
        print("   Looking for: balikwika.db")
        return None
    
    except Exception as e:
        print(f"❌ Error connecting to database: {e}")
        return None


def test_database_schema():
    """Test if database has the correct schema"""
    print("=" * 70)
    print("STEP 1: Verifying Database Schema")
    print("=" * 70)
    
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor()
    
    # Check all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    print(f"\n📋 Tables found: {', '.join(tables)}")
    
    # Check required tables
    required_tables = ['users', 'quiz_attempts', 'student_metrics']
    missing = [t for t in required_tables if t not in tables]
    
    if missing:
        print(f"\n⚠️ Missing recommended tables: {missing}")
        if 'student_metrics' in missing:
            print("\n💡 Creating student_metrics table...")
            cursor.execute("""
                CREATE TABLE "student_metrics" (
                    "metric_id" INTEGER PRIMARY KEY AUTOINCREMENT,
                    "user_id" INTEGER NOT NULL,
                    "avg_score" DECIMAL(5,2),
                    "score_trend" DECIMAL(5,2),
                    "total_attempts" INTEGER,
                    "failed_quizzes_count" INTEGER,
                    "consecutive_fails" INTEGER,
                    "days_inactive" INTEGER,
                    "last_updated" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY("user_id") REFERENCES "users"("id")
                )
            """)
            conn.commit()
            print("✅ Created student_metrics table")
    else:
        print("✅ All required tables exist!")
    
    # Check users table schema
    print("\n👥 Checking users table structure...")
    cursor.execute("PRAGMA table_info(users)")
    columns = cursor.fetchall()
    
    user_columns = [col[1] for col in columns]
    print(f"   Columns: {', '.join(user_columns)}")
    
    if 'mastery_level' in user_columns:
        print("   ✅ mastery_level column exists")
    else:
        print("   ⚠️ mastery_level column missing - will be added")
    
    # Check quiz_attempts table
    if 'quiz_attempts' in tables:
        print("\n📝 Checking quiz_attempts table...")
        cursor.execute("PRAGMA table_info(quiz_attempts)")
        columns = cursor.fetchall()
        print(f"   Columns: {', '.join([col[1] for col in columns])}")
        print("   ✅ quiz_attempts table ready")
    
    return conn


def check_sample_data(conn):
    """Check if there's data to work with"""
    print("\n" + "=" * 70)
    print("STEP 2: Checking Sample Data")
    print("=" * 70)
    
    cursor = conn.cursor()
    
    # Count active students
    student_count = cursor.execute("""
        SELECT COUNT(*) FROM users 
        WHERE role = 'student' AND status = 'active'
    """).fetchone()[0]
    
    print(f"\n👥 Active students: {student_count}")
    
    if student_count == 0:
        print("⚠️ No active students found!")
        print("\n💡 To add a test student:")
        print("""
        INSERT INTO users (email, password, role, status, first_name, last_name, is_verified)
        VALUES ('test@student.com', 'password123', 'student', 'active', 'Test', 'Student', 1);
        """)
        return False
    
    # Count quiz attempts
    attempt_count = cursor.execute("SELECT COUNT(*) FROM quiz_attempts").fetchone()[0]
    
    print(f"📝 Total quiz attempts: {attempt_count}")
    
    if attempt_count == 0:
        print("⚠️ No quiz attempts found!")
        print("\n💡 To add test quiz attempts (assuming user_id=1, quiz_id=1):")
        print("""
        INSERT INTO quiz_attempts (user_id, quiz_id, score, attempt_number)
        VALUES 
        (1, 1, 75, 1),
        (1, 2, 82, 1),
        (1, 3, 68, 1);
        """)
        return False
    
    # Show some sample data
    print("\n📊 Sample Quiz Attempts:")
    cursor.execute("""
        SELECT u.first_name, u.last_name, qa.score, qa.attempted_at
        FROM quiz_attempts qa
        JOIN users u ON qa.user_id = u.id
        WHERE u.role = 'student'
        LIMIT 5
    """)
    
    for row in cursor.fetchall():
        print(f"   {row[0]} {row[1]}: {row[2]}% on {row[3]}")
    
    return True


def test_classification_logic():
    """Test the classification rules"""
    print("\n" + "=" * 70)
    print("STEP 3: Testing Classification Logic")
    print("=" * 70)
    
    # Import here to avoid issues if file doesn't exist yet
    try:
        from ml_classifier_sklearn import classify_student_mastery, get_unlocked_levels
    except ImportError:
        print("❌ ml_classifier_sklearn.py not found!")
        print("   Please copy ml_classifier_sklearn.py to your project directory")
        return False
    
    test_cases = [
        (30, 'Beginner'),
        (55, 'Beginner'),
        (65, 'Intermediate'),
        (75, 'Intermediate'),
        (85, 'Advanced'),
        (95, 'Advanced')
    ]
    
    print("\n📊 Testing Classification Rules:")
    all_passed = True
    
    for score, expected in test_cases:
        result = classify_student_mastery(score)
        unlocked = get_unlocked_levels(score)
        status = "✅" if result == expected else "❌"
        print(f"{status} {score}% → {result} (expected: {expected}) | Unlocked: {unlocked}")
        
        if result != expected:
            all_passed = False
    
    if all_passed:
        print("\n✅ All classification tests PASSED!")
    else:
        print("\n❌ Some tests FAILED!")
    
    return all_passed


def test_student_classification(conn):
    """Test classification on real students"""
    print("\n" + "=" * 70)
    print("STEP 4: Testing Real Student Classification")
    print("=" * 70)
    
    try:
        from ml_classifier_sklearn import calculate_student_metrics
    except ImportError:
        print("❌ ml_classifier_sklearn.py not found!")
        return False
    
    cursor = conn.cursor()
    
    # Get a student with quiz data
    cursor.execute("""
        SELECT DISTINCT u.id, u.first_name, u.last_name
        FROM users u
        JOIN quiz_attempts qa ON u.id = qa.user_id
        WHERE u.role = 'student' AND u.status = 'active'
        LIMIT 1
    """)
    
    student = cursor.fetchone()
    
    if not student:
        print("❌ No students with quiz data found")
        return False
    
    print(f"\n👤 Testing student: {student['first_name']} {student['last_name']}")
    
    # Calculate metrics
    metrics = calculate_student_metrics(student['id'], conn)
    
    print(f"\n📊 Classification Results:")
    print(f"   🎯 Mastery Level: {metrics['mastery_level']}")
    print(f"   📈 Average Score: {metrics['avg_score']}%")
    print(f"   📝 Total Quizzes: {metrics['total_quizzes']}")
    print(f"   ✅ Completion Rate: {metrics['completion_rate']}%")
    print(f"   🔓 Unlocked Levels: {metrics['unlocked_levels']}")
    print(f"   📅 Last Activity: {metrics['last_activity']}")
    print(f"   📉 Score Trend: {metrics['score_trend']}%")
    print(f"   ❌ Failed Quizzes: {metrics['failed_count']}")
    print(f"   🔴 Consecutive Fails: {metrics['consecutive_fails']}")
    
    return True


def test_ml_training(conn):
    """Test ML model training"""
    print("\n" + "=" * 70)
    print("STEP 5: Testing ML Model Training (scikit-learn)")
    print("=" * 70)
    
    try:
        from ml_classifier_sklearn import train_model_with_data, get_model_info
    except ImportError:
        print("❌ ml_classifier_sklearn.py not found!")
        return False
    
    print("\n🔬 Training Decision Tree model...")
    success = train_model_with_data(conn)
    
    if success:
        print("\n✅ Model training successful!")
        print("\n📦 Model Information:")
        info = get_model_info()
        for key, value in info.items():
            print(f"   {key}: {value}")
    else:
        print("\n⚠️ Not enough data to train model")
        print("   Using rule-based classification instead")
    
    return success


def test_all_students(conn):
    """Classify all students"""
    print("\n" + "=" * 70)
    print("STEP 6: Classifying All Students")
    print("=" * 70)
    
    try:
        from ml_classifier_sklearn import get_all_students_with_classification, get_classification_summary
    except ImportError:
        print("❌ ml_classifier_sklearn.py not found!")
        return False
    
    try:
        # Get classification summary BEFORE
        print("\n📊 Classification BEFORE update:")
        summary_before = get_classification_summary(conn)
        print(f"   📚 Beginner: {summary_before['beginner']}")
        print(f"   📖 Intermediate: {summary_before['intermediate']}")
        print(f"   🎓 Advanced: {summary_before['advanced']}")
        print(f"   👥 Total: {summary_before['total']}")
        
        # Run classification
        print("\n🔄 Running ML classification...")
        students = get_all_students_with_classification(conn)
        
        if not students:
            print("❌ No students found or classified")
            return False
        
        # Show results
        print(f"\n📋 Classification Results:")
        print(f"{'Name':<25} {'Level':<15} {'Avg Score':<12} {'Quizzes'}")
        print("-" * 70)
        
        for student in students:
            level = student['mastery_level'].upper()
            print(f"{student['name']:<25} {level:<15} {student['avg_score']:<12} {student['total_quizzes']}")
        
        # Get classification summary AFTER
        print("\n📊 Classification AFTER update:")
        summary_after = get_classification_summary(conn)
        print(f"   📚 Beginner: {summary_after['beginner']}")
        print(f"   📖 Intermediate: {summary_after['intermediate']}")
        print(f"   🎓 Advanced: {summary_after['advanced']}")
        print(f"   👥 Total: {summary_after['total']}")
        
        print("\n✅ All students classified successfully!")
        return True
    
    except Exception as e:
        print(f"❌ Error during classification: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n" + "🤖" * 35)
    print("BALIK-WIKA ML CLASSIFIER TEST SUITE")
    print("SCIKIT-LEARN VERSION (Decision Tree)")
    print("🤖" * 35 + "\n")
    
    # Test 1: Database schema
    conn = test_database_schema()
    if not conn:
        print("\n❌ Cannot continue without database")
        return
    
    # Test 2: Sample data
    has_data = check_sample_data(conn)
    if not has_data:
        print("\n⚠️ Not enough data to test classification")
        print("   Add students and quiz attempts first")
        conn.close()
        return
    
    # Test 3: Classification logic
    test_classification_logic()
    
    # Test 4: Single student
    test_student_classification(conn)
    
    # Test 5: ML model training
    test_ml_training(conn)
    
    # Test 6: All students
    test_all_students(conn)
    
    conn.close()
    
    print("\n" + "=" * 70)
    print("✅ ALL TESTS COMPLETE!")
    print("=" * 70)
    
    print("\n🎯 NEXT STEPS:")
    print("1. Copy ml_classifier_sklearn.py to your teacher/ folder")
    print("2. Import it in your Flask route:")
    print("   from teacher.ml_classifier_sklearn import get_all_students_with_classification")
    print("3. Use it in your kasanayan route")
    print("4. Test in browser!")
    print("\n📦 Required packages:")
    print("   pip install scikit-learn numpy --break-system-packages")


if __name__ == "__main__":
    main()
