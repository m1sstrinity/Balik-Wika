"""
Database Configuration for Railway PostgreSQL Deployment
This file handles both SQLite (local) and PostgreSQL (production) connections
"""

import os
from urllib.parse import urlparse

# Try to import psycopg2, but don't fail if it's not available (for local development)
try:
    import psycopg2
    import psycopg2.extras
    PSYCOPG2_AVAILABLE = True
except ImportError:
    print("⚠️ psycopg2 not installed - PostgreSQL features disabled (OK for local development)")
    PSYCOPG2_AVAILABLE = False

class DatabaseConfig:
    """Unified database configuration for SQLite and PostgreSQL"""
    
    def __init__(self):
        self.is_production = self._is_production()
        self.db_url = self._get_database_url()
    
    def _is_production(self):
        """Check if running in production (Railway)"""
        return bool(os.environ.get('DATABASE_URL'))
    
    def _get_database_url(self):
        """Get appropriate database URL"""
        if self.is_production:
            db_url = os.environ.get('DATABASE_URL')
            # Fix Railway's postgres:// to postgresql://
            if db_url and db_url.startswith('postgres://'):
                db_url = db_url.replace('postgres://', 'postgresql://', 1)
            return db_url
        else:
            return 'sqlite:///balikwika.db'
    
    def get_connection(self):
        """Get database connection based on environment"""
        if self.is_production:
            return self._get_postgres_connection()
        else:
            return self._get_sqlite_connection()
    
    def _get_postgres_connection(self):
        """Get PostgreSQL connection for Railway"""
        if not PSYCOPG2_AVAILABLE:
            raise ImportError("psycopg2 not available - install with: pip install psycopg2-binary")
        
        try:
            url = urlparse(self.db_url)
            
            conn = psycopg2.connect(
                host=url.hostname,
                port=url.port,
                database=url.path[1:],
                user=url.username,
                password=url.password,
                cursor_factory=psycopg2.extras.RealDictCursor
            )
            return conn
        except Exception as e:
            print(f"❌ PostgreSQL connection error: {e}")
            raise
    
    def _get_sqlite_connection(self):
        """Get SQLite connection for local development"""
        import sqlite3
        conn = sqlite3.connect('balikwika.db')
        conn.row_factory = sqlite3.Row
        return conn


# Global database config instance
db_config = DatabaseConfig()


def get_db_connection():
    """Universal database connection function"""
    return db_config.get_connection()


def create_tables():
    """Create all required tables for both SQLite and PostgreSQL"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if db_config.is_production:
            print("🔧 Creating PostgreSQL tables...")
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    first_name VARCHAR(100),
                    last_name VARCHAR(100),
                    otp VARCHAR(10),
                    otp_expiry TIMESTAMP,
                    is_verified INTEGER DEFAULT 0,
                    reset_token VARCHAR(255),
                    reset_token_expiry TIMESTAMP,
                    role VARCHAR(20) DEFAULT 'student',
                    user_profile BYTEA,
                    is_temp_password INTEGER DEFAULT 0,
                    mastery_level VARCHAR(20) DEFAULT 'Beginner',
                    status VARCHAR(20) DEFAULT 'active',
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Subjects table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS subjects (
                    subject_id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    description TEXT,
                    icon VARCHAR(50),
                    color VARCHAR(20)
                )
            ''')
            
            # Lessons table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS lessons (
                    lesson_id SERIAL PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    content TEXT NOT NULL,
                    teacher_id INTEGER NOT NULL,
                    subject_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (teacher_id) REFERENCES users (id),
                    FOREIGN KEY (subject_id) REFERENCES subjects (subject_id)
                )
            ''')
            
            # Quizzes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quizzes (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    mastery_level VARCHAR(20),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Questions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS questions (
                    id SERIAL PRIMARY KEY,
                    quiz_id INTEGER NOT NULL,
                    question_text TEXT NOT NULL,
                    choice_a VARCHAR(255),
                    choice_b VARCHAR(255),
                    choice_c VARCHAR(255),
                    choice_d VARCHAR(255),
                    correct_answer VARCHAR(1),
                    image BYTEA,
                    trivia TEXT,
                    FOREIGN KEY (quiz_id) REFERENCES quizzes (id) ON DELETE CASCADE
                )
            ''')
            
            # Quiz attempts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quiz_attempts (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    quiz_id INTEGER NOT NULL,
                    score DECIMAL(5,2),
                    attempt_number INTEGER DEFAULT 1,
                    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (quiz_id) REFERENCES quizzes (id)
                )
            ''')
            
            # Quiz results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quiz_results (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    quiz_id INTEGER NOT NULL,
                    score DECIMAL(5,2),
                    date_taken TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    attempt_count INTEGER DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (quiz_id) REFERENCES quizzes (id)
                )
            ''')
            
            # Student metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS student_metrics (
                    metric_id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    avg_score DECIMAL(5,2),
                    score_trend DECIMAL(5,2),
                    total_attempts INTEGER,
                    failed_quizzes_count INTEGER,
                    consecutive_fails INTEGER,
                    days_inactive INTEGER,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Lesson videos table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS lesson_videos (
                    id SERIAL PRIMARY KEY,
                    lesson_id INTEGER NOT NULL,
                    video_filename VARCHAR(255) NOT NULL,
                    original_filename VARCHAR(255),
                    file_size BIGINT,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (lesson_id) REFERENCES lessons (lesson_id)
                )
            ''')
            
        else:
            print("🔧 Creating SQLite tables...")
            
            # Users table
            cursor.execute('''
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
                    is_temp_password INTEGER DEFAULT 0,
                    mastery_level TEXT DEFAULT 'Beginner',
                    status TEXT DEFAULT 'active',
                    registered_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Subjects table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS subjects (
                    subject_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    icon TEXT,
                    color TEXT
                )
            ''')
            
            # Lessons table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS lessons (
                    lesson_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    teacher_id INTEGER NOT NULL,
                    subject_id INTEGER NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (teacher_id) REFERENCES users (id),
                    FOREIGN KEY (subject_id) REFERENCES subjects (subject_id)
                )
            ''')
            
            # Quizzes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quizzes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    mastery_level TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Questions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS questions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    quiz_id INTEGER NOT NULL,
                    question_text TEXT NOT NULL,
                    choice_a TEXT,
                    choice_b TEXT,
                    choice_c TEXT,
                    choice_d TEXT,
                    correct_answer TEXT,
                    image BLOB,
                    trivia TEXT,
                    FOREIGN KEY (quiz_id) REFERENCES quizzes (id) ON DELETE CASCADE
                )
            ''')
            
            # Quiz attempts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quiz_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    quiz_id INTEGER NOT NULL,
                    score REAL,
                    attempt_number INTEGER DEFAULT 1,
                    attempted_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (quiz_id) REFERENCES quizzes (id)
                )
            ''')
            
            # Quiz results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quiz_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    quiz_id INTEGER NOT NULL,
                    score REAL,
                    date_taken TEXT DEFAULT CURRENT_TIMESTAMP,
                    attempt_count INTEGER DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (quiz_id) REFERENCES quizzes (id)
                )
            ''')
            
            # Student metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS student_metrics (
                    metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    avg_score REAL,
                    score_trend REAL,
                    total_attempts INTEGER,
                    failed_quizzes_count INTEGER,
                    consecutive_fails INTEGER,
                    days_inactive INTEGER,
                    last_updated TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Lesson videos table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS lesson_videos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    lesson_id INTEGER NOT NULL,
                    video_filename TEXT NOT NULL,
                    original_filename TEXT,
                    file_size INTEGER,
                    uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (lesson_id) REFERENCES lessons (lesson_id)
                )
            ''')
        
        conn.commit()
        print("✅ All tables created successfully!")
        
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        import traceback
        traceback.print_exc()
        conn.rollback()
        raise
    finally:
        conn.close()