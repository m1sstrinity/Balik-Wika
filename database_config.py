"""
Database Configuration for Railway PostgreSQL Deployment
This file handles both SQLite (local) and PostgreSQL (production) connections
"""

import os
import sqlite3
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
            # Parse DATABASE_URL
            url = urlparse(self.db_url)
            
            conn = psycopg2.connect(
                host=url.hostname,
                port=url.port,
                database=url.path[1:],  # Remove leading slash
                user=url.username,
                password=url.password,
                cursor_factory=psycopg2.extras.RealDictCursor
            )
            return conn
        except Exception as e:
            print(f"PostgreSQL connection error: {e}")
            raise
    
    def _get_sqlite_connection(self):
        """Get SQLite connection for local development"""
        conn = sqlite3.connect('balikwika.db')
        conn.row_factory = sqlite3.Row
        return conn


# Global database config instance
db_config = DatabaseConfig()


def get_db_connection():
    """
    Universal database connection function
    Replace all existing get_db_connection() calls with this
    """
    return db_config.get_connection()


def execute_query(query, params=None, fetch_one=False, fetch_all=False):
    """
    Execute database query with automatic connection handling
    ✅ FIXED: Now properly converts ? to %s for PostgreSQL
    
    Args:
        query (str): SQL query (use ? for placeholders)
        params (tuple): Query parameters
        fetch_one (bool): Return single row
        fetch_all (bool): Return all rows
    
    Returns:
        Query result or None
    """
    conn = get_db_connection()
    try:
        if db_config.is_production:
            cursor = conn.cursor()
            # ✅ Convert ? to %s for PostgreSQL
            pg_query = query.replace('?', '%s')
            cursor.execute(pg_query, params or ())
            
            if fetch_one:
                result = cursor.fetchone()
            elif fetch_all:
                result = cursor.fetchall()
            else:
                conn.commit()
                result = cursor.rowcount
            
            return result
        else:
            # SQLite - use ? placeholders
            if fetch_one:
                return conn.execute(query, params or ()).fetchone()
            elif fetch_all:
                return conn.execute(query, params or ()).fetchall()
            else:
                conn.execute(query, params or ())
                conn.commit()
                return conn.total_changes
    finally:
        conn.close()


def create_tables():
    """
    ✅ FIXED: Create all required tables for BOTH SQLite and PostgreSQL
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if db_config.is_production:
            # ✅ PostgreSQL schema
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
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS subjects (
                    subject_id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    description TEXT,
                    icon VARCHAR(50),
                    color VARCHAR(20)
                )
            ''')
            
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
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quizzes (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    mastery_level VARCHAR(20),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
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
            # ✅ SQLite schema
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
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS subjects (
                    subject_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    icon TEXT,
                    color TEXT
                )
            ''')
            
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
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quizzes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    mastery_level TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
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
        conn.rollback()
        raise
    finally:
        conn.close()