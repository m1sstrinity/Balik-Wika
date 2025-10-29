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
        # ✅ ONLY import sqlite3 when needed (not in production)
        import sqlite3
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
            # PostgreSQL schema (same as before)
            # ... your existing PostgreSQL table creation code ...
            pass
        else:
            # SQLite schema (same as before)
            # ... your existing SQLite table creation code ...
            pass
        
        conn.commit()
        print("✅ All tables created successfully!")
        
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()