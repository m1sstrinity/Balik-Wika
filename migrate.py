import psycopg2
import os

conn = psycopg2.connect(os.environ['DATABASE_URL'])
cursor = conn.cursor()

cursor.execute('ALTER TABLE lessons ADD COLUMN IF NOT EXISTS user_id INTEGER;')
conn.commit()

print("Migration complete!")
cursor.close()
conn.close()