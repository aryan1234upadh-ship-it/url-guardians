import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            is_admin INTEGER DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            url TEXT NOT NULL,
            risk_level TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

    # Add is_admin column if it doesn't exist (for existing DBs)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # column already exists

    conn.close()
    print("✅ Database initialized!")

def log_scan(username: str, url: str, risk_level: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (username, url, risk_level) VALUES (?, ?, ?)",
        (username, url, risk_level)
    )
    conn.commit()
    conn.close()

def make_admin(username: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_admin=1 WHERE username=?", (username,))
    conn.commit()
    conn.close()

init_db()