
"""
Create or reset an admin user without importing Flask.
Run with your venv Python, e.g.:
  .\venv\Scripts\python.exe create_or_reset_admin.py
"""
import sqlite3
import getpass
import sys
from werkzeug.security import generate_password_hash

DB = "database.db"

def main():
    username = input("Admin username to create/reset (default 'admin'): ").strip() or "admin"
    pwd = getpass.getpass(f"Password for {username}: ")
    if not pwd:
        print("Password required, exiting.")
        sys.exit(1)
    hashpw = generate_password_hash(pwd)

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0
    )
    """)
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE users SET password_hash = ?, is_admin = 1 WHERE username = ?", (hashpw, username))
        print(f"Updated password and granted admin: {username}")
    else:
        cur.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)", (username, hashpw))
        print(f"Created admin user: {username}")
    conn.commit()
    conn.close()

if __name__ == '__main__':
    main()