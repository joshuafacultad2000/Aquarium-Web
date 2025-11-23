#!/usr/bin/env python3
"""
Standalone script to create or promote an admin user without importing Flask.
Run with the project's venv Python, e.g.:
  .\venv\Scripts\python.exe create_admin_standalone.py

This will:
- create the users table if missing
- insert or replace the user with is_admin = 1
"""
import sqlite3
import getpass
import sys
from werkzeug.security import generate_password_hash

DB_PATH = "database.db"

def main():
    print("This script will create or promote a user to admin in", DB_PATH)
    username = input("Admin username (default 'admin'): ").strip() or "admin"
    pw = getpass.getpass(f"Password for {username}: ")
    if not pw:
        print("Password required. Exiting.")
        sys.exit(1)
    pw_hash = generate_password_hash(pw)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0
    )
    """)

    cur.execute(
        "INSERT OR REPLACE INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
        (username, pw_hash, 1),
    )

    conn.commit()
    conn.close()
    print(f"Admin user created/updated. Username: {username}")

if __name__ == "__main__":
    main()