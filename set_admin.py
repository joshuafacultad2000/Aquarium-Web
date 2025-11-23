#!/usr/bin/env python3
"""
Set a username to be admin and optionally reset its password.
Run with your venv python, e.g.:
  .\venv\Scripts\python.exe set_admin.py
"""
import os
import sqlite3
import getpass
import sys
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

# load .env if present so we use the same DATABASE_PATH as the app
load_dotenv()
DB = os.environ.get("DATABASE_PATH", "database.db")

def prompt(msg, default=None):
    v = input(msg).strip()
    if not v and default is not None:
        return default
    return v

def main():
    print("This will set a user as admin in", DB)
    username = prompt("Enter username to promote to admin (default 'admin'): ", "admin")
    pw_choice = prompt("Do you want to set/change the user's password now? (y/N): ", "N").lower()
    password = None
    if pw_choice == "y":
        password = getpass.getpass("Enter new password: ")
        if not password:
            print("Empty password — aborting.")
            sys.exit(1)
        password_hash = generate_password_hash(password)
    else:
        password_hash = None

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # ensure users table exists (safe)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0
    )
    """)
    conn.commit()

    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row:
        if password_hash is not None:
            cur.execute("UPDATE users SET password_hash = ?, is_admin = 1 WHERE username = ?", (password_hash, username))
            print(f"Updated password and set is_admin=1 for user: {username}")
        else:
            cur.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (username,))
            print(f"Set is_admin=1 for existing user: {username}")
    else:
        if password_hash is None:
            print("User does not exist and no password provided to create one. Provide a password to create the user.")
            conn.close()
            sys.exit(1)
        cur.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)", (username, password_hash))
        print(f"Created user and set is_admin=1: {username}")

    conn.commit()
    conn.close()
    print("Done. Now logout and log back in to refresh your session (so the Admin UI appears).")

if __name__ == "__main__":
    main()