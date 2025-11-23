#!/usr/bin/env python3
"""
Show user list and is_admin flags.
Run with venv python:
  .\venv\Scripts\python.exe show_users.py
"""
import sqlite3
DB = "database.db"
conn = sqlite3.connect(DB)
cur = conn.cursor()
try:
    rows = list(cur.execute("SELECT id, username, is_admin FROM users ORDER BY id"))
    if not rows:
        print("No users found.")
    else:
        print("id | username | is_admin")
        for r in rows:
            print(f"{r[0]:>2} | {r[1]:<20} | {r[2]}")
finally:
    conn.close()