```markdown
# Aquarium-Web (Flask + SQLite)

This project is a simple Flask app using SQLite for persistence. The repo now includes CSRF protection, environment configuration, and helpful CLI commands.

Quick start:
1. Copy `.env.example` to `.env` and edit values (set SECRET_KEY to a long random string).
2. Create & activate a virtualenv and install requirements:
   - python3 -m venv venv
   - source venv/bin/activate
   - pip install -r requirements.txt
3. Initialize DB:
   - flask --app app.py init-db
4. Create a user:
   - flask --app app.py create-user admin
5. Run:
   - python app.py
6. Open http://127.0.0.1:5000/

Notes:
- Do not commit `.env` or `database.db`. Add secrets to `.env` only.
- For production: use HTTPS, set SESSION_COOKIE_SECURE=true, and run behind Gunicorn or another WSGI server.
```