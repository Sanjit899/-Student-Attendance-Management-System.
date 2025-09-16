#!/usr/bin/env python3
"""
attendance_app.py

Single-file Flask + MongoDB student attendance management system generator.
When you run this file, it will automatically create the following (if missing):
 - templates/ (many HTML templates)
 - static/ (images, css)
 - .env (default values)
 - requirements.txt

It uses local MongoDB by default (mongodb://localhost:27017/attendance_db).

Dependencies (requirements.txt will be created automatically):
flask
pymongo
python-dotenv
flask-bcrypt
pandas
openpyxl
fpdf

Run: python attendance_app.py
Then open http://127.0.0.1:5000

Default admin created: admin@example.com / Password: Admin@123

This file is designed for local development and learning. For production, secure the secrets,
use proper email sending for password resets, and configure HTTPS.
"""

import os
import io
import csv
import secrets
import base64
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, send_file, abort
)
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_bcrypt import Bcrypt

# Try to import optional libs; if missing, the app will still create files but some features will need pip install
try:
    import pandas as pd
except Exception:
    pd = None

try:
    from fpdf import FPDF
except Exception:
    FPDF = None

# -----------------------
# Configuration / Bootstrap
# -----------------------
BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
IMAGES_DIR = STATIC_DIR / "images"
ENV_PATH = BASE_DIR / ".env"
REQUIREMENTS_PATH = BASE_DIR / "requirements.txt"

DEFAULT_ENV = {
    "SECRET_KEY": secrets.token_hex(16),
    "MONGO_URI": "mongodb://localhost:27017/attendance_db",
    "ADMIN_EMAIL": "admin@example.com",
    "ADMIN_PASSWORD": "Admin@123"
}

REQUIREMENTS_TEXT = """
flask
pymongo
python-dotenv
flask-bcrypt
pandas
openpyxl
fpdf
"""

# Create Flask app
app = Flask(__name__)
app.template_folder = str(TEMPLATES_DIR)
app.static_folder = str(STATIC_DIR)

# Ensure folders and files exist
def ensure_project_structure():
    TEMPLATES_DIR.mkdir(exist_ok=True)
    STATIC_DIR.mkdir(exist_ok=True)
    IMAGES_DIR.mkdir(exist_ok=True)

    # Write requirements.txt if missing
    if not REQUIREMENTS_PATH.exists():
        REQUIREMENTS_PATH.write_text(REQUIREMENTS_TEXT.strip())

    # Write .env if missing
    if not ENV_PATH.exists():
        lines = []
        for k, v in DEFAULT_ENV.items():
            lines.append(f"{k}={v}")
        ENV_PATH.write_text("\n".join(lines))

    # Write placeholder images (SVGs) if missing
    school_logo = IMAGES_DIR / "school_logo.svg"
    if not school_logo.exists():
        school_logo.write_text("""
<svg xmlns='http://www.w3.org/2000/svg' width='200' height='60'>
  <rect width='100%' height='100%' fill='#0d6efd' rx='8'/>
  <text x='50%' y='50%' font-size='18' fill='white' dominant-baseline='middle' text-anchor='middle'>SCHOOL</text>
</svg>
""")
    student_img = IMAGES_DIR / "student.svg"
    if not student_img.exists():
        student_img.write_text("""
<svg xmlns='http://www.w3.org/2000/svg' width='120' height='120'>
  <circle cx='60' cy='40' r='30' fill='#6c757d'/>
  <rect x='20' y='75' width='80' height='30' fill='#adb5bd' rx='6'/>
</svg>
""")

    teacher_img = IMAGES_DIR / "teacher.svg"
    if not teacher_img.exists():
        teacher_img.write_text("""
<svg xmlns='http://www.w3.org/2000/svg' width='120' height='120'>
  <circle cx='60' cy='40' r='30' fill='#198754'/>
  <rect x='10' y='75' width='100' height='30' fill='#ced4da' rx='6'/>
</svg>
""")

    # Write simple base.html and other templates if missing
    def write_template(name, content):
        p = TEMPLATES_DIR / name
        if not p.exists():
            p.write_text(content)

    base_html = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{% block title %}Attendance System{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body { padding-top: 70px; }
      .sidebar { min-width: 200px; }
      .card-small { min-height: 100px; }
    </style>
  </head>
  <body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary fixed-top">
      <div class="container-fluid">
        <a class="navbar-brand" href="{{ url_for('dashboard') }}">Attendance</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navmenu">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navmenu">
          <ul class="navbar-nav ms-auto">
            {% if session.get('user_id') %}
            <li class="nav-item"><a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('profile') }}">Profile</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
            {% else %}
            <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">Register</a></li>
            {% endif %}
          </ul>
        </div>
      </div>
    </nav>

    <div class="container-fluid">
      <div class="row">
        <div class="col-md-2 d-none d-md-block sidebar">
          <div class="list-group">
            <a href="{{ url_for('dashboard') }}" class="list-group-item list-group-item-action">Dashboard</a>
            <a href="{{ url_for('students') }}" class="list-group-item list-group-item-action">Students</a>
            <a href="{{ url_for('classes') }}" class="list-group-item list-group-item-action">Classes</a>
            <a href="{{ url_for('mark_attendance') }}" class="list-group-item list-group-item-action">Mark Attendance</a>
            <a href="{{ url_for('attendance_history') }}" class="list-group-item list-group-item-action">Attendance History</a>
            <a href="{{ url_for('reports') }}" class="list-group-item list-group-item-action">Reports</a>
            <a href="{{ url_for('notifications') }}" class="list-group-item list-group-item-action">Notifications</a>
          </div>
        </div>
        <main class="col-md-10 ms-sm-auto px-4">
          {% with messages = get_flashed_messages() %}
            {% if messages %}
              <div class="mt-2">
                {% for m in messages %}
                  <div class="alert alert-info">{{ m }}</div>
                {% endfor %}
              </div>
            {% endif %}
          {% endwith %}

          {% block content %}{% endblock %}
        </main>
      </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

    write_template('base.html', base_html)

    # Login template
    write_template('login.html', """{% extends 'base.html' %}
{% block title %}Login{% endblock %}
{% block content %}
<div class="card mt-3 p-3">
  <h4>Login</h4>
  <form method="post">
    <div class="mb-3">
      <label class="form-label">Email</label>
      <input name="email" required class="form-control">
    </div>
    <div class="mb-3">
      <label class="form-label">Password</label>
      <input name="password" type="password" required class="form-control">
    </div>
    <button class="btn btn-primary">Login</button>
    <a href="{{ url_for('forgot_password') }}" class="btn btn-link">Forgot Password?</a>
  </form>
</div>
{% endblock %}
""")

    # Register
    write_template('register.html', """{% extends 'base.html' %}
{% block title %}Register{% endblock %}
{% block content %}
<div class="card mt-3 p-3">
  <h4>Register a new account</h4>
  <form method="post">
    <div class="mb-3"><label class="form-label">Full Name</label><input name="name" required class="form-control"></div>
    <div class="mb-3"><label class="form-label">Email</label><input name="email" type="email" required class="form-control"></div>
    <div class="mb-3"><label class="form-label">Password</label><input name="password" type="password" required class="form-control"></div>
    <div class="mb-3"><label class="form-label">Role</label>
      <select name="role" class="form-control"><option value="teacher">Teacher</option><option value="admin">Admin</option></select>
    </div>
    <button class="btn btn-success">Register</button>
  </form>
</div>
{% endblock %}
""")

    # Dashboard
    write_template('dashboard.html', """{% extends 'base.html' %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<h2 class="mt-2">Dashboard</h2>
<div class="row">
  <div class="col-md-3"><div class="card p-3 card-small"><h5>Total Students</h5><h3>{{ stats.total_students }}</h3></div></div>
  <div class="col-md-3"><div class="card p-3 card-small"><h5>Total Classes</h5><h3>{{ stats.total_classes }}</h3></div></div>
  <div class="col-md-3"><div class="card p-3 card-small"><h5>Attendance Today</h5><h3>{{ stats.attendance_today }}</h3></div></div>
  <div class="col-md-3"><div class="card p-3 card-small"><h5>Absences Today</h5><h3>{{ stats.absent_today }}</h3></div></div>
</div>

<h4 class="mt-4">Recent Absences</h4>
<table class="table mt-2">
  <thead><tr><th>Date</th><th>Student</th><th>Class</th></tr></thead>
  <tbody>
    {% for a in recent_absences %}
      <tr><td>{{ a.date }}</td><td>{{ a.student_name }}</td><td>{{ a.class_name }}</td></tr>
    {% else %}
      <tr><td colspan="3">No recent absences</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
""")

    # Students listing & form
    write_template('students.html', """{% extends 'base.html' %}
{% block title %}Students{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center">
  <h3>Students</h3>
  <a href="{{ url_for('add_student') }}" class="btn btn-primary">Add Student</a>
</div>
<table class="table mt-3">
  <thead><tr><th>#</th><th>Name</th><th>Roll</th><th>Class</th><th>Contact</th><th>Actions</th></tr></thead>
  <tbody>
    {% for s in students %}
    <tr>
      <td>{{ loop.index }}</td>
      <td>{{ s.name }}</td>
      <td>{{ s.roll_no }}</td>
      <td>{{ s.class_name }}</td>
      <td>{{ s.parent_contact }}</td>
      <td>
        <a class="btn btn-sm btn-secondary" href="{{ url_for('edit_student', student_id=s._id) }}">Edit</a>
        <a class="btn btn-sm btn-danger" href="{{ url_for('delete_student', student_id=s._id) }}" onclick="return confirm('Delete student?')">Delete</a>
      </td>
    </tr>
    {% else %}
      <tr><td colspan="6">No students yet</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
""")

    write_template('student_form.html', """{% extends 'base.html' %}
{% block title %}Student Form{% endblock %}
{% block content %}
<div class="card p-3 mt-3">
  <h4>{{ 'Edit' if student else 'Add' }} Student</h4>
  <form method="post" enctype="multipart/form-data">
    <div class="mb-3"><label class="form-label">Full Name</label><input name="name" value="{{ student.name if student }}" required class="form-control"></div>
    <div class="mb-3"><label class="form-label">Roll No</label><input name="roll_no" value="{{ student.roll_no if student }}" class="form-control"></div>
    <div class="mb-3"><label class="form-label">Class</label>
      <select name="class_id" class="form-control">
        {% for c in classes %}
          <option value="{{ c._id }}" {% if student and student.class_id==c._id %}selected{% endif %}>{{ c.name }}</option>
        {% endfor %}
      </select>
    </div>
    <div class="mb-3"><label class="form-label">Parent Contact</label><input name="parent_contact" value="{{ student.parent_contact if student }}" class="form-control"></div>
    <div class="mb-3"><label class="form-label">Email</label><input name="email" value="{{ student.email if student }}" class="form-control"></div>
    <div class="mb-3"><label class="form-label">Date of Birth</label><input name="dob" type="date" value="{{ student.dob if student }}" class="form-control"></div>
    <div class="mb-3"><label class="form-label">Photo (optional)</label><input name="photo" type="file" class="form-control"></div>
    <button class="btn btn-success">Save</button>
  </form>
</div>
{% endblock %}
""")

    # Classes
    write_template('classes.html', """{% extends 'base.html' %}
{% block title %}Classes{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center">
  <h3>Classes</h3>
  <a href="{{ url_for('add_class') }}" class="btn btn-primary">Add Class</a>
</div>
<table class="table mt-3">
  <thead><tr><th>#</th><th>Name</th><th>Section</th><th>Actions</th></tr></thead>
  <tbody>
    {% for c in classes %}
      <tr><td>{{ loop.index }}</td><td>{{ c.name }}</td><td>{{ c.section }}</td>
      <td>
        <a class="btn btn-sm btn-secondary" href="{{ url_for('edit_class', class_id=c._id) }}">Edit</a>
        <a class="btn btn-sm btn-danger" href="{{ url_for('delete_class', class_id=c._id) }}" onclick="return confirm('Delete class?')">Delete</a>
      </td></tr>
    {% else %}
      <tr><td colspan="4">No classes yet</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
""")

    write_template('class_form.html', """{% extends 'base.html' %}
{% block title %}Class Form{% endblock %}
{% block content %}
<div class="card p-3 mt-3">
  <h4>{{ 'Edit' if cls else 'Add' }} Class</h4>
  <form method="post">
    <div class="mb-3"><label class="form-label">Name</label><input name="name" value="{{ cls.name if cls }}" required class="form-control"></div>
    <div class="mb-3"><label class="form-label">Section</label><input name="section" value="{{ cls.section if cls }}" class="form-control"></div>
    <button class="btn btn-success">Save</button>
  </form>
</div>
{% endblock %}
""")

    # Mark attendance
    write_template('attendance_mark.html', """{% extends 'base.html' %}
{% block title %}Mark Attendance{% endblock %}
{% block content %}
<h4>Mark Attendance</h4>
<form method="get" class="row g-2 mb-3">
  <div class="col-md-3"><input type="date" name="date" class="form-control" value="{{ date }}"></div>
  <div class="col-md-4">
    <select name="class_id" class="form-control">
      {% for c in classes %}
        <option value="{{ c._id }}" {% if selected_class and selected_class==c._id %}selected{% endif %}>{{ c.name }}</option>
      {% endfor %}
    </select>
  </div>
  <div class="col-md-2"><button class="btn btn-primary">Load</button></div>
</form>

{% if students %}
<form method="post">
  <input type="hidden" name="date" value="{{ date }}">
  <input type="hidden" name="class_id" value="{{ selected_class }}">
  <table class="table">
    <thead><tr><th>Student</th><th>Roll</th><th>Present?</th></tr></thead>
    <tbody>
      {% for s in students %}
      <tr>
        <td>{{ s.name }}<input type="hidden" name="student_ids" value="{{ s._id }}"></td>
        <td>{{ s.roll_no }}</td>
        <td><input type="checkbox" name="present_{{ s._id }}" {% if s._marked_present %}checked{% endif %}></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  <button class="btn btn-success">Save Attendance</button>
</form>
{% endif %}
{% endblock %}
""")

    # Attendance history
    write_template('attendance_history.html', """{% extends 'base.html' %}
{% block title %}Attendance History{% endblock %}
{% block content %}
<h4>Attendance History</h4>
<form method="get" class="row g-2 mb-3">
  <div class="col-md-3"><input type="date" name="date_from" class="form-control" value="{{ date_from }}"></div>
  <div class="col-md-3"><input type="date" name="date_to" class="form-control" value="{{ date_to }}"></div>
  <div class="col-md-3">
    <select name="class_id" class="form-control">
      <option value="">All Classes</option>
      {% for c in classes %}
        <option value="{{ c._id }}" {% if selected_class and selected_class==c._id %}selected{% endif %}>{{ c.name }}</option>
      {% endfor %}
    </select>
  </div>
  <div class="col-md-2"><button class="btn btn-primary">Filter</button></div>
</form>

<table class="table">
  <thead><tr><th>Date</th><th>Class</th><th>Student</th><th>Status</th></tr></thead>
  <tbody>
    {% for r in results %}
      <tr><td>{{ r.date }}</td><td>{{ r.class_name }}</td><td>{{ r.student_name }}</td><td>{{ r.status }}</td></tr>
    {% else %}
      <tr><td colspan="4">No records</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
""")

    # Reports
    write_template('reports.html', """{% extends 'base.html' %}
{% block title %}Reports{% endblock %}
{% block content %}
<h4>Reports</h4>
<form method="get" class="row g-2 mb-3" action="{{ url_for('export_report') }}">
  <div class="col-md-3"><input type="date" name="date_from" class="form-control"></div>
  <div class="col-md-3"><input type="date" name="date_to" class="form-control"></div>
  <div class="col-md-3">
    <select name="class_id" class="form-control"><option value="">All Classes</option>{% for c in classes %}<option value="{{ c._id }}">{{ c.name }}</option>{% endfor %}</select>
  </div>
  <div class="col-md-3">
    <select name="format" class="form-control"><option value="csv">CSV</option><option value="excel">Excel</option><option value="pdf">PDF</option></select>
  </div>
  <div class="col-md-2 mt-2"><button class="btn btn-primary">Export</button></div>
</form>
{% endblock %}
""")

    # Profile
    write_template('profile.html', """{% extends 'base.html' %}
{% block title %}Profile{% endblock %}
{% block content %}
<div class="card p-3 mt-3"><h4>Profile</h4>
<form method="post">
  <div class="mb-3"><label class="form-label">Name</label><input name="name" value="{{ user.name }}" class="form-control"></div>
  <div class="mb-3"><label class="form-label">Email</label><input name="email" value="{{ user.email }}" class="form-control" readonly></div>
  <div class="mb-3"><label class="form-label">Change Password (leave blank to keep)</label><input name="password" type="password" class="form-control"></div>
  <button class="btn btn-success">Save</button>
</form>
</div>
{% endblock %}
""")

    # Forgot password and reset
    write_template('forgot_password.html', """{% extends 'base.html' %}
{% block title %}Forgot Password{% endblock %}
{% block content %}
<div class="card p-3 mt-3"><h4>Forgot Password</h4>
<form method="post">
  <div class="mb-3"><label class="form-label">Enter your account email</label><input name="email" class="form-control" required></div>
  <button class="btn btn-primary">Request Reset</button>
</form>
</div>
{% endblock %}
""")

    write_template('reset_password.html', """{% extends 'base.html' %}
{% block title %}Reset Password{% endblock %}
{% block content %}
<div class="card p-3 mt-3"><h4>Reset Password</h4>
<form method="post">
  <div class="mb-3"><label class="form-label">New Password</label><input name="password" type="password" class="form-control" required></div>
  <button class="btn btn-success">Reset</button>
</form>
</div>
{% endblock %}
""")

    # Notifications
    write_template('notifications.html', """{% extends 'base.html' %}
{% block title %}Notifications{% endblock %}
{% block content %}
<h4>Notifications</h4>
<table class="table">
  <thead><tr><th>Date</th><th>Message</th></tr></thead>
  <tbody>
    {% for n in notes %}
      <tr><td>{{ n.date }}</td><td>{{ n.msg }}</td></tr>
    {% else %}
      <tr><td colspan="2">No notifications</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
""")

# End ensure_project_structure
ensure_project_structure()

# Load env
load_dotenv(dotenv_path=str(ENV_PATH))
app.secret_key = os.getenv('SECRET_KEY') or DEFAULT_ENV['SECRET_KEY']
MONGO_URI = os.getenv('MONGO_URI') or DEFAULT_ENV['MONGO_URI']

# Setup DB
client = MongoClient(MONGO_URI)
db = client.get_default_database()

bcrypt = Bcrypt(app)

# Utilities

def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    try:
        u = db.users.find_one({'_id': ObjectId(uid)})
        if u:
            u['_id'] = str(u['_id'])
        return u
    except Exception:
        return None


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or u.get('role') != 'admin':
            flash('Admin access required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return wrapper

# Initialize DB with default admin if needed

def ensure_default_admin():
    if db.users.count_documents({}) == 0:
        pw = os.getenv('ADMIN_PASSWORD') or DEFAULT_ENV['ADMIN_PASSWORD']
        email = os.getenv('ADMIN_EMAIL') or DEFAULT_ENV['ADMIN_EMAIL']
        hashed = bcrypt.generate_password_hash(pw).decode()
        db.users.insert_one({
            'name': 'Administrator',
            'email': email,
            'password': hashed,
            'role': 'admin',
            'created_at': datetime.utcnow()
        })
        print(f"Default admin created: {email} / {pw}")

ensure_default_admin()

# --------------------
# Authentication Routes
# --------------------
@app.route('/')
def index():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        user = db.users.find_one({'email': email})
        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['user_role'] = user.get('role', 'teacher')
            flash('Logged in')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        role = request.form.get('role', 'teacher')
        if db.users.find_one({'email': email}):
            flash('Email already registered')
            return redirect(url_for('register'))
        hashed = bcrypt.generate_password_hash(password).decode()
        db.users.insert_one({'name': name, 'email': email, 'password': hashed, 'role': role, 'created_at': datetime.utcnow()})
        flash('Registered. Please login')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out')
    return redirect(url_for('login'))

# Forgot / Reset
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        user = db.users.find_one({'email': email})
        if user:
            token = secrets.token_urlsafe(24)
            db.password_resets.insert_one({'user_id': user['_id'], 'token': token, 'expires': datetime.utcnow() + timedelta(hours=1)})
            reset_link = url_for('reset_password', token=token, _external=True)
            # In production, send email. For local dev we print the link and flash to user.
            print('Password reset link:', reset_link)
            flash('Password reset link generated and printed to console (for dev).')
        else:
            flash('No account with that email')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    rec = db.password_resets.find_one({'token': token})
    if not rec or rec.get('expires') < datetime.utcnow():
        flash('Invalid or expired token')
        return redirect(url_for('login'))
    if request.method == 'POST':
        newpw = request.form['password']
        hashed = bcrypt.generate_password_hash(newpw).decode()
        db.users.update_one({'_id': rec['user_id']}, {'$set': {'password': hashed}})
        db.password_resets.delete_many({'user_id': rec['user_id']})
        flash('Password updated. Please login.')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# ----------------
# Admin / Profile
# ----------------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    u = current_user()
    if not u:
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name'].strip()
        pw = request.form.get('password')
        update = {'name': name}
        if pw:
            update['password'] = bcrypt.generate_password_hash(pw).decode()
        db.users.update_one({'_id': ObjectId(u['_id'])}, {'$set': update})
        flash('Profile updated')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=u)

# ----------------
# Students & Class
# ----------------
@app.route('/students')
@login_required
def students():
    students = list(db.students.find({}))
    classes_map = {str(c['_id']): c['name'] for c in db.classes.find({})}
    out = []
    for s in students:
        out.append({
            '_id': str(s['_id']),
            'name': s.get('name'),
            'roll_no': s.get('roll_no'),
            'class_name': classes_map.get(str(s.get('class_id')), ''),
            'parent_contact': s.get('parent_contact', ''),
        })
    return render_template('students.html', students=out)


@app.route('/students/add', methods=['GET', 'POST'])
@login_required
def add_student():
    classes = list(db.classes.find({}))
    if request.method == 'POST':
        name = request.form['name'].strip()
        roll_no = request.form.get('roll_no')
        class_id = request.form.get('class_id')
        parent_contact = request.form.get('parent_contact')
        email = request.form.get('email')
        dob = request.form.get('dob')
        photo = request.files.get('photo')
        photo_path = None
        if photo and photo.filename:
            filename = secure_filename(photo.filename)
            dest = STATIC_DIR / filename
            photo.save(dest)
            photo_path = f"/static/{filename}"
        doc = {'name': name, 'roll_no': roll_no, 'class_id': ObjectId(class_id) if class_id else None,
               'parent_contact': parent_contact, 'email': email, 'dob': dob, 'photo': photo_path}
        db.students.insert_one(doc)
        flash('Student added')
        return redirect(url_for('students'))
    return render_template('student_form.html', student=None, classes=classes)


@app.route('/students/edit/<student_id>', methods=['GET', 'POST'])
@login_required
def edit_student(student_id):
    s = db.students.find_one({'_id': ObjectId(student_id)})
    if not s:
        flash('Student not found')
        return redirect(url_for('students'))
    classes = list(db.classes.find({}))
    if request.method == 'POST':
        update = {
            'name': request.form['name'].strip(),
            'roll_no': request.form.get('roll_no'),
            'class_id': ObjectId(request.form.get('class_id')) if request.form.get('class_id') else None,
            'parent_contact': request.form.get('parent_contact'),
            'email': request.form.get('email'),
            'dob': request.form.get('dob')
        }
        db.students.update_one({'_id': ObjectId(student_id)}, {'$set': update})
        flash('Student updated')
        return redirect(url_for('students'))
    s['_id'] = str(s['_id'])
    s['class_id'] = str(s['class_id']) if s.get('class_id') else None
    return render_template('student_form.html', student=s, classes=classes)


@app.route('/students/delete/<student_id>')
@login_required
def delete_student(student_id):
    db.students.delete_one({'_id': ObjectId(student_id)})
    flash('Deleted')
    return redirect(url_for('students'))

# Classes CRUD
@app.route('/classes')
@login_required
def classes():
    classes = list(db.classes.find({}))
    out = []
    for c in classes:
        out.append({'_id': str(c['_id']), 'name': c.get('name'), 'section': c.get('section', '')})
    return render_template('classes.html', classes=out)


@app.route('/classes/add', methods=['GET', 'POST'])
@login_required
def add_class():
    if request.method == 'POST':
        name = request.form['name'].strip()
        section = request.form.get('section')
        db.classes.insert_one({'name': name, 'section': section})
        flash('Class added')
        return redirect(url_for('classes'))
    return render_template('class_form.html', cls=None)


@app.route('/classes/edit/<class_id>', methods=['GET', 'POST'])
@login_required
def edit_class(class_id):
    c = db.classes.find_one({'_id': ObjectId(class_id)})
    if not c:
        flash('Class not found')
        return redirect(url_for('classes'))
    if request.method == 'POST':
        db.classes.update_one({'_id': ObjectId(class_id)}, {'$set': {'name': request.form['name'], 'section': request.form.get('section')}})
        flash('Class updated')
        return redirect(url_for('classes'))
    c['_id'] = str(c['_id'])
    return render_template('class_form.html', cls=c)


@app.route('/classes/delete/<class_id>')
@login_required
def delete_class(class_id):
    db.classes.delete_one({'_id': ObjectId(class_id)})
    flash('Deleted class')
    return redirect(url_for('classes'))

# ----------------
# Attendance flows
# ----------------
@app.route('/attendance/mark', methods=['GET', 'POST'])
@login_required
def mark_attendance():
    if request.method == 'GET':
        date = request.args.get('date') or datetime.utcnow().date().isoformat()
        class_id = request.args.get('class_id')
        classes = list(db.classes.find({}))
        students = []
        selected_class = None
        if class_id:
            selected_class = class_id
            students_cursor = db.students.find({'class_id': ObjectId(class_id)})
            for s in students_cursor:
                s['_id'] = str(s['_id'])
                # Pre-marking: check if attendance exists
                att = db.attendances.find_one({'date': date, 'class_id': ObjectId(class_id)})
                s['_marked_present'] = False
                if att:
                    for r in att.get('records', []):
                        if str(r.get('student_id')) == s['_id'] and r.get('status') == 'present':
                            s['_marked_present'] = True
                students.append(s)
        else:
            classes = list(db.classes.find({}))
        return render_template('attendance_mark.html', date=date, classes=classes, students=students, selected_class=selected_class)

    # POST: save attendance
    date = request.form['date']
    class_id = request.form['class_id']
    # Collect student ids from the form (hidden inputs)
    student_ids = request.form.getlist('student_ids')
    records = []
    absent_docs = []
    for sid in student_ids:
        present = request.form.get(f'present_{sid}')
        status = 'present' if present else 'absent'
        records.append({'student_id': ObjectId(sid), 'status': status, 'marked_by': ObjectId(session['user_id']), 'ts': datetime.utcnow()})
        if status == 'absent':
            absent_docs.append({'student_id': ObjectId(sid), 'class_id': ObjectId(class_id), 'date': date, 'notified': False})
    # Upsert attendance doc
    db.attendances.update_one({'date': date, 'class_id': ObjectId(class_id)}, {'$set': {'date': date, 'class_id': ObjectId(class_id), 'records': records, 'updated_at': datetime.utcnow()}}, upsert=True)
    if absent_docs:
        db.absent_records.insert_many(absent_docs)
    flash('Attendance saved')
    return redirect(url_for('mark_attendance') + f"?date={date}&class_id={class_id}")


@app.route('/attendance/absent', methods=['GET', 'POST'])
@login_required
def absent_records():
    if request.method == 'GET':
        date = request.args.get('date') or datetime.utcnow().date().isoformat()
        class_id = request.args.get('class_id')
        classes = list(db.classes.find({}))
        absents = []
        if class_id:
            rows = db.absent_records.find({'date': date, 'class_id': ObjectId(class_id)})
            classes_map = {str(c['_id']): c['name'] for c in classes}
            for r in rows:
                s = db.students.find_one({'_id': r['student_id']})
                absents.append({'student_name': s.get('name'), 'date': r['date'], 'class_name': classes_map.get(str(r['class_id']))})
        return render_template('attendance_mark.html', date=date, classes=classes, students=[], selected_class=class_id)
    # POST: allow manual absent marking (not implemented in UI)
    flash('Not implemented')
    return redirect(url_for('mark_attendance'))


@app.route('/attendance/history')
@login_required
def attendance_history():
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    class_id = request.args.get('class_id')
    classes = list(db.classes.find({}))
    query = {}
    if date_from:
        query['date'] = {'$gte': date_from}
    if date_to:
        if 'date' in query:
            query['date']['$lte'] = date_to
        else:
            query['date'] = {'$lte': date_to}
    if class_id:
        query['class_id'] = ObjectId(class_id)
    results = []
    for att in db.attendances.find(query):
        cname = db.classes.find_one({'_id': att['class_id']})
        for r in att.get('records', []):
            s = db.students.find_one({'_id': r['student_id']})
            results.append({'date': att['date'], 'class_name': cname.get('name') if cname else '', 'student_name': s.get('name') if s else '', 'status': r.get('status')})
    return render_template('attendance_history.html', results=results, classes=classes, date_from=date_from, date_to=date_to, selected_class=class_id)

# ----------------
# Reports / Export
# ----------------
@app.route('/reports')
@login_required
def reports():
    classes = list(db.classes.find({}))
    return render_template('reports.html', classes=classes)


@app.route('/reports/export')
@login_required
def export_report():
    fmt = request.args.get('format', 'csv')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    class_id = request.args.get('class_id')
    # Build rows
    rows = []
    q = {}
    if date_from:
        q['date'] = {'$gte': date_from}
    if date_to:
        if 'date' in q:
            q['date']['$lte'] = date_to
        else:
            q['date'] = {'$lte': date_to}
    if class_id:
        q['class_id'] = ObjectId(class_id)
    for att in db.attendances.find(q):
        cname = db.classes.find_one({'_id': att['class_id']})
        for r in att.get('records', []):
            s = db.students.find_one({'_id': r['student_id']})
            rows.append({'date': att['date'], 'class': cname.get('name') if cname else '', 'student': s.get('name') if s else '', 'status': r.get('status')})

    if fmt == 'csv':
        si = io.StringIO()
        writer = csv.DictWriter(si, fieldnames=['date', 'class', 'student', 'status'])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        mem = io.BytesIO()
        mem.write(si.getvalue().encode())
        mem.seek(0)
        return send_file(mem, download_name='attendance_report.csv', as_attachment=True)

    if fmt == 'excel':
        if pd is None:
            flash('pandas not installed. Please pip install -r requirements.txt')
            return redirect(url_for('reports'))
        df = pd.DataFrame(rows)
        mem = io.BytesIO()
        df.to_excel(mem, index=False, engine='openpyxl')
        mem.seek(0)
        return send_file(mem, download_name='attendance_report.xlsx', as_attachment=True)

    if fmt == 'pdf':
        if FPDF is None:
            flash('fpdf not installed. Please pip install -r requirements.txt')
            return redirect(url_for('reports'))
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Attendance Report', ln=True)
        pdf.ln(4)
        pdf.set_font('Arial', '', 10)
        for r in rows:
            line = f"{r['date']} - {r['class']} - {r['student']} - {r['status']}"
            pdf.multi_cell(0, 6, line)
        mem = io.BytesIO()
        mem.write(pdf.output(dest='S').encode('latin-1'))
        mem.seek(0)
        return send_file(mem, download_name='attendance_report.pdf', as_attachment=True)

    flash('Unknown format')
    return redirect(url_for('reports'))

# ----------------
# Notifications
# ----------------
@app.route("/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    if request.method == "POST":
        msg = request.form.get("msg")
        if msg:
            db.notifications.insert_one({
                "msg": msg,
                "date": datetime.utcnow().strftime("%Y-%m-%d %H:%M")
            })
            flash("Notification added successfully!", "success")
        return redirect(url_for("notifications"))

    # Fetch stored notifications
    notes = list(db.notifications.find().sort("date", -1))
    return render_template("notifications.html", notes=notes)

# ----------------
# Dashboard
# ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    stats = {}
    stats['total_students'] = db.students.count_documents({})
    stats['total_classes'] = db.classes.count_documents({})

    today = datetime.utcnow().date().isoformat()

    # --- Attendance counts ---
    attendance_today = 0
    absent_today = 0
    atts = db.attendances.find({'date': today})
    for a in atts:
        for r in a.get('records', []):
            if r.get('status') == 'present':
                attendance_today += 1
            elif r.get('status') == 'absent':
                absent_today += 1

    # also check absents marked separately in db.absents
    abs_doc = db.absents.find_one({"date": today})
    if abs_doc:
        absent_today += len(abs_doc.get("records", []))

    stats['attendance_today'] = attendance_today
    stats['absent_today'] = absent_today

    # --- Recent absences (from db.absents collection) ---
    recent_abs = []
    recs = db.absents.find({}).sort("date", -1).limit(10)
    for r in recs:
        cls = db.classes.find_one({"_id": r["class_id"]})
        for rec in r.get("records", []):
            s = db.students.find_one({"_id": rec["student_id"]})
            recent_abs.append({
                "date": r["date"],
                "student_name": s.get("name") if s else "Unknown",
                "class_name": cls["name"] if cls else "Unknown"
            })

    return render_template("dashboard.html", stats=stats, recent_absences=recent_abs)


# ---------------- Absent Marking ----------------
@app.route("/absent/mark", methods=["GET", "POST"])
@login_required
def absent_marking():
    classes = list(db.classes.find({}))
    students = []
    selected_class = None
    date = request.args.get("date", datetime.utcnow().date().isoformat())

    if request.method == "POST":
        class_id = request.form.get("class_id")
        selected_class = db.classes.find_one({"_id": ObjectId(class_id)})
        date = request.form.get("date")

        # students absent for this class/date
        student_ids = request.form.getlist("students")
        absent_records = []
        for sid in student_ids:
            absent_records.append({
                "student_id": ObjectId(sid),
                "class_id": ObjectId(class_id),
                "date": date,
                "status": "absent"
            })

        db.absents.update_one(
            {"date": date, "class_id": ObjectId(class_id)},
            {"$set": {"records": absent_records}},
            upsert=True
        )

        flash("Absent records updated successfully!", "success")
        return redirect(url_for("absent_history"))

    # GET method
    class_id = request.args.get("class_id")
    if class_id:
        selected_class = db.classes.find_one({"_id": ObjectId(class_id)})
        students = list(db.students.find({"class_id": ObjectId(class_id)}))

    return render_template(
        "absent_marking.html",
        classes=classes,
        students=students,
        selected_class=selected_class,
        date=date
    )


# ---------------- Absent History ----------------
@app.route("/absent/history")
@login_required
def absent_history():
    date = request.args.get("date")
    class_id = request.args.get("class_id")

    query = {}
    if date:
        query["date"] = date
    if class_id:
        try:
            query["class_id"] = ObjectId(class_id)
        except:
            pass

    absents = db.absent_records.find(query).sort("date", -1)

    records = []
    for a in absents:
        s = db.students.find_one({"_id": a["student_id"]})
        c = db.classes.find_one({"_id": a["class_id"]})
        student_name = s["name"] if s else "Unknown"
        class_name = c["name"] if c else "Unknown"

        records.append({
            "date": a["date"],
            "class": class_name,
            "students": [student_name]
        })

    classes = list(db.classes.find())

    return render_template(
        "absent_history.html",
        records=records,
        classes=classes
    )


# ----------------
# Helpful route: show simple readiness
# ----------------
@app.route('/health')
def health():
    return {'status': 'ok'}

# ---------------
# Run app
# ---------------
if __name__ == '__main__':
    print('Starting Attendance App')
    print('Templates and static files were created under:', TEMPLATES_DIR, STATIC_DIR)
    print('Requirements file written to:', REQUIREMENTS_PATH)
    print('Open your browser at http://127.0.0.1:5000')
    app.run(debug=True)
