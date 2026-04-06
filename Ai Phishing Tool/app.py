"""
Phishing URL Detection Web App
Flask application with user authentication and real-time URL analysis API.
"""

import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, jsonify, session, g)
from werkzeug.security import generate_password_hash, check_password_hash

from models import PhishingDetector

# ─── App Configuration ───────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['DATABASE'] = '/tmp/phishing_detector.db'

detector = PhishingDetector()


# ─── Database ────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            model TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            risk_score REAL NOT NULL,
            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    db.commit()


with app.app_context():
    init_db()


# ─── Auth Helpers ────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    if 'user_id' in session:
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        return user
    return None


# ─── Routes ──────────────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if not email or '@' not in email:
            errors.append('Please enter a valid email address.')
        if not password or len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        if password != confirm_password:
            errors.append('Passwords do not match.')

        if not errors:
            db = get_db()
            try:
                db.execute(
                    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                    (username, email, generate_password_hash(password))
                )
                db.commit()
                flash('Account created successfully! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                errors.append('Username or email already exists.')

        for error in errors:
            flash(error, 'error')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    db = get_db()
    history = db.execute(
        'SELECT * FROM analysis_history WHERE user_id = ? ORDER BY analyzed_at DESC LIMIT 20',
        (session['user_id'],)
    ).fetchall()
    return render_template('dashboard.html', user=user, history=history)


# ─── API Endpoints ───────────────────────────────────────────────────
@app.route('/api/analyze', methods=['POST'])
@login_required
def analyze_url():
    data = request.get_json()

    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400

    url = data['url'].strip()
    model = data.get('model', 'roberta').lower()

    if not url:
        return jsonify({'error': 'URL cannot be empty'}), 400

    # Run analysis
    if model == 'autoencoder':
        result = detector.analyze_autoencoder(url)
    else:
        result = detector.analyze_roberta(url)

    # Save to history
    try:
        db = get_db()
        db.execute(
            'INSERT INTO analysis_history (user_id, url, model, prediction, confidence, risk_score) VALUES (?, ?, ?, ?, ?, ?)',
            (session['user_id'], url, result['model'], result['prediction'],
             result['confidence'], result.get('risk_score', 0))
        )
        db.commit()
    except Exception:
        pass  # Don't fail the API if history save fails

    return jsonify(result)


@app.route('/api/history', methods=['GET'])
@login_required
def get_history():
    db = get_db()
    history = db.execute(
        'SELECT url, model, prediction, confidence, risk_score, analyzed_at FROM analysis_history WHERE user_id = ? ORDER BY analyzed_at DESC LIMIT 50',
        (session['user_id'],)
    ).fetchall()
    return jsonify([dict(row) for row in history])


@app.route('/api/history/clear', methods=['POST'])
@login_required
def clear_history():
    db = get_db()
    db.execute('DELETE FROM analysis_history WHERE user_id = ?', (session['user_id'],))
    db.commit()
    return jsonify({'status': 'ok'})


# ─── Run ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True, port=5000)
