from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
import pickle
import numpy as np
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_conn  # your sqlitecloud helper
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
# Session lifetime configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Context processor to inject current theme into all templates
@app.context_processor
def inject_theme():
    theme = session.get('theme', 'light')
    return dict(theme=theme)

# Route to set theme (light or dark)
@app.route('/set-theme/<string:theme>')
def set_theme(theme):
    if theme in ['light', 'dark']:
        session['theme'] = theme
    return ('', 204)

# Load your ML model
model = pickle.load(open('model.pkl', 'rb'))

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            gender TEXT,
            hemoglobin REAL,
            mch REAL,
            mchc REAL,
            mcv REAL,
            result TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
    conn.commit()
    conn.close()

# Ensure tables exist
init_db()

# Route both '/' and '/login' here
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_conn()
        cur = conn.cursor()
        cur.execute('SELECT id, password FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session.permanent = True  # make the session permanent
            session['user_id'] = user[0]
            session['username'] = username
            # Set default theme if not set
            session.setdefault('theme', 'light')
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password_hash = generate_password_hash(request.form['password'])
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password_hash))
            conn.commit()
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken.', 'danger')
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/index', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    result = None
    if request.method == 'POST':
        gender = request.form['gender']
        gender_val = 1 if gender == 'Male' else 0
        hb = float(request.form['hemoglobin'])
        mch = float(request.form['mch'])
        mchc = float(request.form['mchc'])
        mcv = float(request.form['mcv'])
        pred = model.predict([[gender_val, hb, mch, mchc, mcv]])[0]
        result = 'Anemic' if pred == 1 else 'Normal'

        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO history (user_id, gender, hemoglobin, mch, mchc, mcv, result) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (session['user_id'], gender, hb, mch, mchc, mcv, result)
        )
        conn.commit()
        conn.close()

    return render_template('index.html', result=result)

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        'SELECT gender, hemoglobin, mch, mchc, mcv, result, timestamp '
        'FROM history WHERE user_id = ? ORDER BY timestamp DESC',
        (session['user_id'],)
    )
    records = cur.fetchall()
    conn.close()
    return render_template('history.html', records=records)

if __name__ == '__main__':
    # bind to 0.0.0.0 so Docker/WSL will expose it externally
    app.run(debug=True, host='0.0.0.0', port=5000)
