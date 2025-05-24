from flask import Flask, render_template, request, redirect, url_for, session, flash
import pickle
import numpy as np
import sqlite3
import smtplib
import ssl
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_conn
from datetime import timedelta, datetime
from itsdangerous import URLSafeTimedSerializer
import re
import os
from flask_mail import Mail, Message
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Email credentials
EMAIL_ADDRESS = 'samgsekgd@gmail.com'
EMAIL_PASSWORD = 'umlooleuvqxllbar'

# Serializer
serializer = URLSafeTimedSerializer(app.secret_key)

def send_email(to_email, subject, body):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

@app.context_processor
def inject_theme():
    return dict(theme=session.get('theme', 'light'))

@app.route('/set-theme/<string:theme>')
def set_theme(theme):
    if theme in ['light', 'dark']:
        session['theme'] = theme
    return ('', 204)

model = pickle.load(open('model.pkl', 'rb'))

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            verified BOOLEAN DEFAULT FALSE
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
    cur.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT UNIQUE,
            expires DATETIME,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
    conn.commit()
    conn.close()

init_db()

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_conn()
        cur = conn.cursor()
        cur.execute('SELECT id, password, verified FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            if user[2]:
                session.permanent = True
                session['user_id'] = user[0]
                session['username'] = username
                return redirect(url_for('index'))
            else:
                flash('Please verify your email before logging in.', 'warning')
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

# Email validation
def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

# Forgot username route
@app.route('/forgot-username', methods=['GET', 'POST'])
def forgot_username():
    if request.method == 'POST':
        email = request.form['email'].strip()

        if not is_valid_email(email):
            flash('Invalid email address.', 'danger')
            return render_template('forgot_username.html', theme=session.get('theme', 'light'))

        conn = get_conn()
        cur = conn.cursor()
        cur.execute('SELECT username FROM users WHERE email = ?', (email,))
        user = cur.fetchone()

        if user:
            username = user[0]
            subject = 'Your Username Reminder'
            body = f'''Hello,

You requested your username.

Your username is: {username}

If you did not request this, please ignore this email.

Best regards,
The Team'''
            try:
                send_email(email, subject, body)
                flash('If an account exists with that email, your username has been sent.', 'info')
            except Exception as e:
                print(f"[ERROR] Failed to send username email: {e}")
                flash('Something went wrong while sending the email. Please try again later.', 'danger')
        else:
            # Generic message to avoid confirming email existence
            flash('If an account exists with that email, your username has been sent.', 'info')

        conn.close()
        return redirect(url_for('login'))

    return render_template('forgot_username.html', theme=session.get('theme', 'light'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        conn = get_conn()
        cur = conn.cursor()

        # Check if username already exists
        cur.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cur.fetchone():
            flash('Username already exists. Please choose a different one.', 'danger')
            conn.close()
            return render_template('signup.html')

        # Check if email already exists
        cur.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cur.fetchone():
            flash('Email already exists. Please use a different email.', 'danger')
            conn.close()
            return render_template('signup.html')

        # Insert new user
        try:
            password_hash = generate_password_hash(password)
            cur.execute(
                'INSERT INTO users (username, email, password, verified) VALUES (?, ?, ?, ?)',
                (username, email, password_hash, False)
            )
            conn.commit()

            # Send email verification
            token = serializer.dumps(email, salt='email-verify')
            verify_url = url_for('verify_email', token=token, _external=True)
            body = f'Please click the link to verify your email: {verify_url}'
            send_email(email, 'Verify Your Email', body)

            flash('Signup successful! Check your email to verify your account.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            print(f"Signup Error: {e}")  # For debugging
            flash('An error occurred during signup. Please try again later.', 'danger')

        finally:
            conn.close()

    return render_template('signup.html')


@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=3600)
        conn = get_conn()
        cur = conn.cursor()
        cur.execute('UPDATE users SET verified = TRUE WHERE email = ?', (email,))
        conn.commit()
        conn.close()
        flash('Email verified successfully. You can now log in.', 'success')
    except Exception:
        flash('Invalid or expired verification link.', 'danger')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_conn()
        cur = conn.cursor()
        cur.execute('SELECT id FROM users WHERE email = ?', (email,))
        user = cur.fetchone()
        if user:
            user_id = user[0]
            token = serializer.dumps(email, salt='password-reset')
            expires = datetime.utcnow() + timedelta(hours=1)
            cur.execute('INSERT INTO password_resets (user_id, token, expires) VALUES (?, ?, ?)',
                        (user_id, token, expires))
            conn.commit()
            reset_url = url_for('reset_password', token=token, _external=True)
            body = f'Click to reset your password: {reset_url}'
            send_email(email, 'Reset Your Password', body)
            flash('Password reset link sent to your email.', 'success')
        else:
            flash('Email not found.', 'danger')
        conn.close()
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
        conn = get_conn()
        cur = conn.cursor()
        cur.execute('SELECT user_id FROM password_resets WHERE token = ? AND expires > ?',
                    (token, datetime.utcnow()))
        reset = cur.fetchone()
        if not reset:
            flash('Invalid or expired reset link.', 'danger')
            return redirect(url_for('login'))
        user_id = reset[0]
        if request.method == 'POST':
            new_password = request.form['password']
            password_hash = generate_password_hash(new_password)
            cur.execute('UPDATE users SET password = ? WHERE id = ?', (password_hash, user_id))
            cur.execute('DELETE FROM password_resets WHERE token = ?', (token,))
            conn.commit()
            conn.close()
            flash('Password reset successfully. Please log in.', 'success')
            return redirect(url_for('login'))
        conn.close()
        return render_template('reset_password.html')
    except Exception:
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('login'))

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
    app.run(debug=True, host='0.0.0.0', port=5000)
