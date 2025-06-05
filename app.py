# ==============================================================
# 🚀 Basic Flask App Setup & Configuration
# ==============================================================

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import requests  # For reCAPTCHA validation
import random, string, io, base64
from PIL import Image, ImageDraw, ImageFont
from flask_mail import Mail, Message
import secrets
import os

app = Flask(__name__)

# Secret key and database location
app.config['SECRET_KEY'] = 'supersecurekey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/site.db'

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'your-app-password'    # Replace with your app password

# Google reCAPTCHA keys
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LfAWVYrAAAAADomMEOUKhAwUnOCe8vMDmjRsWRb'
app.config['RECAPTCHA_PRIVATE_KEY'] = 'your-secret-key'  # Replace with your actual secret key

# Initialize Flask extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)


# ==============================================================
# 🧠 Database Models
# ==============================================================

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(100), unique=True)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)

class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    password_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ==============================================================
# 🔐 CAPTCHA Generator for Registration Page
# ==============================================================

def generate_captcha():
    characters = string.ascii_letters + string.digits
    text = ''.join(random.choice(characters) for _ in range(6))

    img = Image.new('RGB', (140, 50), color=(230, 240, 255))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype('LiberationSans-Regular.ttf', 24)
    except:
        try:
            font = ImageFont.truetype('DejaVuSans.ttf', 24)
        except:
            try:
                font = ImageFont.truetype('arial.ttf', 24)
            except:
                font = None
    draw.text((20, 12), text, fill=(20, 20, 100), font=font)

    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    encoded_img = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return text, encoded_img


# ==============================================================
# 📧 Email Functions
# ==============================================================

def send_verification_email(user):
    token = secrets.token_urlsafe(32)
    user.email_verification_token = token
    db.session.commit()
    
    verification_url = url_for('verify_email', token=token, _external=True)
    msg = Message('Verify Your Email',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f'''To verify your email, visit the following link:
{verification_url}

If you did not make this request then simply ignore this email.
'''
    mail.send(msg)

def send_reset_email(user):
    token = secrets.token_urlsafe(32)
    user.reset_token = token
    user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
    db.session.commit()
    
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = Message('Password Reset Request',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

This link will expire in 1 hour.

If you did not make this request then simply ignore this email.
'''
    mail.send(msg)


# ==============================================================
# 🏠 Routes: Home, Onboarding, Register, Login, Logout, Profile
# ==============================================================

@app.route('/')
def onboarding():
    return render_template('onboarding.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form['username']
        email = request.form['email']
        pwd = request.form['password']
        confirm = request.form['confirm_password']
        captcha_input = request.form['captcha']

        if captcha_input != session.get('captcha_text'):
            flash("CAPTCHA did not match. Try again.", "danger")
            return redirect(url_for('register'))

        if pwd != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('register'))

        if User.query.filter((User.username == uname) | (User.email == email)).first():
            flash("Username or email already exists.", "warning")
            return redirect(url_for('register'))

        hashed = bcrypt.generate_password_hash(pwd).decode('utf-8')
        past = PasswordHistory.query.filter_by(password_hash=hashed).first()
        if past:
            flash("This password was already used before.", "warning")
            return redirect(url_for('register'))

        user = User(username=uname, email=email, password=hashed)
        db.session.add(user)
        db.session.commit()

        history = PasswordHistory(user_id=user.id, password_hash=hashed)
        db.session.add(history)
        db.session.commit()

        # Send verification email
        send_verification_email(user)
        flash("Account created successfully. Please check your email to verify your account.", "success")
        return redirect(url_for('login'))

    text, image = generate_captcha()
    session['captcha_text'] = text
    return render_template('register.html', captcha_image=image)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        pwd = request.form['password']
        recaptcha_response = request.form.get('g-recaptcha-response')

        # ✅ Verify Google reCAPTCHA
        secret_key = app.config['RECAPTCHA_PRIVATE_KEY']
        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={'secret': secret_key, 'response': recaptcha_response}
        )
        result = response.json()
        if not result.get('success'):
            flash("Please verify that you are not a robot.", "danger")
            return redirect(url_for('login'))

        # ✅ Authenticate user
        user = User.query.filter((User.email == email) | (User.username == email)).first()
        if user and bcrypt.check_password_hash(user.password, pwd):
            if not user.email_verified:
                flash("Please verify your email before logging in.", "warning")
                return redirect(url_for('login'))
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid login credentials.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/home')
@login_required
def home():
    return render_template('home.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        new_pwd = request.form.get('new_password')
        confirm_pwd = request.form.get('confirm_password')

        current_user.username = username
        current_user.email = email

        if new_pwd:
            if new_pwd != confirm_pwd:
                flash("New passwords do not match.", "danger")
                return redirect(url_for('profile'))

            hashed_new = bcrypt.generate_password_hash(new_pwd).decode('utf-8')
            if PasswordHistory.query.filter_by(password_hash=hashed_new, user_id=current_user.id).first():
                flash("This password was already used before.", "warning")
                return redirect(url_for('profile'))

            current_user.password = hashed_new
            db.session.add(PasswordHistory(user_id=current_user.id, password_hash=hashed_new))

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for('profile'))

    return render_template('profile.html')


@app.route('/refresh_captcha')
def refresh_captcha():
    text, image = generate_captcha()
    session['captcha_text'] = text
    return {'captcha_image': image}


@app.route('/verify-email/<token>')
def verify_email(token):
    user = User.query.filter_by(email_verification_token=token).first()
    if user:
        user.email_verified = True
        user.email_verification_token = None
        db.session.commit()
        flash('Your email has been verified!', 'success')
    else:
        flash('Invalid or expired verification link.', 'danger')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
            flash('Password reset instructions have been sent to your email.', 'info')
        else:
            flash('Email not found.', 'danger')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or user.reset_token_expiry < datetime.utcnow():
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']
        
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        user.password = hashed
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash('Your password has been reset!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')


# ==============================================================
# Auto-create DB and Run the App
# ==============================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
