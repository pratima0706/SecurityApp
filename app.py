from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from collections import defaultdict
import re, secrets, string, random, base64, io, requests
from PIL import Image, ImageDraw, ImageFont
import os
from dotenv import load_dotenv
import smtplib

# Load environment variables
load_dotenv()

# 🔧 Flask App Configuration
app = Flask(__name__)

# Ensure instance folder exists
instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
try:
    os.makedirs(instance_path, exist_ok=True)
except OSError:
    pass

# Database configuration
db_path = os.path.join(instance_path, 'site.db')
app.config['SECRET_KEY'] = 'supersecurekey'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'your-app-password')
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LeJcFcrAAAAAN9X34_z2ZLfVKB19nCEVepUKPdV'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LeJcFcrAAAAANBYoCKAMloXPjmqxGaMEmSFHO_u'

# 🔌 Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# 🔐 Rate Limiting: Prevent Brute Force
login_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 600  # 10 minutes

# 🧠 Database Models
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

class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    event_type = db.Column(db.String(50))
    description = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))

class Captcha(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 🔏 CAPTCHA Generator
def generate_captcha():
    characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
    text = ''.join(random.choices(characters, k=6))
    img = Image.new('RGB', (140, 50), color=(230, 240, 255))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype('arial.ttf', 24)
    except:
        font = None
    draw.text((20, 12), text, fill=(20, 20, 100), font=font)

    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    encoded_img = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return text, encoded_img

# 🔐 Password Strength Checker (Backend)
def is_strong_password(password):
    return all([
        len(password) >= 8,
        re.search(r'[A-Z]', password),
        re.search(r'[a-z]', password),
        re.search(r'\d', password),
        re.search(r'\W', password)
    ])

# 📧 Email Functions
def send_verification_email(user):
    token = secrets.token_urlsafe(32)
    user.email_verification_token = token
    db.session.commit()
    link = url_for('verify_email', token=token, _external=True)
    msg = Message('Verify Your Email', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
    msg.body = f'Click to verify: {link}'
    mail.send(msg)

# Create database tables
with app.app_context():
    try:
        db.create_all()
        print(f"Database created successfully at {db_path}")
    except Exception as e:
        print(f"Error creating database: {e}")
        print(f"Database path: {db_path}")
        print(f"Instance path: {instance_path}")
        print(f"Current working directory: {os.getcwd()}")

# 🌐 Routes
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

        if captcha_input.lower() != session.get('captcha_text', '').lower():
            flash("CAPTCHA did not match.", "danger")
            return redirect(url_for('register'))

        if pwd != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('register'))

        if not is_strong_password(pwd):
            flash("Weak password. Please use a stronger one.", "warning")
            return redirect(url_for('register'))

        if User.query.filter((User.username == uname) | (User.email == email)).first():
            flash("Username or Email already exists.", "warning")
            return redirect(url_for('register'))

        hashed = bcrypt.generate_password_hash(pwd).decode('utf-8')
        if PasswordHistory.query.filter_by(password_hash=hashed).first():
            flash("Password already used before.", "warning")
            return redirect(url_for('register'))

        user = User(username=uname, email=email, password=hashed)
        db.session.add(user)
        db.session.commit()
        db.session.add(PasswordHistory(user_id=user.id, password_hash=hashed))
        db.session.commit()
        send_verification_email(user)
        flash("Account created! Verify your email.", "success")
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

        ip = request.remote_addr
        now = datetime.now().timestamp()
        login_attempts[ip] = [t for t in login_attempts[ip] if now - t < WINDOW_SECONDS]

        if len(login_attempts[ip]) >= MAX_ATTEMPTS:
            flash("Too many attempts. Try again later.", "danger")
            return redirect(url_for('login'))

        login_attempts[ip].append(now)

        # reCAPTCHA Validation
        r = requests.post('https://www.google.com/recaptcha/api/siteverify',
                          data={'secret': app.config['RECAPTCHA_PRIVATE_KEY'], 'response': recaptcha_response})
        if not r.json().get('success'):
            flash("reCAPTCHA failed.", "danger")
            return redirect(url_for('login'))

        user = User.query.filter((User.email == email) | (User.username == email)).first()
        if user and bcrypt.check_password_hash(user.password, pwd):
            if not user.email_verified:
                flash("Email not verified.", "warning")
                return redirect(url_for('login'))
            login_user(user)
            flash("Welcome!", "success")
            return redirect(url_for('home'))
        flash("Invalid credentials.", "danger")
        return redirect(url_for('login'))

    return render_template('login.html', app=app)

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

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
        flash("Email verified!", "success")
    else:
        flash("Invalid or expired link.", "danger")
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
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
            try:
                mail.send(msg)
                flash('Password reset instructions have been sent to your email.', 'info')
            except smtplib.SMTPAuthenticationError as e:
                print(f"SMTP Authentication Error: {e}")
                flash('Failed to send password reset email. Please check your email configuration (App Password, 2FA).', 'danger')
            except Exception as e:
                print(f"An unexpected error occurred while sending email: {e}")
                flash('An unexpected error occurred while sending the password reset email.', 'danger')
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
        
        if not is_strong_password(password):
            flash('Password does not meet security requirements.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        if PasswordHistory.query.filter_by(password_hash=hashed, user_id=user.id).first():
            flash('This password was already used before.', 'warning')
            return redirect(url_for('reset_password', token=token))
        
        user.password = hashed
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.add(PasswordHistory(user_id=user.id, password_hash=hashed))
        db.session.commit()
        
        flash('Your password has been reset!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

# 🏁 Run App
if __name__ == '__main__':
    app.run(debug=True)
