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
# load_dotenv()

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
app.config['MAIL_USERNAME'] = 'pratimaneupane061@gmail.com'
app.config['MAIL_PASSWORD'] = 'gxbo gtqu dcxx luad'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6Lfrj1crAAAAAFAQokAG3WXwmej85mE21ByyoMoW'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6Lfrj1crAAAAAGKu-dwppSY6Xzk3mR9rtaVwayM_'

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

# 🔒 Password Policy Constants
PASSWORD_CHANGE_INTERVAL_DAYS = 90
PASSWORD_HISTORY_COUNT = 3 # Remember the last 3 passwords

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
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow) # Added for password change frequency

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
    try:
        token = secrets.token_urlsafe(32)
        user.email_verification_token = token
        db.session.commit()
        link = url_for('verify_email', token=token, _external=True)
        msg = Message('Verify Your Email', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
        msg.html = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #333;">Welcome to Digital Security!</h2>
            <p>Thank you for creating an account. To complete your registration and ensure the security of your account, please verify your email address by clicking the button below:</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{link}" style="background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Verify Email Address</a>
            </div>
            <p>If the button doesn't work, you can also copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #666;">{link}</p>
            <p style="color: #666; font-size: 0.9em;">This link will expire in 24 hours.</p>
            <hr style="border: 1px solid #eee; margin: 20px 0;">
            <p style="color: #666; font-size: 0.8em;">If you didn't create this account, please ignore this email.</p>
        </div>
        '''
        mail.send(msg)
        print(f"Verification email sent to {user.email}")
    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP Authentication Error: {e}")
        print(f"Username: {app.config['MAIL_USERNAME']}")
        print(f"Password length: {len(app.config['MAIL_PASSWORD'])}")
        raise
    except Exception as e:
        print(f"Error sending email: {e}")
        raise

# Create database tables
with app.app_context():
    try:
        # Drop all tables first to ensure clean state
        db.drop_all()
        # Create all tables
        db.create_all()
        print(f"[DEBUG] Database initialized successfully at {db_path}")
        print("[DEBUG] Created tables:")
        for table in db.metadata.tables:
            print(f"  - {table}")
    except Exception as e:
        print(f"[ERROR] Database initialization failed: {e}")
        print(f"Database path: {db_path}")
        print(f"Instance path: {instance_path}")
        print(f"Current working directory: {os.getcwd()}")
        raise

# 🌐 Routes
@app.route('/')
def onboarding():
    return render_template('onboarding.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if request.method == 'POST':
            print("[DEBUG] Starting registration process...")
            uname = request.form['username']
            email = request.form['email']
            pwd = request.form['password']
            confirm = request.form['confirm_password']
            captcha_input = request.form['captcha']
            
            print(f"[DEBUG] Registration attempt - Username: {uname}, Email: {email}")

            if captcha_input.lower() != session.get('captcha_text', '').lower():
                print("[DEBUG] CAPTCHA mismatch")
                flash("CAPTCHA did not match.", "danger")
                return redirect(url_for('register'))

            if pwd != confirm:
                print("[DEBUG] Password mismatch")
                flash("Passwords do not match.", "danger")
                return redirect(url_for('register'))

            if not is_strong_password(pwd):
                print("[DEBUG] Weak password")
                flash("Weak password. Please use a stronger one.", "warning")
                return redirect(url_for('register'))

            existing_user = User.query.filter((User.username == uname) | (User.email == email)).first()
            if existing_user:
                print(f"[DEBUG] User already exists - Username: {uname}, Email: {email}")
                flash("Username or Email already exists.", "warning")
                return redirect(url_for('register'))

            try:
                print("[DEBUG] Creating new user...")
                hashed = bcrypt.generate_password_hash(pwd).decode('utf-8')
                if PasswordHistory.query.filter_by(password_hash=hashed).first():
                    print("[DEBUG] Password already used before")
                    flash("Password already used before.", "warning")
                    return redirect(url_for('register'))

                user = User(username=uname, email=email, password=hashed, last_password_change=datetime.utcnow()) # Set initial change date
                db.session.add(user)
                db.session.commit()
                print(f"[DEBUG] User created successfully - ID: {user.id}")

                db.session.add(PasswordHistory(user_id=user.id, password_hash=hashed))
                # Prune old password history if exceeding limit (though not strictly necessary for first entry)
                history_count = PasswordHistory.query.filter_by(user_id=user.id).count()
                if history_count > PASSWORD_HISTORY_COUNT:
                     oldest_histories = PasswordHistory.query.filter_by(user_id=user.id).order_by(PasswordHistory.created_at.asc()).limit(history_count - PASSWORD_HISTORY_COUNT).all()
                     for old_hist in oldest_histories:
                         db.session.delete(old_hist)
                db.session.commit()
                print("[DEBUG] Password history updated")

                try:
                    print("[DEBUG] Sending verification email...")
                    send_verification_email(user)
                    print("[DEBUG] Verification email sent successfully")
                except Exception as e:
                    print(f"[ERROR] Failed to send verification email: {e}")
                    flash("Account created, but verification email could not be sent. Please contact support.", "warning")
                    return redirect(url_for('login'))

                flash("Account created! Verify your email.", "success")
                return redirect(url_for('login'))

            except Exception as e:
                print(f"[ERROR] Database error during registration: {e}")
                db.session.rollback()
                flash("An error occurred while creating your account. Please try again.", "danger")
                return redirect(url_for('register'))

        text, image = generate_captcha()
        session['captcha_text'] = text
        return render_template('register.html', captcha_image=image)

    except Exception as e:
        print(f"[ERROR] Registration process failed: {e}")
        flash("An error occurred during registration. Please try again later.", "danger")
        return redirect(url_for('register'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            print("[DEBUG] Starting login process...")
            email = request.form['email']
            pwd = request.form['password']
            recaptcha_response = request.form.get('g-recaptcha-response')
            print(f"[DEBUG] Login attempt - Email/Username: {email}")

            ip = request.remote_addr
            now = datetime.now().timestamp()
            login_attempts[ip] = [t for t in login_attempts[ip] if now - t < WINDOW_SECONDS]

            if len(login_attempts[ip]) >= MAX_ATTEMPTS:
                print(f"[WARNING] Too many login attempts from IP: {ip}")
                flash("Too many attempts. Try again later.", "danger")
                return redirect(url_for('login'))

            login_attempts[ip].append(now)

            # reCAPTCHA Validation
            try:
                print("[DEBUG] Validating reCAPTCHA...")
                r = requests.post('https://www.google.com/recaptcha/api/siteverify',
                                data={'secret': app.config['RECAPTCHA_PRIVATE_KEY'], 'response': recaptcha_response})
                if not r.json().get('success'):
                    print("[WARNING] reCAPTCHA validation failed")
                    flash("reCAPTCHA failed.", "danger")
                    return redirect(url_for('login'))
                print("[DEBUG] reCAPTCHA validation successful")
            except Exception as e:
                print(f"[WARNING] reCAPTCHA validation error: {e}")
                flash("reCAPTCHA validation error. Please try again.", "danger")
                return redirect(url_for('login'))

            print("[DEBUG] Looking up user...")
            user = User.query.filter((User.email == email) | (User.username == email)).first()
            
            if user:
                print(f"[DEBUG] User found - ID: {user.id}")
                if bcrypt.check_password_hash(user.password, pwd):
                    print("[DEBUG] Password verified")
                    if not user.email_verified:
                        print(f"[WARNING] Login attempt with unverified email: {email}")
                        flash("Email not verified.", "warning")
                        return redirect(url_for('login'))
                    login_user(user)
                    print(f"[DEBUG] User logged in successfully - ID: {user.id}")

                    # Check for password change frequency
                    if user.last_password_change is None or (datetime.utcnow() - user.last_password_change).days > PASSWORD_CHANGE_INTERVAL_DAYS:
                        flash(f'Your password has not been changed in over {PASSWORD_CHANGE_INTERVAL_DAYS} days. Please update your password.', 'warning')
                        return redirect(url_for('change_password'))

                    flash("Welcome!", "success")
                    # Log successful login
                    log_event(user.id, 'Successful Login', 'User logged in successfully.', request.remote_addr, request.user_agent.string)
                    return redirect(url_for('home'))
                else:
                    # Check password history if current password check fails
                    old_password_entry = PasswordHistory.query.filter_by(user_id=user.id).order_by(PasswordHistory.created_at.desc()).all()
                    found_old_password = None
                    for entry in old_password_entry:
                        if bcrypt.check_password_hash(entry.password_hash, pwd):
                            found_old_password = entry
                            break

                    if found_old_password:
                         # Calculate time difference and format message
                         now = datetime.utcnow()
                         time_diff = now - found_old_password.created_at
                         time_ago_str = "recently"
                         if time_diff.days > 0:
                             if time_diff.days == 1:
                                 time_ago_str = "1 day ago"
                             elif time_diff.days < 30:
                                 time_ago_str = f"{time_diff.days} days ago"
                             elif time_diff.days < 365:
                                 months = time_diff.days // 30
                                 time_ago_str = f"{months} {'month' if months == 1 else 'months'} ago"
                             else:
                                 years = time_diff.days // 365
                                 time_ago_str = f"{years} {'year' if years == 1 else 'years'} ago"

                         flash(f"Invalid credentials. The password you entered is old. Your password was last changed {time_ago_str}.", "warning")
                         print(f"[WARNING] Old password used for login attempt by user ID {user.id}")
                    else:
                        flash("Invalid credentials.", "danger")
                        print("[DEBUG] Invalid password")
                    # Log failed login
                    log_event(user.id, 'Failed Login', 'Invalid password provided.', request.remote_addr, request.user_agent.string)
            else:
                print("[DEBUG] User not found")
                flash("Invalid credentials.", "danger")
                print(f"[WARNING] Invalid login credentials for: {email} (user not found)")
                # Log failed login attempt for non-existent user (user_id=None)
                log_event(None, 'Failed Login', f'Attempt with non-existent user: {email}', request.remote_addr, request.user_agent.string)
            
            return redirect(url_for('login'))

        return render_template('login.html', app=app)
    except Exception as e:
        print(f"[ERROR] Login process failed: {e}")
        flash("An error occurred during login. Please try again later.", "danger")
        return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

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
    try:
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
                    print(f"Password reset email sent to {user.email}")
                    flash('Password reset instructions have been sent to your email.', 'info')
                except smtplib.SMTPAuthenticationError as e:
                    print(f"[WARNING] SMTP Authentication Error: {e}")
                    print(f"Username: {app.config['MAIL_USERNAME']}")
                    print(f"Password length: {len(app.config['MAIL_PASSWORD'])}")
                    flash('Failed to send password reset email. Please check your email configuration.', 'danger')
                except Exception as e:
                    print(f"[WARNING] Error sending email: {e}")
                    flash('An error occurred while sending the password reset email.', 'danger')
            else:
                flash('Email not found.', 'danger')
                print(f"[WARNING] Password reset requested for non-existent email: {email}")
            return redirect(url_for('login'))
        return render_template('forgot_password.html')
    except Exception as e:
        print(f"[ERROR] Forgot password process failed: {e}")
        flash("An error occurred. Please try again later.", "danger")
        return redirect(url_for('forgot_password'))

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

@app.route('/security-logs')
@login_required
def security_logs():
    logs = SecurityLog.query.filter_by(user_id=current_user.id).order_by(SecurityLog.timestamp.desc()).all()
    return render_template('security_logs.html', logs=logs)

@app.route('/resend-verification', methods=['POST'])
@login_required
def resend_verification():
    if current_user.email_verified:
        flash("Your email is already verified.", "info")
        return redirect(url_for('home'))
    
    try:
        send_verification_email(current_user)
        flash("Verification email has been resent. Please check your inbox.", "success")
    except Exception as e:
        print(f"Error resending verification email: {e}")
        flash("Failed to resend verification email. Please try again later.", "danger")
    
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        user = current_user

        # 1. Verify current password
        if not bcrypt.check_password_hash(user.password, current_password):
            flash('Incorrect current password.', 'danger')
            return render_template('change_password.html')

        # 2. Check if new passwords match
        if new_password != confirm_new_password:
            flash('New passwords do not match.', 'danger')
            return render_template('change_password.html')

        # 3. Check new password strength (using backend validation)
        if not is_strong_password(new_password):
            flash('New password does not meet security requirements (min 8 chars, 1 upper, 1 lower, 1 digit, 1 symbol).', 'danger')
            return render_template('change_password.html')

        # 4. Check password history
        hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Get recent password hashes from history
        recent_passwords = PasswordHistory.query.filter_by(user_id=user.id)\
                                                .order_by(PasswordHistory.created_at.desc())\
                                                .limit(PASSWORD_HISTORY_COUNT).all()

        for history_entry in recent_passwords:
            # Compare new password hash with historical hashes
            # Note: This assumes direct hash comparison which is only safe if using a non-random hash like SHA256
            # Bcrypt generates different hashes for the same password due to salts.
            # A more robust check with bcrypt history would involve checking the new password against the *stored hash*
            # Let's use the correct bcrypt check here:
            if bcrypt.check_password_hash(history_entry.password_hash, new_password):
                flash(f'You cannot reuse a password from your last {PASSWORD_HISTORY_COUNT} changes.', 'warning')
                return render_template('change_password.html')

        # 5. Update password, history, and last change timestamp
        try:
            user.password = hashed_new_password
            user.last_password_change = datetime.utcnow()

            # Add new password to history
            new_history_entry = PasswordHistory(user_id=user.id, password_hash=hashed_new_password)
            db.session.add(new_history_entry)

            # Prune old history entries if count exceeds limit
            history_count = PasswordHistory.query.filter_by(user_id=user.id).count()
            if history_count > PASSWORD_HISTORY_COUNT:
                 oldest_histories = PasswordHistory.query.filter_by(user_id=user.id).order_by(PasswordHistory.created_at.asc()).limit(history_count - PASSWORD_HISTORY_COUNT).all()
                 for old_hist in oldest_histories:
                     db.session.delete(old_hist)

            db.session.commit()

            flash('Your password has been updated successfully.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            print(f"[ERROR] Failed to update password or history: {e}")
            flash('An error occurred while updating your password. Please try again.', 'danger')

    return render_template('change_password.html')

def log_event(user_id, event_type, description, ip_address, user_agent):
    try:
        log = SecurityLog(user_id=user_id, event_type=event_type, description=description, ip_address=ip_address, user_agent=user_agent)
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"[ERROR] Failed to log security event: {e}")
        db.session.rollback()

# 🏁 Run App
if __name__ == '__main__':
    app.run(debug=True)
