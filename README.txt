Project Title:
---------------
Secure Registration and Login System Prototype 
--------------------------------------------------------------

Project Description:
--------------------
This project is a secure web-based prototype system that demonstrates 
best practices in user registration, authentication, and password 
management. The system applies key cybersecurity principles and 
techniques to ensure data confidentiality, integrity, and protection 
against common threats such as brute-force attacks and automated bots.

The application is built using:
- Python (Flask micro-framework) for the backend
- HTML, CSS, and JavaScript for the frontend
- SQLite database for data persistence
- Bcrypt for secure password hashing
- Custom CAPTCHA and Google reCAPTCHA v2 for bot protection
- Flask extensions for session management and email verification

--------------------------------------------------------------

Key Features:
-------------
✅ Secure User Registration  
✅ Email Verification  
✅ Password Strength Enforcement  
✅ Password History Tracking (prevents reuse)  
✅ Custom CAPTCHA on Registration  
✅ Google reCAPTCHA v2 on Login  
✅ Rate Limiting (5 login attempts per 10 minutes per IP)  
✅ Password Reset via Email  
✅ CSRF Protection  
✅ Secure Session Handling  
✅ Responsive, User-friendly UI  
✅ Light/Dark Theme Toggle  
✅ Auto-Generated Password Suggestions  

--------------------------------------------------------------

How to Run the System:
----------------------
1. Ensure you have Python 3.x installed.
2. Install the required packages using:

   pip install -r requirements.txt

3. Configure the following environment variables in `app.py`:
   - MAIL_USERNAME (your email address)
   - MAIL_PASSWORD (your app-specific password)
   - RECAPTCHA_PRIVATE_KEY (your Google reCAPTCHA secret key)

4. Run the application:

   python app.py

5. Access the application at:

   http://127.0.0.1:5000/

--------------------------------------------------------------

Database:
---------
The system uses SQLite for simplicity and prototyping purposes.  
The database is auto-created when the application is first run.  
Tables include:
- User
- PasswordHistory

Passwords are stored using bcrypt hashing as per OWASP recommendations.

--------------------------------------------------------------

Security Principles Applied:
----------------------------
- Defence-in-depth: Multiple security layers (CAPTCHA, rate limiting, password strength enforcement)
- Secure password storage using bcrypt
- Password reuse prevention via password history tracking
- Mitigation of brute-force attacks through rate limiting and CAPTCHA
- CSRF protection on all forms
- Secure session handling using Flask-Login
- Email verification to validate user identity

--------------------------------------------------------------

Known Limitations:
------------------
- Two-Factor Authentication (2FA) not yet implemented.
- Rate limiting is basic and session-based; production systems should use IP-based and more advanced throttling (e.g., Flask-Limiter).
- Currently using SMTP with app password for email; in production, a more secure email service should be used.

--------------------------------------------------------------

