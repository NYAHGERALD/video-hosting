from flask import Blueprint, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user
from models import db, Admin, Passkey

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm = request.form['confirm_password']
        passkey_input = request.form['passkey'].strip()

        if password != confirm:
            flash("❌ Passwords do not match.")
            return render_template('register.html')

        existing_admin = Admin.query.filter_by(email=email).first()
        if existing_admin:
            flash("❌ Email is already registered.")
            return render_template('register.html')

        valid_key = Passkey.query.filter_by(key=passkey_input, used=False).first()
        if not valid_key:
            flash("❌ Invalid or already used access passkey.")
            return render_template('register.html')

        hashed_pw = generate_password_hash(password)
        new_admin = Admin(email=email, password_hash=hashed_pw)
        db.session.add(new_admin)

        valid_key.used = True
        db.session.commit()

        flash("✅ Admin account created successfully. Please log in.")
        return redirect(url_for('auth.login'))

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']

        admin = Admin.query.filter_by(email=email).first()
        if admin and check_password_hash(admin.password_hash, password):
            login_user(admin)  # ✅ Use Flask-Login
            flash("✅ Welcome back!")
            return redirect(url_for('dashboard'))
        else:
            flash("❌ Invalid email or password.")

    return render_template('login.html')


@auth_bp.route('/logout')
def logout():
    logout_user()  # ✅ Proper logout using Flask-Login
    flash("👋 You have been logged out.")
    return redirect(url_for('auth.login'))

