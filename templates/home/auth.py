from flask import Blueprint, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User  # Make sure this imports correctly
from flask_login import login_user, logout_user, login_required

auth_blueprint = Blueprint('auth', __name__)

# REGISTER ROUTE
@auth_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.', 'warning')
            return redirect(url_for('auth.login'))

        # Hash password and create user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, email=email, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('home/register.html')

# LOGIN ROUTE
@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Invalid login credentials.', 'danger')
            return redirect(url_for('auth.login'))

        login_user(user)
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))  # Change this to your actual dashboard route

    return render_template('home/login.html')

# LOGOUT ROUTE
@auth_blueprint.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('auth.login'))
