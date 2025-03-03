import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_session import Session

# Load Environment Variables
load_dotenv()
print(f"Loaded Environment Variables: {os.environ}")

# Flask App Initialization
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your_secret_key")

# Define the base directory and instance directory
basedir = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(basedir, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DATABASE_PATH = os.path.join(INSTANCE_DIR, "app.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DATABASE_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Flask Session Configuration
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(basedir, "flask_session")
app.config["SESSION_FILE_THRESHOLD"] = 500

# Initialize Flask Extensions
from models import db, User  # Import db and User model here
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
Session(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    return "Hello, this is the home page!"

# REGISTER ROUTE
@app.route("/register", methods=["GET", "POST"])
def register():
    print("[DEBUG] Register route hit!")
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if not username or not email or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for("register"))

        print("[DEBUG] Inside app context for User.query")
        existing_user = User.query.filter_by(email=email).first()
        print(f"[DEBUG] Existing user: {existing_user}")

        if existing_user:
            flash("Email already registered. Please log in.", "danger")
            return redirect(url_for("login"))

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Create new user
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        print("[DEBUG] User added to session.")
        db.session.commit()
        print("[DEBUG] User committed to database.")

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# LOGIN ROUTE
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        
        flash("Invalid credentials!", "danger")

    return render_template("login.html")

# Initialize Database Tables on First Run
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
