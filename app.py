import openai
import os
import json
import re
import time
import requests
import urllib.parse
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_session import Session
import cProfile
from ftplib import FTP
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
import random
import math
import threading
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from datetime import timedelta
from sqlalchemy.exc import SQLAlchemyError
from flask_login import login_required
import psycopg2
from psycopg2.extras import DictCursor
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from authlib.integrations.flask_client import OAuth

# ✅ Initialize Flask App
app = Flask(__name__)

# ✅ Configure Database (PostgreSQL for Production, SQLite for Local Testing)
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL:
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL  # Production
else:
    basedir = os.path.abspath(os.path.dirname(__file__))
    DATABASE_PATH = os.path.join(basedir, "instance", "app.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DATABASE_PATH}"  # Local Testing

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=20)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your_secret_key")

# ✅ Initialize Extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
Session(app)
oauth = OAuth(app)

# ✅ Import Models AFTER `db` is initialized
from models import User, Setting

# ✅ User Loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ✅ Function to Get Shopify Credentials (From Render Environment)
def get_shopify_credentials():
    """Fetch Shopify API credentials from Render's environment variables."""
    credentials = {
        "SHOPIFY_API_KEY": os.getenv("SHOPIFY_API_KEY"),
        "SHOPIFY_SECRET": os.getenv("SHOPIFY_SECRET"),
        "SHOPIFY_REDIRECT_URI": os.getenv("SHOPIFY_REDIRECT_URI", "https://racesync.onrender.com/oauth/callback"),
        "SHOPIFY_SCOPES": os.getenv("SHOPIFY_SCOPES", "read_products,write_products,read_orders"),
    }
    if not credentials["SHOPIFY_API_KEY"] or not credentials["SHOPIFY_SECRET"]:
        print("[WARNING] Shopify API credentials are missing! Check Render environment variables.")
    return credentials

# ✅ Function to Get User-Specific Shopify & FTP Credentials
def get_user_credentials(user_id):
    """Fetch user-specific Shopify and FTP credentials from the database."""
    with app.app_context():
        user = User.query.filter_by(id=user_id).first()
        if not user:
            print(f"[WARNING] No user found with ID {user_id}.")
            return None
        return {
            "shopify_domain": user.shopify_domain,
            "shopify_access_token": user.access_token,
            "ftp_host": user.ftp_host,
            "ftp_user": user.ftp_user,
            "ftp_pass": user.ftp_pass,
        }

# ✅ Lazy-Load Shopify Credentials (Only When User is Logged In)
SHOPIFY_CREDENTIALS = get_shopify_credentials()
SHOPIFY_API_KEY = SHOPIFY_CREDENTIALS["SHOPIFY_API_KEY"]
SHOPIFY_SECRET = SHOPIFY_CREDENTIALS["SHOPIFY_SECRET"]
SHOPIFY_REDIRECT_URI = SHOPIFY_CREDENTIALS["SHOPIFY_REDIRECT_URI"]
SHOPIFY_SCOPES = SHOPIFY_CREDENTIALS["SHOPIFY_SCOPES"]

shopify_domain = None
SHOPIFY_ACCESS_TOKEN = None

@app.before_request
def load_user_credentials():
    global shopify_domain, SHOPIFY_ACCESS_TOKEN

    # ✅ Allow static files to load
    if request.path.startswith('/static/'):
        return  

    # ✅ Allow OAuth routes to proceed even if credentials are missing
    allowed_routes = ["profile", "logout", "oauth_start", "oauth_callback"]

    if current_user.is_authenticated:
        user_creds = get_user_credentials(current_user.id)

        # 🚨 Ensure we update global credentials!
        shopify_domain = user_creds.get("shopify_domain", "")
        SHOPIFY_ACCESS_TOKEN = user_creds.get("shopify_access_token", "")

        # ✅ If the request is for an allowed route, let it pass through
        if request.endpoint in allowed_routes:
            return  

        # 🚨 If credentials are STILL missing, redirect to /profile
        if not shopify_domain or not SHOPIFY_ACCESS_TOKEN:
            print("[WARNING] No Shopify credentials! Redirecting to /profile")
            return redirect(url_for("profile"))



# ✅ Define Shopify Headers (Only if the token exists)
def get_shopify_headers():
    """Returns the Shopify API headers if the access token is available."""
    return {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN if SHOPIFY_ACCESS_TOKEN else "",
        "Content-Type": "application/json",
    }

# ✅ Function to Fetch Shopify Products (Only Runs When Needed)
def fetch_shopify_products():
    """Fetch products from Shopify using credentials from the database."""
    if not SHOPIFY_ACCESS_TOKEN or not shopify_domain:
        print("[ERROR] Cannot fetch Shopify products: Missing access token or domain.")
        return None

    url = f"https://{shopify_domain}/admin/api/2024-01/products.json?limit=50"
    response = requests.get(url, headers=get_shopify_headers())
    if response.status_code == 200:
        return response.json()
    else:
        print(f"[ERROR] Shopify API Request Failed: {response.text}")
        return None

# ✅ User Registration Route
from flask import redirect, url_for

from flask import redirect, url_for

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("User already exists. Please log in.", "warning")
            return redirect(url_for("login"))

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Create new user entry without Shopify/FTP data
        new_user = User(
            email=email,
            password_hash=hashed_password,
            role="Regular",  # Default role
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please connect your Shopify store.", "success")

        # ✅ Redirect user to /profile to set up Shopify & FTP
        return redirect(url_for("profile"))

    return render_template("register.html")




# ✅ Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            session['user_id'] = user.id  # Set session user_id
            return redirect(url_for('inventory'))

        flash("Invalid credentials!", "danger")

    return render_template('login.html')

# ✅ Logout Route
@app.route('/logout')
def logout():
    logout_user()
    session.pop('user_id', None)
    session.clear()
    return redirect(url_for('login'))

# ✅ Home Screen Route
@app.route('/')
def main_screen():
    return redirect(url_for('login'))  # Redirect to login

# ✅ Initialize Database Tables on First Run
with app.app_context():
    db.create_all()

@app.route("/oauth/start")
def oauth_start():
    print("[DEBUG] OAuth Callback hit!")
    params = request.args.to_dict()
    print("[DEBUG] OAuth Params:", params)

    if not current_user.is_authenticated:
        flash("You must be logged in to connect your Shopify store!", "danger")
        return redirect(url_for("login"))

    user = User.query.get(current_user.id)

    if not user:
        flash("User not found!", "danger")
        return redirect(url_for("profile"))

    if not user.shopify_domain:
        flash("You must enter your Shopify store URL in your profile!", "danger")
        return redirect(url_for("profile"))

    # ✅ Fix: Ensure the shop URL does NOT contain double 'https://'
    shop = user.shopify_domain.strip().replace("https://", "").replace("http://", "")

    # ✅ Fix: Build the correct Shopify OAuth URL
    authorization_url = (
        f"https://{shop}/admin/oauth/authorize?"
        f"client_id={SHOPIFY_API_KEY}&"
        f"scope={SHOPIFY_SCOPES}&"
        f"redirect_uri={SHOPIFY_REDIRECT_URI}"
    )

    print(f"[DEBUG] Corrected Shopify Domain: {shop}")
    print(f"[DEBUG] Redirecting to Shopify OAuth: {authorization_url}")

    return redirect(authorization_url)






@app.route("/oauth/callback")
def oauth_callback():
    shop = request.args.get("shop")
    code = request.args.get("code")

    if not shop or not code:
        flash("OAuth failed! Missing parameters.", "danger")
        return redirect(url_for("inventory"))  # ✅ Redirect to /inventory instead of index

    # Exchange authorization code for access token
    token_url = f"https://{shop}/admin/oauth/access_token"
    
    response = requests.post(token_url, json={
        "client_id": SHOPIFY_API_KEY,  # ✅ Ensure these variables are correct
        "client_secret": SHOPIFY_SECRET,
        "code": code
    })

    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data.get("access_token")

        if not access_token:
            flash("OAuth failed! No access token received.", "danger")
            return redirect(url_for("inventory"))  # ✅ Redirect to /inventory

        # ✅ Store token in the database
        user = User.query.filter_by(shopify_domain=shop).first()
        if user:
            user.access_token = access_token
        else:
            user = User(shopify_domain=shop, access_token=access_token)
            db.session.add(user)

        db.session.commit()

        flash("Shopify OAuth successful!", "success")
        return redirect(url_for("inventory"))  # ✅ Redirect to /inventory
    
    else:
        flash(f"OAuth failed! Error: {response.text}", "danger")
        return redirect(url_for("inventory"))  # ✅ Redirect to /inventory in case of failure

@app.route("/install")
def install():
    shop = request.args.get("shop")  # Get Shopify store domain

    if not shop:
        flash("Missing 'shop' parameter!", "danger")
        return redirect(url_for("index"))

    install_url = (
        f"https://{shop}/admin/oauth/authorize?"
        f"client_id={SHOPIFY_API_KEY}&"
        f"scope={SHOPIFY_SCOPES}&"
        f"redirect_uri={SHOPIFY_REDIRECT_URI}"
    )

    return redirect(install_url)

def get_shopify_domain(user_id):
    """Fetch the Shopify store domain for a specific user."""
    with app.app_context():
        user = User.query.filter_by(id=user_id).first()
        if user and user.shopify_domain:
            return user.shopify_domain
        else:
            print(f"[WARNING] No Shopify domain found for user {user_id}. They may not have set it yet.")
            return None

def get_shopify_access_token(user_id):
    """Fetch Shopify Access Token for a user from the database."""
    with app.app_context():
        user = User.query.filter_by(id=user_id).first()
        if user and user.access_token:
            return user.access_token
        else:
            print(f"[WARNING] No Shopify access token found for user {user_id}. They may not have set it yet.")
            return None


def admin_required(f):
    """Decorator to ensure only admins can access certain routes."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'Admin':
            return jsonify({"error": "Unauthorized"}), 403
        return f(*args, **kwargs)
    return decorated_function

# 1️⃣ Fetch Users (Paginated)
@app.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def list_users():
    """Fetch all users with search, filtering, and pagination."""
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Change if needed
    search = request.args.get('search', '', type=str)
    role_filter = request.args.get('role', None, type=str)

    query = User.query

    if search:
        query = query.filter(User.username.ilike(f"%{search}%") | User.email.ilike(f"%{search}%"))
    
    if role_filter:
        query = query.filter(User.role == role_filter)

    users = query.order_by(User.signup_date.desc()).paginate(page=page, per_page=per_page, error_out=False)

    user_list = [
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "signup_date": user.signup_date.strftime('%Y-%m-%d'),
            "last_login": user.last_login.strftime('%Y-%m-%d') if user.last_login else "Never"
        }
        for user in users.items
    ]

    return jsonify({
        "users": user_list,
        "total_pages": users.pages,
        "current_page": users.page
    })

# 2️⃣ Update User Role
@app.route('/admin/update_role', methods=['POST'])
@login_required
@admin_required
def update_role():
    """Change a user's role (Admin, Regular User, Read-Only)."""
    data = request.json
    user_id = data.get("user_id")
    new_role = data.get("role")

    if not user_id or not new_role:
        return jsonify({"error": "Missing user ID or role"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        user.role = new_role
        db.session.commit()
        return jsonify({"message": f"User {user.username} role updated to {new_role}"}), 200
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"error": "Database error"}), 500

# 3️⃣ Delete User
@app.route('/admin/delete_user', methods=['DELETE'])
@login_required
@admin_required
def delete_user():
    """Permanently delete a user."""
    user_id = request.json.get("user_id")

    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"User {user.username} deleted successfully"}), 200
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"error": "Database error"}), 500

# 4️⃣ Force Password Reset
@app.route('/admin/reset_password', methods=['POST'])
@login_required
@admin_required
def reset_password():
    """Forces a password reset for a user on next login."""
    user_id = request.json.get("user_id")

    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        # Mark user as requiring a password reset
        user.must_reset_password = True
        db.session.commit()
        return jsonify({"message": f"Password reset forced for {user.username}"}), 200
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"error": "Database error"}), 500


# Profile Route
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    print("[DEBUG] Profile route hit!")

    if request.method == 'POST':
        print("[DEBUG] POST request received")

        # Collect Shopify Store Domain
        shopify_domain = request.form.get('shopify_domain', '').strip()
        openai_api_key = request.form.get('openai_api_key', '').strip()
        ftp_host = request.form.get('ftp_host', '').strip()
        ftp_user = request.form.get('ftp_user', '').strip()
        ftp_pass = request.form.get('ftp_pass', '').strip()

        # Debugging Statements to Verify Form Data
        print(f"[DEBUG] Received Shopify Store: {shopify_domain}")
        print(f"[DEBUG] Received OpenAI API Key: {openai_api_key}")
        print(f"[DEBUG] Received FTP Host: {ftp_host}")
        print(f"[DEBUG] Received FTP User: {ftp_user}")
        print(f"[DEBUG] Received FTP Pass: {ftp_pass}")

        # Update user settings
        current_user.shopify_domain = shopify_domain if shopify_domain else current_user.shopify_domain
        current_user.openai_api_key = openai_api_key if openai_api_key else current_user.openai_api_key
        current_user.ftp_host = ftp_host if ftp_host else current_user.ftp_host
        current_user.ftp_user = ftp_user if ftp_user else current_user.ftp_user
        current_user.ftp_pass = ftp_pass if ftp_pass else current_user.ftp_pass

        print("[DEBUG] Updating user settings in database")

        try:
            db.session.commit()
            print("[DEBUG] Settings updated in database")
            flash("Settings updated successfully!", "success")
        except Exception as e:
            print(f"[DEBUG] Exception occurred while committing to database: {e}")
            db.session.rollback()
            flash("Failed to update settings. Please try again.", "danger")

        return redirect(url_for('profile'))

    # Retrieve stored values
    try:
        shopify_domain = current_user.shopify_domain or ""
        openai_api_key = current_user.openai_api_key or ""
        ftp_host = current_user.ftp_host or ""
        ftp_user = current_user.ftp_user or ""
        ftp_pass = current_user.ftp_pass or ""

        # Debugging Statements
        print(f"[DEBUG] Retrieved Shopify Store: {shopify_domain}")
        print(f"[DEBUG] Retrieved OpenAI API Key: {openai_api_key}")
        print(f"[DEBUG] Retrieved FTP Host: {ftp_host}")
        print(f"[DEBUG] Retrieved FTP User: {ftp_user}")
        print(f"[DEBUG] Retrieved FTP Pass: {ftp_pass}")

    except Exception as e:
        print(f"[DEBUG] Exception occurred while retrieving user settings: {e}")
        flash("Failed to retrieve settings. Please try again.", "danger")
        return redirect(url_for('profile'))

    # Prevent Infinite Redirect Loop
    if not shopify_domain:
        flash("Please connect your Shopify store before accessing other features.", "warning")

    try:
        print("[DEBUG] Attempting to render profile.html")
        return render_template('profile.html', shopify_domain=shopify_domain, openai_api_key=openai_api_key, ftp_host=ftp_host, ftp_user=ftp_user, ftp_pass=ftp_pass)
    except Exception as e:
        print(f"[DEBUG] Exception occurred while rendering template: {e}")
        return str(e), 500



# Settings Route (Handles AJAX updates)
@app.route('/settings', methods=['POST'])
@login_required
def settings():
    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 400

    # Get form data
    user.openai_api_key = request.form.get('openai_api_key')
    user.ftp_host = request.form.get('ftp_host')
    user.ftp_user = request.form.get('ftp_user')
    user.ftp_pass = request.form.get('ftp_pass')

    # Debugging Statements Before Committing to Database
    print("[DEBUG] Updating user settings in database")

    db.session.commit()

    return jsonify({"success": "Settings updated!"})


# ✅ Shopify API Configuration
def get_shopify_headers(shop):
    """Retrieve Shopify API headers using the stored access token for the given shop."""
    user = User.query.filter_by(shopify_domain=shop).first()
    
    if not user or not user.access_token:
        raise ValueError(f"🚨 Shopify access token is missing for {shop}! Check your database settings.")

    return {
        "X-Shopify-Access-Token": user.access_token,
        "Content-Type": "application/json"
    }



def get_shopify_graphql_url(shop):
    """Retrieve the correct Shopify GraphQL API URL for the given store."""
    return f"https://{shop}/admin/api/2024-01/graphql.json"


# ✅ OpenAI Integration
def get_openai_response(prompt):
    user_api_key = current_user.openai_api_key  # Get stored key from DB
    if not user_api_key:
        return "OpenAI API key not set. Please update in settings."
    
    openai.api_key = user_api_key  # Use stored API key
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response["choices"][0]["message"]["content"]

# ✅ FTP Connection Helper
def connect_to_ftp():
    ftp_host = current_user.ftp_host
    ftp_username = current_user.ftp_username
    ftp_password = current_user.ftp_password

    if not ftp_host or not ftp_username or not ftp_password:
        return "FTP credentials are missing. Please update in settings."

    ftp = FTP(ftp_host)
    ftp.login(user=ftp_username, passwd=ftp_password)
    return ftp  # Returns FTP connection object

# ✅ Safe Shopify API Request with Rate Limiting
def safe_request(url, method='get', **kwargs):
    max_retries = 10
    backoff_factor = 2
    jitter = 0.1
    retry_wait = 1

    for attempt in range(max_retries):
        try:
            response = requests.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:  
                retry_after = response.headers.get("Retry-After", retry_wait)
                retry_after = float(retry_after) if retry_after else retry_wait
                retry_after *= random.uniform(1 - jitter, 1 + jitter)
                print(f"Rate limit hit, retrying after {retry_after:.2f} seconds...")
                time.sleep(retry_after)
            else:
                raise
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                retry_wait = 2 ** attempt * random.uniform(1 - jitter, 1 + jitter)
                print(f"Request failed, retrying in {retry_wait:.2f} seconds...")
                time.sleep(retry_wait)
            else:
                raise






CACHE_FILE = "cache.json"

def load_cache():
    """Load cached data from a JSON file and ensure correct structure."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as file:
                cache_data = json.load(file)

                # ✅ Ensure cache_data is a dictionary (not a list)
                if not isinstance(cache_data, dict):
                    print("[ERROR] Cache file is corrupted (expected dict, got list). Resetting cache.")
                    os.remove(CACHE_FILE)
                    return {
                        "product_types": {"data": [], "timestamp": 0},
                        "vendors": {"data": [], "timestamp": 0},
                        "collections": {"data": [], "timestamp": 0}
                    }

                # ✅ Ensure proper structure (fixes partial corruption)
                cache_data.setdefault("product_types", {"data": [], "timestamp": 0})
                cache_data.setdefault("vendors", {"data": [], "timestamp": 0})
                cache_data.setdefault("collections", {"data": [], "timestamp": 0})

                return cache_data

        except json.JSONDecodeError:
            print("[ERROR] Cache file is not valid JSON. Resetting cache.")
            os.remove(CACHE_FILE)
            return {
                "product_types": {"data": [], "timestamp": 0},
                "vendors": {"data": [], "timestamp": 0},
                "collections": {"data": [], "timestamp": 0}
            }

    # ✅ If cache does not exist, return a fresh structure
    return {
        "product_types": {"data": [], "timestamp": 0},
        "vendors": {"data": [], "timestamp": 0},
        "collections": {"data": [], "timestamp": 0}
    }

def save_cache(data):
    """Save cached data to a JSON file."""
    try:
        with open(CACHE_FILE, "w") as file:
            json.dump(data, file, indent=4)
        print("[INFO] Cache saved successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to save cache: {e}")

# ✅ Initialize cache
CACHE = {
    "product_types": {"data": [], "timestamp": 0},
    "vendors": {"data": [], "timestamp": 0},  # <-- Fix: Ensure 'vendors' exists
    "collections": {"data": [], "timestamp": 0}
}


def get_cached_product_types():
    cache = load_cache()

    # 🛠 Debug print to check structure
    print(f"[DEBUG] Cached product_types: {cache.get('product_types')}")

    if isinstance(cache.get("product_types"), list):
        print("[ERROR] product_types is a list! Resetting cache.")
        return []  # Ensure it doesn’t crash

    return cache["product_types"]["data"]


def get_cached_vendors():
    """Fetch vendors from the cache file only."""
    cache = load_cache()
    return cache["vendors"]["data"]

def get_cached_collections():
    """Fetch collections from the cache file only."""
    cache = load_cache()
    return cache["collections"]["data"]

# ✅ Fetch Shopify Data Functions
MAX_RETRIES = 5

def fetch_with_rate_limit(shop, url):
    """Handle Shopify API rate limits for a specific store."""
    retries = 0
    headers = get_shopify_headers(shop)  # ✅ Fetch correct headers for this store

    while retries < MAX_RETRIES:
        response = requests.get(url, headers=headers)
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", "2"))
            print(f"[WARNING] Shopify rate limit hit for {shop}. Retrying in {retry_after} seconds...")
            time.sleep(retry_after)
            retries += 1
        elif response.status_code == 200:
            return response.json(), response.headers
        else:
            print(f"[ERROR] Shopify request failed for {shop}: {response.status_code} - {response.text}")
            return None, None
    
    print(f"[ERROR] Max retries reached. Shopify API request failed for {shop}.")
    return None, None


def fetch_all_product_types(shop):
    """Fetch all product types from Shopify API for a specific store."""
    
    url = f"https://{shop}/admin/api/2023-10/products.json?limit=250&fields=product_type"

    response, _ = fetch_with_rate_limit(shop, url)
    
    if not response:
        print(f"[ERROR] Shopify API request failed for {shop}!")
        return []

    try:
        product_types = sorted({p.get("product_type", "UNKNOWN_PRODUCT_TYPE") for p in response.get("products", [])})
        return product_types
    except Exception as e:
        print(f"[ERROR] JSON decoding failed for {shop}: {e}")
        return []


# ✅ Fetch Product Data from Shopify
def fetch_product_by_id(shop, product_id):
    """Fetch product details from Shopify API for a specific store."""
    product_id = product_id.replace("gid://shopify/Product/", "").strip()
    query = f"""
    {{
        product(id: "gid://shopify/Product/{product_id}") {{
            id
            handle
            title
            vendor
            productType
            descriptionHtml
            seo {{ title description }}
            images(first: 5) {{
                edges {{ node {{ id src altText }} }}
            }}
        }}
    }}
    """
    url = get_shopify_graphql_url(shop)
    headers = get_shopify_headers(shop)

    response = requests.post(url, json={"query": query}, headers=headers)
    response_json = response.json()
    product_data = response_json.get("data", {}).get("product", {})

    if not product_data:
        return None

    images = product_data.get("images", {}).get("edges", [])
    return {
        "id": product_data.get("id"),
        "handle": product_data.get("handle", ""),
        "title": product_data.get("title"),
        "vendor": product_data.get("vendor", ""),
        "productType": product_data.get("productType", ""),
        "descriptionHtml": product_data.get("descriptionHtml", ""),
        "meta_title": product_data.get("seo", {}).get("title", product_data.get("title", "")),
        "meta_description": product_data.get("seo", {}).get("description", product_data.get("descriptionHtml", "")),
        "alt_text": images[0]["node"]["altText"] if images else "",
        "image_url": images[0]["node"]["src"] if images else "",
        "image_id": images[0]["node"]["id"] if images else "",
    }


# ✅ Flask Route: Dashboard (Requires Login)
@app.route("/dashboard")
@login_required
def dashboard():
    return f"Welcome, {current_user.username}! This is your dashboard."

@app.route("/inventory/")
@login_required
def inventory():
    shopify_domain = get_shopify_domain(current_user.id)
    shopify_token = get_shopify_access_token(current_user.id)

    if not shopify_domain or not shopify_token:
        flash("Please connect your Shopify store before accessing inventory.", "warning")
        return redirect(url_for("profile"))  # ✅ Only redirect on inventory access

    # Proceed with Shopify API calls only if credentials exist
    location_id = get_shopify_location_id(shopify_domain, shopify_token)

    return render_template("inventory.html", location_id=location_id)



@app.route('/inventory/api/shopify-skus')
def get_shopify_skus_api():
    try:
        shopify_skus = fetch_shopify_skus_concurrent()
        return jsonify(shopify_skus)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_shopify_location_id(shop):
    """Fetches the Shopify location ID for the given shop domain."""
    headers = {
        "X-Shopify-Access-Token": get_shopify_access_token(current_user.id),
        "Content-Type": "application/json",
    }
    url = f"https://{shop}/admin/api/2024-01/locations.json"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        locations = response.json().get("locations", [])
        if locations:
            return locations[0]["id"]  # ✅ Return the first location ID
        else:
            print("[WARNING] No Shopify locations found!")
            return None
    else:
        print(f"[ERROR] Failed to fetch Shopify locations: {response.text}")
        return None



def fetch_shopify_skus_concurrent(shop):
    """Fetch all Shopify SKUs using concurrent requests."""
    user = User.query.filter_by(shopify_domain=shop).first()
    if not user:
        raise ValueError(f"🚨 Shopify store not found for {shop}.")

    shopify_skus = {}
    headers = get_shopify_headers(shop)
    page_info = None
    products_fetched = 0
    pages_fetched = 0

    def fetch_url(url):
        try:
            print(f"Fetching URL: {url}")
            response = requests.get(url, headers=headers)
            data = response.json()
            return data.get("products", []), response.headers.get("Link", "")
        except Exception as e:
            print(f"❌ Error fetching URL: {url} - {str(e)}")
            return [], ""

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        next_page = True

        while next_page:
            url = f"https://{shop}/admin/api/2024-01/products.json?fields=id,variants&limit=250"
            if page_info:
                url += f"&page_info={page_info}"

            future = executor.submit(fetch_url, url)
            futures.append(future)

            for future in as_completed(futures):
                products, links = future.result()
                products_fetched += len(products)
                pages_fetched += 1
                print(f"✅ Processed page {pages_fetched}, fetched {len(products)} products.")

                for product in products:
                    for variant in product["variants"]:
                        if variant["sku"]:
                            shopify_skus[variant["sku"]] = {
                                "product_id": product["id"],
                                "variant_id": variant["id"],
                                "inventory_item_id": variant["inventory_item_id"]
                            }
                
                if links:
                    next_page_link = next((link for link in links.split(", ") if 'rel="next"' in link), None)
                    if next_page_link:
                        page_info = next_page_link[next_page_link.find("<")+1:next_page_link.find(">")]
                    else:
                        next_page = False
                else:
                    next_page = False

            time.sleep(1)

    print(f"✅ Finished fetching SKUs. Total pages fetched: {pages_fetched}. Total SKUs fetched: {len(shopify_skus)} ({products_fetched} products processed).")
    return shopify_skus



@app.route('/inventory/api/shopify-products', methods=['POST'])
def get_shopify_products():
    shop = request.json.get("shopify_domain")  # Get shop from request
    user = User.query.filter_by(shopify_domain=shop).first()
    
    if not user or not user.access_token:
        return jsonify({'error': 'Missing Shopify credentials for this store'}), 500
    
    # Ensure correct URL format
    shopify_url = f"https://{shop}/admin/api/2024-01/products.json?limit=50&order=title asc"
    headers = get_shopify_headers(shop)
    
    graphql_query = request.json.get('query')

    try:
        response = requests.post(shopify_url, json={"query": graphql_query}, headers=headers)
        response.raise_for_status()
        products = response.json()
        return jsonify(products)
    except requests.exceptions.RequestException as e:
        print(f'❌ Error fetching Shopify products: {e}')
        return jsonify({'error': 'Failed to fetch products from Shopify'}), 500


CSV_FILENAME = "Motorstate1.csv"
# ✅ Function to Fetch User-Specific FTP Credentials
def get_user_ftp_credentials(user_id):
    """Fetch user-specific FTP credentials from the database."""
    with app.app_context():
        user = User.query.filter_by(id=user_id).first()
        if user:
            return {
                "FTP_HOST": user.ftp_host or os.getenv("FTP_HOST"),
                "FTP_USER": user.ftp_user or os.getenv("FTP_USER"),
                "FTP_PASS": user.ftp_pass or os.getenv("FTP_PASS"),
            }
        else:
            print(f"[WARNING] No FTP credentials found for user {user_id}. Using environment variables.")
            return {
                "FTP_HOST": os.getenv("FTP_HOST"),
                "FTP_USER": os.getenv("FTP_USER"),
                "FTP_PASS": os.getenv("FTP_PASS"),
            }

# ✅ Load FTP Credentials for the Logged-in User (Lazy Loading)
FTP_CREDENTIALS = None



# ✅ Prevent Crashing - If FTP Credentials Are Still Missing, Just Warn
if not FTP_CREDENTIALS or not FTP_CREDENTIALS["FTP_HOST"] or not FTP_CREDENTIALS["FTP_USER"] or not FTP_CREDENTIALS["FTP_PASS"]:
    print("[WARNING] FTP credentials are missing! Some features may not work.")
    FTP_CREDENTIALS = None  # Ensure it doesn't break other parts of the code


from sqlalchemy import text  # ✅ Import text from SQLAlchemy

def get_setting(key):
    """Fetch a setting from the database within an app context."""
    with app.app_context():
        result = db.session.execute(
            text("SELECT value FROM settings WHERE key = :key"), {"key": key}
        ).fetchone()


        return result[0] if result else None


# ✅ Ensure database queries happen inside an app context
with app.app_context():
    ftp_host = get_setting("ftp_host") or os.getenv("FTP_HOST")
    ftp_user = get_setting("ftp_user") or os.getenv("FTP_USER")
    ftp_pass = get_setting("ftp_pass") or os.getenv("FTP_PASS")

if not ftp_host or not ftp_user or not ftp_pass:
    if not FTP_CREDENTIALS:
        print("[WARNING] Missing FTP credentials. Some features may not work.")

def connect_to_ftp():
    """Establish FTP connection using credentials from the database."""
    ftp_host, ftp_user, ftp_pass = get_ftp_credentials()

    if not ftp_host or not ftp_user or not ftp_pass:
        raise ValueError("Missing FTP credentials from database")

    try:
        ftp = FTP(ftp_host)
        ftp.login(ftp_user, ftp_pass)
        print("[DEBUG] Connected to FTP successfully!")
        return ftp
    except Exception as e:
        print(f"[ERROR] Failed to connect to FTP: {e}")
        return None

def download_csv_from_ftp():
    """Download CSV inventory file from FTP server using credentials from the database."""
    print("Connecting to FTP server...")
    
    ftp = connect_to_ftp()
    if not ftp:
        return False

    try:
        print("Checking for the CSV file...")
        if CSV_FILENAME in ftp.nlst():  # List files in FTP directory
            with open(CSV_FILENAME, "wb") as file:
                ftp.retrbinary(f"RETR {CSV_FILENAME}", file.write)
            print(f"[SUCCESS] {CSV_FILENAME} downloaded successfully.")
            ftp.quit()
            return True
        else:
            print(f"[ERROR] {CSV_FILENAME} not found on FTP server.")
            ftp.quit()
            return False
    except Exception as e:
        print(f"[ERROR] Failed to download from FTP: {e}")
        return False

@app.route('/inventory/download_csv', methods=['POST'])
def handle_download_csv():
    """Endpoint to initiate CSV download from FTP and respond with status."""
    print("Attempting to download CSV from FTP...")
    try:
        if download_csv_from_ftp():
            print("[SUCCESS] CSV downloaded successfully.")
            return jsonify({"status": "success", "message": "CSV downloaded successfully"})
        else:
            print("[ERROR] CSV not found on FTP server.")
            return jsonify({"status": "error", "message": "CSV not found on FTP server"}), 404
    except Exception as e:
        print(f"[ERROR] Failed to download CSV: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

def load_csv():
    """Load and preprocess CSV data, adjusting vendor names and SKUs."""
    csv_path = CSV_FILENAME
    if os.path.exists(csv_path):
        try:
            df = pd.read_csv(csv_path, encoding="ISO-8859-1", on_bad_lines='skip')  # Skip bad lines

            # Normalize vendor names
            brand_mapping = {
                'MAHLE ORIGINAL/CLEVITE': 'Mahle Motorsport',
                'MAHLE PISTONS': 'Mahle Motorsport',
                'STRANGE': 'Strange Engineering',
                'STRANGE OVAL': 'Strange Engineering'
            }
            df['Brand'] = df['Brand'].replace(brand_mapping)

            # Generate Shopify SKU format
            df['Shopify_SKU'] = df['Brand'].str.title() + ' - ' + df['ManufacturerPart']

            print("[SUCCESS] CSV loaded and formatted successfully.")
            return df
        except Exception as e:
            print(f"[ERROR] Error loading CSV: {str(e)}")
            return None
    else:
        print(f"[ERROR] {csv_path} not found after supposed download.")
        return None

def update_inventory_and_pricing(shop, product_id, variant_id, inventory_item_id, quantity, suggested_retail, cost, map_price, location_id):
    try:
        headers = get_shopify_headers(shop)  # ✅ Fetch correct Shopify headers per store

        # Update Inventory
        print(f"Updating inventory for Product ID {product_id}, Variant ID {variant_id} in {shop}")
        inventory_payload = {
            "location_id": location_id,
            "inventory_item_id": inventory_item_id,
            "available": quantity
        }
        inventory_url = f"https://{shop}/admin/api/2024-01/inventory_levels/set.json"

        response = requests.post(inventory_url, json=inventory_payload, headers=headers)
        response.raise_for_status()
        print("✅ Inventory updated successfully.")

        # Update Pricing
        print(f"Updating pricing for Variant ID {variant_id}")
        pricing_payload = {
            "variant": {
                "id": variant_id,
                "price": suggested_retail,
                "compare_at_price": map_price if pd.notna(map_price) else suggested_retail
            }
        }
        pricing_url = f"https://{shop}/admin/api/2024-01/variants/{variant_id}.json"

        response = requests.put(pricing_url, json=pricing_payload, headers=headers)
        response.raise_for_status()
        print("✅ Pricing updated successfully.")
    except requests.exceptions.HTTPError as e:
        print(f"❌ Failed to update due to HTTP Error: {e.response.text}")
        raise
    except Exception as e:
        print(f"❌ General Error: {str(e)}")
        raise


def bulk_update_inventory(shop, df, shopify_skus, location_id):
    matched_count = 0
    total_skus = len(shopify_skus)

    with ThreadPoolExecutor(max_workers=3) as executor:  # Adjust workers for efficiency
        futures = []
        for index, row in df.iterrows():
            sku_data = shopify_skus.get(row['Shopify_SKU'])
            if sku_data:
                matched_count += 1
                future = executor.submit(update_inventory_and_pricing, shop, sku_data['product_id'], sku_data['variant_id'],
                                         sku_data['inventory_item_id'], row['QtyAvail'], row['SuggestedRetail'],
                                         row['Cost'], row['MapPrice'], location_id)
                futures.append(future)
            if index % 100 == 0:  # Log progress every 100 rows
                print(f"Processed {index + 1}/{len(df)} rows.")

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"❌ Error updating SKU: {e}")

    print(f"✅ Matched {matched_count} out of {total_skus} SKUs from Shopify with the CSV data.")
    return matched_count, total_skus




@app.route('/inventory/trigger_update', methods=['POST'])
def trigger_update():
    print("Triggering the inventory and pricing update process...")
    try:
        profiler = cProfile.Profile()
        profiler.enable()

        shop = request.json.get("shopify_domain")  # ✅ Get shop from request
        user = User.query.filter_by(shopify_domain=shop).first()
        if not user:
            return jsonify({"status": "error", "message": "Shopify store not found."}), 500

        if not download_csv_from_ftp():
            return jsonify({"status": "error", "message": "Failed to download CSV file from FTP server."}), 500

        print("✅ CSV downloaded successfully, proceeding with updates...")
        location_id = get_shopify_location_id(shop)
        if not location_id:
            return jsonify({"status": "error", "message": "Failed to fetch location ID from Shopify."}), 500

        print("✅ Fetching SKUs from Shopify...")
        shopify_skus = fetch_shopify_skus_concurrent(shop)
        if not shopify_skus:
            return jsonify({"status": "error", "message": "Failed to fetch SKUs from Shopify."}), 500
        print(f"✅ Fetched {len(shopify_skus)} SKUs from Shopify.")

        df = load_csv()
        if df is None:
            return jsonify({"status": "error", "message": "CSV data could not be loaded."}), 500

        print("✅ Starting bulk update of inventory and pricing...")
        matched_count, total_skus = bulk_update_inventory(shop, df, shopify_skus, location_id)
        print(f"✅ Completed bulk update. Matched {matched_count} SKUs out of {total_skus}.")

        profiler.disable()
        profiler.print_stats(sort='time')

        return jsonify({"status": "success", "message": "Inventory and pricing updated successfully!", "matched_count": matched_count, "total_skus": total_skus})
    except Exception as e:
        print(f"❌ An error occurred: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500



@app.route('/inventory/update_inventory_pricing', methods=['POST'])
def handle_update_inventory_pricing():
    data = request.get_json()
    product_id = data.get('product_id')
    variant_id = data.get('variant_id')
    inventory_item_id = data.get('inventory_item_id')
    quantity = data.get('quantity')
    suggested_retail = data.get('suggested_retail')
    cost = data.get('cost')
    map_price = data.get('map_price')
    location_id = data.get('location_id')

    try:
        update_inventory_and_pricing(product_id, variant_id, inventory_item_id, quantity, suggested_retail, cost, map_price, location_id)
        return jsonify({'status': 'success', 'message': 'Inventory and pricing updated successfully'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/inventory/api/products')
def get_products():
    try:
        shop = request.args.get("shopify_domain")  # ✅ Get shop from request
        user = User.query.filter_by(shopify_domain=shop).first()
        
        if not user or not user.access_token:
            raise ValueError("❌ Missing Shopify credentials for this store.")
        
        # ✅ Ensure SHOPIFY_DOMAIN has https://
        shopify_url = f"https://{shop}/admin/api/2024-01/products.json?limit=50&order=title asc"
        headers = get_shopify_headers(shop)

        response = requests.get(shopify_url, headers=headers)
        response.raise_for_status()
        return jsonify(response.json())
    except Exception as e:
        print(f"❌ Error in get_products: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


def fetch_vendor_list(shop):
    """
    Fetches a list of all vendors from Shopify for a specific store.
    """
    user = User.query.filter_by(shopify_domain=shop).first()
    if not user:
        raise ValueError(f"🚨 Shopify store not found for {shop}.")

    url = f"https://{shop}/admin/api/2024-01/products.json?fields=vendor&limit=250"
    headers = get_shopify_headers(shop)

    vendors = set()  # Use a set to avoid duplicate vendors

    try:
        page_info = None
        while True:
            page_url = f"{url}&page_info={page_info}" if page_info else url
            response = requests.get(page_url, headers=headers)
            response.raise_for_status()
            data = response.json()
            vendors.update({product['vendor'] for product in data.get('products', []) if product.get('vendor')})

            links = response.headers.get("Link", "")
            page_info = None
            for link in links.split(','):
                if 'rel="next"' in link:
                    page_info = link.split(';')[0].strip('<>')
                    break

            if not page_info:
                break

    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to fetch vendors for {shop}: {str(e)}")
        return []

    return list(vendors)  # Convert set to list to make it JSON serializable



@app.route('/inventory/get_vendors')
def get_vendors():
    shop = request.args.get("shopify_domain")
    if not shop:
        return jsonify({"error": "Missing shopify_domain parameter"}), 400

    vendors = fetch_vendor_list(shop)
    return jsonify(vendors)

@app.route('/inventory/update_by_vendor', methods=['POST'])
def update_by_vendor():
    data = request.get_json()
    shop = data.get('shopify_domain')
    selected_vendors = data.get('vendors', [])

    if not shop:
        return jsonify({"status": "error", "message": "Missing shopify_domain parameter"}), 400

    user = User.query.filter_by(shopify_domain=shop).first()
    if not user:
        return jsonify({"status": "error", "message": "Shopify store not found."}), 500

    df = load_csv()  # Load your CSV containing product data
    if df is not None:
        df_filtered = df[df['Brand'].isin(selected_vendors)]
        location_id = get_shopify_location_id(shop)
        if location_id:
            shopify_skus = fetch_shopify_skus_concurrent(shop)
            bulk_update_inventory(shop, df_filtered, shopify_skus, location_id)
            return jsonify({"status": "success", "message": "Inventory updated for selected vendors!"})
        else:
            return jsonify({"status": "error", "message": "Location ID could not be fetched."})
    return jsonify({"status": "error", "message": "CSV data could not be loaded."})


@app.route('/inventory/api/get-skus')
def api_get_skus():
    shop = request.args.get("shopify_domain")
    if not shop:
        return jsonify({"error": "Missing shopify_domain parameter"}), 400

    shopify_skus = fetch_shopify_skus_concurrent(shop)
    return jsonify(shopify_skus)


@app.route('/inventory/process_inventory_update', methods=['POST'])
def process_inventory_update():
    try:
        data = request.get_json()
        shop = data.get("shopify_domain")

        if not shop:
            return jsonify({"status": "error", "message": "Missing shopify_domain parameter"}), 400

        user = User.query.filter_by(shopify_domain=shop).first()
        if not user:
            return jsonify({"status": "error", "message": "Shopify store not found."}), 500

        # ✅ Download CSV from FTP
        if not download_csv_from_ftp():
            raise Exception("Failed to download CSV from FTP server.")

        # ✅ Load CSV data
        df = load_csv()
        if df is None:
            raise Exception("Failed to load data from CSV.")

        # ✅ Fetch Shopify SKUs
        shopify_skus = fetch_shopify_skus_concurrent(shop)
        if not shopify_skus:
            raise Exception("Failed to fetch SKUs from Shopify.")

        # ✅ Get location ID
        location_id = get_shopify_location_id(shop)
        if not location_id:
            raise Exception("Failed to fetch Shopify location ID.")

        # ✅ Perform inventory update
        bulk_update_inventory(shop, df, shopify_skus, location_id)

        return jsonify({"status": "success", "message": "Inventory and pricing updated successfully!"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500



def get_openai_client():
    """Retrieve OpenAI client with the user's API key."""
    api_key = current_user.openai_api_key  # Fetch from database
    if not api_key:
        raise ValueError("OpenAI API Key is missing from user settings.")

    # Initialize OpenAI client
    return openai.OpenAI(api_key=api_key)

@app.route('/seo/api/product_details/<product_id>')
def product_details_api(product_id):
    shop = request.args.get("shopify_domain")  # ✅ Get shop from request

    if not shop:
        return jsonify({"error": "Missing shopify_domain parameter"}), 400

    print(f"[DEBUG] API call to fetch details for product ID: {product_id} from {shop}")

    product = fetch_product_by_id(shop, product_id)

    if not product:
        print(f"[ERROR] Product not found for ID: {product_id}")
        return jsonify({"error": "Product data not found or invalid response from Shopify."}), 404

    return jsonify(product)

    


# ✅ Fetch Collection ID (Supports Both Custom & Smart Collections)
def get_collection_id_by_name(shop, collection_name):
    """Fetch collection ID by name (supports both Custom & Smart Collections)."""
    try:
        headers = get_shopify_headers(shop)

        # ✅ Fetch Custom Collections
        url = f"https://{shop}/admin/api/2024-01/custom_collections.json?limit=250"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        collections = response.json().get("custom_collections", [])

        for collection in collections:
            if collection["title"].lower() == collection_name.lower():
                return collection["id"]

        # ✅ Fetch Smart Collections
        url = f"https://{shop}/admin/api/2024-01/smart_collections.json?limit=250"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        collections = response.json().get("smart_collections", [])

        for collection in collections:
            if collection["title"].lower() == collection_name.lower():
                return collection["id"]

        return None  # Collection not found

    except Exception as e:
        print(f"[ERROR] Failed to fetch collection ID for {shop}: {e}")
        return None



def fetch_products_from_api(shop, limit=50, product_type=None, vendor=None, collection_name=None, sort_by="title", page_info=None):
    print(f"[DEBUG] Fetching products for {shop} with parameters:")
    print(f"  Limit: {limit}, Product Type: {product_type}, Vendor: {vendor}, Collection: {collection_name}, Sort By: {sort_by}, Page Info: {page_info}")

    headers = get_shopify_headers(shop)

    # ✅ Handle Collection Filtering
    collection_id = None
    if collection_name:
        collection_id = get_collection_id_by_name(shop, collection_name)

    # ✅ Base URL setup
    if collection_id:
        url = f"https://{shop}/admin/api/2024-01/collections/{collection_id}/products.json?limit={limit}"
    else:
        url = f"https://{shop}/admin/api/2024-01/products.json?limit={limit}"

    # ✅ Shopify Pagination Handling
    if page_info:
        url = f"https://{shop}/admin/api/2024-01/products.json?limit={limit}&page_info={page_info}"  # No sorting when paginating
    else:
        params = []
        if product_type:
            params.append(f"product_type={product_type}")
        if vendor:
            params.append(f"vendor={vendor}")
        if sort_by == "price_asc":
            params.append("order=variants.price asc")
        elif sort_by == "price_desc":
            params.append("order=variants.price desc")
        else:
            params.append("order=title asc")

        if params:
            url += "&" + "&".join(params)

    print(f"[DEBUG] Shopify API Request URL: {url}")

    # ✅ API Call with Rate Limit Handling
    while True:
        try:
            response = requests.get(url, headers=headers)
            
            # **Handle 429 Rate Limiting**
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "2")  # Default to 2 if missing
                try:
                    retry_after = max(1, int(float(retry_after)))  # Ensure at least 1 second
                except ValueError:
                    retry_after = 2  # Default to 2 if conversion fails

                print(f"[WARNING] Shopify API rate limit hit! Retrying after {retry_after} seconds...")
                time.sleep(retry_after)
                continue  # Retry request
            
            response.raise_for_status()  # Raise other HTTP errors if any
            products = response.json().get('products', [])

            print(f"[DEBUG] Successfully fetched {len(products)} products")
            break  # **Exit loop if successful**

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Failed to fetch products for {shop}: {e}")
            return [], None, None  # Ensure three return values

    # ✅ Extract `page_info` for pagination
    next_page_url = None
    if 'Link' in response.headers:
        links = response.headers['Link'].split(',')
        for link in links:
            if 'rel="next"' in link:
                next_page_url = link.split(';')[0].strip('<>').split('page_info=')[1]

    return products, next_page_url, None  # Ensure three return values


 # ✅ Place these above the `/api/seo_audit` route

def analyze_product_seo(product):
    """Analyzes a product's SEO and assigns a score."""
    issues = []
    score = 100  # Start perfect, deduct points for problems

    # Title Check
    title = product.get("title", "").strip()
    if not title:
        issues.append("Missing product title")
        score -= 20

    # Description Check
    description = product.get("body_html", "").strip()
    if not description:
        issues.append("Missing product description")
        score -= 20

    # Image Alt Text Check
    images = product.get("images", [])  # Ensure images is a list
    has_alt_text = any(img.get("alt", "").strip() if img.get("alt") else "" for img in images)
    
    if not images:
        issues.append("No product images")
        score -= 15
    elif not has_alt_text:
        issues.append("Product images missing alt text")
        score -= 10

    # Meta Description Check
    meta_description = product.get("metafields", {}).get("global", {}).get("description_tag", "").strip()
    if not meta_description:
        issues.append("Missing meta description")
        score -= 15

    # Keep score within 0-100
    score = max(0, score)

    return score, issues


def generate_seo_recommendations(product_scores):
    """Generates SEO improvement recommendations based on product scores."""
    issues_count = {}

    # Count how often each issue appears
    for product in product_scores:
        for issue in product["issues"]:
            issues_count[issue] = issues_count.get(issue, 0) + 1

    # Sort issues by frequency
    sorted_issues = sorted(issues_count.items(), key=lambda x: x[1], reverse=True)

    # Create recommendations
    recommendations = []
    for issue, count in sorted_issues:
        recommendations.append(f"{issue} (Found in {count} products)")

    return recommendations



@app.route('/seo/api/seo_audit', methods=['GET'])
def seo_audit():
    """Runs an SEO audit on all products in the store and returns a JSON report."""
    print("[DEBUG] Running SEO audit...")

    all_products = []
    page_info = None

    # ✅ Fetch all products with pagination support
    while True:
        products, next_page_url, _ = fetch_products_from_api(limit=50, page_info=page_info)
        if not products:
            break
        all_products.extend(products)
        if not next_page_url:
            break
        page_info = next_page_url  # Move to next page

    total_products = len(all_products)
    if total_products == 0:
        return jsonify({"error": "No products found in store"}), 404

    print(f"[DEBUG] Total products fetched: {total_products}")

    # ✅ Run SEO Analysis
    product_scores = []
    total_score = 0

    for product in all_products:
        score, issues = analyze_product_seo(product)
        product_scores.append({
            "id": product["id"],
            "title": product["title"],
            "score": score,
            "issues": issues
        })
        total_score += score

    # ✅ Calculate overall store SEO score
    store_score = round(total_score / total_products, 2) if total_products else 0

    # ✅ Generate recommendations based on common issues
    recommendations = generate_seo_recommendations(product_scores)

    # ✅ Build response
    response = {
        "store_score": store_score,
        "total_products_analyzed": total_products,
        "products": product_scores,
        "recommendations": recommendations
    }

    print(f"[DEBUG] SEO audit completed. Store Score: {store_score}")
    return jsonify(response)

def fetch_product_types(shop):
    """Fetch all unique product types from Shopify and update the cache with rate limit handling."""
    try:
        headers = get_shopify_headers(shop)
        product_types = set()
        url = f"https://{shop}/admin/api/2024-01/products.json?limit=250&fields=product_type"

        while url:
            response = requests.get(url, headers=headers)

            # ✅ Handle rate limiting (429 error)
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", "2"))
                print(f"[WARNING] Shopify API rate limit hit (product types). Retrying after {retry_after} seconds...")
                time.sleep(retry_after)
                continue  # Retry request

            response.raise_for_status()
            data = response.json()

            for product in data.get("products", []):
                if product.get("product_type"):
                    product_types.add(product["product_type"])

            # ✅ Handle Pagination
            url = None
            link_header = response.headers.get("Link")
            if link_header:
                for link in link_header.split(","):
                    if 'rel="next"' in link:
                        url = link.split(";")[0].strip("<> ")

        print(f"[DEBUG] Final Product Types Retrieved for {shop}: {sorted(product_types)}")
        return sorted(product_types)

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch product types for {shop}: {e}")
        return []



def fetch_vendors(shop):
    """Fetch all unique vendors from Shopify and update the cache with rate limit handling."""
    try:
        headers = get_shopify_headers(shop)
        vendors = set()
        url = f"https://{shop}/admin/api/2024-01/products.json?limit=250&fields=vendor"

        while url:
            response = requests.get(url, headers=headers)

            # ✅ Handle rate limiting (429 error)
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", "2"))
                print(f"[WARNING] Shopify API rate limit hit (vendors). Retrying after {retry_after} seconds...")
                time.sleep(retry_after)
                continue  # Retry request

            response.raise_for_status()
            data = response.json()

            for product in data.get("products", []):
                vendor_name = product.get("vendor", "").strip()
                if vendor_name:
                    vendors.add(vendor_name)

            # ✅ Handle Pagination
            url = None
            link_header = response.headers.get("Link")
            if link_header:
                for link in link_header.split(","):
                    if 'rel="next"' in link:
                        url = link.split(";")[0].strip("<> ")

        print(f"[DEBUG] Final Vendors Retrieved for {shop}: {sorted(vendors)}")
        return sorted(vendors)

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch vendors for {shop}: {e}")
        return []


def fetch_collections(shop):
    """Fetch all custom and smart collections from Shopify with retry logic for rate limits and pagination."""
    try:
        headers = get_shopify_headers(shop)
        collections = set()  # Store unique collections

        for endpoint in ["custom_collections", "smart_collections"]:
            url = f"https://{shop}/admin/api/2024-01/{endpoint}.json?limit=250"

            while url:
                print(f"[DEBUG] Fetching collections from {shop}: {url}")

                response = requests.get(url, headers=headers)

                # ✅ Handle Rate Limiting (429 Error)
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", "2"))
                    print(f"[WARNING] Shopify API rate limit hit. Retrying after {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue  # Retry the request

                response.raise_for_status()
                data = response.json()

                # ✅ Collect collection names
                collections.update(col["title"] for col in data.get(endpoint, []))

                # ✅ Handle Pagination
                url = None  # Reset URL
                link_header = response.headers.get("Link")
                if link_header:
                    for link in link_header.split(","):
                        if 'rel="next"' in link:
                            url = link.split(";")[0].strip("<> ")

        sorted_collections = sorted(collections)  # Sort collections alphabetically
        print(f"[DEBUG] Final Collections Retrieved for {shop}: {sorted_collections}")
        return sorted_collections

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch collections for {shop}: {e}")
        return []



@app.route('/seo/')
def home():
    print("[DEBUG] Rendering home page")

    product_type = request.args.get('product_type')
    vendor = request.args.get('vendor')
    collection_name = request.args.get('collection_name')
    sort_by = request.args.get('sort_by', 'title')
    page_info = request.args.get('page_info')

    # ✅ Fetch only if products need to be updated
    products, next_page_url, previous_page_url = fetch_products_from_api(
        limit=50, product_type=product_type, vendor=vendor,
        collection_name=collection_name, sort_by=sort_by, page_info=page_info
    )

    # ✅ Fetch Product Types, Vendors, and Collections
    product_types = get_cached_product_types()
    vendors = get_cached_vendors()
    collections = get_cached_collections()

    # ✅ Debugging Output
    print(f"[DEBUG] Vendors: {vendors}")
    print(f"[DEBUG] Product Types: {product_types}")
    print(f"[DEBUG] Collections: {collections}")

    # ✅ Store fetched products in session for `next_product`
    session["cached_products"] = products
    session["next_page_url"] = next_page_url



    return render_template('products.html',
                           products=products,
                           next_page_url=next_page_url,
                           previous_page_url=previous_page_url,
                           product_types=product_types,
                           vendors=vendors,
                           collections=collections,
                           product_type=product_type,
                           vendor=vendor,
                           segment="product_details",
                           collection_name=collection_name,
                           sort_by=sort_by)

    


@app.route('/seo/save_prompt', methods=['POST'])
def save_prompt():
    if request.content_type != "application/json":
        return jsonify({"error": "Request must be JSON"}), 415  # Ensure JSON request

    try:
        data = request.get_json()
        new_prompt = data.get("prompt", "").strip()

        if not new_prompt:
            return jsonify({"error": "Prompt cannot be empty"}), 400

        session["custom_prompt"] = new_prompt  # ✅ Store in session
        session.modified = True  # ✅ Ensure session updates persist

        print(f"[DEBUG] Custom Prompt Saved: {new_prompt}")  # ✅ Debugging Output

        return jsonify({"success": "Prompt saved successfully!", "prompt": new_prompt})

    except Exception as e:
        print(f"[ERROR] Failed to save prompt: {str(e)}")
        return jsonify({"error": f"Failed to save prompt: {str(e)}"}), 500




@app.route('/seo/update_shopify_data')
def update_shopify_data():
    """Fetch fresh data from Shopify and update cache when needed."""
    shop = request.args.get("shopify_domain")  # ✅ Get shop from request

    if not shop:
        return jsonify({"error": "Missing shopify_domain parameter"}), 400

    print(f"[INFO] Updating Shopify data for {shop}...")

    # ✅ Fetch fresh data from Shopify
    fresh_product_types = fetch_product_types(shop)
    fresh_vendors = fetch_vendors(shop)
    fresh_collections = fetch_collections(shop)

    # ✅ Update cache
    cache = load_cache()
    cache["product_types"]["data"] = fresh_product_types
    cache["vendors"]["data"] = fresh_vendors
    cache["collections"]["data"] = fresh_collections
    cache["product_types"]["timestamp"] = time.time()
    cache["vendors"]["timestamp"] = time.time()
    cache["collections"]["timestamp"] = time.time()

    save_cache(cache)  # ✅ Save updated cache properly

    flash("Shopify data updated successfully!")
    return redirect(url_for('home'))


@app.route('/seo/update_seo_details/<product_id>', methods=['POST'])
def update_seo_details(product_id):
    """Updates Shopify product meta title, description, and alt text."""
    try:
        shop = request.form.get("shopify_domain")  # ✅ Get shop from form input

        if not shop:
            return jsonify({"error": "Missing shopify_domain parameter"}), 400

        print(f"[INFO] Updating SEO for Product ID: {product_id} in {shop}")

        meta_title = request.form.get("meta_title", "").strip()
        meta_description = request.form.get("meta_description", "").strip()
        alt_text = request.form.get("alt_text", "").strip()

        headers = get_shopify_headers(shop)  # ✅ Fetch correct headers per store

        mutation = f"""
        mutation {{
            metafieldsSet(metafields: [
                {{
                    ownerId: "gid://shopify/Product/{product_id}",
                    namespace: "seo",
                    key: "title_tag",
                    type: "single_line_text_field",
                    value: "{meta_title}"
                }},
                {{
                    ownerId: "gid://shopify/Product/{product_id}",
                    namespace: "seo",
                    key: "description_tag",
                    type: "single_line_text_field",
                    value: "{meta_description}"
                }}
            ]) {{
                metafields {{
                    id
                    value
                }}
                userErrors {{
                    field
                    message
                }}
            }}
        }}
        """

        response = requests.post(f"https://{shop}/admin/api/2024-01/graphql.json",
                                 json={"query": mutation}, headers=headers)

        response_data = response.json()
        print(f"[DEBUG] Shopify API Response: {json.dumps(response_data, indent=4)}")

        user_errors = response_data.get("data", {}).get("metafieldsSet", {}).get("userErrors", [])
        if user_errors:
            print(f"[ERROR] Shopify API Error: {user_errors}")
            flash(f"Failed to update SEO: {user_errors[0]['message']}", "error")
        else:
            print("[SUCCESS] SEO details updated successfully.")
            flash("SEO details updated successfully!", "success")

        if alt_text:
            update_alt_text(shop, product_id, alt_text)  # ✅ Ensure shop is passed

        return redirect(url_for('seo.product_details', product_id=product_id))

    except Exception as e:
        print(f"[ERROR] Exception while updating SEO for {shop}: {e}")
        flash("An error occurred while updating SEO.", "error")
        return redirect(url_for('seo.product_details', product_id=product_id))



def calculate_seo_score(title, description, alt_text):
    """Calculate a basic SEO score based on best practices."""
    score = 0
    max_score = 100

    # ✅ Title Length (Ideal: 50-60 characters)
    if 50 <= len(title) <= 60:
        score += 30
    elif len(title) < 50:
        score += 15  # Partial credit for shorter but decent length

    # ✅ Meta Description Length (Ideal: 150-160 characters)
    if 150 <= len(description) <= 160:
        score += 30
    elif len(description) < 150:
        score += 15

    # ✅ Alt Text Presence
    if alt_text and len(alt_text) > 10:
        score += 20

    # ✅ Keyword Presence in Title & Description
    keywords = ["performance", "Chevrolet", "GM", "race", "autocross"]  # Example keywords
    keyword_hits = sum(1 for kw in keywords if kw.lower() in (title + description).lower())
    score += min(20, keyword_hits * 5)  # Up to 20 points for relevant keywords

    return min(max_score, score)  # Ensure score is capped at 100

@app.route("/product/<product_id>")
def product_details(product_id):
    shop = request.args.get("shopify_domain")  # ✅ Get shop from request

    if not shop:
        return jsonify({"error": "Missing shopify_domain parameter"}), 400

    print(f"[DEBUG] Rendering product details for ID: {product_id} in {shop}")

    product_data = fetch_product_by_id(shop, product_id)  # ✅ Pass shop parameter
    print(f"[DEBUG] Final Processed Product Data: {product_data}")  

    if not product_data:
        return "Product not found", 404

    if not isinstance(product_data, dict):
        print("[ERROR] Unexpected product data type:", type(product_data))
        return "Product data error", 500

    meta_title = product_data.get("meta_title") or product_data.get("title", "").strip()
    meta_description = product_data.get("meta_description") or product_data.get("descriptionHtml", "").strip()
    image_url = product_data.get("image_url", "")

    # ✅ Get filters from request args (if any)
    filters = request.args.to_dict()

    return render_template(
        "product_details.html",
        product=product_data,
        meta_title=meta_title,
        meta_description=meta_description,
        image_url=image_url,
        filters=filters,  # ✅ Pass filters so Jinja knows what it is
        segment="product_details"
    )


def generate_ai_content(shop, prompt, max_tokens=50):
    """Generates AI-generated content based on the given prompt using OpenAI's API."""
    try:
        user = User.query.filter_by(shopify_domain=shop).first()
        if not user or not user.openai_api_key:
            print(f"[ERROR] OpenAI API key not found for {shop}.")
            return None

        openai_api_key = user.openai_api_key

        client = openai.OpenAI(api_key=openai_api_key)  # ✅ Use per-request API key

        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens
        )

        return response.choices[0].message.content.strip()  # ✅ Corrected response parsing

    except Exception as e:
        print(f"[ERROR] AI Content Generation Failed: {e}")
        return None



@app.route('/seo/generate_title/<product_id>', methods=['POST'])
def generate_title(product_id):
    """Generate an AI-based SEO title for a product."""
    shop = request.args.get("shopify_domain")  # ✅ Get store dynamically
    if not shop:
        return jsonify({"error": "Missing shopify_domain parameter"}), 400

    product = fetch_product_by_id(shop, product_id)  # ✅ Fetch product data dynamically
    if not product:
        return jsonify({"error": "Product not found"}), 404

    title = product.get("title", "").strip()
    vendor = product.get("vendor", "").strip()
    product_type = product.get("productType", "").strip()

    if not title:
        return jsonify({"error": "Missing product title"}), 400

    prompt = f"""
Generate a product title using only the details provided:
- Product Title: {title}
- Vendor: {vendor}
- Product Type: {product_type}

**Guidelines:**
- Max **60 characters**.
- Use **key specs** (size, fitment, material, etc.).
- **Do NOT** use generic adjectives like "premium," "durable," or "cost-effective."
- **No unnecessary filler words.**
- **NO quotation marks around the title.**
"""

    print(f"[DEBUG] OpenAI Prompt for Title:\n{prompt.strip()}")

    generated_title = generate_ai_content(shop, prompt, max_tokens=50)

    if not generated_title:
        return jsonify({"error": "Failed to generate product title"}), 500

    # ✅ **Remove unwanted quotes**
    generated_title = generated_title.strip('"').strip("'")

    print(f"[DEBUG] Cleaned Generated Title: {generated_title}")

    return jsonify({"product_title": generated_title})




@app.route('/seo/generate_description/<product_id>', methods=['POST'])
def generate_description(product_id):
    """Generate an AI-optimized product description with custom prompt integration."""
    shop = request.args.get("shopify_domain")
    if not shop:
        return jsonify({"error": "Missing shopify_domain parameter"}), 400

    product = fetch_product_by_id(shop, product_id)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    title = product.get("title", "").strip()
    vendor = product.get("vendor", "Unknown Vendor").strip()
    product_type = product.get("productType", "N/A").strip()
    description = product.get("descriptionHtml", "").strip()

    custom_prompt = session.get("custom_prompt", "").strip()

    prompt = f"""
    {custom_prompt if custom_prompt else "Write a clear, no-fluff product description."}

    **STRICT RULES:**
    - **NO vague marketing phrases** (e.g., "boost performance," "enhance ride").
    - **DO NOT assume fitment unless explicitly listed.**
    - **DO NOT change the vendor name `{vendor}`.**
    - **If vendor is known, mention it naturally at least once.**
    - Ensure technical accuracy while maintaining clarity.

    **Product details:**
    - **Name:** {title}
    - **Vendor:** {vendor}
    - **Type:** {product_type}
    - **Current Description:** {description if description else "No description available."}
"""

    print(f"[DEBUG] OpenAI Prompt for Description:\n{prompt.strip()}")

    generated_description = generate_ai_content(shop, prompt, max_tokens=600)

    if not generated_description:
        return jsonify({"error": "Failed to generate description"}), 500

    # ✅ **Truncate to avoid cut-off sentences**
    if len(generated_description) > 600:
        last_full_stop = generated_description[:600].rfind(".")
        if last_full_stop != -1:
            generated_description = generated_description[:last_full_stop + 1]  # Cut at last full stop
        else:
            generated_description = generated_description[:590] + "..."  # Prevent mid-word cut-off

    print(f"[DEBUG] Cleaned Generated Description: {generated_description}")

    return jsonify({"product_description": generated_description})







@app.route('/seo/generate_seo_title/<product_id>', methods=['POST'])
def generate_seo_title(product_id):
    """Generate a highly optimized, clear, and concise SEO product title."""
    shop = request.args.get("shopify_domain")  # ✅ Get store dynamically
    if not shop:
        return jsonify({"error": "Missing shopify_domain parameter"}), 400

    product = fetch_product_by_id(shop, product_id)  # ✅ Fetch product data dynamically
    if not product:
        return jsonify({"error": "Product not found"}), 404

    title = product.get("title", "").strip()
    vendor = product.get("vendor", "Unknown Vendor").strip()
    product_type = product.get("productType", "N/A").strip()

    # ✅ Improved AI Prompt with Stricter Rules
    prompt = f"""
Generate a concise and **SEO-optimized** product title.

**Product Details:**
- Existing Title: {title}
- Vendor: {vendor}
- Product Type: {product_type}

**Strict Formatting Rules:**
- Max **60 characters**.
- **Start with the most important spec** (e.g., size, gear ratio, axle type).
- **Include brand/vendor only if necessary for clarity.**
- **NO generic words like "for vehicles."** Be specific!
- **NO vague terms like "premium," "high-performance," or "enhance."**
- **NO unnecessary filler words.**
- **DO NOT wrap the title in quotes.**
"""

    print(f"[DEBUG] OpenAI Prompt for SEO Title:\n{prompt.strip()}")

    try:
        # Load API key from the database
        user = User.query.filter_by(shopify_domain=shop).first()
        if not user or not user.openai_api_key:
            return jsonify({"error": "OpenAI API key not found"}), 500

        client = openai.OpenAI(api_key=user.openai_api_key)  # ✅ Use per-request API key

        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt.strip()}
            ],
            max_tokens=50
        )

        generated_title = response.choices[0].message.content.strip()

        # ✅ **Remove unwanted quotes**
        generated_title = generated_title.strip('"').strip("'")

        print(f"[DEBUG] Cleaned Generated SEO Title: {generated_title}")

        return jsonify({"seo_title": generated_title})

    except Exception as e:
        print(f"[ERROR] OpenAI API Call Failed: {e}")
        return jsonify({"error": "Failed to generate SEO title"}), 500




@app.route('/seo/generate_seo_description/<product_id>', methods=['POST'])
def generate_seo_description(product_id):
    """Generate a concise, clear, SEO-optimized product meta description (150-160 characters)."""
    shop = request.args.get("shopify_domain")  # ✅ Get store dynamically
    if not shop:
        return jsonify({"error": "Missing shopify_domain parameter"}), 400

    product = fetch_product_by_id(shop, product_id)  # ✅ Fetch product data dynamically
    if not product:
        return jsonify({"error": "Product not found"}), 404

    title = product.get("title", "").strip()
    vendor = product.get("vendor", "Unknown Vendor").strip()
    product_type = product.get("productType", "N/A").strip()
    description = product.get("descriptionHtml", "").strip()

    if not description:
        return jsonify({"error": "Missing product description"}), 400

    # ✅ Get user's custom prompt if set
    custom_prompt = session.get("custom_prompt", "").strip()

    # ✅ Build AI Prompt – User input takes priority if available
    prompt = f"""
    {custom_prompt if custom_prompt else "Generate a clear, factual SEO description."}

    **SEO Meta Description Rules:**
    - Keep it between **150-160 characters**.
    - **DO NOT cut off mid-sentence**—the description must be complete.
    - **No marketing words.** Skip "Unleash," "Enhance," "Boost," "Optimize," "Engineered for."
    - **No fluff.** Just real specs (size, fitment, material, function).
    - **Ensure "{vendor}" is naturally mentioned.**
    
    **Product Details:**
    - **Title:** {title}
    - **Vendor:** {vendor}
    - **Type:** {product_type}
    - **Current Description:** {description}

    **Final Output Rules:**
    - **MUST BE a full, natural sentence (no trailing off).**
    - **NO quotation marks or unnecessary punctuation.**
    """

    print(f"[DEBUG] OpenAI Prompt for SEO Description:\n{prompt.strip()}")

    try:
        # Load API key from the database
        user = User.query.filter_by(shopify_domain=shop).first()
        if not user or not user.openai_api_key:
            return jsonify({"error": "OpenAI API key not found"}), 500

        client = openai.OpenAI(api_key=user.openai_api_key)  # ✅ Use per-request API key

        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt.strip()}
            ],
            max_tokens=180
        )

        generated_description = response.choices[0].message.content.strip()

        # ✅ Remove unnecessary punctuation or formatting issues
        generated_description = generated_description.strip('"').strip("'").strip()

        # ✅ Ensure the AI doesn’t generate an incomplete sentence
        if len(generated_description) > 160:
            last_full_stop = generated_description[:160].rfind(".")
            if last_full_stop != -1:
                generated_description = generated_description[:last_full_stop + 1]  # Cut at last full stop
            else:
                generated_description = generated_description[:157].rsplit(' ', 1)[0] + "..."  # Prevent cut-off words

        print(f"[DEBUG] Cleaned SEO Description: {generated_description}")

        return jsonify({"seo_description": generated_description})

    except Exception as e:
        print(f"[ERROR] OpenAI API Call Failed: {e}")
        return jsonify({"error": "Failed to generate SEO description"}), 500







# ✅ Save Industry Route
@app.route('/seo/save_industry', methods=['POST'])
def save_industry():
    industry = request.form.get('industry')
    if industry:
        session['industry'] = industry
        flash("Industry saved successfully!")
    else:
        flash("Industry cannot be empty.")
    return redirect(request.referrer or url_for('seo.home'))


# ✅ Next Product Route (Corrected to Prevent Errors)
from flask import session

@app.route('/seo/next_product/<current_product_id>')
def next_product(current_product_id):
    shop = request.args.get("shopify_domain")  # ✅ Ensure we fetch the correct store
    if not shop:
        return jsonify({"error": "Missing shopify_domain parameter"}), 400

    clean_current_id = current_product_id.replace("gid://shopify/Product/", "").strip()

    filters = {
        'product_type': request.args.get('product_type'),
        'vendor': request.args.get('vendor'),
        'collection_name': request.args.get('collection_name'),
        'sort_by': request.args.get('sort_by'),
    }

    print(f"[DEBUG] Cleaned Current Product ID: {clean_current_id}")

    products = session.get("cached_products", [])

    if not products:
        print("[ERROR] No products found in session cache! Re-fetching...")
        products, next_page_url, _ = fetch_products_from_api(shop, **filters)  # ✅ Fetch products with store
        session["cached_products"] = products
        session["next_page_url"] = next_page_url

    all_product_ids = [str(p['id']) for p in products]
    print(f"[DEBUG] Available Product IDs: {all_product_ids}")

    current_index = next((index for index, p in enumerate(products) if str(p['id']) == clean_current_id), None)
    print(f"[DEBUG] Current Product Index: {current_index}")

    if current_index is not None and current_index + 1 < len(products):
        next_product_id = products[current_index + 1]['id']
        print(f"[DEBUG] Redirecting to Next Product ID: {next_product_id}")
        return redirect(url_for('seo.product_details', product_id=next_product_id, shopify_domain=shop, **filters))

    elif session.get("next_page_url"):
        print(f"[DEBUG] Moving to Next Page: {session['next_page_url']}")
        return redirect(url_for('seo.home', page_info=session["next_page_url"], shopify_domain=shop, **filters))

    else:
        print(f"[DEBUG] No more products available.")
        flash("No more products available.", "warning")
        return redirect(url_for('seo.home'))


# ✅ Generate AI SEO Content (Title, Description, Alt Text)
@app.route('/seo/generate_<seo_type>/<product_id>', methods=['POST'])
def generate_seo_content(seo_type, product_id):
    """Generate AI SEO content for meta titles, meta descriptions, and alt text using OpenAI."""
    shop = request.args.get("shopify_domain")
    if not shop:
        return jsonify({"error": "Missing shopify_domain parameter"}), 400

    product_id = product_id.replace("gid://shopify/Product/", "").strip()
    print(f"[DEBUG] Cleaned product_id: {product_id}")

    product = fetch_product_by_id(shop, product_id)  # ✅ Fetch product data with store
    if not product:
        print(f"[ERROR] Product not found for ID: {product_id}")
        return jsonify({"error": "Product not found"}), 404

    title = product.get("title", "Unknown Product")
    vendor = product.get("vendor", "Unknown Vendor")
    product_type = product.get("productType", "N/A")
    description = product.get("descriptionHtml", "").strip()

    if seo_type == "meta_title":
        prompt = f"Generate an SEO-optimized meta title under 60 characters using the details:\n- Title: {title}\n- Vendor: {vendor}\n- Product Type: {product_type}"
    elif seo_type == "meta_description":
        prompt = f"Generate an SEO-optimized meta description:\n- {description}\n- Keep it under 160 characters."
    elif seo_type == "alt_text":
        prompt = f"Generate a concise alt text under 125 characters for this product image:\n- Product: {title}."
    else:
        return jsonify({"error": "Invalid SEO type"}), 400

    user = User.query.filter_by(shopify_domain=shop).first()
    if not user or not user.openai_api_key:
        return jsonify({"error": "OpenAI API key not found"}), 500

    client = openai.OpenAI(api_key=user.openai_api_key)

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=100
    )

    generated_content = response.choices[0].message.content.strip()
    return jsonify({seo_type: generated_content})


@app.route('/seo/save_<seo_type>/<product_id>', methods=['POST'])
def save_seo_content(seo_type, product_id):
    """Save AI-generated SEO content to Shopify"""

    shop = request.args.get("shopify_domain")
    if not shop:
        return jsonify({"error": "Missing shopify_domain parameter"}), 400

    product_id = product_id.replace("gid://shopify/Product/", "").strip()
    data = request.get_json()
    content = data.get("content", "").strip()

    if not content:
        return jsonify({"error": f"Cannot save empty {seo_type}"}), 400

    metafield_key = {
        "meta_title": "title_tag",
        "meta_description": "description_tag",
        "alt_text": "alt_text"
    }.get(seo_type)

    if not metafield_key:
        return jsonify({"error": "Invalid SEO type"}), 400

    mutation = f"""
    mutation {{
        productUpdate(input: {{
            id: "gid://shopify/Product/{product_id}",
            metafields: [{{
                key: "{metafield_key}",
                namespace: "global",
                value: "{content}",
                type: "single_line_text_field"
            }}]
        }}) {{
            product {{
                id
            }}
            userErrors {{
                field
                message
            }}
        }}
    }}
    """

    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(f"{SHOPIFY_STORE_URL}/admin/api/2023-10/graphql.json",
                                 json={"query": mutation}, headers=headers)
        response_data = response.json()

        if "errors" in response_data or response_data.get("data", {}).get("productUpdate", {}).get("userErrors"):
            print(f"[ERROR] Failed to update metafield: {response_data}")
            return jsonify({"error": f"Failed to update {seo_type}"}), 500

        return jsonify({"success": f"{seo_type.replace('_', ' ').capitalize()} updated successfully!"})

    except Exception as e:
        return jsonify({"error": f"Failed to update {seo_type}: {str(e)}"}), 500


@app.route('/seo/update_seo/<product_id>', methods=['POST'])
def update_seo(product_id):
    try:
        shop = request.args.get("shopify_domain")
        if not shop:
            return jsonify({"error": "Missing shopify_domain parameter"}), 400

        print(f"[DEBUG] Updating SEO for Product ID: {product_id}")

        meta_title = request.form.get("meta_title", "").strip()
        meta_description = request.form.get("meta_description", "").strip()
        alt_text = request.form.get("alt_text", "").strip()

        # ✅ Shopify GraphQL Mutation for Metafield Update
        mutation = f"""
        mutation {{
            productUpdate(input: {{
                id: "gid://shopify/Product/{product_id}",
                metafields: [
                    {{
                        key: "title_tag",
                        namespace: "global",
                        value: "{meta_title}",
                        type: "single_line_text_field"
                    }},
                    {{
                        key: "description_tag",
                        namespace: "global",
                        value: "{meta_description}",
                        type: "single_line_text_field"
                    }}
                ]
            }}) {{
                product {{
                    id
                }}
                userErrors {{
                    field
                    message
                }}
            }}
        }}
        """

        headers = {
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
            "Content-Type": "application/json"
        }

        # ✅ Send GraphQL Request to Shopify
        response = requests.post(f"{SHOPIFY_STORE_URL}/admin/api/2023-10/graphql.json",
                                 json={"query": mutation}, headers=headers)
        response_data = response.json()

        if "errors" in response_data or response_data.get("data", {}).get("productUpdate", {}).get("userErrors"):
            print(f"[ERROR] Failed to update metafields: {response_data}")
            flash("Failed to update SEO details. Check logs for more info.", "error")
        else:
            print("[SUCCESS] SEO Details updated successfully.")
            flash("SEO details updated successfully!", "success")

        # ✅ Update Alt Text if provided
        if alt_text:
            update_alt_text(shop, product_id, alt_text)

        return redirect(url_for('seo.product_details', product_id=product_id, shopify_domain=shop))

    except Exception as e:
        print(f"[ERROR] Exception while updating SEO: {e}")
        flash("An error occurred while updating SEO.", "error")
        return redirect(url_for('seo.product_details', product_id=product_id, shopify_domain=shop))


@app.route('/seo/generate_alt_text/<product_id>', methods=['POST'])
def generate_alt_text(product_id):
    """Generate optimized alt text for product images using OpenAI."""
    shop = request.args.get("shopify_domain")
    if not shop:
        return jsonify({"error": "Missing shopify_domain parameter"}), 400

    product = fetch_product_by_id(shop, product_id)

    if not product:
        return jsonify({"error": "Product not found"}), 404

    title = product.get("title", "Unknown Product").strip()
    vendor = product.get("vendor", "Unknown Vendor").strip()
    product_type = product.get("productType", "N/A").strip()
    image_alt = product.get("alt_text", "").strip()

    if image_alt and len(image_alt.split()) > 3:
        return jsonify({"alt_text": image_alt})  # ✅ Avoid redundant calls if we already have alt text

    prompt = f"""
Generate a short, SEO-optimized alt text for a product image.
- Product: {title}
- Vendor: {vendor}
- Type: {product_type}

**Rules:**
- Max 10 words.
- Describe the image visually.
- Avoid generic terms like "image of" or "picture of."
- No unnecessary marketing phrases.
"""

    print(f"[DEBUG] OpenAI Prompt for Alt Text:\n{prompt.strip()}")

    try:
        user = User.query.filter_by(shopify_domain=shop).first()
        if not user or not user.openai_api_key:
            return jsonify({"error": "OpenAI API key not found"}), 500

        client = openai.OpenAI(api_key=user.openai_api_key)

        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt.strip()}],
            max_tokens=20
        )

        generated_alt_text = response.choices[0].message.content.strip()
        print(f"[DEBUG] Generated Alt Text: {generated_alt_text}")

        return jsonify({"alt_text": generated_alt_text})

    except Exception as e:
        print(f"[ERROR] OpenAI API Call Failed: {e}")
        return jsonify({"error": "Failed to generate alt text"}), 500




def update_alt_text(shop, product_id, alt_text):
    """Updates the alt text of the first image in Shopify."""
    try:
        print(f"[DEBUG] Updating Alt Text for Product ID: {product_id}")

        product = fetch_product_by_id(shop, product_id)
        if not product or not product.get('image_id'):
            print("[ERROR] No image found for product.")
            return

        image_id = product['image_id']

        mutation = f"""
        mutation {{
            productImageUpdate(input: {{
                id: "{image_id}",
                altText: "{alt_text}"
            }}) {{
                image {{
                    id
                    altText
                }}
                userErrors {{
                    field
                    message
                }}
            }}
        }}
        """

        headers = {
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
            "Content-Type": "application/json"
        }

        response = requests.post(f"{SHOPIFY_STORE_URL}/admin/api/2023-10/graphql.json",
                                 json={"query": mutation}, headers=headers)
        response_data = response.json()

        print(f"[DEBUG] Shopify Alt Text API Response: {json.dumps(response_data, indent=4)}")

        if response_data.get("data", {}).get("productImageUpdate", {}).get("userErrors"):
            print(f"[ERROR] Failed to update Alt Text: {response_data}")
        else:
            print("[SUCCESS] Alt Text updated successfully!")

    except Exception as e:
        print(f"[ERROR] Exception while updating Alt Text: {e}")


def ensure_metafield_exists(product_id, key, metafield_type):
    """Ensure a Shopify metafield exists before updating it."""
    query = f"""
    mutation {{
        metafieldDefinitionCreate(definition: {{
            name: "{key}",
            namespace: "global",
            key: "{key}",
            type: "{metafield_type}",
            ownerType: PRODUCT
        }}) {{
            createdDefinition {{
                id
            }}
            userErrors {{
                field
                message
            }}
        }}
    }}
    """

    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
    }

    response = requests.post(f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json",
                             json={"query": query}, headers=headers)
    result = response.json()

    print(f"[DEBUG] Ensure Metafield '{key}' Exists Response: {json.dumps(result, indent=4)}")

def send_shopify_request(query, variables):
    """Send a GraphQL request to Shopify with full debugging."""
    try:
        headers = {
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
            "Content-Type": "application/json"
        }
        response = requests.post(
            f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json",
            json={"query": query, "variables": variables},
            headers=headers
        )

        # ✅ Print full response details for debugging
        print("\n[DEBUG] --- Shopify Raw Response ---")
        print(f"Status Code: {response.status_code}")
        print("Response Text:", response.text)
        print("[DEBUG] --------------------------------\n")

        response_json = response.json()

        # ✅ Print formatted JSON response for Shopify errors
        print("\n[DEBUG] --- Shopify JSON Response ---")
        print(json.dumps(response_json, indent=4))
        print("[DEBUG] --------------------------------\n")

        return response_json

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Shopify API Request Failed: {e}")
        return None



def update_product_metafield(product_id, namespace, key, value, field_type="single_line_text_field"):
    """Update a metafield for a Shopify product with proper API handling."""
    try:
        print(f"[DEBUG] Updating metafield '{key}' for Product ID: {product_id} (Type: {field_type})")

        product_id_gid = f"gid://shopify/Product/{product_id}"

        mutation = """
        mutation metafieldUpdate($metafields: [MetafieldsSetInput!]!) {
            metafieldsSet(metafields: $metafields) {
                metafields {
                    id
                    value
                }
                userErrors {
                    field
                    message
                }
            }
        }
        """

        variables = {
            "metafields": [
                {
                    "ownerId": product_id_gid,
                    "namespace": namespace,
                    "key": key,
                    "type": field_type,  # ✅ Dynamically set the field type
                    "value": value
                }
            ]
        }

        headers = {
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
            "Content-Type": "application/json"
        }

        response = requests.post(
            f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json",  # ✅ Updated API version
            json={"query": mutation, "variables": variables},
            headers=headers
        )

        response_data = response.json()

        # ✅ Print response for debugging
        print(f"[DEBUG] Shopify Metafield Update Response: {json.dumps(response_data, indent=4)}")

        # ✅ Handle user errors
        user_errors = response_data.get("data", {}).get("metafieldsSet", {}).get("userErrors", [])
        if user_errors:
            print(f"[ERROR] Shopify API User Errors: {user_errors}")
            return {"error": user_errors[0]["message"], "details": user_errors}

        return {"success": f"Metafield '{key}' updated successfully!"}

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Shopify API Request Failed: {e}")
        return {"error": f"Request exception: {str(e)}"}

    except Exception as e:
        print(f"[ERROR] General Exception: {e}")
        return {"error": f"Unexpected error: {str(e)}"}

def update_image_alt_text(product_id, image_id, alt_text):
    """Update the alt text of a product image using Shopify's REST API."""
    try:
        print(f"[DEBUG] Updating Alt Text for Image ID: {image_id}")

        url = f"{SHOPIFY_STORE_URL}/admin/api/2023-10/products/{product_id}/images/{image_id}.json"

        headers = {
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
            "Content-Type": "application/json"
        }

        payload = {
            "image": {
                "id": image_id,
                "alt": alt_text
            }
        }

        response = requests.put(url, json=payload, headers=headers)
        response_data = response.json()

        if response.status_code != 200:
            print(f"[ERROR] Shopify API Error: {json.dumps(response_data, indent=4)}")
            return {"error": "Failed to update image alt text", "details": response_data}

        print(f"[DEBUG] Image Alt Text updated successfully: {response_data}")
        return response_data

    except Exception as e:
        print(f"[ERROR] Exception occurred while updating image alt text: {e}")
        return {"error": str(e)}


@app.route('/seo/save_alt_text/<product_id>', methods=['POST'])
def save_alt_text(product_id):
    """Save AI-generated alt text to Shopify product image."""
    try:
        data = request.get_json()
        alt_text = data.get("content", "").strip().replace('"', '').replace("'", "")

        if not alt_text:
            return jsonify({"error": "Alt text cannot be empty!"}), 400

        print(f"[DEBUG] Received request to save alt text for product ID: {product_id}")

        # ✅ Fetch product details to get image ID
        product = fetch_product_by_id(product_id)

        if not product:
            print(f"[ERROR] No product found for ID: {product_id}")
            return jsonify({"error": "Product not found!"}), 404

        # ✅ Extract image ID properly
        image_id = product.get("image_id")
        if not image_id:
            return jsonify({"error": "No images found for this product!"}), 400

        # ✅ Correct Shopify GraphQL Mutation Format
        mutation = """
        mutation productImageUpdate($input: ProductImageUpdateInput!) {
            productImageUpdate(input: $input) {
                image {
                    id
                    altText
                }
                userErrors {
                    field
                    message
                }
            }
        }
        """

        variables = {
            "input": {
                "id": image_id,
                "altText": alt_text
            }
        }

        headers = {
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
            "Content-Type": "application/json"
        }

        print(f"[DEBUG] Sending GraphQL Mutation to Shopify: {json.dumps(variables, indent=4)}")

        response = requests.post(
            f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json",
            json={"query": mutation, "variables": variables},
            headers=headers
        )

        response_json = response.json()
        print("[DEBUG] Shopify Response:", json.dumps(response_json, indent=2))

        # ✅ Check for errors in Shopify response
        user_errors = response_json.get("data", {}).get("productImageUpdate", {}).get("userErrors", [])
        if user_errors:
            return jsonify({"error": user_errors[0]["message"]}), 400

        return jsonify({"success": "Alt text updated successfully!"})

    except Exception as e:
        print(f"[ERROR] Exception while updating alt text: {e}")
        return jsonify({"error": f"Exception: {str(e)}"}), 500


@app.route('/seo/save_seo_title/<product_id>', methods=['POST'])
def save_seo_title(product_id):
    """Saves the AI-generated SEO Title into the correct Shopify SEO field (Search Engine Listing Title)."""
    try:
        data = request.get_json()
        seo_title = data.get("content", "").strip()

        if not seo_title:
            return jsonify({"error": "Cannot save empty SEO title"}), 400

        mutation = """
        mutation productUpdate($input: ProductInput!) {
            productUpdate(input: $input) {
                product {
                    id
                    seo {
                        title
                    }
                }
                userErrors {
                    field
                    message
                }
            }
        }
        """

        headers = {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
        }

        variables = {
            "input": {
                "id": f"gid://shopify/Product/{product_id}",
                "seo": {
                    "title": seo_title  # ✅ Now correctly saving into `seo.title`
                }
            }
        }

        print(f"[DEBUG] Sending request to Shopify: {json.dumps(variables, indent=4)}")

        response = requests.post(f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json",
                                 json={"query": mutation, "variables": variables}, headers=headers)

        response_data = response.json()
        print(f"[DEBUG] Shopify Response: {json.dumps(response_data, indent=4)}")

        user_errors = response_data.get("data", {}).get("productUpdate", {}).get("userErrors", [])
        if user_errors:
            return jsonify({"error": user_errors[0]["message"]}), 400

        return jsonify({"success": "SEO Title updated successfully!"})

    except Exception as e:
        print(f"[ERROR] Exception while updating SEO title: {e}")
        return jsonify({"error": f"Exception: {str(e)}"}), 500







@app.route('/seo/save_seo_description/<product_id>', methods=['POST'])
def save_seo_description(product_id):
    """Update the Shopify SEO description (search engine listing description)."""
    try:
        data = request.get_json()
        seo_description = data.get("content", "").strip()

        if not seo_description:
            return jsonify({"error": "SEO description cannot be empty!"}), 400

        # ✅ Shopify GraphQL mutation for updating `seo.description`
        mutation = """
        mutation updateProductSeo($input: ProductInput!) {
            productUpdate(input: $input) {
                product {
                    id
                    seo {
                        description
                    }
                }
                userErrors {
                    field
                    message
                }
            }
        }
        """

        payload = {
            "query": mutation,
            "variables": {
                "input": {
                    "id": f"gid://shopify/Product/{product_id}",
                    "seo": {"description": seo_description}
                }
            }
        }

        # ✅ Shopify API Request
        headers = {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
        }

        response = requests.post(
            f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json",
            json=payload, headers=headers
        )
        response_data = response.json()
        print(f"[DEBUG] Shopify Response: {json.dumps(response_data, indent=4)}")

        # ✅ Handle API errors
        user_errors = response_data.get("data", {}).get("productUpdate", {}).get("userErrors", [])
        if user_errors:
            return jsonify({"error": user_errors[0]["message"]}), 400

        return jsonify({"success": "SEO Description updated successfully!"})

    except Exception as e:
        print(f"[ERROR] Exception while updating SEO description: {e}")
        return jsonify({"error": f"Exception: {str(e)}"}), 500


@app.route('/seo/save_title/<product_id>', methods=['POST'])
def save_title(product_id):
    """Update the product title in Shopify."""
    try:
        data = request.get_json()
        new_title = data.get("content", "").strip()

        if not new_title:
            return jsonify({"error": "Product title cannot be empty!"}), 400

        mutation = """
        mutation updateProductTitle($input: ProductInput!) {
            productUpdate(input: $input) {
                product {
                    id
                    title
                }
                userErrors {
                    field
                    message
                }
            }
        }
        """

        payload = {
            "query": mutation,
            "variables": {
                "input": {
                    "id": f"gid://shopify/Product/{product_id}",
                    "title": new_title
                }
            }
        }

        headers = {
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
            "Content-Type": "application/json"
        }

        response = requests.post(f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json",
                                 json=payload, headers=headers)

        response_data = response.json()
        print(f"[DEBUG] Shopify Response: {json.dumps(response_data, indent=4)}")

        # ✅ Handle Shopify API errors
        user_errors = response_data.get("data", {}).get("productUpdate", {}).get("userErrors", [])
        if user_errors:
            return jsonify({"error": user_errors[0]["message"]}), 400

        return jsonify({"success": "Product title updated successfully!"})

    except Exception as e:
        print(f"[ERROR] Exception while updating product title: {e}")
        return jsonify({"error": f"Exception: {str(e)}"}), 500


@app.route('/seo/save_description/<product_id>', methods=['POST'])
def save_description(product_id):
    """Update the product description in Shopify."""
    try:
        data = request.get_json()
        new_description = data.get("content", "").strip()

        if not new_description:
            return jsonify({"error": "Product description cannot be empty!"}), 400

        mutation = """
        mutation updateProductDescription($input: ProductInput!) {
            productUpdate(input: $input) {
                product {
                    id
                    descriptionHtml
                }
                userErrors {
                    field
                    message
                }
            }
        }
        """

        payload = {
            "query": mutation,
            "variables": {
                "input": {
                    "id": f"gid://shopify/Product/{product_id}",
                    "descriptionHtml": new_description
                }
            }
        }

        headers = {
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
            "Content-Type": "application/json"
        }

        response = requests.post(f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json",
                                 json=payload, headers=headers)

        response_data = response.json()
        print(f"[DEBUG] Shopify Response: {json.dumps(response_data, indent=4)}")

        # ✅ Handle Shopify API errors
        user_errors = response_data.get("data", {}).get("productUpdate", {}).get("userErrors", [])
        if user_errors:
            return jsonify({"error": user_errors[0]["message"]}), 400

        return jsonify({"success": "Product description updated successfully!"})

    except Exception as e:
        print(f"[ERROR] Exception while updating product description: {e}")
        return jsonify({"error": f"Exception: {str(e)}"}), 500



@app.route('/seo/generate_all/<product_id>', methods=['POST'])
def generate_all(product_id):
    """Generates AI content for all SEO fields (title, description, SEO title, SEO description, alt text)."""
    try:
        product = fetch_product_by_id(product_id)

        if not product:
            return jsonify({"error": "Product not found"}), 404

        custom_prompt = session.get('custom_prompt', "Generate an optimized SEO title and description.")

        # ✅ Generate AI content for all fields
        product_title = generate_ai_content(f"{custom_prompt}\n\nProduct Title: {product.get('title', '')}")
        product_description = generate_ai_content(f"{custom_prompt}\n\nProduct Description: {product.get('descriptionHtml', '')}", max_tokens=150)
        seo_title = generate_ai_content(f"{custom_prompt}\n\nSEO Title: {product.get('title', '')}")
        seo_description = generate_ai_content(f"{custom_prompt}\n\nSEO Description: {product.get('descriptionHtml', '')}", max_tokens=160)
        alt_text = generate_ai_content(f"{custom_prompt}\n\nGenerate alt text for this image: {product.get('image_url', '')}")

        return jsonify({
            "product_title": product_title,
            "product_description": product_description,
            "seo_title": seo_title,
            "seo_description": seo_description,
            "alt_text": alt_text
        })

    except Exception as e:
        print(f"[ERROR] Failed to generate AI content: {e}")
        return jsonify({"error": "Failed to generate content"}), 500


@app.route('/seo/save_all/<product_id>', methods=['POST'])
def save_all(product_id):
    """Save AI-generated content for all fields to Shopify."""
    try:
        data = request.get_json()

        product_title = data.get("product_title", "").strip()
        product_description = data.get("product_description", "").strip()
        seo_title = data.get("seo_title", "").strip()
        seo_description = data.get("seo_description", "").strip()
        alt_text = data.get("alt_text", "").strip()

        print(f"[DEBUG] Saving AI content for Product ID: {product_id}")

        # ✅ Update Shopify Fields (Ensuring API Calls Work Correctly)
        if product_title:
            response = save_title(product_id, product_title)
            print(f"[DEBUG] Title Update Response: {response}")

        if product_description:
            response = save_description(product_id, product_description)
            print(f"[DEBUG] Description Update Response: {response}")

        if seo_title or seo_description:
            response = save_seo_details(product_id, seo_title, seo_description)
            print(f"[DEBUG] SEO Update Response: {response}")

        if alt_text:
            response = save_alt_text(product_id, alt_text)
            print(f"[DEBUG] Alt Text Update Response: {response}")

        return jsonify({"success": "All AI-generated content saved successfully!"})

    except Exception as e:
        print(f"[ERROR] Failed to save AI content: {e}")
        return jsonify({"error": "Failed to save content"}), 500





if __name__ == "__main__":
        app.run(debug=True)
