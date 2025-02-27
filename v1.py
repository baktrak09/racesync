import openai
import os
import json
import re
import time
import requests
import urllib.parse
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Blueprint
from dotenv import load_dotenv, dotenv_values
from openai import OpenAI
from flask_session import Session
import cProfile
from ftplib import FTP
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import time
import pandas as pd
import random
import math
import threading
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

# ✅ Flask Setup
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"  # SQLite for now, switch to PostgreSQL/MySQL later if needed
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "your_secret_key_here"  # Needed for session security
db = SQLAlchemy(app)

# ✅ User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Store hashed password!

# ✅ Set Up Login Manager
login_manager = LoginManager(app)
login_manager.login_view = "login"  # Redirect to login if not logged in

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ✅ Create DB Tables (Only Runs When Needed)
with app.app_context():
    db.create_all()

# ✅ Flask Session Configuration
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(os.getcwd(), "flask_session")
app.config["SESSION_FILE_THRESHOLD"] = 500
Session(app)



# ✅ Load environment variables
load_dotenv()

env_vars = dotenv_values(".env")


# ✅ Get Shopify credentials
SHOPIFY_STORE_URL = os.getenv("SHOPIFY_STORE_URL", "").strip()
SHOPIFY_ACCESS_TOKEN = os.getenv("SHOPIFY_ACCESS_TOKEN", "").strip()
API_VERSION = "2024-01"  # Use the latest Shopify API version
SHOPIFY_STORE = SHOPIFY_STORE_URL  # Ensure consistency
ACCESS_TOKEN = SHOPIFY_ACCESS_TOKEN
SHOP_URL = os.getenv('SHOP_URL')
ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
API_VERSION = os.getenv('API_VERSION')
FTP_HOST = os.getenv('FTP_HOST')
FTP_USER = os.getenv('FTP_USER')
FTP_PASS = os.getenv('FTP_PASS')
SHOPIFY_DOMAIN = os.getenv('SHOPIFY_DOMAIN')
SHOPIFY_ACCESS_TOKEN = os.getenv('SHOPIFY_ACCESS_TOKEN')
CSV_FILENAME = "Motorstate1.csv"

# Print to verify environment variables
print(f"SHOP_URL: {SHOP_URL}")
print(f"ACCESS_TOKEN: {ACCESS_TOKEN}")
print(f"API_VERSION: {API_VERSION}")
print(f"FTP_HOST: {FTP_HOST}")
print(f"FTP_USER: {FTP_USER}")
print(f"SHOPIFY_DOMAIN: {SHOPIFY_DOMAIN}")
print(f"SHOPIFY_ACCESS_TOKEN: {SHOPIFY_ACCESS_TOKEN}")
# 🔍 Debugging Output
print("[DEBUG] Final Shopify Store URL:", SHOPIFY_STORE_URL)
print("[DEBUG] Registered Routes:", app.url_map)


# ✅ Ensure SHOPIFY_STORE_URL is properly formatted
if SHOPIFY_STORE_URL and not SHOPIFY_STORE_URL.startswith("https://"):
    SHOPIFY_STORE_URL = "https://" + SHOPIFY_STORE_URL.lstrip("/")

SHOPIFY_GRAPHQL_URL = f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json"

# ✅ Ensure access token exists
if not SHOPIFY_ACCESS_TOKEN:
    raise ValueError("🚨 SHOPIFY_ACCESS_TOKEN is missing! Check your .env file.")

# ✅ Shopify API Headers (used across all functions)
SHOPIFY_HEADERS = {
    "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
    "Content-Type": "application/json"
}

def safe_request(url, method='get', **kwargs):
    max_retries = 10
    backoff_factor = 2
    jitter = 0.1  # Jitter percentage
    retry_wait = 1  # Initial wait time for rate limit

    for attempt in range(max_retries):
        try:
            response = requests.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:  # Rate limit exceeded
                retry_after = response.headers.get("Retry-After", retry_wait)
                try:
                    retry_after = float(retry_after)
                except ValueError:
                    retry_after = retry_wait
                # Add jitter to the retry wait time
                jitter_value = random.uniform(1 - jitter, 1 + jitter)
                retry_after *= jitter_value
                print(f"Rate limit hit, retrying after {retry_after:.2f} seconds...")
                time.sleep(retry_after)
                retry_wait *= backoff_factor  # Increase the wait time for the next retry
            elif attempt < max_retries - 1:
                retry_wait = 2 ** attempt
                jitter_value = random.uniform(1 - jitter, 1 + jitter)
                retry_wait *= jitter_value
                print(f"Request failed, retrying in {retry_wait:.2f} seconds...")
                time.sleep(retry_wait)
            else:
                raise
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                retry_wait = 2 ** attempt
                jitter_value = random.uniform(1 - jitter, 1 + jitter)
                retry_wait *= jitter_value
                print(f"Request failed, retrying in {retry_wait:.2f} seconds...")
                time.sleep(retry_wait)
            else:
                raise

# ✅ Cache Setup
CACHE_FILE = "shopify_cache.json"

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

def fetch_with_rate_limit(url):
    """Handle Shopify API rate limits."""
    retries = 0
    while retries < MAX_RETRIES:
        response = requests.get(url, headers=SHOPIFY_HEADERS)
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", "2"))
            print(f"[WARNING] Shopify rate limit hit. Retrying in {retry_after} seconds...")
            time.sleep(retry_after)
            retries += 1
        elif response.status_code == 200:
            return response.json(), response.headers
        else:
            print(f"[ERROR] Shopify request failed: {response.status_code} - {response.text}")
            return None, None
    print("[ERROR] Max retries reached. API request failed.")
    return None, None

def fetch_all_product_types():
    """Fetch all product types from Shopify API."""
    product_types = set()
    url = f"{SHOPIFY_STORE_URL}/admin/api/2023-10/products.json?limit=250&fields=product_type"

    while url:
        data, headers = fetch_with_rate_limit(url)
        if not data:
            return []

        for product in data.get("products", []):
            product_types.add(product.get("product_type", "UNKNOWN_PRODUCT_TYPE"))

        url = None
        if headers and "Link" in headers:
            for link in headers["Link"].split(", "):
                if 'rel="next"' in link:
                    url = link.split("; ")[0].strip("<>")

    return sorted(product_types)

def fetch_product_by_id(product_id):
    """Fetch a product's details from Shopify API."""
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
    response = requests.post(SHOPIFY_GRAPHQL_URL, json={"query": query}, headers=SHOPIFY_HEADERS)
    response_json = response.json()

    product_data = response_json.get('data', {}).get('product', {})
    if not product_data:
        print(f"[ERROR] No product data found for ID {product_id}")
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

def fetch_metafield(product_id, key):
    """Fetch a specific metafield from Shopify API."""
    metafield_query = f"""
    {{
        product(id: "gid://shopify/Product/{product_id}") {{
            metafield(namespace: "global", key: "{key}") {{ value }}
        }}
    }}
    """
    response = requests.post(SHOPIFY_GRAPHQL_URL, json={"query": metafield_query}, headers=SHOPIFY_HEADERS)
    response_json = response.json()
    metafield = response_json.get('data', {}).get('product', {}).get('metafield')

    return metafield.get('value', "") if metafield else ""

# ✅ OpenAI Setup
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
openai_client = OpenAI(api_key=OPENAI_API_KEY)



@app.route('/')
def redirect_to_inventory():
    return redirect(url_for('index'))  # Redirect to /inventory/



@app.route('/inventory/')
def index():
    location_id = get_shopify_location_id()
    shopify_skus = {}
    return render_template('index.html', location_id=location_id, shopify_skus=shopify_skus, segment='index')

@app.route('/inventory/api/shopify-skus')
def get_shopify_skus_api():
    try:
        shopify_skus = fetch_shopify_skus_concurrent()
        return jsonify(shopify_skus)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_shopify_location_id():
    """Fetch the first location ID from Shopify."""
    url = f"{SHOPIFY_STORE_URL}/admin/api/{API_VERSION}/locations.json"
    headers = {"X-Shopify-Access-Token": ACCESS_TOKEN}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        locations = response.json().get("locations", [])
        location_id = locations[0]["id"] if locations else None
        print(f"Location ID fetched: {location_id}")
        return location_id
    except Exception as e:
        print(f"Failed to fetch location ID: {str(e)}")
        return None

def fetch_shopify_skus_concurrent():
    print("Starting concurrent fetch of Shopify SKUs...")
    shopify_skus = {}
    headers = {"X-Shopify-Access-Token": ACCESS_TOKEN}
    page_info = None
    products_fetched = 0
    pages_fetched = 0

    def fetch_url(url):
        try:
            print(f"Fetching URL: {url}")
            response = safe_request(url, method='get', headers=headers)
            data = response.json()
            print(f"Successfully fetched URL: {url}")
            return data["products"], response.headers.get("Link", "")
        except Exception as e:
            print(f"Error fetching URL: {url} - {str(e)}")
            return [], ""

    with ThreadPoolExecutor(max_workers=10) as executor:  # Adjust number of workers based on system resources
        futures = []
        next_page = True

        while next_page:
            url = f"{SHOP_URL}/admin/api/{API_VERSION}/products.json?fields=id,variants&limit=250"
            if page_info:
                url += f"&page_info={page_info}"

            # Submit the fetch job to the executor
            future = executor.submit(fetch_url, url)
            futures.append(future)

            for future in as_completed(futures):
                products, links = future.result()
                products_fetched += len(products)
                pages_fetched += 1
                print(f"Processed page {pages_fetched}, fetched {len(products)} products.")

                for product in products:
                    for variant in product["variants"]:
                        if variant["sku"]:
                            shopify_skus[variant["sku"]] = {
                                "product_id": product["id"],
                                "variant_id": variant["id"],
                                "inventory_item_id": variant["inventory_item_id"]
                            }
                
                # Process the `Link` header for pagination
                if links:
                    next_page_link = next((link for link in links.split(", ") if 'rel="next"' in link), None)
                    if next_page_link:
                        page_info = next_page_link[next_page_link.find("<")+1:next_page_link.find(">")]
                        print(f"Next page info: {page_info}")
                    else:
                        next_page = False
                        print("No more pages to fetch. Exiting loop.")
                else:
                    next_page = False
                    print("No `Link` header found. Exiting loop.")

            time.sleep(1)  # Shorter delay

    print(f"Finished fetching SKUs. Total pages fetched: {pages_fetched}. Total SKUs fetched: {len(shopify_skus)} ({products_fetched} products processed).")
    return shopify_skus


@app.route('/inventory/api/shopify-products', methods=['POST'])
def get_shopify_products():
    shopify_domain = os.getenv('SHOPIFY_DOMAIN')
    access_token = os.getenv('SHOPIFY_ACCESS_TOKEN')
    api_version = os.getenv('API_VERSION')

    if not shopify_domain or not access_token or not api_version:
        return jsonify({'error': 'Missing Shopify configuration'}), 500

    shopify_url = f'https://{shopify_domain}/api/{api_version}/graphql.json'
    headers = {'X-Shopify-Storefront-Access-Token': access_token}
    graphql_query = request.json.get('query')

    try:
        response = requests.post(shopify_url, json={"query": graphql_query}, headers=headers)
        response.raise_for_status()
        products = response.json()
        return jsonify(products)
    except requests.exceptions.RequestException as e:
        print(f'Error fetching Shopify products: {e}')
        return jsonify({'error': 'Failed to fetch products from Shopify'}), 500

@app.route('/inventory/download_csv', methods=['POST'])
def handle_download_csv():
    """Endpoint to initiate CSV download from FTP and respond with status."""
    print("Attempting to download CSV from FTP...")
    try:
        if download_csv_from_ftp():
            print("CSV downloaded successfully.")
            return jsonify({"status": "success", "message": "CSV downloaded successfully"})
        else:
            print("CSV not found on FTP server.")
            return jsonify({"status": "error", "message": "CSV not found on FTP server"}), 404
    except Exception as e:
        print(f"Failed to download CSV: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

def download_csv_from_ftp():
    """Download CSV inventory file from FTP server using FTP credentials from environment variables."""
    print("Connecting to FTP server...")
    try:
        with FTP(FTP_HOST) as ftp:
            ftp.login(FTP_USER, FTP_PASS)
            print("Logged in successfully, checking for the CSV file...")
            if CSV_FILENAME in ftp.nlst():
                with open(CSV_FILENAME, "wb") as file:
                    ftp.retrbinary(f"RETR {CSV_FILENAME}", file.write)
                print(f"{CSV_FILENAME} downloaded successfully.")
                return True
            else:
                print(f"{CSV_FILENAME} not found on FTP server.")
                return False
    except Exception as e:
        print(f"Failed to connect or download from FTP: {e}")
        

def load_csv():
    """Load and preprocess CSV data, adjusting vendor names and SKUs as needed."""
    csv_path = CSV_FILENAME
    if os.path.exists(csv_path):
        try:
            df = pd.read_csv(csv_path, encoding="ISO-8859-1", on_bad_lines='skip')  # Skip bad lines
            df['Brand'] = df['Brand'].replace({
                'MAHLE ORIGINAL/CLEVITE': 'Mahle Motorsport',
                'MAHLE PISTONS': 'Mahle Motorsport',
                'STRANGE': 'Strange Engineering',
                'STRANGE OVAL': 'Strange Engineering'
            })
            df['Shopify_SKU'] = df['Brand'].str.title() + ' - ' + df['ManufacturerPart']
            print("CSV loaded and formatted successfully.")
            return df
        except Exception as e:
            print(f"Error loading CSV: {str(e)}")
            return None
    else:
        print(f"{csv_path} not found after supposed download.")
        return None

def update_inventory_and_pricing(product_id, variant_id, inventory_item_id, quantity, suggested_retail, cost, map_price, location_id):
    try:
        # Update Inventory
        print(f"Updating inventory for Product ID {product_id}, Variant ID {variant_id}")
        inventory_payload = {
            "location_id": location_id,
            "inventory_item_id": inventory_item_id,
            "available": quantity
        }
        inventory_url = f"{SHOP_URL}/admin/api/{API_VERSION}/inventory_levels/set.json"
        safe_request(inventory_url, method='post', json=inventory_payload, headers={
            "X-Shopify-Access-Token": ACCESS_TOKEN,
            "Content-Type": "application/json"
        })
        print("Inventory updated successfully.")

        # Update Pricing
        print(f"Updating pricing for Variant ID {variant_id}")
        pricing_payload = {
            "variant": {
                "id": variant_id,
                "price": suggested_retail,
                "compare_at_price": map_price if pd.notna(map_price) else suggested_retail
            }
        }
        pricing_url = f"{SHOP_URL}/admin/api/{API_VERSION}/variants/{variant_id}.json"
        safe_request(pricing_url, method='put', json=pricing_payload, headers={
            "X-Shopify-Access-Token": ACCESS_TOKEN,
            "Content-Type": "application/json"
        })
        print("Pricing updated successfully.")
    except requests.exceptions.HTTPError as e:
        print(f"Failed to update due to HTTP Error: {e.response.text}")
        raise
    except Exception as e:
        print(f"General Error: {str(e)}")
        raise

def bulk_update_inventory(df, shopify_skus, location_id):
    matched_count = 0
    total_skus = len(shopify_skus)
    with ThreadPoolExecutor(max_workers=3) as executor:  # Reduce number of concurrent workers
        futures = []
        for index, row in df.iterrows():
            sku_data = shopify_skus.get(row['Shopify_SKU'])
            if sku_data:
                matched_count += 1
                future = executor.submit(update_inventory_and_pricing, sku_data['product_id'], sku_data['variant_id'], sku_data['inventory_item_id'], row['QtyAvail'], row['SuggestedRetail'], row['Cost'], row['MapPrice'], location_id)
                futures.append(future)
            if index % 100 == 0:  # Log progress every 100 rows
                print(f"Processed {index + 1}/{len(df)} rows.")
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Error updating SKU: {e}")

    print(f"✅ Matched {matched_count} out of {total_skus} SKUs from Shopify with the CSV data.")
    return matched_count, total_skus



@app.route('/inventory/trigger_update', methods=['POST'])
def trigger_update():
    print("Triggering the inventory and pricing update process...")
    try:
        profiler = cProfile.Profile()
        profiler.enable()
        
        if not download_csv_from_ftp():
            return jsonify({"status": "error", "message": "Failed to download CSV file from FTP server."}), 500

        print("CSV downloaded successfully, proceeding with updates...")
        location_id = get_shopify_location_id()
        if not location_id:
            return jsonify({"status": "error", "message": "Failed to fetch location ID from Shopify."}), 500

        print("Fetching SKUs from Shopify...")
        shopify_skus = fetch_shopify_skus_concurrent()
        if not shopify_skus:
            return jsonify({"status": "error", "message": "Failed to fetch SKUs from Shopify."}), 500
        print(f"Fetched {len(shopify_skus)} SKUs from Shopify.")

        df = load_csv()
        if df is None:
            return jsonify({"status": "error", "message": "CSV data could not be loaded."}), 500

        print("Starting bulk update of inventory and pricing...")
        matched_count, total_skus = bulk_update_inventory(df, shopify_skus, location_id)
        print(f"Completed bulk update. Matched {matched_count} SKUs out of {total_skus}.")

        profiler.disable()
        profiler.print_stats(sort='time')

        return jsonify({"status": "success", "message": "Inventory and pricing updated successfully!", "matched_count": matched_count, "total_skus": total_skus})
    except Exception as e:
        print(f"An error occurred: {str(e)}")
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
        shopify_domain = os.getenv('SHOPIFY_DOMAIN')
        access_token = os.getenv('SHOPIFY_ACCESS_TOKEN')
        api_version = os.getenv('API_VERSION')

        if not shopify_domain or not access_token or not api_version:
            raise ValueError("Missing environment variables")

        shopify_url = f"https://{shopify_domain}/admin/api/{api_version}/products.json"
        headers = {"X-Shopify-Access-Token": access_token}

        response = requests.get(shopify_url, headers=headers)
        response.raise_for_status()
        return jsonify(response.json())
    except Exception as e:
        print(f"Error in get_products: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

def fetch_vendor_list():
    """
    Fetches a list of all vendors from Shopify.
    """
    url = f"{SHOP_URL}/admin/api/{API_VERSION}/products.json?fields=vendor&limit=250"
    headers = {"X-Shopify-Access-Token": ACCESS_TOKEN}
    vendors = set()  # Use a set to avoid duplicate vendors

    try:
        page_info = None
        while True:
            page_url = f"{url}&page_info={page_info}" if page_info else url
            response = requests.get(page_url, headers=headers)
            response.raise_for_status()
            data = response.json()
            vendors.update({product['vendor'] for product in data['products'] if product.get('vendor')})

            links = response.headers.get("Link", "")
            page_info = None
            for link in links.split(','):
                if 'rel="next"' in link:
                    page_info = link.split(';')[0].strip('<>')
                    break

            if not page_info:
                break

    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch vendors: {str(e)}")
        return []

    return list(vendors)  # Convert set to list to make it JSON serializable


@app.route('/inventory/get_vendors')
def get_vendors():
    # Assuming you have a function that gets vendor data
    vendors = fetch_vendor_list()  # You need to define this function
    return jsonify(vendors)


def fetch_and_save_vendors():
    url = f"{SHOP_URL}/admin/api/{API_VERSION}/vendors.json"
    headers = {"X-Shopify-Access-Token": ACCESS_TOKEN}
    response = requests.get(url, headers=headers)
    vendors = response.json().get('vendors', [])
    with open('vendors.json', 'w') as f:
        json.dump(vendors, f)
    return vendors

@app.route('/inventory/update_by_vendor', methods=['POST'])
def update_by_vendor():
    data = request.get_json()
    selected_vendors = data.get('vendors', [])
    df = load_csv()  # Load your CSV containing product data
    if df is not None:
        df_filtered = df[df['Brand'].isin(selected_vendors)]
        location_id = get_shopify_location_id()
        if location_id:
            shopify_skus = fetch_all_shopify_skus()
            bulk_update_inventory(df_filtered, shopify_skus, location_id)
            return jsonify({"status": "success", "message": "Inventory updated for selected vendors!"})
        else:
            return jsonify({"status": "error", "message": "Location ID could not be fetched."})
    return jsonify({"status": "error", "message": "CSV data could not be loaded."})

@app.route('/inventory/api/get-skus')
def api_get_skus():
    shopify_skus = fetch_all_shopify_skus()
    return jsonify(shopify_skus)

@app.route('/inventory/process_inventory_update', methods=['POST'])
def process_inventory_update():
    try:
        # Download CSV from FTP
        if not download_csv_from_ftp():
            raise Exception("Failed to download CSV from FTP server.")

        # Load CSV data
        df = load_csv()
        if df is None:
            raise Exception("Failed to load data from CSV.")

        # Fetch Shopify SKUs
        shopify_skus = fetch_all_shopify_skus()
        if not shopify_skus:
            raise Exception("Failed to fetch SKUs from Shopify.")

        # Get location ID
        location_id = get_shopify_location_id()
        if not location_id:
            raise Exception("Failed to fetch Shopify location ID.")

        # Perform inventory update
        bulk_update_inventory(df, shopify_skus, location_id)
        
        return jsonify({"status": "success", "message": "Inventory and pricing updated successfully!"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500




@app.route('/seo/api/product_details/<product_id>')
def product_details_api(product_id):
    print(f"[DEBUG] API call to fetch details for product ID: {product_id}")
    product = fetch_product_by_id(product_id)

    if not product:
        print(f"[ERROR] Product not found for ID: {product_id}")
        return jsonify({"error": "Product data not found or invalid response from Shopify."}), 404

    return jsonify(product)
    


# ✅ Fetch Collection ID (Supports Both Custom & Smart Collections)
def get_collection_id_by_name(collection_name):
    """Fetch collection ID by name (supports both Custom & Smart Collections)."""
    try:
        headers = {"X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN, "Content-Type": "application/json"}
        
        # ✅ Fetch Custom Collections
        url = f"{SHOPIFY_STORE_URL}/admin/api/2023-10/custom_collections.json?limit=250"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        collections = response.json().get("custom_collections", [])
        for collection in collections:
            if collection["title"].lower() == collection_name.lower():
                return collection["id"]

        # ✅ Fetch Smart Collections
        url = f"{SHOPIFY_STORE_URL}/admin/api/2023-10/smart_collections.json?limit=250"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        collections = response.json().get("smart_collections", [])
        for collection in collections:
            if collection["title"].lower() == collection_name.lower():
                return collection["id"]

        return None  # Collection not found

    except Exception as e:
        print(f"[ERROR] Failed to fetch collection ID: {e}")
        return None


def fetch_products_from_api(limit=50, product_type=None, vendor=None, collection_name=None, sort_by="title", page_info=None):
    print("[DEBUG] Fetching products with the following parameters:")
    print(f"  Limit: {limit}, Product Type: {product_type}, Vendor: {vendor}, Collection: {collection_name}, Sort By: {sort_by}, Page Info: {page_info}")

    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
    }

    # ✅ Handle Collection Filtering
    collection_id = None
    if collection_name:
        collection_id = get_collection_id_by_name(collection_name)

    # ✅ Base URL setup
    if collection_id:
        url = f"{SHOPIFY_STORE_URL}/admin/api/2023-10/collections/{collection_id}/products.json?limit={limit}"
    else:
        url = f"{SHOPIFY_STORE_URL}/admin/api/2023-10/products.json?limit={limit}"

    # ✅ Shopify Pagination Handling
    if page_info:
        url = f"{SHOPIFY_STORE_URL}/admin/api/2023-10/products.json?limit={limit}&page_info={page_info}"  # No sorting when paginating
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
            print(f"[ERROR] Failed to fetch products: {e}")
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

def fetch_product_types():
    """Fetch all unique product types from Shopify and update the cache with rate limit handling."""
    try:
        product_types = set()
        url = f"{SHOPIFY_STORE_URL}/admin/api/2023-10/products.json?limit=250&fields=product_type"
        headers = {"X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN, "Content-Type": "application/json"}

        while url:
            response = requests.get(url, headers=headers)

            # Handle rate limiting (429 error)
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "2")  # Default to 2 if missing
                try:
                    retry_after = max(1, int(float(retry_after)))  # Ensure at least 1 second
                except ValueError:
                    retry_after = 2  # Default to 2 if conversion fails

                print(f"[WARNING] Shopify API rate limit hit (product types). Retrying after {retry_after} seconds...")
                time.sleep(retry_after)
                continue  # Retry request

            response.raise_for_status()
            data = response.json()

            for product in data.get("products", []):
                if product.get("product_type"):
                    product_types.add(product["product_type"])

            url = None
            link_header = response.headers.get("Link")
            if link_header:
                for link in link_header.split(","):
                    if 'rel="next"' in link:
                        url = link.split(";")[0].strip("<> ")

        print(f"[DEBUG] Final Product Types Retrieved: {sorted(product_types)}")
        return sorted(product_types)

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch product types: {e}")
        return []


def fetch_vendors():
    """Fetch all unique vendors from Shopify and update the cache with rate limit handling."""
    try:
        vendors = set()
        url = f"{SHOPIFY_STORE_URL}/admin/api/2023-10/products.json?limit=250&fields=vendor"
        headers = {"X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN, "Content-Type": "application/json"}

        while url:
            response = requests.get(url, headers=headers)

            # Handle rate limiting (429 error)
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "2")  # Default to 2 if missing
                try:
                    retry_after = max(1, int(float(retry_after)))  # Ensure at least 1 second
                except ValueError:
                    retry_after = 2  # Default to 2 if conversion fails

                print(f"[WARNING] Shopify API rate limit hit (vendors). Retrying after {retry_after} seconds...")
                time.sleep(retry_after)
                continue  # Retry request

            response.raise_for_status()
            data = response.json()

            for product in data.get("products", []):
                vendor_name = product.get("vendor", "").strip()
                if vendor_name:
                    vendors.add(vendor_name)

            url = None
            link_header = response.headers.get("Link")
            if link_header:
                for link in link_header.split(","):
                    if 'rel="next"' in link:
                        url = link.split(";")[0].strip("<> ")

        print(f"[DEBUG] Final Vendors Retrieved: {sorted(vendors)}")
        return sorted(vendors)

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch vendors: {e}")
        return []

def fetch_collections():
    """Fetch all custom and smart collections from Shopify with retry logic for rate limits and pagination."""
    try:
        headers = {"X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN, "Content-Type": "application/json"}
        collections = set()  # Store unique collections

        for endpoint in ["custom_collections", "smart_collections"]:
            url = f"{SHOPIFY_STORE_URL}/admin/api/2023-10/{endpoint}.json?limit=250"

            while url:
                print(f"[DEBUG] Fetching collections from: {url}")

                response = requests.get(url, headers=headers)

                # ✅ Handle Rate Limiting (429 Error)
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After", "2")  # Default to 2 if missing
                    try:
                        retry_after = float(retry_after)
                        retry_after = max(1, int(retry_after))  # Ensure at least 1 second
                    except ValueError:
                        retry_after = 2  # Default to 2 if conversion fails

                    print(f"[WARNING] Shopify API rate limit hit. Retrying after {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue  # Retry the request

                response.raise_for_status()  # Raise an error if request fails
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
        print(f"[DEBUG] Final Collections Retrieved: {sorted_collections}")
        return sorted_collections

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch collections: {e}")
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
    print("[INFO] Updating Shopify data...")

    # Fetch fresh data from Shopify
    fresh_product_types = fetch_product_types()
    fresh_vendors = fetch_vendors()
    fresh_collections = fetch_collections()

    # Update cache
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
        print(f"[INFO] Updating SEO for Product ID: {product_id}")

        meta_title = request.form.get("meta_title", "").strip()
        meta_description = request.form.get("meta_description", "").strip()
        alt_text = request.form.get("alt_text", "").strip()

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

        headers = {
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
            "Content-Type": "application/json"
        }

        response = requests.post(f"{SHOPIFY_STORE_URL}/admin/api/2023-10/graphql.json",
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
            update_alt_text(product_id, alt_text)

        return redirect(url_for('seo.product_details', product_id=product_id))

    except Exception as e:
        print(f"[ERROR] Exception while updating SEO: {e}")
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
    print(f"[DEBUG] Rendering product details for ID: {product_id}")

    product_data = fetch_product_by_id(product_id)  
    print(f"[DEBUG] Final Processed Product Data: {product_data}")  

    if not product_data:
        return "Product not found", 404

    product = product_data

    if not isinstance(product, dict):
        print("[ERROR] Unexpected product data type:", type(product))
        return "Product data error", 500

    meta_title = product.get("meta_title") or product.get("title", "").strip()
    meta_description = product.get("meta_description") or product.get("descriptionHtml", "").strip()
    image_url = product.get("image_url", "")

    # ✅ Get filters from request args (if any)
    filters = request.args.to_dict()

    return render_template(
        "product_details.html",
        product=product,
        meta_title=meta_title,
        meta_description=meta_description,
        image_url=image_url,
        filters=filters,  # ✅ Pass filters so Jinja knows what it is
        segment="product_details"
    )


def generate_ai_content(prompt, max_tokens=50):
    """Generates AI-generated content based on the given prompt using OpenAI's new API format."""
    try:
        client = openai.OpenAI()  # ✅ Create an OpenAI client

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
    product = fetch_product_by_id(product_id)
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

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt.strip()}],
            max_tokens=50
        )
        generated_title = response.choices[0].message.content.strip()

        # ✅ **Remove unwanted quotes** if the AI still adds them
        generated_title = generated_title.strip('"').strip("'")

        print(f"[DEBUG] Cleaned Generated Title: {generated_title}")

        return jsonify({"product_title": generated_title})

    except Exception as e:
        print(f"[ERROR] OpenAI API Call Failed: {e}")
        return jsonify({"error": "Failed to generate title"}), 500



@app.route('/seo/generate_description/<product_id>', methods=['POST'])
def generate_description(product_id):
    """Generate an AI-optimized product description with custom prompt integration."""
    product = fetch_product_by_id(product_id)

    if not product:
        return jsonify({"error": "Product not found"}), 404

    # ✅ Extract and sanitize product data
    title = product.get("title", "").strip()
    vendor = product.get("vendor", "").strip()
    product_type = product.get("productType", "").strip()
    description = product.get("descriptionHtml", "").strip()

    # ✅ Ensure vendor is valid and use fallback if needed
    if not vendor or vendor.lower() in ["not provided", "unknown vendor", "n/a"]:
        print("[WARNING] Vendor missing. Using fallback from cached vendors.")
        cached_vendors = get_cached_vendors()
        vendor = cached_vendors[0] if cached_vendors else "Unknown Vendor"

    print(f"[DEBUG] Final Vendor Used in Prompt: '{vendor}'")

    # ✅ Retrieve user custom prompt, if available
    custom_prompt = session.get("custom_prompt", "").strip()

    # ✅ Build AI prompt (merging strict rules with custom flair)
    prompt = f"""
    {custom_prompt if custom_prompt else "Write a clear, natural product description with a direct, no-fluff style."}

    **STRICT RULES:**
    - **NO vague marketing phrases** (e.g., "boost performance," "brings an edge," "enhances ride").
    - **NO filler words** like "constructed from" or "designed for maximum efficiency."
    - **DO NOT assume fitment unless explicitly listed.**
    - **DO NOT change the vendor name** `{vendor}` – It must appear exactly as provided.
    - **DO NOT add or assume a different brand name.**
    - If a vendor is provided, **mention it naturally at least once.**
    - Ensure technical accuracy while maintaining an engaging style.

    **Product details:**
    - **Name:** {title}
    - **Vendor:** {vendor}
    - **Type:** {product_type if product_type else "Not Specified"}
    - **Current Description:** {description if description else "No description available."}

    **Ensure the vendor name "{vendor}" appears naturally in the description.**
    **Stick to the details provided. Do not add or assume extra information.**
    """

    print(f"[DEBUG] OpenAI Prompt for Description:\n{prompt.strip()}")

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt.strip()}],
            max_tokens=600  # ✅ Adjusted for better length control
        )

        generated_description = response.choices[0].message.content.strip()
        print(f"[DEBUG] Generated Description: {generated_description}")

        return jsonify({"product_description": generated_description})

    except Exception as e:
        print(f"[ERROR] OpenAI API Call Failed: {e}")
        return jsonify({"error": "Failed to generate description"}), 500





@app.route('/seo/generate_seo_title/<product_id>', methods=['POST'])
def generate_seo_title(product_id):
    """Generate a highly optimized, clear, and concise SEO product title."""
    product = fetch_product_by_id(product_id)

    if not product:
        return jsonify({"error": "Product not found"}), 404

    # ✅ Ensure variables exist
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
    
    **Example Titles:**
    - "Yukon 3.42 Ring & Pinion Set for GM 8.5" Axle"
    - "GM 7.5 28-Spline 30.31" Axle Shaft - Ten Factory"
    - "Chevy 12-Bolt 4.11 Ring & Pinion - Richmond Gear"
    """

    print(f"[DEBUG] OpenAI Prompt for SEO Title:\n{prompt.strip()}")

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt.strip()}],
            max_tokens=50
        )

        generated_title = response.choices[0].message.content.strip()

        # ✅ **Remove unwanted quotes** if AI still adds them
        generated_title = generated_title.strip('"').strip("'")

        print(f"[DEBUG] Cleaned Generated SEO Title: {generated_title}")

        return jsonify({"seo_title": generated_title})

    except Exception as e:
        print(f"[ERROR] OpenAI API Call Failed: {e}")
        return jsonify({"error": "Failed to generate SEO title"}), 500




@app.route('/seo/generate_seo_description/<product_id>', methods=['POST'])
def generate_seo_description(product_id):
    """Generate a **concise, clear, SEO-optimized product meta description (150-160 characters)."""
    product = fetch_product_by_id(product_id)

    if not product:
        return jsonify({"error": "Product not found"}), 404

    # ✅ Ensure essential data exists
    title = product.get("title", "").strip()
    vendor = product.get("vendor", "").strip()
    product_type = product.get("productType", "").strip()
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
        response = openai_client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt.strip()}],
            max_tokens=180  # 🚀 Forces the AI to keep it **concise and complete**
        )

        generated_description = response.choices[0].message.content.strip()

        # ✅ Remove unnecessary punctuation or formatting issues
        generated_description = generated_description.strip('"').strip("'").strip()

        # ✅ Ensure the AI doesn’t generate an incomplete sentence
        if len(generated_description) > 180:
            last_full_stop = generated_description[:180].rfind(".")
            if last_full_stop != -1:
                generated_description = generated_description[:last_full_stop]  # Cut at last full stop
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
    # ✅ Ensure only the numeric ID is used
    clean_current_id = current_product_id.replace("gid://shopify/Product/", "").strip()

    # ✅ Fetch filters from request
    filters = {
        'product_type': request.args.get('product_type'),
        'vendor': request.args.get('vendor'),
        'collection_name': request.args.get('collection_name'),
        'sort_by': request.args.get('sort_by'),
    }

    print(f"[DEBUG] Cleaned Current Product ID: {clean_current_id}")

    # ✅ Load products from session cache (instead of always refetching)
    products = session.get("cached_products", [])

    if not products:
        print("[ERROR] No products found in session cache! Re-fetching...")
        products, next_page_url, _ = fetch_products_from_api(**filters)
        session["cached_products"] = products  # ✅ Store for future use

    # ✅ Convert all product IDs to strings for correct matching
    all_product_ids = [str(p['id']) for p in products]
    print(f"[DEBUG] Available Product IDs: {all_product_ids}")

    # ✅ Find current product in list
    current_index = next((index for index, p in enumerate(products) if str(p['id']) == clean_current_id), None)

    print(f"[DEBUG] Current Product Index: {current_index}")

    # ✅ If there's a next product, redirect to it
    if current_index is not None and current_index + 1 < len(products):
        next_product_id = products[current_index + 1]['id']
        print(f"[DEBUG] Redirecting to Next Product ID: {next_product_id}")
        return redirect(url_for('seo.product_details', product_id=next_product_id, **filters))

    # ✅ If no next product, check for next page
    elif session.get("next_page_url"):
        print(f"[DEBUG] Moving to Next Page: {session['next_page_url']}")
        return redirect(url_for('seo.home', page_info=session["next_page_url"], **filters))

    # ✅ If nothing left, go home
    else:
        print(f"[DEBUG] No more products available.")
        flash("No more products available.", "warning")
        return redirect(url_for('seo.home'))

# ✅ Generate AI SEO Content (Title, Description, Alt Text)
@app.route('/seo/generate_<seo_type>/<product_id>', methods=['POST'])
def generate_seo_content(seo_type, product_id):
    """Generate AI SEO content for meta titles, meta descriptions, and alt text using OpenAI."""

    product_id = product_id.replace("gid://shopify/Product/", "").strip()
    print(f"[DEBUG] Cleaned product_id: {product_id}")

    product = fetch_product_by_id(product_id)
    if not product:
        print(f"[ERROR] Product not found for ID: {product_id}")
        return jsonify({"error": "Product not found"}), 404

    title = product.get("title", "Unknown Product")
    vendor = product.get("vendor", "Unknown Vendor")
    product_type = product.get("productType", "N/A")
    description = product.get("descriptionHtml", "").strip()

    if seo_type == "meta_title":
        prompt = f"Generate an SEO-optimized meta title using the product details:\n- Title: {title}\n- Vendor: {vendor}\n- Product Type: {product_type}\n- Keep it under 60 characters."
    elif seo_type == "meta_description":
        prompt = f"Generate an SEO-optimized meta description:\n- {description}\n- Keep it under 160 characters."
    elif seo_type == "alt_text":
        prompt = f"Generate a concise alt text for this product image:\n- Product: {title}\n- Keep it under 125 characters."
    else:
        return jsonify({"error": "Invalid SEO type"}), 400

    response = openai_client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=100
    )

    generated_content = response.choices[0].message.content.strip()
    return jsonify({seo_type: generated_content})

@app.route('/seo/save_<seo_type>/<product_id>', methods=['POST'])
def save_seo_content(seo_type, product_id):
    """Save AI-generated SEO content to Shopify"""

    if product_id.startswith("gid://shopify/Product/"):
        product_id = product_id.replace("gid://shopify/Product/", "").strip()

    data = request.get_json()
    content = data.get("content", "").strip()

    if not content:
        return jsonify({"error": f"Cannot save empty {seo_type}"}), 400

    product_update_data = {}
    if seo_type == "meta_title":
        product_update_data["product"] = {"metafields": [{"key": "title_tag", "namespace": "global", "value": content}]}
    elif seo_type == "meta_description":
        product_update_data["product"] = {"metafields": [{"key": "description_tag", "namespace": "global", "value": content}]}
    elif seo_type == "alt_text":
        product_update_data["product"] = {"metafields": [{"key": "alt_text", "namespace": "global", "value": content}]}
    else:
        return jsonify({"error": "Invalid SEO type"}), 400

    url = f"{SHOPIFY_STORE_URL}/admin/api/2023-10/products/{product_id}.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
    }

    try:
        response = requests.put(url, headers=headers, json=product_update_data)
        response.raise_for_status()
        return jsonify({"success": f"{seo_type.replace('_', ' ').capitalize()} updated successfully!"})

    except Exception as e:
        return jsonify({"error": f"Failed to update {seo_type}: {str(e)}"}), 500

@app.route('/seo/update_seo/<product_id>', methods=['POST'])
def update_seo(product_id):
    try:
        print(f"[DEBUG] Updating SEO for Product ID: {product_id}")

        # Get form data
        meta_title = request.form.get("meta_title", "").strip()
        meta_description = request.form.get("meta_description", "").strip()
        alt_text = request.form.get("alt_text", "").strip()

        # Shopify GraphQL Mutation to Update Metafields
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

        # ✅ Handle response
        if "errors" in response_data or response_data.get("data", {}).get("productUpdate", {}).get("userErrors"):
            print(f"[ERROR] Failed to update metafields: {response_data}")
            flash("Failed to update SEO details. Check logs for more info.", "error")
        else:
            print("[SUCCESS] SEO Details updated successfully.")
            flash("SEO details updated successfully!", "success")

        # ✅ Update Alt Text if provided
        if alt_text:
            update_alt_text(product_id, alt_text)

        return redirect(url_for('seo.product_details', product_id=product_id))

    except Exception as e:
        print(f"[ERROR] Exception while updating SEO: {e}")
        flash("An error occurred while updating SEO.", "error")
        return redirect(url_for('seo.product_details', product_id=product_id))

@app.route('/seo/generate_alt_text/<product_id>', methods=['POST'])
def generate_alt_text(product_id):
    """Generate optimized alt text for product images."""
    product = fetch_product_by_id(product_id)

    if not product:
        return jsonify({"error": "Product not found"}), 404

    # ✅ Ensure variables exist
    title = product.get("title", "Unknown Product").strip()
    vendor = product.get("vendor", "Unknown Vendor").strip()
    product_type = product.get("productType", "N/A").strip()
    image_alt = product.get("alt_text", "").strip()

    # ✅ Avoid redundant calls if we already have a decent alt text
    if image_alt and len(image_alt.split()) > 3:
        return jsonify({"alt_text": image_alt})

    # ✅ Improved AI Prompt
    prompt = f"""
    Generate short, concise, and SEO-optimized alt text for an image.
    - Product: {title}
    - Vendor: {vendor}
    - Type: {product_type}

    Guidelines:
    - Max 10 words.
    - Describe the image visually.
    - Avoid generic terms like "image of" or "picture of."
    - NO unnecessary marketing phrases.
    """

    print(f"[DEBUG] OpenAI Prompt for Alt Text:\n{prompt.strip()}")

    try:
        response = openai_client.chat.completions.create(
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



def update_alt_text(product_id, alt_text):
    """Updates the alt text of the first image in Shopify"""
    try:
        print(f"[DEBUG] Updating Alt Text for Product ID: {product_id}")

        # Fetch product details to get image ID
        product = fetch_product_by_id(product_id)
        if not product or not product.get('images'):
            print("[ERROR] No images found for product.")
            return

        image_id = product['images'][0]  # Get first image ID

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

        if "errors" in response_data or response_data.get("data", {}).get("productImageUpdate", {}).get("userErrors"):
            print(f"[ERROR] Failed to update Alt Text: {response_data}")
        else:
            print("[SUCCESS] Alt Text updated successfully!")

    except Exception as e:
        print(f"[ERROR] Exception while updating Alt Text: {e}")

def ensure_metafield_exists(product_id, key, type):
    """Ensure metafield exists before updating it."""
    query = f"""
    mutation {{
        metafieldDefinitionCreate(definition: {{
            name: "{key}",
            namespace: "global",
            key: "{key}",
            type: "{type}",
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

    response = requests.post(f"{SHOPIFY_STORE_URL}/admin/api/2023-10/graphql.json", json={"query": query}, headers=headers)
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
            f"{SHOPIFY_STORE_URL}/admin/api/2023-10/graphql.json",
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

    except Exception as e:
        print(f"[ERROR] Shopify API Request Failed: {e}")
        return None

def update_product_metafield(product_id, namespace, key, value, field_type="single_line_text_field"):
    """Update a metafield for a product in Shopify, using the correct field type."""
    try:
        print(f"[DEBUG] Updating metafield '{key}' for product ID: {product_id} with type '{field_type}'")

        product_id = f"gid://shopify/Product/{product_id}"

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
                    "ownerId": product_id,
                    "namespace": namespace,
                    "key": key,
                    "type": field_type,  # Dynamically set the field type
                    "value": value
                }
            ]
        }

        headers = {
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
            "Content-Type": "application/json"
        }

        response = requests.post(f"{SHOPIFY_STORE_URL}/admin/api/2023-10/graphql.json",
                                 json={"query": mutation, "variables": variables}, headers=headers)

        response_data = response.json()

        if "errors" in response_data or response_data.get("data", {}).get("metafieldsSet", {}).get("userErrors"):
            print(f"[ERROR] Shopify API Error: {json.dumps(response_data, indent=4)}")
            return {"error": "Failed to update metafield", "details": response_data}

        print(f"[DEBUG] Metafield updated successfully: {response_data}")
        return response_data

    except Exception as e:
        print(f"[ERROR] Exception occurred while updating metafield: {e}")
        return {"error": str(e)}

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
    """Save AI-generated alt text to Shopify product image"""
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

        # ✅ Correct Shopify API Mutation Format (Fixes the syntax error)
        mutation = """
        mutation {
            productImageUpdate(
                productId: "%s",
                image: {
                    id: "%s",
                    altText: %s
                }
            ) {
                image { id altText }
                userErrors { field message }
            }
        }
        """ % (product["id"], image_id, json.dumps(alt_text))  # ✅ Ensures safe formatting

        
        headers = {
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
            "Content-Type": "application/json"
        }
        print(f"[DEBUG] Sending GraphQL Mutation to Shopify:\n{mutation}")

        response = requests.post(
            f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json",
            json={"query": mutation}, headers=headers
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
            return jsonify({"error": "Cannot save empty seo_title"}), 400

        # ✅ Shopify GraphQL mutation to update the **SEO Title (search engine listing title)**
        mutation = """
        mutation updateProductSeo($input: ProductInput!) {
            productUpdate(input: $input) {
                product {
                    id
                    seo {
                        title  # ✅ Updating the actual Shopify SEO Title field!
                    }
                }
                userErrors {
                    field
                    message
                }
            }
        }
        """

        SHOPIFY_GRAPHQL_URL = f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json"

        headers = {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
        }

        payload = {
            "query": mutation,
            "variables": {
                "input": {
                    "id": f"gid://shopify/Product/{product_id}",
                    "seo": {
                        "title": seo_title  # ✅ Now correctly saving into `seo.title`
                    }
                }
            }
        }

        print(f"[DEBUG] Sending request to Shopify: {json.dumps(payload, indent=4)}")

        response = requests.post(SHOPIFY_GRAPHQL_URL, json=payload, headers=headers)
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
    """Updates the Shopify SEO description (search engine listing description)"""
    try:
        data = request.get_json()
        seo_description = data.get("content", "").strip()

        if not seo_description:
            return jsonify({"error": "SEO description is empty!"}), 400

        # ✅ Shopify GraphQL mutation to update `seo.description`
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

        # ✅ Shopify GraphQL API URL
        SHOPIFY_GRAPHQL_URL = f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json"

        # ✅ Shopify API Headers
        headers = {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
        }

        # ✅ GraphQL Payload (Updating ONLY `seo.description`)
        payload = {
            "query": mutation,
            "variables": {
                "input": {
                    "id": f"gid://shopify/Product/{product_id}",
                    "seo": {
                        "description": seo_description
                    }
                }
            }
        }

        print(f"[DEBUG] Sending request to Shopify: {json.dumps(payload, indent=4)}")

        # ✅ Send the GraphQL request
        response = requests.post(SHOPIFY_GRAPHQL_URL, json=payload, headers=headers)

        # ✅ Debug the full response
        response_data = response.json()
        print(f"[DEBUG] Shopify Response: {json.dumps(response_data, indent=4)}")

        # ✅ Handle Shopify API errors
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
    data = request.get_json()
    new_title = data.get("content", "").strip()

    if not new_title:
        return jsonify({"error": "Missing product title"}), 400

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

    variables = {
        "input": {
            "id": f"gid://shopify/Product/{product_id}",
            "title": new_title
        }
    }

    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
    }

    response = requests.post(f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json",
                             json={"query": mutation, "variables": variables}, headers=headers)
    
    response_data = response.json()
    
    if response_data.get("data", {}).get("productUpdate", {}).get("userErrors"):
        return jsonify({"error": "Failed to update product title", "details": response_data}), 400

    return jsonify({"success": "Product title updated successfully!"})

@app.route('/seo/save_description/<product_id>', methods=['POST'])
def save_description(product_id):
    """Update the product description in Shopify."""
    data = request.get_json()
    new_description = data.get("content", "").strip()

    if not new_description:
        return jsonify({"error": "Missing product description"}), 400

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

    variables = {
        "input": {
            "id": f"gid://shopify/Product/{product_id}",
            "descriptionHtml": new_description
        }
    }

    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
    }

    response = requests.post(f"{SHOPIFY_STORE_URL}/admin/api/2024-01/graphql.json",
                             json={"query": mutation, "variables": variables}, headers=headers)

    response_data = response.json()

    if response_data.get("data", {}).get("productUpdate", {}).get("userErrors"):
        return jsonify({"error": "Failed to update product description", "details": response_data}), 400

    return jsonify({"success": "Product description updated successfully!"})

@app.route('/seo/generate_all/<product_id>', methods=['POST'])
def generate_all(product_id):
    """Generates AI content for all SEO fields (title, description, SEO title, SEO description, alt text)."""
    try:
        product = fetch_product_by_id(product_id)  # ✅ FIX: Use correct function name

        if not product:
            return jsonify({"error": "Product not found"}), 404

        # ✅ Ensure custom prompt is used
        custom_prompt = session.get('custom_prompt', "Generate an optimized SEO title and description.")

        # ✅ Generate AI content for all fields
        product_title = generate_ai_content(f"{custom_prompt}\n\nProduct Title: {product['title']}")
        product_description = generate_ai_content(f"{custom_prompt}\n\nProduct Description: {product['descriptionHtml']}", max_tokens=150)
        seo_title = generate_ai_content(f"{custom_prompt}\n\nSEO Title: {product['title']}")
        seo_description = generate_ai_content(f"{custom_prompt}\n\nSEO Description: {product['descriptionHtml']}", max_tokens=160)
        alt_text = generate_ai_content(f"{custom_prompt}\n\nGenerate alt text for this image: {product['image_url']}")

        return jsonify({
            "product_title": product_title,
            "product_description": product_description,
            "seo_title": seo_title,
            "seo_description": seo_description,
            "alt_text": alt_text
        })

    except Exception as e:
        print(f"[ERROR] Failed to generate all AI content: {e}")
        return jsonify({"error": "Failed to generate content"}), 500





@app.route('/seo/save_all/<product_id>', methods=['POST'])
def save_all(product_id):
    """Save AI-generated content for all fields to Shopify."""
    try:
        data = request.get_json()

        # Extract content to save
        product_title = data.get("product_title", "").strip()
        product_description = data.get("product_description", "").strip()
        seo_title = data.get("seo_title", "").strip()
        seo_description = data.get("seo_description", "").strip()
        alt_text = data.get("alt_text", "").strip()

        # Update Shopify fields
        if product_title:
            update_product_title(product_id, product_title)
        if product_description:
            update_product_description(product_id, product_description)
        if seo_title or seo_description:
            update_product_seo(product_id, seo_title, seo_description)
        if alt_text:
            update_alt_text(product_id, alt_text)

        return jsonify({"success": "All content saved successfully!"})

    except Exception as e:
        print(f"[ERROR] Failed to save content: {e}")
        return jsonify({"error": "Failed to save content"}), 500



def start_flask_app():
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == "__main__":
    start_flask_app()
