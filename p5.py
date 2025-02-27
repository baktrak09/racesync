import requests
import pandas as pd
import os
from ftplib import FTP
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random
import math
from flask import Flask, jsonify, request
from flask import Flask, render_template
from dotenv import load_dotenv
from flask_cors import CORS
import threading

load_dotenv()

# Shopify and FTP credentials
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

app = Flask(__name__)
CORS(app)  # This enables CORS for all domains on all routes. Adjust as needed.

@app.route('/')
def index():
    return render_template('index.html')


def get_shopify_location_id():
    """Fetch the first location ID from Shopify."""
    url = f"{SHOP_URL}/admin/api/{API_VERSION}/locations.json"
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

def fetch_all_shopify_skus():
    shopify_skus = {}
    page_info = None
    headers = {"X-Shopify-Access-Token": ACCESS_TOKEN}
    try:
        while True:
            url = f"{SHOP_URL}/admin/api/{API_VERSION}/products.json?fields=id,variants&limit=250"
            url += f"&page_info={page_info}" if page_info else ""
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Ensure any HTTP errors are caught
            data = response.json()
            for product in data["products"]:
                for variant in product["variants"]:
                    if variant["sku"]:
                        shopify_skus[variant["sku"]] = {
                            "product_id": product["id"],
                            "variant_id": variant["id"],
                            "inventory_item_id": variant["inventory_item_id"]
                        }
            links = response.headers.get("Link", "")
            next_page_link = next((link for link in links.split(", ") if 'rel="next"' in link), None)
            if next_page_link:
                page_info = next_page_link.split(";")[0].strip("<>")
            else:
                break
            
            time.sleep(1)  # Add a delay between requests to avoid rate limits

        print(f"✅ Fetched {len(shopify_skus)} SKUs from Shopify.")
        return shopify_skus
    except requests.exceptions.HTTPError as e:
        print(f"Failed to fetch SKUs due to an HTTP Error: {str(e)}")
        return {}
    except Exception as e:
        print(f"An error occurred while fetching SKUs: {str(e)}")
        return {}

@app.route('/api/shopify-products', methods=['POST'])
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

@app.route('/download_csv', methods=['POST'])
def handle_download_csv():
    if download_csv_from_ftp():
        return jsonify({"status": "success", "message": "CSV downloaded successfully"})
    else:
        return jsonify({"status": "error", "message": "Failed to download CSV"}), 400

def download_csv_from_ftp():
    """Download CSV inventory file from FTP server."""
    try:
        with FTP(FTP_HOST) as ftp:
            ftp.set_pasv(True)  # Use passive mode
            ftp.login(FTP_USER, FTP_PASS)
            if CSV_FILENAME in ftp.nlst():
                with open(CSV_FILENAME, "wb") as file:
                    ftp.retrbinary(f"RETR {CSV_FILENAME}", file.write)
                print(f"✅ {CSV_FILENAME} downloaded successfully!")
                return True
            else:
                print(f"❌ Error: {CSV_FILENAME} not found on FTP server!")
                return False
    except Exception as e:
        print(f"Failed to connect to FTP server: {e}")
        return False


def load_csv():
    """Load and preprocess CSV data."""
    if os.path.exists(CSV_FILENAME):
        df = pd.read_csv(CSV_FILENAME, encoding="ISO-8859-1")
        df['Shopify_SKU'] = df['Brand'].str.title() + ' - ' + df['ManufacturerPart']
        print("✅ CSV loaded and formatted successfully!")
        return df
    else:
        print(f"❌ Error: {CSV_FILENAME} not found after download!")
        return None


def safe_request(url, method='get', **kwargs):
    max_retries = 10
    backoff_factor = 1
    retry_wait = backoff_factor

    for attempt in range(max_retries):
        try:
            response = requests.request(method, url, **kwargs)
            # Log request and response for debugging
            print(f"Request URL: {url}")
            print(f"Request Method: {method}")
            print(f"Request Headers: {kwargs.get('headers')}")
            print(f"Request Payload: {kwargs.get('json')}")
            print(f"Response Status: {response.status_code}")
            print(f"Response Body: {response.text}")

            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:  # Rate Limit Exceeded
                retry_after = int(response.headers.get("Retry-After", retry_wait))
                print(f"Rate limit hit, retrying after {retry_after} seconds...")
                time.sleep(retry_after)
                retry_wait *= backoff_factor  # Increase the wait time for the next retry
            else:
                raise  # Re-raise the exception if it's not a rate limit error
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                print(f"Request failed, retrying in {retry_wait} seconds...")
                time.sleep(retry_wait)
                retry_wait *= backoff_factor
            else:
                raise



def update_inventory_and_pricing(product_id, variant_id, inventory_item_id, quantity, suggested_retail, cost, map_price, location_id):
    headers = {
        "X-Shopify-Access-Token": ACCESS_TOKEN,
        "Content-Type": "application/json"
    }

    # Update Inventory
    inventory_url = f"{SHOP_URL}/admin/api/{API_VERSION}/inventory_levels/set.json"
    inventory_payload = {
        "location_id": location_id,
        "inventory_item_id": inventory_item_id,  # Use inventory_item_id here
        "available": quantity
    }
    try:
        inventory_response = requests.post(inventory_url, json=inventory_payload, headers=headers)
        inventory_response.raise_for_status()
        print(f"Successfully updated inventory for variant {variant_id}")
    except requests.exceptions.HTTPError as e:
        print(f"Failed to update inventory for variant {variant_id}: {e.response.text}")

    # Update Pricing
    pricing_url = f"{SHOP_URL}/admin/api/{API_VERSION}/variants/{variant_id}.json"
    pricing_payload = {
        "variant": {
            "id": variant_id,
            "price": suggested_retail,
            "compare_at_price": map_price if pd.notna(map_price) else suggested_retail  # Use MapPrice or default to SuggestedRetail
        }
    }
    try:
        pricing_response = requests.put(pricing_url, json=pricing_payload, headers=headers)
        pricing_response.raise_for_status()
        print(f"Successfully updated pricing for variant {variant_id}")
    except requests.exceptions.HTTPError as e:
        print(f"Failed to update pricing for variant {variant_id}: {e.response.text}")

def bulk_update_inventory(df, shopify_skus, location_id):
    with ThreadPoolExecutor(max_workers=2) as executor:  # Reduce number of workers
        futures = []
        for index, row in df.iterrows():
            time.sleep(1)  # Increase delay between requests
            sku_data = shopify_skus.get(row['Shopify_SKU'])
            if sku_data:
                future = executor.submit(update_inventory_and_pricing, sku_data['product_id'], sku_data['variant_id'], sku_data['inventory_item_id'], row['QtyAvail'], row['SuggestedRetail'], row['Cost'], row['MapPrice'], location_id)
                futures.append(future)
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Error updating SKU: {e}")


def safe_request(url, method='get', **kwargs):
    max_retries = 10
    for i in range(max_retries):
        try:
            response = requests.request(method, url, **kwargs)
            # Log request and response for debugging
            print(f"Request URL: {url}")
            print(f"Request Method: {method}")
            print(f"Request Headers: {kwargs.get('headers')}")
            print(f"Request Payload: {kwargs.get('json')}")
            print(f"Response Status: {response.status_code}")
            print(f"Response Body: {response.text}")

            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:  # Rate Limit Exceeded
                print(f"Rate limit hit, retrying in {retry_wait} seconds...")
                time.sleep(retry_wait)
                retry_wait *= backoff_factor  # double the wait time for the next retry
            else:
                raise  # re-raise the exception if it's not a rate limit error
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                print(f"Request failed, retrying in {retry_wait} seconds...")
                time.sleep(retry_wait)
                retry_wait *= backoff_factor
            else:
                raise

@app.route('/api/products')
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


@app.route('/get_vendors')
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

@app.route('/update_by_vendor', methods=['POST'])
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









@app.route('/trigger_update', methods=['POST'])
def trigger_update():
    try:
        # Ensure this only runs when triggered manually
        location_id = get_shopify_location_id()
        if location_id:
            shopify_skus = fetch_all_shopify_skus()
            if shopify_skus:
                df = load_csv()  # Assuming CSV is already downloaded and correct
                if df is not None:
                    bulk_update_inventory(df, shopify_skus, location_id)
                    return jsonify({"status": "success", "message": "Inventory and pricing updated successfully!"})
                else:
                    return jsonify({"status": "error", "message": "Failed to load CSV data."})
            else:
                return jsonify({"status": "error", "message": "Failed to fetch SKUs from Shopify."})
        else:
            return jsonify({"status": "error", "message": "Failed to fetch location ID from Shopify."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})



def initial_setup():
    required_env_vars = ['SHOP_URL', 'ACCESS_TOKEN', 'FTP_HOST', 'FTP_USER', 'FTP_PASS']
    for var in required_env_vars:
        if not os.getenv(var):
            raise ValueError(f"Environment variable {var} not set")
    
    if download_csv_from_ftp():
        df = load_csv()
        if df is not None:
            location_id = get_shopify_location_id()
            if location_id:
                shopify_skus = fetch_all_shopify_skus()
                if shopify_skus:
                    bulk_update_inventory(df, shopify_skus, location_id)
                    print("✅ Inventory and pricing update completed successfully!")
                else:
                    print("❌ No SKUs fetched from Shopify.")
            else:
                print("❌ Location ID could not be fetched.")
        else:
            print("❌ CSV data could not be loaded.")
    else:
        print("❌ Failed to download CSV.")

def start_flask_app():
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == "__main__":
    # Start initial setup in a separate thread
    # setup_thread = threading.Thread(target=initial_setup)
    # setup_thread.start()

    # Start the Flask app
    start_flask_app()

