import requests
import pandas as pd
import os
from ftplib import FTP
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random
import math
from flask import Flask, jsonify, request, render_template, Blueprint
from dotenv import load_dotenv
from flask_cors import CORS
import threading
import concurrent.futures
import cProfile



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

@app.route('/')
def index():
    location_id = get_shopify_location_id()
    shopify_skus = {}
    return render_template('index.html', location_id=location_id, shopify_skus=shopify_skus, segment='index')

@app.route('/api/shopify-skus')
def get_shopify_skus_api():
    try:
        shopify_skus = fetch_shopify_skus_concurrent()
        return jsonify(shopify_skus)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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


@app.route('/trigger_update', methods=['POST'])
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


@app.route('/update_inventory_pricing', methods=['POST'])
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

@app.route('/api/get-skus')
def api_get_skus():
    shopify_skus = fetch_all_shopify_skus()
    return jsonify(shopify_skus)

@app.route('/process_inventory_update', methods=['POST'])
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


def start_flask_app():
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == "__main__":
    # Start the Flask app
    start_flask_app()


