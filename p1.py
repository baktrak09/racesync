import requests
import pandas as pd
import os
from ftplib import FTP
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random
import math

# Shopify and FTP credentials
SHOP_URL = "https://d74b39-d2.myshopify.com"
ACCESS_TOKEN = "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"
API_VERSION = "2023-01"
FTP_HOST = "ftp.motorstateftp.com"
FTP_USER = "851409@motorstateftp.com"
FTP_PASS = ";~#K_#UB3I}C"
CSV_FILENAME = "Motorstate1.csv"

def get_shopify_location_id():
    """Fetch the first location ID from Shopify."""
    url = f"{SHOP_URL}/admin/api/{API_VERSION}/locations.json"
    headers = {"X-Shopify-Access-Token": ACCESS_TOKEN}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    locations = response.json().get("locations", [])
    return locations[0]["id"] if locations else None

def download_csv_from_ftp():
    """Download CSV inventory file from FTP server."""
    with FTP(FTP_HOST) as ftp:
        ftp.login(FTP_USER, FTP_PASS)
        if CSV_FILENAME in ftp.nlst():
            with open(CSV_FILENAME, "wb") as file:
                ftp.retrbinary(f"RETR {CSV_FILENAME}", file.write)
            print(f"✅ {CSV_FILENAME} downloaded successfully!")
            return True
        else:
            print(f"❌ Error: {CSV_FILENAME} not found on FTP server!")
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

def fetch_all_shopify_skus():
    """Fetch all SKUs from Shopify and return a dictionary with SKU details."""
    shopify_skus = {}
    page_info = None
    headers = {"X-Shopify-Access-Token": ACCESS_TOKEN}
    while True:
        url = f"{SHOP_URL}/admin/api/{API_VERSION}/products.json?fields=id,variants&limit=250"
        url += f"&page_info={page_info}" if page_info else ""
        response = requests.get(url, headers=headers)
        response.raise_for_status()
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
    print(f"✅ Fetched {len(shopify_skus)} SKUs from Shopify.")
    return shopify_skus



def get_rate_limit_delay(response):
    # Read the rate limit header to determine the appropriate delay
    rate_limit = response.headers.get('X-Shopify-Shop-Api-Call-Limit', '1/1')
    used, limit = map(int, rate_limit.split('/'))
    # Prevent division by zero by checking if limit is equal to used
    if used >= limit:
        remaining = max(1, limit - used)  # Ensure this value is never zero
    else:
        remaining = limit - used
    # Implement exponential backoff with a minimum of 1 second
    delay = (limit / remaining) * 2 if remaining > 0 else 1
    return delay


def safe_request(url, method='get', **kwargs):
    max_retries = 10
    for i in range(max_retries):
        try:
            if method == 'post':
                response = requests.post(url, **kwargs)
            else:
                response = requests.get(url, **kwargs)
            response.raise_for_status()  # raise an exception for HTTP error codes
            return response
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:
                delay = get_rate_limit_delay(response)
                time.sleep(delay)
            else:
                raise e  # Re-raise the exception if it's not a rate limit error
        except requests.exceptions.RequestException as e:
            if i < max_retries - 1:
                time.sleep(math.pow(2, i))  # Exponential backoff
            else:
                raise e  # Re-raise the last exception if all retries fail


def update_inventory_exact(inventory_item_id, quantity, location_id):
    url = f"{SHOP_URL}/admin/api/{API_VERSION}/inventory_levels/set.json"
    payload = {
        "location_id": location_id,
        "inventory_item_id": inventory_item_id,
        "available": quantity
    }
    headers = {
        "X-Shopify-Access-Token": ACCESS_TOKEN,
        "Content-Type": "application/json"
    }
    response = safe_request(url, method='post', json=payload, headers=headers)
    return response.json()  # Return the JSON response from the API

# Use safe_request in other parts of your script where API calls are made




def bulk_update_inventory(df, shopify_skus, location_id):
    for _, row in df.iterrows():
        if row['Shopify_SKU'] in shopify_skus:
            sku_info = shopify_skus[row['Shopify_SKU']]
            response = update_inventory_exact(sku_info['inventory_item_id'], int(row['QtyAvail']), location_id)
            
            # Check if the response is a dictionary and handle accordingly
            if isinstance(response, dict) and 'error' in response:
                print(f"Failed to update {row['Shopify_SKU']}: {response['error']}")
            else:
                print(f"Successfully updated {row['Shopify_SKU']}")

    print("Inventory update process completed.")


if __name__ == "__main__":
    if download_csv_from_ftp():
        df = load_csv()
        if df is not None:
            location_id = get_shopify_location_id()
            if location_id:
                shopify_skus = fetch_all_shopify_skus()
                if shopify_skus:
                    bulk_update_inventory(df, shopify_skus, location_id)
