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
        print(f"✅ Fetched {len(shopify_skus)} SKUs from Shopify.")
        return shopify_skus
    except requests.exceptions.HTTPError as e:
        print(f"Failed to fetch SKUs due to an HTTP Error: {str(e)}")
        return {}
    except Exception as e:
        print(f"An error occurred while fetching SKUs: {str(e)}")
        return {}




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
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 10))
                print(f"Rate limit hit, retrying after {retry_after} seconds.")
                time.sleep(retry_after)
            else:
                if i < max_retries - 1:
                    sleep_time = min(2 ** i, 10)
                    print(f"Retrying in {sleep_time} seconds...")
                    time.sleep(sleep_time)
                else:
                    raise
        except requests.exceptions.RequestException as e:
            if i < max_retries - 1:
                sleep_time = min(2 ** i, 10)
                print(f"Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)
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
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 10))
                print(f"Rate limit hit, retrying after {retry_after} seconds.")
                time.sleep(retry_after)
            else:
                if i < max_retries - 1:
                    sleep_time = min(2 ** i, 10)
                    print(f"Retrying in {sleep_time} seconds...")
                    time.sleep(sleep_time)
                else:
                    raise
        except requests.exceptions.RequestException as e:
            if i < max_retries - 1:
                sleep_time = min(2 ** i, 10)
                print(f"Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)
            else:
                raise

if __name__ == "__main__":
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
