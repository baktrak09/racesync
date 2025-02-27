import requests
import pandas as pd
import os
from ftplib import FTP
from time import sleep
from concurrent.futures import ThreadPoolExecutor

# 🚀 Shopify Credentials
SHOP_URL = "https://d74b39-d2.myshopify.com"
ACCESS_TOKEN = "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"
API_VERSION = "2023-01"

# 🔹 FTP Credentials
FTP_HOST = "ftp.motorstateftp.com"
FTP_USER = "851409@motorstateftp.com"
FTP_PASS = ";~#K_#UB3I}C"
CSV_FILENAME = "Motorstate1.csv"

# 🔹 Fetch Shopify Location ID dynamically
def get_shopify_location_id():
    url = f"{SHOP_URL}/admin/api/{API_VERSION}/locations.json"
    headers = {"X-Shopify-Access-Token": ACCESS_TOKEN}
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Raises stored HTTPError, if one occurred.
    locations = response.json().get("locations", [])
    if not locations:
        print("❌ No locations found in Shopify!")
        return None
    return locations[0]["id"]

# 🔹 Download CSV from FTP Server
def download_csv_from_ftp():
    print("📡 Connecting to FTP server...")
    with FTP(FTP_HOST) as ftp:
        ftp.login(FTP_USER, FTP_PASS)
        files = ftp.nlst()
        if CSV_FILENAME not in files:
            print(f"❌ Error: {CSV_FILENAME} not found on FTP server!")
            return False
        with open(CSV_FILENAME, "wb") as file:
            ftp.retrbinary(f"RETR {CSV_FILENAME}", file.write)
    print(f"✅ {CSV_FILENAME} downloaded successfully!")
    return True

# 🔹 Load and process CSV file
def load_csv():
    if not os.path.exists(CSV_FILENAME):
        print(f"❌ Error: {CSV_FILENAME} not found after download!")
        return None
    df = pd.read_csv(CSV_FILENAME, encoding="ISO-8859-1")
    df.rename(columns={df.columns[0]: "PartNumber"}, inplace=True)
    df['Shopify_SKU'] = df['Brand'].str.title() + ' - ' + df['ManufacturerPart']
    print("✅ CSV loaded and formatted successfully!")
    return df[['Brand', 'ManufacturerPart', 'Shopify_SKU', 'QtyAvail', 'SuggestedRetail', 'Cost']]

# 🔹 Fetch all Shopify SKUs
def fetch_all_shopify_skus():
    shopify_skus = {}
    page_info = None
    headers = {"X-Shopify-Access-Token": ACCESS_TOKEN}
    while True:
        url = f"{SHOP_URL}/admin/api/{API_VERSION}/products.json?fields=id,variants&limit=250" + (f"&page_info={page_info}" if page_info else "")
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        products = data.get("products", [])
        for product in products:
            for variant in product["variants"]:
                sku = variant["sku"]
                if sku:
                    shopify_skus[sku] = {
                        "product_id": product["id"],
                        "variant_id": variant["id"],
                        "inventory_item_id": variant["inventory_item_id"]
                    }
        links = response.headers.get("Link", "")
        next_page = [link.split(";")[0].strip("<>") for link in links.split(",") if 'rel="next"' in link]
        if not next_page:
            break
        page_info = next_page[0]
    print(f"✅ Fetched {len(shopify_skus)} SKUs from Shopify.")
    return shopify_skus

# 🔹 Update inventory to match exactly
def update_inventory_exact(inventory_item_id, quantity, location_id):
    """Update inventory and verify the update was successful."""
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
    while True:
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 10))
            print(f"Rate limit hit, retrying after {retry_after} seconds...")
            sleep(retry_after)
        elif response.status_code != 200:
            print(f"Failed to update inventory for {inventory_item_id}, error: {response.text}")
            break
        else:
            data = response.json()
            if data.get('errors'):
                print(f"Update error for {inventory_item_id}: {data['errors']}")
                break
            if verify_inventory_update(inventory_item_id, quantity, location_id):
                return data
            else:
                print(f"Verification failed for {inventory_item_id}, retrying update...")
                continue

def verify_inventory_update(inventory_item_id, expected_quantity, location_id):
    """Fetch the current inventory level and compare with expected."""
    url = f"{SHOP_URL}/admin/api/{API_VERSION}/inventory_levels.json?inventory_item_ids={inventory_item_id}&location_ids={location_id}"
    response = requests.get(url, headers={"X-Shopify-Access-Token": ACCESS_TOKEN})
    if response.status_code == 200:
        data = response.json()
        current_quantity = next((level['available'] for level in data['inventory_levels'] if level['inventory_item_id'] == inventory_item_id), None)
        return current_quantity == expected_quantity
    return False

def bulk_update_inventory(df, shopify_skus, location_id):
    """Run inventory updates using threading to manage concurrency and respect rate limits."""
    with ThreadPoolExecutor(max_workers=5) as executor:  # Limit number of workers to reduce rate limit hits
        futures = []
        for _, row in df.iterrows():
            sku_data = shopify_skus.get(row['Shopify_SKU'])
            if sku_data:
                futures.append(executor.submit(update_inventory_exact, sku_data['inventory_item_id'], int(row['QtyAvail']), location_id))

        for future in as_completed(futures):
            try:
                future.result()  # Will re-raise any exceptions caught during the executor's operation
            except Exception as e:
                print(f"Error during inventory update: {str(e)}")

# 🚀 Run all steps
if __name__ == "__main__":
    if download_csv_from_ftp():
        df = load_csv()
        if df is not None:
            location_id = get_shopify_location_id()
            if location_id:
                shopify_skus = fetch_all_shopify_skus()
                if shopify_skus:
                    bulk_update_inventory(df, shopify_skus, location_id)
