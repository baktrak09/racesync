import requests
import pandas as pd
import os
from ftplib import FTP
from concurrent.futures import ThreadPoolExecutor

# 🚀 Shopify Credentials (Replace with your actual store details)
SHOP_URL = "https://d74b39-d2.myshopify.com"
ACCESS_TOKEN = "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"

# 🔹 FTP Credentials
FTP_HOST = "ftp.motorstateftp.com"
FTP_USER = "851409@motorstateftp.com"
FTP_PASS = ";~#K_#UB3I}C"

# 🔹 Shopify API Version
API_VERSION = "2023-01"

# 🔹 Shopify Location ID (Fetched Dynamically)
LOCATION_ID = None

# 🔹 File Name
CSV_FILENAME = "Motorstate1.csv"

# ✅ Step 1: Download CSV from FTP Server
def download_csv_from_ftp():
    print("📡 Connecting to FTP server...")
    ftp = FTP(FTP_HOST)
    ftp.login(FTP_USER, FTP_PASS)

    # Ensure file exists on FTP
    files = ftp.nlst()
    if CSV_FILENAME not in files:
        print(f"❌ Error: {CSV_FILENAME} not found on FTP server!")
        ftp.quit()
        exit()

    # Download the file
    print(f"⬇️ Downloading {CSV_FILENAME} from FTP...")
    with open(CSV_FILENAME, "wb") as file:
        ftp.retrbinary(f"RETR {CSV_FILENAME}", file.write)
    
    ftp.quit()
    print(f"✅ {CSV_FILENAME} downloaded successfully!")

# ✅ Step 2: Load & Process CSV
def load_csv():
    if not os.path.exists(CSV_FILENAME):
        print(f"❌ Error: {CSV_FILENAME} not found after download!")
        exit()

    print("📂 Loading CSV file...")
    df = pd.read_csv(CSV_FILENAME, encoding="ISO-8859-1")
    df.rename(columns={df.columns[0]: "PartNumber"}, inplace=True)

    # Select necessary columns
    df_filtered = df.loc[:, ["Brand", "ManufacturerPart", "QtyAvail", "SuggestedRetail", "Cost"]]

    # Format brand names correctly
    df_filtered.loc[:, "Brand"] = df_filtered["Brand"].str.title()

    # Create Shopify SKU format
    df_filtered.loc[:, "Shopify_SKU"] = df_filtered["Brand"] + " - " + df_filtered["ManufacturerPart"]

    print("✅ CSV loaded and formatted successfully!")
    return df_filtered

# ✅ Step 3: Fetch Shopify Location ID
def get_shopify_location_id():
    url = f"{SHOP_URL}/admin/api/{API_VERSION}/locations.json"
    headers = {"X-Shopify-Access-Token": ACCESS_TOKEN}

    response = requests.get(url, headers=headers)
    locations = response.json().get("locations", [])
    
    if locations:
        return locations[0]["id"]
    else:
        print("❌ No locations found in Shopify!")
        return None

# ✅ Step 4: Fetch All Shopify SKUs
def get_all_shopify_skus():
    print("📦 Fetching all Shopify SKUs...")
    shopify_skus = {}
    page_info = None

    while True:
        url = f"{SHOP_URL}/admin/api/{API_VERSION}/products.json?fields=id,variants&limit=250"
        if page_info:
            url += f"&page_info={page_info}"

        headers = {"X-Shopify-Access-Token": ACCESS_TOKEN}
        response = requests.get(url, headers=headers)
        products = response.json().get("products", [])

        for product in products:
            for variant in product["variants"]:
                shopify_skus[variant["sku"]] = {
                    "product_id": product["id"],
                    "variant_id": variant["id"],
                    "inventory_item_id": variant["inventory_item_id"]
                }

        # Check if there is more data to fetch
        if "Link" in response.headers:
            links = response.headers["Link"].split(", ")
            next_page = [link for link in links if 'rel="next"' in link]
            if next_page:
                page_info = next_page[0].split(";")[0].strip("<>")
            else:
                break  # No more pages
        else:
            break  # No more pages

    print(f"✅ Fetched {len(shopify_skus)} SKUs from Shopify.")
    return shopify_skus

# ✅ Step 5: Update Inventory to Match Exactly
def update_inventory_exact(inventory_item_id, quantity):
    url = f"{SHOP_URL}/admin/api/{API_VERSION}/inventory_levels/set.json"
    headers = {"X-Shopify-Access-Token": ACCESS_TOKEN, "Content-Type": "application/json"}
    
    payload = {
        "location_id": LOCATION_ID,
        "inventory_item_id": inventory_item_id,
        "available": int(quantity)  # Force inventory to match Motorstate
    }

    response = requests.post(url, json=payload, headers=headers)
    return response.json()

# ✅ Step 6: Bulk Update Inventory with Exact Values
def bulk_update_inventory(df_filtered, shopify_sku_data):
    with ThreadPoolExecutor(max_workers=10) as executor:
        for _, row in df_filtered.iterrows():
            if row["Shopify_SKU"] in shopify_sku_data:
                executor.submit(update_inventory_exact, shopify_sku_data[row["Shopify_SKU"]]["inventory_item_id"], row["QtyAvail"])

# 🚀 Run All Steps Automatically
if __name__ == "__main__":
    print("🚀 Starting Shopify Inventory Sync...")

    # Step 1: Download CSV from FTP
    download_csv_from_ftp()

    # Step 2: Load CSV
    df_filtered = load_csv()

    # Step 3: Get Shopify Location ID
    LOCATION_ID = get_shopify_location_id()
    if not LOCATION_ID:
        print("❌ Cannot proceed without Location ID!")
        exit()

    # Step 4: Fetch All Shopify SKUs
    shopify_sku_data = get_all_shopify_skus()
    if not shopify_sku_data:
        print("❌ No SKUs found in Shopify! Exiting.")
        exit()

    # Step 5: Filter Products to Only Update Matching SKUs
    df_filtered = df_filtered[df_filtered["Shopify_SKU"].isin(shopify_sku_data.keys())]

    if df_filtered.empty:
        print("❌ No matching products found in Shopify!")
        exit()

    print(f"✅ Found {len(df_filtered)} matching products. Proceeding with updates...")

    # Step 6: Bulk Update Inventory
    bulk_update_inventory(df_filtered, shopify_sku_data)
    print("✅ Inventory Sync Completed!")

