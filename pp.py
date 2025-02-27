import requests
import pandas as pd
import os
from ftplib import FTP
import time

# 🚀 Shopify Credentials
SHOP_URL = "https://d74b39-d2.myshopify.com"
ACCESS_TOKEN = "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"

# 🔹 FTP Credentials
FTP_HOST = "ftp.motorstateftp.com"
FTP_USER = "851409@motorstateftp.com"
FTP_PASS = ";~#K_#UB3I}C"
FTP_FILENAME = "Motorstate1.csv"

# 🔹 Shopify API Version
API_VERSION = "2023-01"

# 🔹 Shopify Location ID (Fetched Dynamically)
LOCATION_ID = None


# ✅ Step 1: Download CSV from FTP Server
def download_csv_from_ftp():
    print("📡 Connecting to FTP server...")
    ftp = FTP(FTP_HOST)
    ftp.login(FTP_USER, FTP_PASS)

    if FTP_FILENAME not in ftp.nlst():
        print(f"❌ Error: {FTP_FILENAME} not found on FTP server!")
        ftp.quit()
        exit()

    with open(FTP_FILENAME, "wb") as file:
        ftp.retrbinary(f"RETR {FTP_FILENAME}", file.write)

    ftp.quit()
    print(f"✅ {FTP_FILENAME} downloaded successfully!")


# ✅ Step 2: Load & Process CSV
def load_csv():
    if not os.path.exists(FTP_FILENAME):
        print(f"❌ Error: {FTP_FILENAME} not found after download!")
        exit()

    print("📂 Loading CSV file...")
    df = pd.read_csv(FTP_FILENAME, encoding="ISO-8859-1")
    df.rename(columns={df.columns[0]: "PartNumber"}, inplace=True)

    # Select relevant columns
    df_filtered = df.loc[:, ["Brand", "ManufacturerPart", "QtyAvail", "SuggestedRetail", "Cost"]]

    # Format brand names correctly
    df_filtered["Brand"] = df_filtered["Brand"].str.strip().str.title()
    df_filtered["ManufacturerPart"] = df_filtered["ManufacturerPart"].str.strip()

    # ✅ Ensure Shopify SKU format matches exactly: "Brand - ManufacturerPart"
    df_filtered["Shopify_SKU"] = df_filtered["Brand"] + " - " + df_filtered["ManufacturerPart"]

    print(f"✅ CSV loaded and formatted successfully! Found {len(df_filtered)} products.")
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


# ✅ Step 4: Fetch ALL Shopify SKUs using GraphQL Pagination
def get_all_shopify_skus():
    print("📦 Fetching all Shopify SKUs using GraphQL pagination...")
    shopify_skus = {}
    page_info = None

    query_template = """
    {
      products(first: 250, after: PAGE_INFO) {
        edges {
          cursor
          node {
            id
            variants(first: 250) {
              edges {
                node {
                  id
                  sku
                  inventoryItem {
                    id
                  }
                  price
                }
              }
            }
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
    """

    headers = {
        "X-Shopify-Access-Token": ACCESS_TOKEN,
        "Content-Type": "application/json",
    }

    while True:
        graphql_query = query_template.replace("PAGE_INFO", f'"{page_info}"' if page_info else "null")

        response = requests.post(f"{SHOP_URL}/admin/api/{API_VERSION}/graphql.json",
                                 json={"query": graphql_query}, headers=headers)
        data = response.json()

        if "errors" in data:
            if data["errors"][0]["extensions"]["code"] == "THROTTLED":
                wait_time = data["extensions"]["cost"]["throttleStatus"]["restoreRate"]
                print(f"⏳ API Throttled. Waiting {wait_time} seconds before retrying...")
                time.sleep(wait_time)  # ✅ Wait before retrying
                continue  # Retry the same request
            else:
                print(f"❌ Shopify SKU Fetch Error: {data}")
                break

        products = data["data"]["products"]["edges"]
        for product in products:
            for variant in product["node"]["variants"]["edges"]:
                sku = variant["node"]["sku"]
                inventory_item_gid = variant["node"].get("inventoryItem", {}).get("id")

                # ✅ Extract numeric inventory item ID
                inventory_item_id = inventory_item_gid.split("/")[-1] if inventory_item_gid else None

                if sku:
                    shopify_skus[sku] = {
                        "product_id": product["node"]["id"],
                        "variant_id": variant["node"]["id"],
                        "inventory_item_id": inventory_item_id,
                        "current_price": variant["node"]["price"]
                    }

        if data["data"]["products"]["pageInfo"]["hasNextPage"]:
            page_info = data["data"]["products"]["pageInfo"]["endCursor"]
        else:
            break

    print(f"✅ Finished fetching {len(shopify_skus)} Shopify SKUs.")
    return shopify_skus


# ✅ Step 5: Batch Update Inventory Levels
def bulk_update_inventory(df_filtered, shopify_skus, location_id):
    print("🚀 Starting Bulk Inventory Update...")

    headers = {"X-Shopify-Access-Token": ACCESS_TOKEN, "Content-Type": "application/json"}
    inventory_updates = []

    # Create inventory update list
    for _, row in df_filtered.iterrows():
        sku = row["Shopify_SKU"]
        quantity = int(row["QtyAvail"])

        if sku in shopify_skus:
            inventory_item_id = shopify_skus[sku]["inventory_item_id"]
            inventory_updates.append(f"""
                {{
                    inventoryItemId: "gid://shopify/InventoryItem/{inventory_item_id}",
                    locationId: "gid://shopify/Location/{location_id}",
                    quantity: {quantity}
                }}
            """)

    if not inventory_updates:
        print("❌ No matching SKUs for inventory update!")
        return

    # Shopify allows max 250 per request, so split into chunks
    for i in range(0, len(inventory_updates), 250):
        batch = inventory_updates[i:i+250]

        mutation_query = f"""
        mutation {{
            inventorySetOnHandQuantities(input: {{
                reason: "Stock Adjustment",
                setQuantities: [{",".join(batch)}]
            }}) {{
                inventoryAdjustmentGroup {{
                    id
                }}
                userErrors {{
                    field
                    message
                }}
            }}
        }}
        """

        print(f"🔍 Sending Inventory Update Batch {i // 250 + 1}...")

        response = requests.post(f"{SHOP_URL}/admin/api/{API_VERSION}/graphql.json",
                                 json={"query": mutation_query}, headers=headers)

        if "errors" in response.json():
            print(f"❌ Inventory Update Failed for Batch {i // 250 + 1}")






def bulk_update_prices(df_filtered, shopify_skus):
    print("🚀 Starting Bulk Price Update...")

    headers = {"X-Shopify-Access-Token": ACCESS_TOKEN, "Content-Type": "application/json"}

    product_updates = {}  # Group updates by productId

    for _, row in df_filtered.iterrows():
        sku = row["Shopify_SKU"]
        price = float(row["SuggestedRetail"])

        if sku in shopify_skus:
            product_id = shopify_skus[sku]["product_id"]
            variant_id = shopify_skus[sku]["variant_id"]

            # Ensure product ID is properly formatted
            if not product_id.startswith("gid://shopify/Product/"):
                product_id = f"gid://shopify/Product/{product_id}"

            if product_id not in product_updates:
                product_updates[product_id] = []

            product_updates[product_id].append(f"""
                {{
                    id: "{variant_id}",
                    price: "{price}"
                }}
            """)

    if not product_updates:
        print("❌ No matching SKUs for price update!")
        return

    # Loop through each product and send updates in batches
    for product_id, variants in product_updates.items():
        mutation_query = f"""
        mutation {{
            productVariantsBulkUpdate(
                productId: "{product_id}",
                variants: [{",".join(variants)}]
            ) {{
                productVariants {{
                    id
                    price
                }}
                userErrors {{
                    field
                    message
                }}
            }}
        }}
        """

        response = requests.post(f"{SHOP_URL}/admin/api/{API_VERSION}/graphql.json", json={"query": mutation_query}, headers=headers)

        response_json = response.json()
        if "errors" in response_json:
            print(f"❌ Price Update Failed for Product {product_id}: {response_json}")
        else:
            print(f"✅ Bulk Price Update Successful for Product {product_id}!")




# 🚀 Main Function
# 🚀 Run All Steps Automatically
if __name__ == "__main__":
    print("🚀 Starting Shopify Inventory & Price Sync...")

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

    # Step 6: Bulk Update Inventory & Prices
    bulk_update_inventory(df_filtered, shopify_sku_data, LOCATION_ID)
    bulk_update_prices(df_filtered, shopify_sku_data)

    print("✅ Inventory & Price Sync Completed!")

