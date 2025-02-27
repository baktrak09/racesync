import requests
import csv
import time  # ✅ Required for API throttling

# 🚀 Shopify API Credentials
SHOP_URL = "https://d74b39-d2.myshopify.com"
ACCESS_TOKEN = "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"
API_VERSION = "2023-01"
OUTPUT_CSV = "shopify_products.csv"

# ✅ Fetch All Products
def fetch_all_products():
    all_products = []
    page_info = None

    while True:
        query = """
        {
            products(first: 250, after: PAGE_INFO) {
                edges {
                    node {
                        id
                        title
                        handle
                        vendor
                        variants(first: 250) {
                            edges {
                                node {
                                    id
                                    sku
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

        response = requests.post(
            f"{SHOP_URL}/admin/api/{API_VERSION}/graphql.json",
            json={"query": query.replace("PAGE_INFO", f'"{page_info}"' if page_info else "null")},
            headers={"X-Shopify-Access-Token": ACCESS_TOKEN}
        )
        
        data = response.json()

        # ✅ Handle API Errors Gracefully
        if "errors" in data:
            error_message = data["errors"][0].get("message", "Unknown error")
            
            if "extensions" in data["errors"][0]:  # Check if 'extensions' key exists
                if data["errors"][0]["extensions"]["code"] == "THROTTLED":
                    wait_time = 5  # Adjust wait time as needed
                    print(f"⏳ Shopify API Throttled. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue  # Retry the same request

            print(f"❌ Shopify API Error: {error_message}")
            break  # Stop the loop if the error is not "THROTTLED"

        products = data["data"]["products"]["edges"]

        # ✅ Extract only relevant product info for CSV
        for product in products:
            product_node = product["node"]
            product_id = product_node["id"]
            title = product_node["title"]
            vendor = product_node["vendor"]
            handle = product_node["handle"]

            for variant in product_node["variants"]["edges"]:
                variant_node = variant["node"]
                variant_id = variant_node["id"]
                sku = variant_node["sku"]
                price = variant_node["price"]

                all_products.append([product_id, title, vendor, handle, variant_id, sku, price])

        if data["data"]["products"]["pageInfo"]["hasNextPage"]:
            page_info = data["data"]["products"]["pageInfo"]["endCursor"]
        else:
            break

    return all_products


# ✅ Save Products to CSV
def save_to_csv(products_data):
    print("💾 Saving products to CSV...")
    with open(OUTPUT_CSV, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Product ID", "Title", "Vendor", "Handle", "Variant ID", "SKU", "Price"])
        writer.writerows(products_data)
    print(f"✅ Products saved to {OUTPUT_CSV}!")


# 🚀 Run the Script
if __name__ == "__main__":
    print("📦 Fetching all Shopify products...")
    products_data = fetch_all_products()

    if products_data:
        print(f"✅ Successfully fetched {len(products_data)} products.")
        save_to_csv(products_data)
    else:
        print("❌ No products fetched.")
