import requests
import pandas as pd
import random

# 🚀 Shopify Credentials
SHOP_URL = "https://d74b39-d2.myshopify.com"
ACCESS_TOKEN = "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"
API_VERSION = "2023-01"

# ✅ Load CSV file
CSV_FILENAME = "Motorstate1.csv"

try:
    df = pd.read_csv(CSV_FILENAME, encoding="ISO-8859-1")
    df.rename(columns={df.columns[0]: "PartNumber"}, inplace=True)
    df["Brand"] = df["Brand"].str.strip().str.title()
    df["ManufacturerPart"] = df["ManufacturerPart"].str.strip()
    df["Shopify_SKU"] = df["Brand"] + " - " + df["ManufacturerPart"]
    
    csv_skus = df["Shopify_SKU"].dropna().tolist()
except Exception as e:
    print(f"❌ Error loading CSV: {e}")
    exit()

# ✅ Fetch Shopify SKUs from API using GraphQL
def get_shopify_skus():
    print("📦 Fetching Shopify SKUs...")
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
                  sku
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
            print(f"❌ Shopify SKU Fetch Error: {data}")
            break

        products = data["data"]["products"]["edges"]
        for product in products:
            for variant in product["node"]["variants"]["edges"]:
                sku = variant["node"]["sku"]
                if sku:
                    shopify_skus[sku] = True  # Use dict to avoid duplicates

        if data["data"]["products"]["pageInfo"]["hasNextPage"]:
            page_info = data["data"]["products"]["pageInfo"]["endCursor"]
        else:
            break

    print(f"✅ Finished fetching {len(shopify_skus)} Shopify SKUs.")
    return list(shopify_skus.keys())

# ✅ Get SKUs from Shopify
shopify_skus = get_shopify_skus()
if not shopify_skus:
    print("❌ No SKUs found in Shopify! Exiting.")
    exit()

# ✅ Pick 100 random SKUs from each list
random_csv_skus = random.sample(csv_skus, min(100, len(csv_skus)))
random_shopify_skus = random.sample(shopify_skus, min(100, len(shopify_skus)))

# ✅ Print side-by-side comparison
print("\n🔍 Comparing 100 Random SKUs from CSV and Shopify:\n")
print(f"{'CSV SKU':<40} | {'Shopify SKU':<40}")
print("-" * 85)

for csv_sku, shopify_sku in zip(random_csv_skus, random_shopify_skus):
    print(f"{csv_sku:<40} | {shopify_sku:<40}")

print("\n✅ SKU Comparison Complete! Look for differences in spaces, dashes, cases, etc.")
