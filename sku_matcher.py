import pandas as pd
import json
import os
from fuzzywuzzy import process

# 📂 File paths (update these if needed)
CSV_FILENAME = "Motorstate1.csv"   # Your Motorstate inventory CSV
SHOPIFY_SKUS_FILE = "shopify_skus.json"  # JSON file with all Shopify SKUs

# 🔹 Vendor Name Mapping
vendor_mapping = {
    "XRP-XTREME RACING PROD.": "XRP",
    "WISECO-PRO TRU": "Wiseco",
    "HOLLEY PERFORMANCE PROD.": "Holley",
    "FLOWTECH EXHAUST": "Flowtech",
    # Add more mappings as needed...
}

# ✅ Step 1: Load Motorstate CSV
def load_motorstate_csv():
    if not os.path.exists(CSV_FILENAME):
        print(f"❌ Error: {CSV_FILENAME} not found!")
        return None

    print(f"📂 Loading {CSV_FILENAME}...")
    df = pd.read_csv(CSV_FILENAME, encoding="ISO-8859-1")
    
    # Rename first column (assuming it's PartNumber)
    df.rename(columns={df.columns[0]: "PartNumber"}, inplace=True)
    
    # Select relevant columns
    df_filtered = df.loc[:, ["Brand", "ManufacturerPart", "QtyAvail"]]

    # Apply Vendor Name Mapping
    df_filtered["Brand"] = df_filtered["Brand"].replace(vendor_mapping)
    
    # Standardize formatting (strip spaces, title case, etc.)
    df_filtered["Brand"] = df_filtered["Brand"].str.strip().str.title()
    df_filtered["ManufacturerPart"] = df_filtered["ManufacturerPart"].str.strip()
    
    # Generate standardized SKU format
    df_filtered["Shopify_SKU"] = df_filtered["Brand"].str.upper() + " - " + df_filtered["ManufacturerPart"].str.upper()
    
    print(f"✅ Motorstate CSV loaded with {len(df_filtered)} products.")
    return df_filtered

# ✅ Step 2: Load Shopify SKUs from JSON
def load_shopify_skus():
    if not os.path.exists(SHOPIFY_SKUS_FILE):
        print(f"❌ Error: {SHOPIFY_SKUS_FILE} not found!")
        return None

    print(f"📂 Loading Shopify SKUs from {SHOPIFY_SKUS_FILE}...")
    with open(SHOPIFY_SKUS_FILE, "r") as file:
        shopify_skus = json.load(file)

    print(f"✅ Loaded {len(shopify_skus)} Shopify SKUs.")
    return shopify_skus

# ✅ Step 3: Match SKUs using exact and fuzzy matching
def match_skus(df_filtered, shopify_skus):
    print("🔍 Matching SKUs...")

    # Convert Shopify SKUs to a list for fuzzy matching
    shopify_sku_list = list(shopify_skus.keys())

    def find_best_match(sku):
        match, score = process.extractOne(sku, shopify_sku_list)
        return match if score > 90 else None  # Only match if similarity is 90%+

    df_filtered["Matched_SKU"] = df_filtered["Shopify_SKU"].apply(lambda x: x if x in shopify_skus else find_best_match(x))

    # Show sample mismatches
    mismatched = df_filtered[df_filtered["Matched_SKU"].isna()]
    if not mismatched.empty:
        print(f"⚠️ {len(mismatched)} SKUs did not match!")
        print(mismatched[["Shopify_SKU"]].head(20))  # Show first 20 mismatches

    print(f"✅ Matching completed. {len(df_filtered) - len(mismatched)} SKUs matched.")
    return df_filtered

# 🚀 Run Matching Process
if __name__ == "__main__":
    motorstate_data = load_motorstate_csv()
    shopify_skus = load_shopify_skus()

    if motorstate_data is not None and shopify_skus is not None:
        matched_data = match_skus(motorstate_data, shopify_skus)
        
        # Save results to CSV for review
        matched_data.to_csv("matched_skus.csv", index=False)
        print("✅ SKU matching results saved to matched_skus.csv!")
