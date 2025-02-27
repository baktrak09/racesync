import pandas as pd
from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from ftplib import FTP
import requests
import os
import threading
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class ShopifyApp(App):
    def __init__(self, **kwargs):
        super(ShopifyApp, self).__init__(**kwargs)
        self.skus = {}  # Ensure skus is always initialized

class ShopifyApp(App):
    def build(self):
        # Setup the main layout
        layout = BoxLayout(orientation='vertical')
        
        # Status label
        self.label = Label(text='Ready to update SKUs')
        
        # Button to fetch SKUs
        fetch_button = Button(text='Fetch SKUs')
        fetch_button.bind(on_press=lambda x: self.on_fetch_press())
        
        # Button to update inventory and pricing
        update_button = Button(text='Update Inventory and Pricing')
        update_button.bind(on_press=lambda x: self.on_update_press())

        # New button to fetch and save all product data
        fetch_all_button = Button(text='Fetch All Products')
        fetch_all_button.bind(on_press=lambda x: self.on_fetch_all_products_press())

        # Adding widgets to the layout
        layout.add_widget(self.label)
        layout.add_widget(fetch_button)
        layout.add_widget(update_button)
        layout.add_widget(fetch_all_button)  # Add the new button to the layout

        return layout

    def on_fetch_press(self):
        # This method should implement the fetching of SKUs
        self.label.text = 'Fetching SKUs...'
        # Call a function to fetch SKUs
        # Example: fetch_skus()

    def on_update_press(self):
        # This method should implement the updating of inventory and pricing
        self.label.text = 'Updating inventory and pricing...'
        # Call a function to update inventory
        # Example: update_inventory()
    
    def on_fetch_all_products_press(self):
        # This method should implement the fetching and saving of all product data
        self.label.text = 'Fetching and saving all product data...'
        # Implement or call a function that fetches and saves all products
        # Example: fetch_all_products()
        products = fetch_all_products()  # Assuming fetch_all_products is defined to handle fetching and saving
        if isinstance(products, str):
            self.label.text = products
        else:
            self.label.text = f'Successfully fetched and saved {len(products)} products.'

    def on_fetch_skus(self):
        threading.Thread(target=self.fetch_all_shopify_skus).start()

    def fetch_all_shopify_skus(self):
        shop_url = os.getenv('SHOP_URL')
        access_token = os.getenv('ACCESS_TOKEN')
        api_version = os.getenv('API_VERSION')
        headers = {"X-Shopify-Access-Token": access_token}
        products = []
        url = f"{shop_url}/admin/api/{api_version}/products.json?fields=id,variants&limit=250"

        while url:
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                self.label.text = "Error fetching data from Shopify."
                return

            data = response.json()
            products.extend(data['products'])

            link = response.headers.get('Link')
            next_link = None
            if link:
                links = link.split(',')
                next_link = next((l for l in links if 'rel="next"' in l), None)
            if next_link:
                url = next_link[next_link.find('<')+1:next_link.find('>')]
            else:
                url = None

        self.skus = {variant['sku']: variant for product in products for variant in product['variants'] if 'sku' in variant}
        print("SKUs fetched:", self.skus)
        self.label.text = f'Fetched {len(self.skus)} SKUs'
        self.download_csv_from_ftp()

    def on_download_csv(self):
        threading.Thread(target=self.download_csv_from_ftp).start()

    def download_csv_from_ftp(self):
        FTP_HOST = os.getenv('FTP_HOST')
        FTP_USER = os.getenv('FTP_USER')
        FTP_PASS = os.getenv('FTP_PASS')
        CSV_FILENAME = "Motorstate1.csv"

        try:
            with FTP(FTP_HOST) as ftp:
                ftp.login(FTP_USER, FTP_PASS)
                ftp.set_pasv(True)
                if CSV_FILENAME in ftp.nlst():
                    with open(CSV_FILENAME, "wb") as file:
                        ftp.retrbinary(f'RETR {CSV_FILENAME}', file.write)
                    print(f"{CSV_FILENAME} downloaded.")
                    self.load_and_match_csv(CSV_FILENAME)
                else:
                    print("CSV file not found on FTP server.")
                    self.label.text = "CSV not found on FTP server."
        except Exception as e:
            print(f"FTP connection failed: {str(e)}")
            self.label.text = f"Failed to connect to FTP server: {str(e)}"
            self.load_and_match_csv("Motorstate1.csv")

    def load_and_match_csv(self, filename):
        try:
            df = pd.read_csv(filename, encoding="ISO-8859-1")
            # Normalize SKU data
            df['Shopify_SKU'] = df['Brand'].str.strip().str.title() + ' - ' + df['ManufacturerPart'].str.strip()
            
            # Print a few SKUs for debugging
            print("First few SKUs from CSV:")
            print(df['Shopify_SKU'].head())

            # Attempt to match SKUs
            matched_skus = df[df['Shopify_SKU'].isin(self.skus.keys())]
            print(f"Matched SKUs: {matched_skus}")

            if matched_skus.empty:
                print("No SKUs matched. Check formatting and presence in Shopify.")
            else:
                print(f"Total matched SKUs: {len(matched_skus)}")

            self.label.text = f"Loaded CSV and matched {len(matched_skus)} SKUs"
        except Exception as e:
            print(f"Failed to load and process CSV: {str(e)}")
            self.label.text = f"Failed to load and process CSV: {str(e)}"
 
    def update_inventory_and_pricing(skus):
    # Assuming skus is a dictionary with SKU as key and variant details as value
        for sku, details in skus.items():
            product_id = details['product_id']
            variant_id = details['variant_id']
            new_inventory = 100  # Example static value, fetch real values from your CSV
            new_price = 29.99  # Example static value, fetch real values from your CSV

            # Construct the API endpoint
            endpoint = f"{os.getenv('SHOP_URL')}/admin/api/{os.getenv('API_VERSION')}/variants/{variant_id}.json"
            data = {
                "variant": {
                    "id": variant_id,
                    "price": new_price,
                    "inventory_quantity": new_inventory
                }
            }
            headers = {"X-Shopify-Access-Token": os.getenv('ACCESS_TOKEN'), "Content-Type": "application/json"}
            response = requests.put(endpoint, json=data, headers=headers)
            if response.status_code != 200:
                return f"Failed to update {sku}: {response.text}"
        return "All SKUs updated successfully."
        
    def fetch_all_products():
        api_version = os.getenv('API_VERSION')
        shop_url = os.getenv('SHOP_URL')
        access_token = os.getenv('ACCESS_TOKEN')
        headers = {
            'Content-Type': 'application/json',
            'X-Shopify-Access-Token': access_token
        }

        # Extensive list of fields to include in the API call
        fields = ('id, title, body_html, vendor, product_type, created_at, handle, '
                'updated_at, published_at, template_suffix, status, published_scope, '
                'tags, admin_graphql_api_id, variants, options, images, image')

        products = []
        url = f"{shop_url}/admin/api/{api_version}/products.json?fields={fields}&limit=250"
        
        while url:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                products.extend(data['products'])
                # Check for link to next page
                link = response.headers.get('Link', None)
                url = None
                if link:
                    next_links = [l for l in link.split(',') if 'rel="next"' in l]
                    if next_links:
                        url = next_links[0].split(';')[0].strip('<>')
            else:
                print(f"Failed to fetch products: {response.text}")
                break

        # Save the data to a local file
        with open('shopify_products.json', 'w') as f:
            json.dump(products, f)
        print(f"Saved {len(products)} products to 'shopify_products.json'")


    def load_products_from_file():
        with open('shopify_products.json', 'r') as f:
            products = json.load(f)
        return products

        products = load_products_from_file()
        print(f"Loaded {len(products)} products from file.")

    def fetch_products(self, instance):
        # Call the fetch all products function
        products = fetch_all_products()  # This function needs to be defined elsewhere in your codebase
        
        if isinstance(products, str):
            # If the returned value is a string, it's an error message
            self.status_label.text = products
        else:
            # Update label with success message
            self.status_label.text = f'Successfully fetched and saved {len(products)} products.'


if __name__ == '__main__':
    ShopifyApp().run()
