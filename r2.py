import json
import os
import threading
import requests
import pandas as pd
from ftplib import FTP
from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from urllib.parse import unquote
from dotenv import load_dotenv
import urllib.parse
import time

load_dotenv()

class ShopifyApp(App):
    def build(self):
        layout = BoxLayout(orientation='vertical')
        self.label = Label(text='Ready to manage SKUs')
        fetch_button = Button(text='Fetch SKUs')
        update_button = Button(text='Update Inventory and Pricing')
        fetch_all_button = Button(text='Fetch All Products')

        fetch_button.bind(on_press=lambda x: self.on_fetch_press())
        update_button.bind(on_press=lambda x: self.on_update_press())
        fetch_all_button.bind(on_press=lambda x: self.on_fetch_all_products_press())

        layout.add_widget(self.label)
        layout.add_widget(fetch_button)
        layout.add_widget(update_button)
        layout.add_widget(fetch_all_button)
        return layout

    def on_fetch_press(self):
        threading.Thread(target=self.fetch_all_shopify_skus).start()

    def on_update_press(self):
        threading.Thread(target=self.update_inventory_and_pricing).start()

    def on_fetch_all_products_press(self):
        threading.Thread(target=self.fetch_all_products).start()

    def fetch_all_shopify_skus(self):
        shop_url = os.getenv('SHOP_URL')
        access_token = os.getenv('ACCESS_TOKEN')
        api_version = os.getenv('API_VERSION')
        headers = {"X-Shopify-Access-Token": access_token}
        products = []
        url = f"{shop_url}/admin/api/{api_version}/products.json?fields=id,variants&limit=250"

        while url:
            print("Fetching URL:", url)  # Debug print
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                products.extend(data['products'])
                link = response.headers.get('Link')
                if link:
                    links = link.split(',')
                    next_link = next((l for l in links if 'rel="next"' in l), None)
                    if next_link:
                        url = unquote(next_link[next_link.find('<')+1:next_link.find('>')])
                else:
                    url = None
            else:
                print("Error fetching products:", response.text)
                break
        self.label.text = f'Fetched {len(products)} products.'

    def update_inventory_and_pricing(self):
        self.label.text = "Updating inventory and pricing..."

    def fetch_all_products(self):
        shop_url = os.getenv('SHOP_URL')
        access_token = os.getenv('ACCESS_TOKEN')
        api_version = os.getenv('API_VERSION')
        headers = {"X-Shopify-Access-Token": access_token}

        products = []
        url = f"{shop_url}/admin/api/{api_version}/products.json?fields=id,title,body_html,vendor,product_type,created_at,updated_at,published_at,tags,variants,options,images,metafields&limit=250"

        while url:
            print("Fetching URL:", url)  # Debug: print the URL being fetched
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    products.extend(data['products'])
                    link = response.headers.get('Link')
                    if link:
                        links = link.split(',')
                        next_url = next((l for l in links if 'rel="next"' in l), None)
                        if next_url:
                            url = next_url[next_url.find('<')+1:next_url.find('>')]
                            url = urllib.parse.unquote(url)  # Ensure the URL is correctly decoded
                        else:
                            url = None
                    else:
                        url = None
                else:
                    print(f"Failed to fetch products: {response.text}, Status Code: {response.status_code}")
                    break
            except requests.exceptions.RequestException as e:
                print(f"Request failed: {e}, URL was: {url}")
                break  # Optionally, you might want to retry or handle differently
            time.sleep(1)  # Delay to manage API rate limiting

        # Save the data to a local JSON file
        with open('shopify_products.json', 'w') as file:
            json.dump(products, file)
        print(f"Saved {len(products)} products to 'shopify_products.json'")



if __name__ == "__main__":
    app = ShopifyApp()
    app.fetch_all_products()