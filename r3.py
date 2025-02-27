import json
import os
import threading
import requests
from kivy.app import App
from kivy.clock import Clock
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from dotenv import load_dotenv
from urllib.parse import unquote
import time

load_dotenv()

class ShopifyApp(App):
    def build(self):
        self.root = BoxLayout(orientation='vertical')
        self.label = Label(text='Ready to manage SKUs')
        self.root.add_widget(self.label)

        # Buttons with actions
        buttons = {
            'Fetch SKUs': self.on_fetch_skus,
            'Update Inventory and Pricing': self.on_update_inventory,
            'Fetch All Products': self.on_fetch_all_products
        }

        for text, action in buttons.items():
            button = Button(text=text)
            button.bind(on_press=lambda instance, x=action: x())
            self.root.add_widget(button)

        return self.root

    def on_fetch_skus(self, *args):
        threading.Thread(target=self.fetch_skus).start()

    def on_update_inventory(self, *args):
        threading.Thread(target=self.update_inventory_and_pricing).start()

    def on_fetch_all_products(self, *args):
        threading.Thread(target=self.fetch_all_products).start()

    def fetch_skus(self):
        # Simulating SKU fetching
        time.sleep(2)  # Simulate time delay
        Clock.schedule_once(lambda dt: self.update_label('SKUs fetched.'))

    def update_inventory_and_pricing(self):
        # Simulating inventory update
        time.sleep(2)  # Simulate time delay
        Clock.schedule_once(lambda dt: self.update_label('Inventory and pricing updated.'))

    def fetch_all_products(self):
        shop_url = os.getenv('SHOP_URL')
        access_token = os.getenv('ACCESS_TOKEN')
        api_version = os.getenv('API_VERSION')
        headers = {"X-Shopify-Access-Token": access_token}

        products = []
        url = f"{shop_url}/admin/api/{api_version}/products.json?fields=id,title,body_html,vendor,product_type,created_at,updated_at,published_at,tags,variants,options,images,metafields&limit=250"

        while url:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                products.extend(data['products'])
                link = response.headers.get('Link')
                if link:
                    links = link.split(',')
                    next_url = next((l for l in links if 'rel="next"' in l), None)
                    if next_url:
                        url = unquote(next_url[next_url.find('<')+1:next_url.find('>')])
                else:
                    url = None
            else:
                Clock.schedule_once(lambda dt: self.update_label(f"Failed to fetch products: {response.status_code}"))
                break

        with open('shopify_products.json', 'w') as file:
            json.dump(products, file)

        Clock.schedule_once(lambda dt: self.update_label(f'Saved {len(products)} products to shopify_products.json'))

    def update_label(self, text):
        self.label.text = text

if __name__ == "__main__":
    ShopifyApp().run()
