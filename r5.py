import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QTextEdit
import requests

class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Shopify Flask App Control Panel")
        self.setGeometry(100, 100, 800, 600)  # Position and size of the window

        # Main widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        # Buttons
        self.btn_fetch_products = QPushButton("Fetch Products")
        self.btn_update_inventory = QPushButton("Update Inventory")
        self.btn_download_csv = QPushButton("Download CSV")

        # Connect buttons to functions
        self.btn_fetch_products.clicked.connect(self.fetch_products)
        self.btn_update_inventory.clicked.connect(self.update_inventory)
        self.btn_download_csv.clicked.connect(self.download_csv)

        # Add buttons to layout
        self.layout.addWidget(self.btn_fetch_products)
        self.layout.addWidget(self.btn_update_inventory)
        self.layout.addWidget(self.btn_download_csv)

        # Text area for displaying information
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.layout.addWidget(self.text_area)

    def fetch_products(self):
        try:
            response = requests.get('http://127.0.0.1:5000/api/products')  # Corrected URL
            if response.status_code == 200:
                self.text_area.setText(str(response.json()))  # Display products in the text area
            else:
                self.text_area.setText("Failed to fetch products")
        except Exception as e:
            self.text_area.setText(f"Error: {str(e)}")

    def update_inventory(self):
        # Placeholder for inventory update code
        self.text_area.setText("Updating inventory...")

    def download_csv(self):
        # Placeholder for CSV download code
        self.text_area.setText("Downloading CSV...")

def main():
    app = QApplication(sys.argv)
    window = MainApp()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
