import pandas as pd

# Load the CSV file
filename = "Inventory.csv"

try:
    df = pd.read_csv(filename, encoding="utf-8")  # Try UTF-8 first
except UnicodeDecodeError:
    df = pd.read_csv(filename, encoding="ISO-8859-1")  # Try fallback encoding

# Display the first 5 rows
print(df.head())
