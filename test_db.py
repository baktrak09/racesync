import sqlite3
import os

db_path = os.path.abspath("instance/app.db")
print("Using database:", db_path)

try:
    conn = sqlite3.connect(db_path)
    print("✅ Successfully connected to database!")
except sqlite3.OperationalError as e:
    print("🚨 ERROR: Unable to open database file:", e)
