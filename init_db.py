import os
import psycopg2

DATABASE_URL = "postgresql://racesyncapp_user:GLSjATuwmhK5hsmlF84ol6uPnF8BMzC4@dpg-cv2hj1hu0jms73902ku0-a/racesyncapp"

def create_tables():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS shopify_stores (
            id SERIAL PRIMARY KEY,
            store_url TEXT UNIQUE NOT NULL,
            access_token TEXT NOT NULL,
            api_key TEXT NOT NULL,
            api_secret TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("Database initialized!")

if __name__ == "__main__":
    create_tables()
