import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

DB_NAME = "emails.db"

def connect_db(db_name="DB_NAME"):
    """Connect to the SQLite database."""
    conn = sqlite3.connect(db_name)
    return conn

def create_table_if_not_exists(conn):
    """Create the emails table if it does not exist."""
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT,
                sender TEXT,
                date TEXT,
                body TEXT,
                spam INTEGER DEFAULT 0
            )
        ''')
        conn.commit()
        print("Database and table created/verified successfully.")
    except sqlite3.Error as e:
        print(f"Error creating table: {e}")

def add_spam_column_if_not_exists(conn):
    """Add the 'spam' column to the table if it does not exist."""
    try:
        cursor = conn.cursor()
        cursor.execute('''
            ALTER TABLE emails
            ADD COLUMN spam INTEGER DEFAULT 0
        ''')
        conn.commit()
        print("Spam column added to the table.")
    except sqlite3.OperationalError as e:
        # If the column already exists, ignore the error.
        print(f"Spam column already exists: {e}")

if __name__ == "__main__":
    conn = connect_db()
    create_table_if_not_exists(conn)
    add_spam_column_if_not_exists(conn)
    conn.close()