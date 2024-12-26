import email
import imaplib
import sqlite3
import time
from email.header import decode_header
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

DB_NAME = "emails.db"

def connect_db(db_name="emails.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    return conn


def insert_emails(conn, subject, sender, date, body, spam):
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR IGNORE INTO emails (subject, sender, date, body, spam)
        VALUES (?, ?, ?, ?, ?)
    ''', (subject, sender, date, body, int(spam)))
    conn.commit()


def fetch_emails():
    conn = connect_db()

    imap_host = 'imap.mail.yahoo.com'
    imap_user = os.getenv('IMAP_USER')
    imap_pass = os.getenv('IMAP_PASS')

    mail = imaplib.IMAP4_SSL(imap_host)
    mail.login(imap_user, imap_pass)

    print("Successfully logged in to IMAP server.")

    mail.select("inbox")

    status, data = mail.search(None, "ALL")
    email_ids = data[0].split()
    print(f"Found {len(email_ids)} emails.")

    for email_id in email_ids:
        try:
            status, data = mail.fetch(email_id, "(RFC822)")
            for response_part in data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject = decode_header(msg["Subject"])[0][0]
                    sender = msg.get("From")
                    date = msg.get("Date")

                    if msg.is_multipart():
                        body = ""
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    else:
                        body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

                    spam = 'Yes'  # Placeholder for actual spam detection logic
                    insert_emails(conn, subject, sender, date, body, spam)
        except Exception as e:
            print(f"Error processing email ID {email_id}: {e}")

    mail.logout()
    print("Finished processing emails.")
    conn.close()


if __name__ == "__main__":
    fetch_emails()
