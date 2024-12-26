import pandas as pd
import sqlite3
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
import joblib
import os


def connect_db(db_name="emails.db"):
    conn = sqlite3.connect(db_name)
    return conn


def fetch_emails_for_training(conn):
    df = pd.read_sql_query('SELECT * FROM emails WHERE spam IS NULL', conn)
    print(f"Fetched {len(df)} emails for training.")
    return df


def train_model(df):
    if df.empty:
        print("No data available for training. Skipping model training.")
        return None

    X = df['body']
    y = df['spam']

    if os.path.exists('model.pkl'):
        model = joblib.load('model.pkl')
    else:
        model = make_pipeline(CountVectorizer(), MultinomialNB())
        model.fit(X, y)
        joblib.dump(model, 'model.pkl')

    return model


def detect_phishing():
    conn = connect_db()
    df = fetch_emails_for_training(conn)
    if df.empty:
        print("No data available for training.")
        conn.close()
        return

    model = train_model(df)
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT * FROM emails WHERE spam IS NULL')
        emails = cursor.fetchall()
        print(f"Detected {len(emails)} emails for phishing detection.")

        for email in emails:
            email_id, subject, sender, date, body, _ = email
            prediction = model.predict([body])[0]
            if prediction == 1:
                cursor.execute('UPDATE emails SET spam = ? WHERE id = ?', (1, email_id))
                print(f"Email with ID {email_id} marked as spam.")
            else:
                cursor.execute('UPDATE emails SET spam = ? WHERE id = ?', (0, email_id))

        conn.commit()
        print("Phishing detection completed successfully.")
    except Exception as e:
        print(f"Error in phishing detection: {e}")

    conn.close()


if __name__ == "__main__":
    detect_phishing()
