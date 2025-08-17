import psycopg2
import numpy as np
from sklearn.naive_bayes import MultinomialNB
import joblib
import os

# Placeholder: Fill in your DB config here
DB_CONFIG = {...}
MODEL_PATH = 'unified_guard_model.pkl'

def connect_db():
    '''Connect to the PostgreSQL database.'''
    return psycopg2.connect(**DB_CONFIG)

def fetch_training_data(conn, guard_type=None):
    '''
    Fetch embeddings and labels from the DB.
    If guard_type is specified, filter by type ('email', 'sms', 'voice').
    '''
    with conn.cursor() as cursor:
        if guard_type:
            cursor.execute("SELECT embedding, spam FROM messages WHERE spam IS NOT NULL AND type = %s", (guard_type,))
        else:
            cursor.execute("SELECT embedding, spam FROM messages WHERE spam IS NOT NULL")
        rows = cursor.fetchall()
        X = np.array([np.array(row[0]) for row in rows])
        y = np.array([row[1] for row in rows])
    return X, y

def train_model(X, y):
    '''
    Train a Naive Bayes classifier on embeddings and save the model.
    '''
    model = MultinomialNB()
    model.fit(X, y)
    joblib.dump(model, MODEL_PATH)
    return model

def load_model():
    '''Load the trained model from disk, or return None if not found.'''
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    return None

def predict_message(model, embedding):
    '''Predict spam/threat for a single message embedding.'''
    return model.predict([embedding])[0]

def incremental_train(conn, guard_type=None):
    '''
    Incrementally train the model with new data from the DB.
    '''
    X, y = fetch_training_data(conn, guard_type)
    if len(X) == 0:
        print("No data available for training.")
        return
    model = train_model(X, y)
    print(f"Model trained on {'all types' if not guard_type else guard_type} and saved to {MODEL_PATH}.")
    return model

def detect_threats(guard_type=None):
    '''
    Main entry: train model (if needed), predict on new/unlabeled messages, and update DB.
    '''
    conn = connect_db()
    model = load_model()
    if model is None:
        print("No model found. Training a new model...")
        model = incremental_train(conn, guard_type)
    with conn.cursor() as cursor:
        if guard_type:
            cursor.execute("SELECT id, embedding FROM messages WHERE spam IS NULL AND type = %s", (guard_type,))
        else:
            cursor.execute("SELECT id, embedding FROM messages WHERE spam IS NULL")
        messages = cursor.fetchall()
        for msg_id, embedding in messages:
            prediction = predict_message(model, np.array(embedding))
            cursor.execute("UPDATE messages SET spam = %s WHERE id = %s", (int(prediction), msg_id))
    conn.commit()
    print("Threat detection completed and DB updated.")
    conn.close()

if __name__ == "__main__":
    # Example usage: detect_threats() or detect_threats('sms')
    detect_threats()