import numpy as np
import pandas as pd
import joblib
import os
import logging
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
import torch
import torch.nn as nn
from pathlib import Path
import sys
from datetime import datetime, timedelta

# import path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))
from Autobot.VectorDB.NullPoint_Vector import connect_db
from Autobot.VectorDB.NullPoint_Vector import encrypt_data, decrypt_data

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).parent / 'models'
MODEL_DIR.mkdir(exist_ok=True)
MODEL_PATH = MODEL_DIR / 'phishing_logreg_model.pkl'
SCALER_PATH = MODEL_DIR / 'scaler.pkl'
NN_MODEL_PATH = MODEL_DIR / 'phishing_nn_model.pth'
FEATURE_ENGINEERING_PATH = MODEL_DIR / 'feature_engineering.pkl'

class FeatureEngineering:
    def __init__(self):
        self.feature_columns = [
            'hour_of_day', 'day_of_week', 'is_weekend',
            'has_urgent_words', 'has_suspicious_domain',
            'has_money_mentions', 'has_personal_info',
            'url_count', 'attachment_count'
        ]
        
    def extract_features(self, email_data):
        """Extract features from email data."""
        df = pd.DataFrame(email_data)
        
        # Time-based features
        df['timestamp'] = pd.to_datetime(df['date'])
        df['hour_of_day'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        
        # Content-based features
        df['has_urgent_words'] = df['subject'].str.contains('urgent|immediate|action required', case=False).astype(int)
        df['has_suspicious_domain'] = df['sender'].str.contains('suspicious|unusual|unknown', case=False).astype(int)
        df['has_money_mentions'] = df['body'].str.contains('money|payment|bank|account|transfer', case=False).astype(int)
        df['has_personal_info'] = df['body'].str.contains('password|login|account|verify|confirm', case=False).astype(int)
        
        # Structure-based features
        df['url_count'] = df['body'].str.count('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        df['attachment_count'] = df['body'].str.count('attachment|attached|enclosed').astype(int)
        
        return df[self.feature_columns]

class SimpleNN(nn.Module):
    def __init__(self, input_size=384):
        super().__init__()
        self.layers = nn.Sequential(
            nn.Linear(input_size, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 2)
        )
    def forward(self, x):
        return self.layers(x)

class PhishingDetector:
    def __init__(self, use_nn=False):
        self.use_nn = use_nn
        self.model = None
        self.scaler = None
        self.feature_engineering = FeatureEngineering()
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.conn = None
        self.load_model()

    def connect_db(self):
        self.conn = connect_db()
        logger.info("Connected to database for PhishingDetector")

    def fetch_training_data(self):
        with self.conn.cursor() as cursor:
            cursor.execute("""
                SELECT embedding, label, subject, sender, date, body 
                FROM messages
                WHERE label IS NOT NULL AND message_type = 'email'
            """)
            rows = cursor.fetchall()
            if not rows:
                logger.warning("No training data found for emails")
                return np.array([]), np.array([])
            
            # Convert to DataFrame for feature engineering
            data = [{'embedding': row[0], 'label': row[1], 'subject': row[2], 
                    'sender': row[3], 'date': row[4], 'body': row[5]} for row in rows]
            df = pd.DataFrame(data)
            
            # Extract features
            features = self.feature_engineering.extract_features(df)
            
            # Combine with embeddings
            X = np.column_stack([np.array([np.array(row[0]) for row in rows]), features])
            y = np.array([row[1] for row in rows])
            
            return X, y

    def generate_analysis_report(self):
        """Generate detailed analysis report of phishing attempts."""
        with self.conn.cursor() as cursor:
            cursor.execute("""
                SELECT date, subject, sender, is_threat, confidence
                FROM messages
                WHERE message_type = 'email'
                ORDER BY date DESC
            """)
            rows = cursor.fetchall()
            
        df = pd.DataFrame(rows, columns=['date', 'subject', 'sender', 'is_threat', 'confidence'])
        df['date'] = pd.to_datetime(df['date'])
        
        # Time-based analysis
        time_analysis = {
            'total_emails': len(df),
            'threat_count': df['is_threat'].sum(),
            'threat_percentage': (df['is_threat'].sum() / len(df)) * 100,
            'hourly_distribution': df.groupby(df['date'].dt.hour)['is_threat'].mean(),
            'daily_distribution': df.groupby(df['date'].dt.day_name())['is_threat'].mean(),
            'top_senders': df[df['is_threat'] == 1]['sender'].value_counts().head(10),
            'avg_confidence': df.groupby('is_threat')['confidence'].mean()
        }
        
        # Save report
        report_path = MODEL_DIR / 'phishing_analysis_report.json'
        pd.Series(time_analysis).to_json(report_path)
        logger.info(f"Analysis report saved to {report_path}")
        
        return time_analysis

    def train_model(self, X, y):
        if len(X) == 0 or len(y) == 0:
            logger.warning("No data available for training.")
            return None
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        joblib.dump(self.scaler, SCALER_PATH)
        if self.use_nn:
            self.model = SimpleNN(input_size=X.shape[1]).to(self.device)
            criterion = nn.CrossEntropyLoss()
            optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
            X_tensor = torch.FloatTensor(X_scaled).to(self.device)
            y_tensor = torch.LongTensor(y).to(self.device)
            self.model.train()
            for epoch in range(30):  # Fewer epochs for speed; tune as needed
                optimizer.zero_grad()
                outputs = self.model(X_tensor)
                loss = criterion(outputs, y_tensor)
                loss.backward()
                optimizer.step()
                if (epoch+1) % 10 == 0:
                    logger.info(f"Epoch {epoch+1}, Loss: {loss.item():.4f}")
            torch.save(self.model.state_dict(), NN_MODEL_PATH)
            logger.info(f"NN model trained and saved to {NN_MODEL_PATH}")
        else:
            self.model = LogisticRegression(max_iter=2000, solver='liblinear', random_state=42)
            self.model.fit(X_scaled, y)
            joblib.dump(self.model, MODEL_PATH)
            logger.info(f"Logistic Regression model trained and saved to {MODEL_PATH}")
        return self.model

    def load_model(self):
        if self.use_nn:
            if NN_MODEL_PATH.exists() and SCALER_PATH.exists():
                self.model = SimpleNN().to(self.device)
                self.model.load_state_dict(torch.load(NN_MODEL_PATH, map_location=self.device))
                self.scaler = joblib.load(SCALER_PATH)
                logger.info("NN model and scaler loaded successfully")
        else:
            if MODEL_PATH.exists() and SCALER_PATH.exists():
                self.model = joblib.load(MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)
                logger.info("Logistic Regression model and scaler loaded successfully")

    def predict(self, embedding):
        X_scaled = self.scaler.transform([embedding])
        if self.use_nn:
            self.model.eval()
            with torch.no_grad():
                X_tensor = torch.FloatTensor(X_scaled).to(self.device)
                outputs = self.model(X_tensor)
                probs = torch.softmax(outputs, dim=1)
                pred = torch.argmax(probs, dim=1).item()
                confidence = torch.max(probs).item()
                return pred, confidence
        else:
            pred = self.model.predict(X_scaled)[0]
            confidence = self.model.predict_proba(X_scaled)[0][pred]
            return pred, confidence

    def detect_threats(self):
        self.connect_db()
        if self.model is None or self.scaler is None:
            X, y = self.fetch_training_data()
            self.train_model(X, y)
        with self.conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, embedding FROM messages
                WHERE is_threat = 0 AND message_type = 'email'
            """)
            messages = cursor.fetchall()
            for msg_id, embedding in messages:
                pred, confidence = self.predict(np.array(embedding))
                cursor.execute(
                    "UPDATE messages SET is_threat = %s, confidence = %s WHERE id = %s",
                    (int(pred), float(confidence), msg_id)
                )
                logger.info(f"Email {msg_id} classified as {'THREAT' if pred else 'LEGITIMATE'} (confidence: {confidence:.2f})")
            self.conn.commit()
        self.conn.close()

if __name__ == "__main__":
    detector = PhishingDetector(use_nn=False)
    detector.detect_threats()
    report = detector.generate_analysis_report()