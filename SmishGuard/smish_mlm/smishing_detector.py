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
import re

# Fix import path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))
from Autobot.VectorDB.NullPoint_Vector import connect_db
from Autobot.VectorDB.NullPoint_Vector import encrypt_data, decrypt_data

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).parent / 'models'
MODEL_DIR.mkdir(exist_ok=True)
MODEL_PATH = MODEL_DIR / 'smishing_logreg_model.pkl'
SCALER_PATH = MODEL_DIR / 'scaler.pkl'
NN_MODEL_PATH = MODEL_DIR / 'smishing_nn_model.pth'
FEATURE_ENGINEERING_PATH = MODEL_DIR / 'feature_engineering.pkl'

class FeatureEngineering:
    def __init__(self):
        self.feature_columns = [
            'hour_of_day', 'day_of_week', 'is_weekend',
            'has_urgent_words', 'has_suspicious_number',
            'has_money_mentions', 'has_personal_info',
            'url_count', 'shortened_url_count',
            'message_length', 'has_unicode_chars'
        ]
        
    def extract_features(self, sms_data):
        """Extract features from SMS data."""
        df = pd.DataFrame(sms_data)
        
        # Time-based features
        df['timestamp'] = pd.to_datetime(df['date'])
        df['hour_of_day'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        
        # Content-based features
        df['has_urgent_words'] = df['body'].str.contains('urgent|immediate|action required|expire|limited time', case=False).astype(int)
        df['has_suspicious_number'] = df['sender'].str.contains(r'\+?\d{10,}', regex=True).astype(int)
        df['has_money_mentions'] = df['body'].str.contains('money|payment|bank|account|transfer|refund|claim', case=False).astype(int)
        df['has_personal_info'] = df['body'].str.contains('password|login|account|verify|confirm|security|update', case=False).astype(int)
        
        # Structure-based features
        df['url_count'] = df['body'].str.count('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        df['shortened_url_count'] = df['body'].str.count('bit\.ly|t\.co|goo\.gl|tinyurl\.com').astype(int)
        df['message_length'] = df['body'].str.len()
        df['has_unicode_chars'] = df['body'].str.contains(r'[^\x00-\x7F]').astype(int)
        
        return df[self.feature_columns]

class SmishingDetector:
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
        logger.info("Connected to database for SmishingDetector")

    def fetch_training_data(self):
        with self.conn.cursor() as cursor:
            cursor.execute("""
                SELECT embedding, label, sender, date, body 
                FROM messages
                WHERE label IS NOT NULL AND message_type = 'sms'
            """)
            rows = cursor.fetchall()
            if not rows:
                logger.warning("No training data found for SMS")
                return np.array([]), np.array([])
            
            # Convert to DataFrame for feature engineering
            data = [{'embedding': row[0], 'label': row[1], 'sender': row[2], 
                    'date': row[3], 'body': row[4]} for row in rows]
            df = pd.DataFrame(data)
            
            # Extract features
            features = self.feature_engineering.extract_features(df)
            
            # Combine with embeddings
            X = np.column_stack([np.array([np.array(row[0]) for row in rows]), features])
            y = np.array([row[1] for row in rows])
            
            return X, y

    def generate_analysis_report(self):
        """Generate detailed analysis report of smishing attempts."""
        with self.conn.cursor() as cursor:
            cursor.execute("""
                SELECT date, sender, body, is_threat, confidence
                FROM messages
                WHERE message_type = 'sms'
                ORDER BY date DESC
            """)
            rows = cursor.fetchall()
            
        df = pd.DataFrame(rows, columns=['date', 'sender', 'body', 'is_threat', 'confidence'])
        df['date'] = pd.to_datetime(df['date'])
        
        # Time-based analysis
        time_analysis = {
            'total_sms': len(df),
            'threat_count': df['is_threat'].sum(),
            'threat_percentage': (df['is_threat'].sum() / len(df)) * 100,
            'hourly_distribution': df.groupby(df['date'].dt.hour)['is_threat'].mean(),
            'daily_distribution': df.groupby(df['date'].dt.day_name())['is_threat'].mean(),
            'top_senders': df[df['is_threat'] == 1]['sender'].value_counts().head(10),
            'avg_confidence': df.groupby('is_threat')['confidence'].mean(),
            'common_keywords': self._extract_common_keywords(df[df['is_threat'] == 1]['body'])
        }
        
        # Save report
        report_path = MODEL_DIR / 'smishing_analysis_report.json'
        pd.Series(time_analysis).to_json(report_path)
        logger.info(f"Analysis report saved to {report_path}")
        
        return time_analysis

    def _extract_common_keywords(self, texts):
        """Extract common keywords from threat messages."""
        words = ' '.join(texts).lower()
        words = re.findall(r'\b\w+\b', words)
        return pd.Series(words).value_counts().head(20).to_dict()

    # ... (rest of the methods similar to PhishingDetector)

if __name__ == "__main__":
    detector = SmishingDetector(use_nn=False)
    detector.detect_threats()
    detector.generate_analysis_report() 