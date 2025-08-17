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


project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))
from Autobot.VectorDB.NullPoint_Vector import connect_db
from Autobot.VectorDB.NullPoint_Vector import encrypt_data, decrypt_data

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).parent / 'models'
MODEL_DIR.mkdir(exist_ok=True)
MODEL_PATH = MODEL_DIR / 'vishing_logreg_model.pkl'
SCALER_PATH = MODEL_DIR / 'scaler.pkl'
NN_MODEL_PATH = MODEL_DIR / 'vishing_nn_model.pth'
FEATURE_ENGINEERING_PATH = MODEL_DIR / 'feature_engineering.pkl'

class FeatureEngineering:
    def __init__(self):
        self.feature_columns = [
            'hour_of_day', 'day_of_week', 'is_weekend',
            'has_urgent_words', 'has_suspicious_number',
            'has_money_mentions', 'has_personal_info',
            'call_duration', 'has_robocall_pattern',
            'has_automated_voice', 'has_background_noise'
        ]
        
    def extract_features(self, voice_data):
        """Extract features from voice call data."""
        df = pd.DataFrame(voice_data)
        
        # Time-based features
        df['timestamp'] = pd.to_datetime(df['date'])
        df['hour_of_day'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        
        # Content-based features
        df['has_urgent_words'] = df['transcript'].str.contains('urgent|immediate|action required|expire|limited time', case=False).astype(int)
        df['has_suspicious_number'] = df['caller_id'].str.contains(r'\+?\d{10,}', regex=True).astype(int)
        df['has_money_mentions'] = df['transcript'].str.contains('money|payment|bank|account|transfer|refund|claim', case=False).astype(int)
        df['has_personal_info'] = df['transcript'].str.contains('password|login|account|verify|confirm|security|update', case=False).astype(int)
        
        # Call-specific features
        df['call_duration'] = df['duration'].fillna(0)
        df['has_robocall_pattern'] = df['transcript'].str.contains('press|press 1|press 2|press 3|press 4|press 5|press 6|press 7|press 8|press 9|press 0', case=False).astype(int)
        df['has_automated_voice'] = df['transcript'].str.contains('automated|robot|machine|system', case=False).astype(int)
        df['has_background_noise'] = df['audio_quality'].str.contains('noise|static|interference', case=False).astype(int)
        
        return df[self.feature_columns]

class VishingDetector:
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
        logger.info("Connected to database for VishingDetector")

    def fetch_training_data(self):
        with self.conn.cursor() as cursor:
            cursor.execute("""
                SELECT embedding, label, caller_id, date, transcript, duration, audio_quality
                FROM messages
                WHERE label IS NOT NULL AND message_type = 'voice'
            """)
            rows = cursor.fetchall()
            if not rows:
                logger.warning("No training data found for voice calls")
                return np.array([]), np.array([])
            
            # Convert to DataFrame for feature engineering
            data = [{'embedding': row[0], 'label': row[1], 'caller_id': row[2], 
                    'date': row[3], 'transcript': row[4], 'duration': row[5],
                    'audio_quality': row[6]} for row in rows]
            df = pd.DataFrame(data)
            
            # Extract features
            features = self.feature_engineering.extract_features(df)
            
            # Combine with embeddings
            X = np.column_stack([np.array([np.array(row[0]) for row in rows]), features])
            y = np.array([row[1] for row in rows])
            
            return X, y

    def generate_analysis_report(self):
        """Generate detailed analysis report of vishing attempts."""
        with self.conn.cursor() as cursor:
            cursor.execute("""
                SELECT date, caller_id, transcript, duration, is_threat, confidence
                FROM messages
                WHERE message_type = 'voice'
                ORDER BY date DESC
            """)
            rows = cursor.fetchall()
            
        df = pd.DataFrame(rows, columns=['date', 'caller_id', 'transcript', 'duration', 'is_threat', 'confidence'])
        df['date'] = pd.to_datetime(df['date'])
        
        # Time-based analysis
        time_analysis = {
            'total_calls': len(df),
            'threat_count': df['is_threat'].sum(),
            'threat_percentage': (df['is_threat'].sum() / len(df)) * 100,
            'hourly_distribution': df.groupby(df['date'].dt.hour)['is_threat'].mean(),
            'daily_distribution': df.groupby(df['date'].dt.day_name())['is_threat'].mean(),
            'top_callers': df[df['is_threat'] == 1]['caller_id'].value_counts().head(10),
            'avg_confidence': df.groupby('is_threat')['confidence'].mean(),
            'avg_call_duration': df.groupby('is_threat')['duration'].mean(),
            'common_phrases': self._extract_common_phrases(df[df['is_threat'] == 1]['transcript'])
        }
        
        # Save report
        report_path = MODEL_DIR / 'vishing_analysis_report.json'
        pd.Series(time_analysis).to_json(report_path)
        logger.info(f"Analysis report saved to {report_path}")
        
        return time_analysis

    def _extract_common_phrases(self, texts):
        """Extract common phrases from threat transcripts."""
        # Join all transcripts and convert to lowercase
        text = ' '.join(texts).lower()
        
        # Extract 2-3 word phrases
        phrases = []
        for i in range(len(texts)):
            words = texts[i].lower().split()
            for j in range(len(words)-1):
                phrases.append(' '.join(words[j:j+2]))
            for j in range(len(words)-2):
                phrases.append(' '.join(words[j:j+3]))
        
        return pd.Series(phrases).value_counts().head(20).to_dict()

    # ... (rest of the methods similar to PhishingDetector)

if __name__ == "__main__":
    detector = VishingDetector(use_nn=False)
    detector.detect_threats()
    detector.generate_analysis_report() 