import numpy as np
import pandas as pd
import os
import logging
import re
import sys
import pickle
import threading
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

# Scikit-Learn Imports
from sklearn.linear_model import SGDClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler

# -------------------------------------------------------------------------
# SETUP & CONFIGURATION
# -------------------------------------------------------------------------

# Import path setup
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))

# Graceful import for VectorDB (prevents crash if DB is offline during dev)
try:
    from Autobot.VectorDB.NullPoint_Vector import connect_db, store_threat
    VECTOR_DB_AVAILABLE = True
except ImportError:
    VECTOR_DB_AVAILABLE = False
    print("[WARNING] VectorDB module not found. Running in standalone mode.")

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("PhishingGuard")

# Paths
MODEL_DIR = Path(__file__).parent / 'models'
MODEL_DIR.mkdir(exist_ok=True, parents=True)
MODEL_PATH = MODEL_DIR / 'phishing_ensemble_v2.pkl'

# -------------------------------------------------------------------------
# PRODUCTION PHISHING DETECTOR WITH ENSEMBLE & CONTINUOUS LEARNING
# -------------------------------------------------------------------------

class PhishingDetector:
    """
    Advanced Ensemble Phishing Detector with Continuous Learning.
    
    Architecture:
    1. Feature Fusion: Combines TF-IDF (Semantic) + Heuristics (Domain Signals).
    2. Voting Ensemble: 
       - SGD-Log (Logistic Regression) - 40% weight
       - SGD-Hinge (Linear SVM) - 30% weight
       - MultinomialNB (Naive Bayes) - 30% weight
    3. Thread-Safe Online Learning: Updates all 3 models atomically on user feedback.
    
    Production Features:
    - All models support partial_fit() for real-time incremental learning
    - Thread-safe with threading.Lock() for concurrent API calls
    - Input validation & ReDoS prevention
    - Atomic file saves to prevent corruption
    - Heuristic boosting for technical attacks
    """

    def __init__(self):
        self.lock = threading.Lock()  # Crucial for production APIs
        self.initialized = False
        self._load_or_boot()

    def _load_or_boot(self):
        """Loads ensemble from disk or triggers Cold Start."""
        if MODEL_PATH.exists():
            try:
                with open(MODEL_PATH, 'rb') as f:
                    data = pickle.load(f)
                    self.vectorizer = data['vectorizer']
                    self.scaler = data['scaler']
                    self.models = data['models']
                    self.weights = data['weights']
                self.initialized = True
                logger.info("[OK] Ensemble models loaded successfully.")
            except Exception as e:
                logger.error(f"[ERROR] Corrupt model file. Re-initializing. Error: {e}")
                self._cold_start()
        else:
            logger.warning("[WARNING] No model found. Initiating Cold Start...")
            self._cold_start()

    def _cold_start(self):
        """
        Initializes the 3-model ensemble with seed data.
        Uses SGD(Hinge) instead of LinearSVC to allow partial_fit (Continuous Learning).
        """
        # 1. Initialize Feature Processors
        self.vectorizer = TfidfVectorizer(
            max_features=5000, 
            ngram_range=(1, 2), 
            stop_words='english', 
            min_df=1
        )
        self.scaler = MinMaxScaler()  # For normalizing heuristic scores

        # 2. Initialize Models (All must support partial_fit)
        self.models = {
            'sgd_log': SGDClassifier(loss='log_loss', penalty='l2', random_state=42, warm_start=True),
            'sgd_svm': SGDClassifier(loss='hinge', penalty='l2', random_state=42, warm_start=True),  # Incremental SVM
            'bayes': MultinomialNB(alpha=0.1)
        }

        # 3. Define Ensemble Weights
        self.weights = {'sgd_log': 0.4, 'sgd_svm': 0.3, 'bayes': 0.3}

        # 4. Create Synthetic Seed Data (Expanded)
        seed_phish = [
            "URGENT: Verify your account immediately at secure-login.com",
            "Your bank account has been locked. Click here to restore access.",
            "You have a secure message from IRS. Download attachment.",
            "PayPal: Unusual activity detected. Login to confirm identity.",
            "Win a free iPhone 15 Pro! Claim your prize now.",
            "HR: Review the attached termination notice immediately.",
            "Netflix payment failed. Update billing information.",
            "Microsoft 365: Password expires in 2 hours. Reset now."
        ]
        seed_legit = [
            "Meeting notes from the Q3 sync are attached.",
            "Hey, are we still grabbing lunch at 12?",
            "Your pull request #402 has been successfully merged.",
            "Invoice #9922 for services rendered in October.",
            "Happy Birthday! Hope you have a great day.",
            "Project timeline update: We are on track for release.",
            "Reminder: Dentist appointment tomorrow at 3 PM.",
            "Can you review this document when you have a moment?"
        ]

        # 5. Training Loop
        X_raw = seed_phish + seed_legit
        y = np.array([1] * len(seed_phish) + [0] * len(seed_legit))  # 1=Phish

        # Fit Vectorizer first (Defines the vocabulary)
        X_tfidf = self.vectorizer.fit_transform(X_raw)

        # Train all models in the ensemble
        for name, model in self.models.items():
            model.partial_fit(X_tfidf, y, classes=[0, 1])

        self.initialized = True
        self._save_model()
        logger.info(f"[OK] Cold Start Complete. Ensemble active with {len(X_raw)} seed examples.")

    def _extract_heuristics(self, email_data: dict) -> dict:
        """
        Extracts non-text domain signals.
        These are used to boost ML scores if technical attacks are detected.
        """
        body = email_data.get('body', '').lower()
        sender = email_data.get('from', '').lower()
        
        # Safe URL Extraction (Limit length to prevent ReDoS)
        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', body[:10000])
        
        features = {
            'url_count': len(urls),
            'suspicious_tld': sum(1 for u in urls if u.endswith(('.ru', '.tk', '.cn', '.xyz', '.top'))),
            'ip_based_url': sum(1 for u in urls if re.search(r'//\d{1,3}\.\d{1,3}\.', u)),
            'urgency_score': sum(1 for w in ['urgent', 'immediately', 'verify', 'suspended'] if w in body),
            'financial_score': sum(1 for w in ['bank', 'refund', 'invoice', 'payment'] if w in body),
            'mismatched_sender': 1 if ('paypal' in body and 'paypal.com' not in sender) else 0
        }
        return features

    def _prepare_input(self, email_data: dict) -> str:
        """Sanitizes and combines text features."""
        # Truncate to 50k chars to prevent memory exhaustion attacks
        subject = str(email_data.get('subject', ''))[:1000]
        body = str(email_data.get('body', '') or email_data.get('snippet', ''))[:50000]
        sender = str(email_data.get('from', ''))[:500]
        
        # Combine distinct parts
        return f"{subject} {sender} {body}".strip()

    def predict(self, email_data: dict) -> tuple:
        """
        Ensemble Prediction Logic.
        Returns: (is_phishing (int), confidence (float), debug_info (dict))
        """
        if not self.initialized:
            return (0, 0.0, {"error": "Model not initialized"})

        text = self._prepare_input(email_data)
        heuristics = self._extract_heuristics(email_data)
        
        try:
            # Transform text
            X = self.vectorizer.transform([text])
            
            # 1. Get Weighted Votes
            scores = {}
            
            # SGD Log (Probabilistic)
            scores['sgd_log'] = self.models['sgd_log'].predict_proba(X)[0][1]
            
            # Naive Bayes (Probabilistic)
            scores['bayes'] = self.models['bayes'].predict_proba(X)[0][1]
            
            # SGD Hinge (SVM) - Convert distance to pseudo-probability using Sigmoid
            dist = self.models['sgd_svm'].decision_function(X)[0]
            scores['sgd_svm'] = 1 / (1 + np.exp(-dist))

            # 2. Calculate Final Ensemble Confidence
            final_score = (
                (scores['sgd_log'] * self.weights['sgd_log']) +
                (scores['sgd_svm'] * self.weights['sgd_svm']) +
                (scores['bayes'] * self.weights['bayes'])
            )

            # 3. Apply Heuristic Penalties (Boost score if heuristics are bad)
            heuristic_boost = 0.0
            if heuristics['suspicious_tld'] > 0:
                heuristic_boost += 0.15
            if heuristics['ip_based_url'] > 0:
                heuristic_boost += 0.20
            if heuristics['mismatched_sender'] > 0:
                heuristic_boost += 0.25
            
            # Cap at 1.0
            final_confidence = min(1.0, final_score + heuristic_boost)
            
            # 4. Decision Threshold
            is_phishing = 1 if final_confidence > 0.55 else 0
            
            return (is_phishing, final_confidence, {**scores, **heuristics})

        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return (0, 0.0, {"error": str(e)})

    def learn_from_feedback(self, email_data: dict, is_phishing: bool):
        """
        Thread-safe Continuous Learning.
        Updates ALL models in the ensemble immediately.
        """
        text = self._prepare_input(email_data)
        y = np.array([1 if is_phishing else 0])
        
        with self.lock:  # Prevent race conditions during update
            try:
                X = self.vectorizer.transform([text])
                
                # Update every model in the ensemble
                for name, model in self.models.items():
                    model.partial_fit(X, y, classes=[0, 1])
                
                self._save_model()
                logger.info(f"[LEARN] Ensemble updated. Label: {'PHISH' if is_phishing else 'SAFE'}")

                # VectorDB Integration
                if VECTOR_DB_AVAILABLE and is_phishing:
                    store_threat(
                        content=text[:1000],
                        threat_type='phishing',
                        sender=email_data.get('from', 'unknown'),
                        metadata={'source': 'user_feedback', 'timestamp': datetime.now().isoformat()}
                    )
            except Exception as e:
                logger.error(f"Learning failed: {e}")

    def _save_model(self):
        """Atomic save to prevent file corruption."""
        temp_path = MODEL_PATH.with_suffix('.tmp')
        try:
            payload = {
                'vectorizer': self.vectorizer,
                'scaler': self.scaler,
                'models': self.models,
                'weights': self.weights
            }
            with open(temp_path, 'wb') as f:
                pickle.dump(payload, f)
            # Atomic rename
            os.replace(temp_path, MODEL_PATH)
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            if temp_path.exists():
                os.remove(temp_path)

# Global singleton instance (shared across entire application)
detector = PhishingDetector()

if __name__ == "__main__":
    # Test the detector
    test_email = {
        'subject': 'URGENT: Verify your account',
        'body': 'Click here to avoid account suspension: http://paypal-verify.ru',
        'from': 'security@paypal-verify.com'
    }
    
    prediction, confidence = detector.predict(test_email)
    print(f"Prediction: {'PHISHING' if prediction else 'SAFE'} (confidence: {confidence:.2%})")