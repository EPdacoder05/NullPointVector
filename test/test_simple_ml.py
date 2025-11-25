#!/usr/bin/env python3
"""
Simple ML test without requiring pre-trained models.
"""

import sys
import os
sys.path.append('.')

def test_sentence_transformer():
    """Test sentence transformer loading."""
    print("🔍 Testing Sentence Transformer...")
    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Test encoding
        text = "This is a test email about urgent payment"
        embedding = model.encode(text)
        print(f"✅ Sentence Transformer: Generated embedding of shape {embedding.shape}")
        return True
    except Exception as e:
        print(f"❌ Sentence Transformer failed: {e}")
        return False

def test_feature_engineering():
    """Test feature engineering."""
    print("\n🔍 Testing Feature Engineering...")
    try:
        from PhishGuard.phish_mlm.phishing_detector import FeatureEngineering
        
        # Test data
        test_emails = [
            {
                'subject': 'Urgent payment required',
                'sender': 'bank@example.com',
                'date': '2024-01-01 10:00:00',
                'body': 'Please click here to verify your account: http://example.com'
            },
            {
                'subject': 'Meeting reminder',
                'sender': 'colleague@company.com',
                'date': '2024-01-01 14:00:00',
                'body': 'Don\'t forget our meeting tomorrow'
            }
        ]
        
        fe = FeatureEngineering()
        features = fe.extract_features(test_emails)
        print(f"✅ Feature Engineering: Generated {len(features)} feature vectors")
        print(f"   Features: {list(features.columns)}")
        return True
    except Exception as e:
        print(f"❌ Feature Engineering failed: {e}")
        return False

def test_simple_prediction():
    """Test simple prediction without pre-trained model."""
    print("\n🔍 Testing Simple Prediction...")
    try:
        from sentence_transformers import SentenceTransformer
        import numpy as np
        
        # Load model
        model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Test emails
        test_emails = [
            "Urgent: Your account has been suspended. Click here to verify: http://suspicious.com",
            "Meeting reminder for tomorrow at 2 PM",
            "You've won $1,000,000! Click here to claim: http://scam.com"
        ]
        
        # Generate embeddings
        embeddings = model.encode(test_emails)
        
        # Simple rule-based classification
        suspicious_keywords = ['urgent', 'suspended', 'verify', 'click', 'won', 'claim', 'money']
        
        for i, email in enumerate(test_emails):
            email_lower = email.lower()
            suspicious_score = sum(1 for keyword in suspicious_keywords if keyword in email_lower)
            is_suspicious = suspicious_score >= 2
            
            print(f"  Email {i+1}: {'SUSPICIOUS' if is_suspicious else 'SAFE'} (score: {suspicious_score})")
        
        print("✅ Simple prediction completed")
        return True
    except Exception as e:
        print(f"❌ Simple prediction failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🚀 Testing ML Components\n")
    
    results = []
    
    results.append(test_sentence_transformer())
    results.append(test_feature_engineering())
    results.append(test_simple_prediction())
    
    successful = sum(results)
    total = len(results)
    
    print(f"\n📊 Results: {successful}/{total} tests passed")
    
    if successful == total:
        print("🎉 All ML components working!")
    else:
        print("⚠️  Some ML tests failed.")

if __name__ == "__main__":
    main()
