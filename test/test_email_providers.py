#!/usr/bin/env python3
"""
Test script to validate all email providers work correctly.
This will test the core IDPS functionality without requiring actual credentials.
"""

import sys
import os
sys.path.append('.')

def test_imports():
    """Test that all core modules can be imported."""
    print("🔍 Testing imports...")
    
    try:
        from PhishGuard.providers.email_fetcher.yahoo_doggy import YahooDoggy
        print("✅ YahooDoggy imported successfully")
    except Exception as e:
        print(f"❌ YahooDoggy import failed: {e}")
        return False
    
    try:
        from PhishGuard.providers.email_fetcher.gmail_doggy import GmailDoggy
        print("✅ GmailDoggy imported successfully")
    except Exception as e:
        print(f"❌ GmailDoggy import failed: {e}")
        return False
    
    try:
        from PhishGuard.providers.email_fetcher.outlook_doggy import OutlookDoggy
        print("✅ OutlookDoggy imported successfully")
    except Exception as e:
        print(f"❌ OutlookDoggy import failed: {e}")
        return False
    
    try:
        from PhishGuard.phish_mlm.phishing_detector import PhishingDetector
        print("✅ PhishingDetector imported successfully")
    except Exception as e:
        print(f"❌ PhishingDetector import failed: {e}")
        return False
    
    try:
        from Autobot.VectorDB.NullPoint_Vector import connect_db
        print("✅ VectorDB imported successfully")
    except Exception as e:
        print(f"❌ VectorDB import failed: {e}")
        return False
    
    return True

def test_provider_initialization():
    """Test that providers can be initialized (without credentials)."""
    print("\n🔍 Testing provider initialization...")
    
    try:
        from PhishGuard.providers.email_fetcher.yahoo_doggy import YahooDoggy
        # Test Yahoo - should fail gracefully without credentials
        yahoo = YahooDoggy()
        print("✅ YahooDoggy initialized")
    except Exception as e:
        print(f"⚠️  YahooDoggy initialization: {e}")
    
    try:
        from PhishGuard.providers.email_fetcher.gmail_doggy import GmailDoggy
        # Test Gmail - should fail gracefully without credentials
        gmail = GmailDoggy()
        print("✅ GmailDoggy initialized")
    except Exception as e:
        print(f"⚠️  GmailDoggy initialization: {e}")
    
    try:
        from PhishGuard.providers.email_fetcher.outlook_doggy import OutlookDoggy
        # Test Outlook - should fail gracefully without credentials
        outlook = OutlookDoggy()
        print("✅ OutlookDoggy initialized")
    except Exception as e:
        print(f"⚠️  OutlookDoggy initialization: {e}")

def test_ml_model():
    """Test that the ML model can be initialized."""
    print("\n🔍 Testing ML model...")
    
    try:
        from PhishGuard.phish_mlm.phishing_detector import PhishingDetector
        detector = PhishingDetector()
        print("✅ PhishingDetector initialized")
        
        # Test with a sample email
        sample_email = {
            'subject': 'Test email',
            'body': 'This is a test email body',
            'from': 'test@example.com'
        }
        
        result = detector.predict(sample_email)
        print(f"✅ ML prediction successful: {result}")
        
    except Exception as e:
        print(f"❌ ML model test failed: {e}")

def test_vector_db():
    """Test VectorDB connection."""
    print("\n🔍 Testing VectorDB...")
    
    try:
        # This will fail without proper database setup, but should import correctly
        from Autobot.VectorDB.NullPoint_Vector import connect_db
        print("✅ VectorDB module accessible")
        
        # Try to connect (will fail without proper setup, but that's expected)
        try:
            conn = connect_db()
            print("✅ VectorDB connection successful")
        except Exception as e:
            print(f"⚠️  VectorDB connection (expected without setup): {e}")
            
    except Exception as e:
        print(f"❌ VectorDB test failed: {e}")

def main():
    """Run all tests."""
    print("🚀 Starting IDPS Core Functionality Tests\n")
    
    # Test 1: Imports
    if not test_imports():
        print("\n❌ Import tests failed. Please check your installation.")
        return
    
    # Test 2: Provider initialization
    test_provider_initialization()
    
    # Test 3: ML model
    test_ml_model()
    
    # Test 4: VectorDB
    test_vector_db()
    
    print("\n🎉 Core functionality tests completed!")
    print("\n📋 Next steps:")
    print("1. Set up your .env file with email credentials")
    print("2. Configure PostgreSQL database")
    print("3. Run the main orchestrator: python Autobot/run_all.py")
    print("4. Test with real email data")

if __name__ == "__main__":
    main()
