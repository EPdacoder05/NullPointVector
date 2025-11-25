#!/usr/bin/env python3
"""
Test script to fetch real emails using user credentials.
"""

import sys
import os
sys.path.append('.')

def test_yahoo_emails():
    """Test Yahoo email fetching."""
    print("🔍 Testing Yahoo email fetching...")
    try:
        from PhishGuard.providers.email_fetcher.yahoo_doggy import YahooDoggy
        yahoo = YahooDoggy()
        emails = yahoo.fetch_emails(limit=5)
        print(f"✅ Yahoo: Fetched {len(emails)} emails")
        for i, email in enumerate(emails[:3]):  # Show first 3
            print(f"  {i+1}. From: {email.get('from', 'Unknown')}")
            print(f"     Subject: {email.get('subject', 'No subject')}")
        return True
    except Exception as e:
        print(f"❌ Yahoo failed: {e}")
        return False

def test_gmail_emails():
    """Test Gmail email fetching."""
    print("\n🔍 Testing Gmail email fetching...")
    try:
        from PhishGuard.providers.email_fetcher.gmail_doggy import GmailDoggy
        gmail = GmailDoggy()
        emails = gmail.fetch_emails(limit=5)
        print(f"✅ Gmail: Fetched {len(emails)} emails")
        for i, email in enumerate(emails[:3]):  # Show first 3
            print(f"  {i+1}. From: {email.get('from', 'Unknown')}")
            print(f"     Subject: {email.get('subject', 'No subject')}")
        return True
    except Exception as e:
        print(f"❌ Gmail failed: {e}")
        return False

def test_outlook_emails():
    """Test Outlook email fetching."""
    print("\n🔍 Testing Outlook email fetching...")
    try:
        from PhishGuard.providers.email_fetcher.outlook_doggy import OutlookDoggy
        outlook = OutlookDoggy()
        emails = outlook.fetch_emails(limit=5)
        print(f"✅ Outlook: Fetched {len(emails)} emails")
        for i, email in enumerate(emails[:3]):  # Show first 3
            print(f"  {i+1}. From: {email.get('from', 'Unknown')}")
            print(f"     Subject: {email.get('subject', 'No subject')}")
        return True
    except Exception as e:
        print(f"❌ Outlook failed: {e}")
        return False

def test_ml_analysis():
    """Test ML analysis on fetched emails."""
    print("\n🔍 Testing ML analysis...")
    try:
        from PhishGuard.phish_mlm.phishing_detector import PhishingDetector
        detector = PhishingDetector()
        
        # Test with sample email
        sample_email = {
            'subject': 'Test email',
            'body': 'This is a test email body',
            'from': 'test@example.com'
        }
        
        result = detector.predict(sample_email)
        print(f"✅ ML analysis: {result}")
        return True
    except Exception as e:
        print(f"❌ ML analysis failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🚀 Testing Real Email Fetching with Your Credentials\n")
    
    results = []
    
    # Test each email provider
    results.append(test_yahoo_emails())
    results.append(test_gmail_emails())
    results.append(test_outlook_emails())
    
    # Test ML analysis
    results.append(test_ml_analysis())
    
    # Summary
    successful = sum(results)
    total = len(results)
    
    print(f"\n📊 Results: {successful}/{total} tests passed")
    
    if successful == total:
        print("🎉 All tests passed! Your IDPS system is working!")
    else:
        print("⚠️  Some tests failed. Check the errors above.")

if __name__ == "__main__":
    main()
