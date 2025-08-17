#!/usr/bin/env python3
import os
import sys
import argparse
import logging
from datetime import datetime
from dotenv import load_dotenv
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

# Import security modules
from SmishGuard.providers.sms_fetcher.iphone_doggy import IPhoneSMSFetcher
from VishGuard.voice_fetch.twilio_doggy import fetch_voice
from PhishGuard.providers.email_fetcher.registry import EmailFetcherRegistry
from utils.threat_intelligence import check_sender, check_url

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_test.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def test_sms_security():
    """Test SMS security with iPhone data."""
    logger.info("Testing SMS security with iPhone...")
    try:
        # Check if we can access the backup directory
        backup_path = os.path.expanduser(os.getenv('IPHONE_BACKUP_PATH', ''))
        if not os.path.exists(backup_path):
            logger.warning(f"Cannot access iPhone backup directory at {backup_path}. This may be due to macOS security restrictions.")
            logger.warning("To enable iPhone backup access:")
            logger.warning("1. Open System Preferences > Security & Privacy > Privacy > Full Disk Access")
            logger.warning("2. Add Terminal (or your IDE) to the list of apps with full disk access")
            logger.warning("3. Restart Terminal (or your IDE)")
            return

        fetcher = IPhoneSMSFetcher()
        messages = fetcher.fetch_sms()
        logger.info(f"Fetched {len(messages)} SMS messages")
        logger.info("iPhone SMS security test completed")
    except Exception as e:
        logger.error(f"iPhone SMS security test failed: {e}")
        logger.warning("Skipping iPhone tests due to access restrictions")

def test_voice_security():
    """Test voice call security with real Twilio data."""
    logger.info("Testing voice call security...")
    try:
        fetch_voice()
        logger.info("Voice security test completed")
    except Exception as e:
        logger.error(f"Voice security test failed: {e}")

def test_email_security(provider):
    """Test email security for a specific provider."""
    logger.info(f"Testing email security for {provider}...")
    try:
        fetcher = EmailFetcherRegistry.get_fetcher(provider)
        emails = fetcher.fetch_emails()
        logger.info(f"Successfully fetched {len(emails)} emails from {provider}")
        
        # Analyze emails for phishing attempts
        suspicious_emails = []
        for i, email in enumerate(emails, 1):
            # Check for suspicious patterns
            suspicious = False
            reasons = []
            
            # Check sender
            sender = email.get('from', '').lower()
            if 'noreply' in sender or 'no-reply' in sender:
                suspicious = True
                reasons.append("Uses no-reply address")
            
            # Check subject for urgency
            subject = email.get('subject', '').lower()
            urgency_words = ['urgent', 'immediate', 'action required', 'verify', 'confirm', 'suspended', 'locked', 'expired']
            if any(word in subject for word in urgency_words):
                suspicious = True
                reasons.append("Contains urgency in subject")
            
            # Check body for suspicious links
            body = email.get('body', '').lower()
            if 'click here' in body or 'verify your account' in body:
                suspicious = True
                reasons.append("Contains suspicious call-to-action")
            
            # Check for financial institutions
            financial_institutions = ['chase', 'bank of america', 'wells fargo', 'citibank', 'american express']
            if any(bank in sender for bank in financial_institutions):
                if 'verify' in body or 'confirm' in body:
                    suspicious = True
                    reasons.append("Suspicious financial institution email")
            
            if suspicious:
                suspicious_emails.append({
                    'number': i,
                    'from': email.get('from', 'N/A'),
                    'subject': email.get('subject', 'N/A'),
                    'date': email.get('date', 'N/A'),
                    'reasons': reasons
                })
        
        # Log results
        if suspicious_emails:
            logger.warning(f"\nFound {len(suspicious_emails)} potentially suspicious emails:")
            for email in suspicious_emails:
                logger.warning(f"\nSuspicious Email {email['number']}:")
                logger.warning(f"From: {email['from']}")
                logger.warning(f"Subject: {email['subject']}")
                logger.warning(f"Date: {email['date']}")
                logger.warning(f"Reasons: {', '.join(email['reasons'])}")
        else:
            logger.info("No suspicious emails detected")
            
        logger.info(f"Email security test for {provider} completed")
    except Exception as e:
        logger.error(f"Email security test for {provider} failed: {e}")
        raise

def check_environment(args):
    """Check if required environment variables are set based on which tests are being run."""
    required_vars = {
        'sms': {
            'IPHONE_NUMBER': 'iPhone Number',
            'IPHONE_BACKUP_PATH': 'iPhone Backup Path'
        },
        'voice': {
            'TWILIO_ACCOUNT_SID': 'Twilio Account SID',
            'TWILIO_AUTH_TOKEN': 'Twilio Auth Token'
        },
        'yahoo': {
            'YAHOO_USER': 'Yahoo Email',
            'YAHOO_PASS': 'Yahoo Password'
        },
        'gmail': {
            'GMAIL_USER': 'Gmail Email',
            'GMAIL_PASS': 'Gmail Password'
        },
        'outlook': {
            'OUTLOOK_USER': 'Outlook Email',
            'OUTLOOK_PASS': 'Outlook Password'
        }
    }
    
    # Determine which providers to check based on args
    providers_to_check = []
    if args.all:
        providers_to_check = ['sms', 'voice', 'yahoo', 'gmail', 'outlook']
    else:
        if args.sms:
            providers_to_check.append('sms')
        if args.voice:
            providers_to_check.append('voice')
        if args.email:
            if args.email == 'all':
                providers_to_check.extend(['yahoo', 'gmail', 'outlook'])
            else:
                providers_to_check.append(args.email)
    
    # If no specific tests requested, default to checking all
    if not providers_to_check:
        providers_to_check = ['yahoo', 'gmail', 'outlook']
    
    missing = []
    for provider in providers_to_check:
        if provider in required_vars:
            for var, desc in required_vars[provider].items():
                if not os.getenv(var):
                    missing.append(f"{var} ({desc})")
    
    if missing:
        logger.warning("Missing environment variables for requested tests:")
        for var in missing:
            logger.warning(f"  - {var}")
        logger.warning("Tests for providers with missing credentials will be skipped.")
        return False
    return True

def main():
    parser = argparse.ArgumentParser(description='Test security features')
    parser.add_argument('--sms', action='store_true', help='Test SMS security')
    parser.add_argument('--voice', action='store_true', help='Test voice call security')
    parser.add_argument('--email', choices=['yahoo', 'gmail', 'outlook', 'all'], 
                      help='Test email security for specific provider')
    parser.add_argument('--all', action='store_true', help='Test all security features')
    
    args = parser.parse_args()
    
    # Load environment variables
    load_dotenv()
    
    # Check environment
    check_environment(args)
    
    # Run tests based on arguments
    if args.all or args.sms:
        test_sms_security()
    
    if args.all or args.voice:
        if os.getenv('TWILIO_ACCOUNT_SID') and os.getenv('TWILIO_AUTH_TOKEN'):
            test_voice_security()
        else:
            logger.warning("Skipping voice test due to missing credentials")
    
    if args.all or args.email:
        if args.email == 'all':
            for provider in ['yahoo', 'gmail', 'outlook']:
                if provider == 'yahoo' and os.getenv('YAHOO_USER') and os.getenv('YAHOO_PASS'):
                    test_email_security(provider)
                elif provider == 'gmail' and os.getenv('GMAIL_USER') and os.getenv('GMAIL_PASS'):
                    test_email_security(provider)
                elif provider == 'outlook' and os.getenv('OUTLOOK_USER') and os.getenv('OUTLOOK_PASS'):
                    test_email_security(provider)
                else:
                    logger.warning(f"Skipping {provider} test due to missing credentials")
        else:
            if (args.email == 'yahoo' and os.getenv('YAHOO_USER') and os.getenv('YAHOO_PASS')) or \
               (args.email == 'gmail' and os.getenv('GMAIL_USER') and os.getenv('GMAIL_PASS')) or \
               (args.email == 'outlook' and os.getenv('OUTLOOK_USER') and os.getenv('OUTLOOK_PASS')):
                test_email_security(args.email)
            else:
                logger.warning(f"Skipping {args.email} test due to missing credentials")

if __name__ == "__main__":
    main() 