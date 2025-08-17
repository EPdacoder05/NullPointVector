import os
import re
from twilio.rest import Client
from dotenv import load_dotenv
import sys
import logging
from urllib.parse import urlparse
from typing import List, Dict, Any

# Add project root to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
sys.path.append(project_root)

from utils.threat_intelligence import check_sender, check_url
from utils.database import connect_db, insert_message

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_sms_features(body: str, sender: str) -> Dict[str, Any]:
    """Extract SMS-specific features for ML."""
    # URL count
    urls = re.findall(r'https?://\S+', body)
    url_count = len(urls)
    
    # Sender heuristics
    is_numeric_sender = sender.isdigit()
    is_alphanumeric_sender = sender.isalnum() and not sender.isdigit()
    sender_length = len(sender)
    
    # SMS length
    sms_length = len(body)
    
    # STOP/HELP presence
    has_stop = 'stop' in body.lower()
    has_help = 'help' in body.lower()
    
    # Digit/letter ratio
    digit_count = sum(c.isdigit() for c in body)
    letter_count = sum(c.isalpha() for c in body)
    digit_letter_ratio = digit_count / (letter_count + 1e-5)
    
    return {
        'url_count': url_count,
        'is_numeric_sender': is_numeric_sender,
        'is_alphanumeric_sender': is_alphanumeric_sender,
        'sender_length': sender_length,
        'sms_length': sms_length,
        'has_stop': has_stop,
        'has_help': has_help,
        'digit_letter_ratio': digit_letter_ratio,
        'urls': urls
    }

def fetch_sms() -> List[Dict[str, Any]]:
    """Fetch SMS messages from Twilio."""
    try:
        # Load environment variables
        load_dotenv()
        
        # Get Twilio credentials
        account_sid = os.getenv('TWILIO_ACCOUNT_SID')
        auth_token = os.getenv('TWILIO_AUTH_TOKEN')
        
        if not account_sid or not auth_token:
            raise ValueError("Missing Twilio credentials in environment variables")
        
        # Initialize Twilio client
        client = Client(account_sid, auth_token)
        
        # Fetch recent messages
        messages = client.messages.list(limit=100)
        
        # Connect to database
        conn = connect_db()
        
        processed_messages = []
        for msg in messages:
            try:
                body = msg.body or ""
                sender = msg.from_ or ""
                recipient = msg.to or ""
                
                # Extract features
                features = extract_sms_features(body, sender)
                
                # Check threat intelligence
                blocked_sender = check_sender(sender)
                blocked_url = any(check_url(url) for url in features['urls'])
                
                # Determine if message is a threat
                is_threat = int(blocked_sender or blocked_url)
                
                # Store message in database
                insert_message(
                    conn,
                    message_type='sms',
                    sender=sender,
                    raw_content=body,
                    preprocessed_text=body.lower(),
                    recipient=recipient,
                    timestamp=msg.date_sent,
                    metadata=features,
                    is_threat=is_threat
                )
                
                processed_messages.append({
                    'body': body,
                    'sender': sender,
                    'recipient': recipient,
                    'date': msg.date_sent,
                    'features': features,
                    'is_threat': is_threat
                })
                
                logger.info(f"Processed SMS from {sender} to {recipient}")
                
            except Exception as e:
                logger.error(f"Error processing message {msg.sid}: {e}")
                continue
        
        conn.close()
        return processed_messages
        
    except Exception as e:
        logger.error(f"Error fetching SMS messages: {e}")
        raise

if __name__ == "__main__":
    fetch_sms() 