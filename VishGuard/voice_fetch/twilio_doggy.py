import os
import re
from twilio.rest import Client
from dotenv import load_dotenv
import sys
import logging
from typing import List, Dict, Any
from datetime import datetime

# Add project root to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
sys.path.append(project_root)

from utils.threat_intelligence import check_sender
from utils.database import connect_db, insert_message

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_voice_features(call: Dict[str, Any]) -> Dict[str, Any]:
    """Extract voice call-specific features for ML."""
    duration = call.get('duration', 0)
    caller_id = call.get('from', '')
    
    # Call duration features
    is_short_call = duration < 30  # Less than 30 seconds
    is_long_call = duration > 300  # More than 5 minutes
    
    # Caller ID features
    is_numeric_caller = caller_id.isdigit()
    is_alphanumeric_caller = caller_id.isalnum() and not caller_id.isdigit()
    caller_length = len(caller_id)
    
    # Time-based features
    call_time = datetime.fromisoformat(call.get('date_created', ''))
    hour_of_day = call_time.hour
    is_off_hours = hour_of_day < 8 or hour_of_day > 20
    
    return {
        'duration': duration,
        'is_short_call': is_short_call,
        'is_long_call': is_long_call,
        'is_numeric_caller': is_numeric_caller,
        'is_alphanumeric_caller': is_alphanumeric_caller,
        'caller_length': caller_length,
        'hour_of_day': hour_of_day,
        'is_off_hours': is_off_hours
    }

def fetch_voice() -> List[Dict[str, Any]]:
    """Fetch voice calls from Twilio."""
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
        
        # Fetch recent calls
        calls = client.calls.list(limit=100)
        
        # Connect to database
        conn = connect_db()
        
        processed_calls = []
        for call in calls:
            try:
                caller_id = call.from_ or ""
                recipient = call.to or ""
                duration = int(call.duration or 0)
                
                # Extract features
                features = extract_voice_features({
                    'duration': duration,
                    'from': caller_id,
                    'date_created': call.date_created
                })
                
                # Check threat intelligence
                blocked_caller = check_sender(caller_id)
                
                # Determine if call is a threat
                is_threat = int(blocked_caller)
                
                # Store call in database
                insert_message(
                    conn,
                    message_type='voice',
                    sender=caller_id,
                    recipient=recipient,
                    timestamp=call.date_created,
                    metadata=features,
                    is_threat=is_threat,
                    call_duration=duration
                )
                
                processed_calls.append({
                    'caller_id': caller_id,
                    'recipient': recipient,
                    'duration': duration,
                    'date': call.date_created,
                    'features': features,
                    'is_threat': is_threat
                })
                
                logger.info(f"Processed call from {caller_id} to {recipient}")
                
            except Exception as e:
                logger.error(f"Error processing call {call.sid}: {e}")
                continue
        
        conn.close()
        return processed_calls
        
    except Exception as e:
        logger.error(f"Error fetching voice calls: {e}")
        raise

if __name__ == "__main__":
    fetch_voice() 