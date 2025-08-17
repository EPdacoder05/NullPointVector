import os
import logging
from datetime import datetime
import sqlite3
from pathlib import Path
import json
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IPhoneSMSFetcher:
    """Fetches SMS messages from iPhone using local database."""
    
    def __init__(self):
        """Initialize iPhone SMS fetcher."""
        load_dotenv()
        self.phone_number = os.getenv('IPHONE_NUMBER')
        self.db_path = self._get_sms_db_path()
        
    def _get_sms_db_path(self):
        """Get the path to iPhone SMS database."""
        # Get backup path and expand user directory
        backup_path = os.path.expanduser(os.getenv('IPHONE_BACKUP_PATH', ''))
        if not backup_path:
            raise ValueError("IPHONE_BACKUP_PATH not set in environment variables")
        
        # Check if backup directory exists
        backup_dir = Path(backup_path)
        if not backup_dir.exists():
            raise ValueError(f"iPhone backup directory not found at: {backup_path}")
        
        # Look for the most recent backup folder
        backup_folders = list(backup_dir.glob('*'))
        if not backup_folders:
            raise ValueError(f"No backup folders found in: {backup_path}")
        
        # Sort by modification time and get the most recent
        latest_backup = max(backup_folders, key=lambda x: x.stat().st_mtime)
        logger.info(f"Using backup folder: {latest_backup}")
        
        # Construct path to SMS database
        sms_db = latest_backup / '3d' / '3d0d7e5fb2ce288813306e4d4636395e047a3d28'
        if not sms_db.exists():
            raise ValueError(f"SMS database not found at: {sms_db}")
        
        return sms_db
    
    def fetch_sms(self):
        """Fetch SMS messages from iPhone database."""
        try:
            logger.info(f"Connecting to SMS database at: {self.db_path}")
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Query recent messages
            cursor.execute("""
                SELECT 
                    message.text,
                    message.date,
                    message.is_from_me,
                    handle.id
                FROM message
                JOIN handle ON message.handle_id = handle.ROWID
                WHERE message.date > strftime('%s', 'now', '-1 day')
                ORDER BY message.date DESC
            """)
            
            messages = []
            for row in cursor.fetchall():
                text, date, is_from_me, sender = row
                if not is_from_me:  # Only process incoming messages
                    messages.append({
                        'body': text,
                        'date': datetime.fromtimestamp(date + 978307200).isoformat(),  # Apple's epoch
                        'sender': sender,
                        'type': 'sms'
                    })
            
            conn.close()
            logger.info(f"Fetched {len(messages)} SMS messages")
            return messages
            
        except Exception as e:
            logger.error(f"Error fetching SMS: {e}")
            raise

    def monitor_realtime(self, callback):
        """Monitor SMS in real-time using iOS notifications."""
        try:
            # This would use Apple's Push Notification service
            # to receive real-time SMS notifications
            pass
        except Exception as e:
            logger.error(f"Error in real-time monitoring: {e}")
            raise 