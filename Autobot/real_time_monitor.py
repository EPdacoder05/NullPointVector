import os
import logging
import time
from datetime import datetime
from pathlib import Path
import json
from dotenv import load_dotenv
import threading
from queue import Queue
import sqlite3

from SmishGuard.providers.sms_fetcher.iphone_doggy import IPhoneSMSFetcher
from VishGuard.voice_fetch.iphone_doggy import IPhoneVoiceFetcher
from SmishGuard.smish_mlm.smishing_detector import SmishingDetector
from VishGuard.vish_mlm.vishing_detector import VishingDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('monitor_logs.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RealTimeMonitor:
    """Real-time monitoring service for iPhone SMS and calls."""
    
    def __init__(self):
        """Initialize the monitoring service."""
        load_dotenv()
        self.phone_number = os.getenv('IPHONE_NUMBER')
        self.backup_path = os.getenv('IPHONE_BACKUP_PATH')
        
        # Initialize fetchers
        self.sms_fetcher = IPhoneSMSFetcher()
        self.voice_fetcher = IPhoneVoiceFetcher()
        
        # Initialize detectors
        self.smish_detector = SmishingDetector()
        self.vish_detector = VishingDetector()
        
        # Initialize queues for real-time processing
        self.sms_queue = Queue()
        self.call_queue = Queue()
        
        # Initialize last check timestamps
        self.last_sms_check = datetime.now()
        self.last_call_check = datetime.now()
        
    def start_monitoring(self):
        """Start real-time monitoring of SMS and calls."""
        logger.info("Starting real-time monitoring service...")
        
        # Start monitoring threads
        sms_thread = threading.Thread(target=self._monitor_sms)
        call_thread = threading.Thread(target=self._monitor_calls)
        
        sms_thread.daemon = True
        call_thread.daemon = True
        
        sms_thread.start()
        call_thread.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping monitoring service...")
    
    def _monitor_sms(self):
        """Monitor SMS messages in real-time."""
        while True:
            try:
                # Check for new messages
                messages = self.sms_fetcher.fetch_sms()
                for message in messages:
                    if datetime.fromisoformat(message['date']) > self.last_sms_check:
                        self.sms_queue.put(message)
                
                # Process queued messages
                while not self.sms_queue.empty():
                    message = self.sms_queue.get()
                    self._process_sms(message)
                
                self.last_sms_check = datetime.now()
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in SMS monitoring: {e}")
                time.sleep(30)  # Wait longer on error
    
    def _monitor_calls(self):
        """Monitor calls in real-time."""
        while True:
            try:
                # Check for new calls
                calls = self.voice_fetcher.fetch_calls()
                for call in calls:
                    if datetime.fromisoformat(call['date']) > self.last_call_check:
                        self.call_queue.put(call)
                
                # Process queued calls
                while not self.call_queue.empty():
                    call = self.call_queue.get()
                    self._process_call(call)
                
                self.last_call_check = datetime.now()
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in call monitoring: {e}")
                time.sleep(30)  # Wait longer on error
    
    def _process_sms(self, message):
        """Process a new SMS message."""
        try:
            # Detect if message is smishing
            is_threat, confidence = self.smish_detector.predict(message)
            
            if is_threat:
                logger.warning(f"Potential smishing detected! Confidence: {confidence:.2f}")
                self._send_alert('sms', message, confidence)
            
            # Update database
            self._update_database('sms', message, is_threat, confidence)
            
        except Exception as e:
            logger.error(f"Error processing SMS: {e}")
    
    def _process_call(self, call):
        """Process a new call."""
        try:
            # Detect if call is vishing
            is_threat, confidence = self.vish_detector.predict(call)
            
            if is_threat:
                logger.warning(f"Potential vishing detected! Confidence: {confidence:.2f}")
                self._send_alert('call', call, confidence)
            
            # Update database
            self._update_database('call', call, is_threat, confidence)
            
        except Exception as e:
            logger.error(f"Error processing call: {e}")
    
    def _send_alert(self, alert_type, data, confidence):
        """Send alert for detected threat."""
        alert = {
            'type': alert_type,
            'timestamp': datetime.now().isoformat(),
            'data': data,
            'confidence': confidence,
            'phone_number': self.phone_number
        }
        
        # Save alert to file
        alert_path = Path('alerts') / f"{alert_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        alert_path.parent.mkdir(exist_ok=True)
        
        with open(alert_path, 'w') as f:
            json.dump(alert, f, indent=2)
        
        logger.info(f"Alert saved to {alert_path}")
    
    def _update_database(self, message_type, data, is_threat, confidence):
        """Update the database with processed message/call."""
        try:
            conn = sqlite3.connect('monitor.db')
            cursor = conn.cursor()
            
            # Create table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT,
                    date TEXT,
                    sender TEXT,
                    content TEXT,
                    is_threat INTEGER,
                    confidence REAL,
                    processed_at TEXT
                )
            """)
            
            # Insert record
            cursor.execute("""
                INSERT INTO messages (type, date, sender, content, is_threat, confidence, processed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                message_type,
                data['date'],
                data.get('sender', data.get('caller_id')),
                data.get('body', ''),
                int(is_threat),
                confidence,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error updating database: {e}")

if __name__ == "__main__":
    monitor = RealTimeMonitor()
    monitor.start_monitoring() 