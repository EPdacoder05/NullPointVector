import os
import logging
import sqlite3
import time
import hashlib
import hmac
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import json
from pathlib import Path

logger = logging.getLogger(__name__)

class SecurityMonitor:
    """Monitors and logs security-related events."""
    
    def __init__(self, log_file: str = "security.log"):
        self.log_file = log_file
        self._setup_logging()
        
    def _setup_logging(self):
        """Set up security logging."""
        handler = logging.FileHandler(self.log_file)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(handler)
        
    def log_event(self, event_type: str, details: Dict):
        """Log a security event.
        
        Args:
            event_type: Type of security event
            details: Event details
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'details': details
        }
        logger.info(json.dumps(log_entry))

class SMSDatabaseHandler(FileSystemEventHandler):
    """Handles real-time monitoring of SMS database changes."""
    
    def __init__(self, callback, security_monitor: SecurityMonitor):
        self.callback = callback
        self.last_modified = 0
        self.security_monitor = security_monitor
        self.last_hash = None
        
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file.
        
        Args:
            file_path: Path to file
            
        Returns:
            SHA-256 hash of file
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
        
    def on_modified(self, event):
        if event.src_path.endswith('sms.db'):
            current_time = time.time()
            if current_time - self.last_modified > 1:  # Debounce changes
                self.last_modified = current_time
                
                # Calculate new hash
                new_hash = self._calculate_file_hash(event.src_path)
                
                # Log change
                self.security_monitor.log_event('database_modified', {
                    'file': event.src_path,
                    'old_hash': self.last_hash,
                    'new_hash': new_hash,
                    'timestamp': datetime.now().isoformat()
                })
                
                self.last_hash = new_hash
                self.callback()

class IPhoneSMSFetcher:
    """Fetches SMS messages from iPhone backup in real-time."""
    
    def __init__(self):
        load_dotenv()
        self.backup_path = os.getenv('IPHONE_BACKUP_PATH')
        self.observer = None
        self.sms_db_path = None
        self.security_monitor = SecurityMonitor()
        self._find_sms_database()
        
    def _validate_backup_path(self) -> bool:
        """Validate iPhone backup path.
        
        Returns:
            bool: True if valid, False otherwise
        """
        if not self.backup_path:
            self.security_monitor.log_event('error', {
                'type': 'missing_backup_path',
                'message': 'iPhone backup path not set in environment'
            })
            return False
            
        if not os.path.exists(self.backup_path):
            self.security_monitor.log_event('error', {
                'type': 'invalid_backup_path',
                'message': f'Backup path does not exist: {self.backup_path}'
            })
            return False
            
        return True
        
    def _find_sms_database(self) -> Optional[str]:
        """Find the SMS database in the iPhone backup."""
        if not self._validate_backup_path():
            return None
            
        try:
            # Look for the most recent backup directory
            backup_dirs = [d for d in os.listdir(self.backup_path) 
                          if os.path.isdir(os.path.join(self.backup_path, d))]
            if not backup_dirs:
                self.security_monitor.log_event('error', {
                    'type': 'no_backups',
                    'message': 'No backup directories found'
                })
                return None
                
            latest_backup = max(backup_dirs, key=lambda x: os.path.getmtime(os.path.join(self.backup_path, x)))
            sms_db_path = os.path.join(self.backup_path, latest_backup, '3d', '3d0d7e5fb2ce288813306e4d4636395e047a3d28')
            
            if os.path.exists(sms_db_path):
                self.sms_db_path = sms_db_path
                self.security_monitor.log_event('info', {
                    'type': 'database_found',
                    'path': sms_db_path
                })
                return sms_db_path
                
            self.security_monitor.log_event('error', {
                'type': 'database_not_found',
                'path': sms_db_path
            })
            return None
            
        except Exception as e:
            self.security_monitor.log_event('error', {
                'type': 'database_search_error',
                'error': str(e)
            })
            return None
        
    def _sanitize_message(self, text: str) -> str:
        """Sanitize message text to prevent injection attacks.
        
        Args:
            text: Raw message text
            
        Returns:
            Sanitized message text
        """
        if not text:
            return ""
        # Remove potentially dangerous characters
        return text.replace('<', '&lt;').replace('>', '&gt;')
        
    def fetch_sms(self, limit: int = 100) -> List[Dict]:
        """Fetch SMS messages from iPhone backup.
        
        Args:
            limit: Maximum number of messages to fetch
            
        Returns:
            List of dictionaries containing SMS messages
        """
        try:
            if not self.sms_db_path:
                self.security_monitor.log_event('error', {
                    'type': 'fetch_error',
                    'message': 'SMS database not found'
                })
                return []
                
            conn = sqlite3.connect(self.sms_db_path)
            cursor = conn.cursor()
            
            # Query recent messages
            cursor.execute("""
                SELECT 
                    message.text,
                    message.date,
                    handle.id
                FROM message
                LEFT JOIN handle ON message.handle_id = handle.ROWID
                ORDER BY message.date DESC
                LIMIT ?
            """, (limit,))
            
            messages = []
            for text, date, sender in cursor.fetchall():
                # Convert Apple's timestamp (milliseconds since 2001) to datetime
                apple_epoch = datetime(2001, 1, 1)
                date = apple_epoch + datetime.timedelta(seconds=date/1000000000)
                
                # Sanitize message text
                sanitized_text = self._sanitize_message(text)
                
                messages.append({
                    'text': sanitized_text,
                    'date': date.isoformat(),
                    'sender': sender or 'Unknown',
                    'type': 'sms'
                })
                
            conn.close()
            
            self.security_monitor.log_event('info', {
                'type': 'fetch_success',
                'count': len(messages)
            })
            
            return messages
            
        except Exception as e:
            self.security_monitor.log_event('error', {
                'type': 'fetch_error',
                'error': str(e)
            })
            return []
            
    def start_monitoring(self, callback):
        """Start real-time monitoring of SMS database.
        
        Args:
            callback: Function to call when new messages are detected
        """
        if not self.sms_db_path:
            self.security_monitor.log_event('error', {
                'type': 'monitor_error',
                'message': 'Cannot start monitoring: SMS database not found'
            })
            return
            
        try:
            event_handler = SMSDatabaseHandler(callback, self.security_monitor)
            self.observer = Observer()
            self.observer.schedule(event_handler, 
                                 os.path.dirname(self.sms_db_path), 
                                 recursive=False)
            self.observer.start()
            
            self.security_monitor.log_event('info', {
                'type': 'monitor_started',
                'path': self.sms_db_path
            })
            
        except Exception as e:
            self.security_monitor.log_event('error', {
                'type': 'monitor_error',
                'error': str(e)
            })
            
    def stop_monitoring(self):
        """Stop real-time monitoring of SMS database."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            
            self.security_monitor.log_event('info', {
                'type': 'monitor_stopped'
            }) 