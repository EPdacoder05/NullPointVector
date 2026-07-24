#!/usr/bin/env python3
"""
Safe Sender Manager - Whitelist System for Legitimate Emails

FEATURES:
- Database-backed whitelist (safe_senders table)
- Pattern matching (exact match or domain wildcards)
- Auto-learning from user feedback (mark as safe)
- Bulk operations for efficiency
- Integration with ML model for continuous learning

ARCHITECTURE:
1. Check sender against safe_senders table
2. If match → skip ML prediction, mark as safe
3. If no match → run ML prediction
4. User feedback → update safe_senders + retrain ML incrementally

PREVENTS:
- False positives from legitimate services (LinkedIn, GitHub, etc.)
- Wasted ML inference on known-safe senders
- User frustration from blocking important emails
"""

import logging
from typing import Optional, List, Dict, Tuple
from datetime import datetime
import re

logger = logging.getLogger(__name__)


class SafeSenderManager:
    """Manages whitelist of safe email senders with pattern matching."""
    
    def __init__(self, db_connection):
        """
        Initialize with database connection.
        
        Args:
            db_connection: Active psycopg2 connection object
        """
        self.conn = db_connection
        self._ensure_table_exists()
    
    def _ensure_table_exists(self):
        """Create safe_senders table if it doesn't exist."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS safe_senders (
                    id SERIAL PRIMARY KEY,
                    domain VARCHAR(255) UNIQUE,
                    sender_pattern VARCHAR(255),
                    added_date TIMESTAMP DEFAULT NOW(),
                    reason TEXT,
                    auto_learned BOOLEAN DEFAULT FALSE,
                    confidence_threshold FLOAT DEFAULT 0.0
                )
            """)
            self.conn.commit()
            logger.debug("✅ safe_senders table verified/created")
        except Exception as e:
            logger.error(f"Failed to create safe_senders table: {e}")
            self.conn.rollback()
    
    def is_safe_sender(self, sender_email: str) -> Tuple[bool, Optional[str]]:
        """
        Check if sender is in whitelist.
        
        Args:
            sender_email: Email address to check (e.g., "jobs@linkedin.com")
        
        Returns:
            Tuple of (is_safe: bool, reason: str or None)
            
        Example:
            is_safe, reason = manager.is_safe_sender("jobs@linkedin.com")
            if is_safe:
                print(f"Whitelisted: {reason}")
        """
        if not sender_email or '@' not in sender_email:
            return False, None
        
        try:
            cursor = self.conn.cursor()
            
            # Extract domain from email
            domain = sender_email.split('@')[-1].lower()
            
            # Check 1: Exact sender match
            cursor.execute("""
                SELECT reason FROM safe_senders
                WHERE sender_pattern = %s
            """, (sender_email.lower(),))
            
            result = cursor.fetchone()
            if result:
                return True, result[0]
            
            # Check 2: Domain wildcard match (e.g., %@linkedin.com)
            cursor.execute("""
                SELECT reason FROM safe_senders
                WHERE %s LIKE sender_pattern
            """, (sender_email.lower(),))
            
            result = cursor.fetchone()
            if result:
                return True, result[0]
            
            # Check 3: Domain-only match
            cursor.execute("""
                SELECT reason FROM safe_senders
                WHERE domain = %s
            """, (domain,))
            
            result = cursor.fetchone()
            if result:
                return True, result[0]
            
            return False, None
            
        except Exception as e:
            logger.error(f"Error checking safe sender: {e}")
            return False, None
    
    def add_safe_sender(self, sender_email: str, reason: str = "User marked as safe", 
                       auto_learned: bool = False) -> bool:
        """
        Add sender to whitelist.
        
        Args:
            sender_email: Email or pattern (e.g., "%@linkedin.com")
            reason: Why this sender is safe
            auto_learned: True if added by ML feedback, False if manual
        
        Returns:
            True if added successfully, False otherwise
        """
        try:
            cursor = self.conn.cursor()
            
            # Extract domain if it's a full email
            if '@' in sender_email:
                domain = sender_email.split('@')[-1].lower()
            else:
                domain = sender_email.lower()
            
            cursor.execute("""
                INSERT INTO safe_senders (domain, sender_pattern, reason, auto_learned)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (domain) DO UPDATE
                SET sender_pattern = EXCLUDED.sender_pattern,
                    reason = EXCLUDED.reason,
                    auto_learned = EXCLUDED.auto_learned
            """, (domain, sender_email.lower(), reason, auto_learned))
            
            self.conn.commit()
            logger.info(f"✅ Added safe sender: {sender_email} - {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add safe sender: {e}")
            self.conn.rollback()
            return False
    
    def remove_safe_sender(self, sender_email: str) -> bool:
        """Remove sender from whitelist."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                DELETE FROM safe_senders
                WHERE sender_pattern = %s OR domain = %s
            """, (sender_email.lower(), sender_email.lower()))
            
            self.conn.commit()
            logger.info(f"🗑️ Removed safe sender: {sender_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove safe sender: {e}")
            self.conn.rollback()
            return False
    
    def get_all_safe_senders(self) -> List[Dict]:
        """Get all whitelisted senders."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT domain, sender_pattern, reason, added_date, auto_learned
                FROM safe_senders
                ORDER BY added_date DESC
            """)
            
            results = cursor.fetchall()
            return [
                {
                    'domain': row[0],
                    'pattern': row[1],
                    'reason': row[2],
                    'added_date': row[3],
                    'auto_learned': row[4]
                }
                for row in results
            ]
            
        except Exception as e:
            logger.error(f"Failed to get safe senders: {e}")
            return []
    
    def bulk_add_safe_senders(self, senders: List[Tuple[str, str]]) -> int:
        """
        Add multiple safe senders at once.
        
        Args:
            senders: List of (sender_email, reason) tuples
        
        Returns:
            Number of senders added successfully
        """
        added_count = 0
        for sender_email, reason in senders:
            if self.add_safe_sender(sender_email, reason):
                added_count += 1
        
        logger.info(f"✅ Bulk added {added_count}/{len(senders)} safe senders")
        return added_count


# Singleton instance creator
def create_safe_sender_manager(db_connection):
    """Factory function to create SafeSenderManager with DB connection."""
    return SafeSenderManager(db_connection)
