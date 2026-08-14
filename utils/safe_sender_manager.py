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
    
    def __init__(self, db_connection, *, account_sub: str):
        """
        Initialize with database connection.
        
        Args:
            db_connection: Active psycopg2 connection object
        """
        self.conn = db_connection
        from common.tenant_rls import require_account_sub
        self.account_sub = require_account_sub(account_sub)
        self._ensure_table_exists()
        from common.tenant_rls import set_tenant
        set_tenant(self.conn, self.account_sub)
    
    def _ensure_table_exists(self):
        """Create safe_senders table if it doesn't exist."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS safe_senders (
                    id SERIAL PRIMARY KEY,
                    account_sub TEXT,
                    domain VARCHAR(255),
                    sender_pattern VARCHAR(255),
                    match_type VARCHAR(16) NOT NULL DEFAULT 'exact',
                    added_date TIMESTAMP DEFAULT NOW(),
                    reason TEXT,
                    auto_learned BOOLEAN DEFAULT FALSE,
                    confidence_threshold FLOAT DEFAULT 0.0
                );
                ALTER TABLE safe_senders ADD COLUMN IF NOT EXISTS account_sub TEXT;
                ALTER TABLE safe_senders ADD COLUMN IF NOT EXISTS match_type
                    VARCHAR(16) NOT NULL DEFAULT 'exact';
                UPDATE safe_senders
                SET match_type = CASE
                    WHEN POSITION('%' IN COALESCE(sender_pattern, '')) > 0 THEN 'pattern'
                    WHEN POSITION('@' IN COALESCE(sender_pattern, '')) > 0 THEN 'exact'
                    ELSE 'domain'
                END
                WHERE match_type = 'exact'
                  AND (POSITION('%' IN COALESCE(sender_pattern, '')) > 0
                       OR POSITION('@' IN COALESCE(sender_pattern, '')) = 0);
                ALTER TABLE safe_senders DROP CONSTRAINT IF EXISTS safe_senders_domain_key;
                DROP INDEX IF EXISTS idx_safe_senders_tenant_domain;
                CREATE UNIQUE INDEX IF NOT EXISTS idx_safe_senders_tenant_pattern
                    ON safe_senders (account_sub, sender_pattern)
                    WHERE account_sub IS NOT NULL;
                DO $$ BEGIN
                  ALTER TABLE safe_senders ADD CONSTRAINT safe_senders_new_rows_need_tenant
                    CHECK (account_sub IS NOT NULL AND btrim(account_sub) <> '') NOT VALID;
                EXCEPTION WHEN duplicate_object THEN NULL;
                END $$;
                DO $$ BEGIN
                  ALTER TABLE safe_senders ADD CONSTRAINT safe_senders_match_type_valid
                    CHECK (match_type IN ('exact', 'pattern', 'domain')) NOT VALID;
                EXCEPTION WHEN duplicate_object THEN NULL;
                END $$
            """)
            self.conn.commit()
            from common.tenant_rls import ensure_rls
            ensure_rls(self.conn)
            logger.debug("✅ safe_senders table verified/created")
        except Exception as e:
            logger.error(f"Failed to create safe_senders table: {e}")
            self.conn.rollback()
            raise RuntimeError("safe sender storage unavailable") from e
    
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
                WHERE account_sub = %s AND match_type = 'exact'
                  AND sender_pattern = %s
                LIMIT 1
            """, (self.account_sub, sender_email.lower()))
            
            result = cursor.fetchone()
            if result:
                return True, result[0]
            
            # Check 2: Domain wildcard match (e.g., %@linkedin.com)
            cursor.execute("""
                SELECT reason FROM safe_senders
                WHERE account_sub = %s AND match_type = 'pattern'
                  AND %s LIKE sender_pattern
                LIMIT 1
            """, (self.account_sub, sender_email.lower()))
            
            result = cursor.fetchone()
            if result:
                return True, result[0]
            
            # Check 3: Domain-only match
            cursor.execute("""
                SELECT reason FROM safe_senders
                WHERE account_sub = %s AND match_type = 'domain' AND domain = %s
                LIMIT 1
            """, (self.account_sub, domain))
            
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
            sender_pattern = (sender_email or "").strip().lower()
            if not sender_pattern or len(sender_pattern) > 255:
                return False

            cursor = self.conn.cursor()

            # Exact addresses remain exact. A domain-wide allow requires an
            # explicit bare domain or SQL-LIKE pattern (for example
            # ``%@linkedin.com``); grading one sender must not trust its peers.
            if '@' in sender_pattern:
                domain = sender_pattern.split('@')[-1]
            else:
                domain = sender_pattern
            if not domain or len(domain) > 255:
                return False
            match_type = (
                "pattern" if "%" in sender_pattern
                else "exact" if "@" in sender_pattern
                else "domain"
            )
            
            cursor.execute("""
                INSERT INTO safe_senders
                    (account_sub, domain, sender_pattern, match_type, reason, auto_learned)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (account_sub, sender_pattern)
                    WHERE account_sub IS NOT NULL DO UPDATE
                SET match_type = EXCLUDED.match_type,
                    domain = EXCLUDED.domain,
                    reason = EXCLUDED.reason,
                    auto_learned = EXCLUDED.auto_learned
            """, (self.account_sub, domain, sender_pattern, match_type,
                  reason, auto_learned))
            
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
            sender_pattern = (sender_email or "").strip().lower()
            cursor.execute("""
                DELETE FROM safe_senders
                WHERE account_sub = %s AND sender_pattern = %s
            """, (self.account_sub, sender_pattern))
            
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
                SELECT domain, sender_pattern, match_type, reason, added_date, auto_learned
                FROM safe_senders
                WHERE account_sub = %s
                ORDER BY added_date DESC
            """, (self.account_sub,))
            
            results = cursor.fetchall()
            return [
                {
                    'domain': row[0],
                    'pattern': row[1],
                    'match_type': row[2],
                    'reason': row[3],
                    'added_date': row[4],
                    'auto_learned': row[5]
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
def create_safe_sender_manager(db_connection, *, account_sub: str):
    """Factory function to create SafeSenderManager with DB connection."""
    return SafeSenderManager(db_connection, account_sub=account_sub)
