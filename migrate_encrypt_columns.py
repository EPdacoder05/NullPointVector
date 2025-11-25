#!/usr/bin/env python3
"""
Database Migration: Encrypt Existing Email Content
Encrypts subject and preprocessed_text columns for existing messages.

SECURITY UPGRADE: Column-Level Encryption
- Encrypts email subjects (prevents plaintext exposure)
- Encrypts preprocessed content (ML training data protection)
- Maintains raw_content encryption (already implemented)

SAFE TO RUN: Idempotent migration (checks for already-encrypted data)
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn, encrypt_data, decrypt_data
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def is_encrypted(data):
    """Check if data is already encrypted (Fernet tokens start with 'gAAAAA')."""
    if not data or not isinstance(data, (str, bytes)):
        return False
    
    data_str = data.decode('utf-8') if isinstance(data, bytes) else data
    return data_str.startswith('gAAAAA')  # Fernet token signature

def migrate_encrypt_columns():
    """Encrypt subject and preprocessed_text columns for all messages."""
    conn = get_conn()
    if not conn:
        logger.error("❌ Database connection failed")
        return False
    
    try:
        with conn.cursor() as cursor:
            # Get all messages with unencrypted subject/preprocessed_text
            cursor.execute('''
                SELECT id, subject, preprocessed_text
                FROM messages
                WHERE subject IS NOT NULL OR preprocessed_text IS NOT NULL
            ''')
            
            messages = cursor.fetchall()
            total = len(messages)
            encrypted = 0
            skipped = 0
            
            logger.info(f"📊 Found {total} messages to process")
            
            for row in messages:
                msg_id, subject, preprocessed_text = row
                
                try:
                    # Check if already encrypted
                    subject_encrypted = is_encrypted(subject) if subject else True
                    preprocessed_encrypted = is_encrypted(preprocessed_text) if preprocessed_text else True
                    
                    if subject_encrypted and preprocessed_encrypted:
                        skipped += 1
                        continue
                    
                    # Encrypt fields
                    encrypted_subject = encrypt_data(subject) if subject and not subject_encrypted else subject
                    encrypted_preprocessed = encrypt_data(preprocessed_text) if preprocessed_text and not preprocessed_encrypted else preprocessed_text
                    
                    # Update database
                    cursor.execute('''
                        UPDATE messages
                        SET subject = %s, preprocessed_text = %s
                        WHERE id = %s
                    ''', (encrypted_subject, encrypted_preprocessed, msg_id))
                    
                    encrypted += 1
                    
                    if encrypted % 100 == 0:
                        logger.info(f"   ✅ Encrypted {encrypted}/{total} messages...")
                        conn.commit()  # Commit in batches
                
                except Exception as e:
                    logger.error(f"   ⚠️  Failed to encrypt message {msg_id}: {e}")
                    continue
            
            conn.commit()
            
            logger.info(f"\n{'='*70}")
            logger.info(f"🔒 ENCRYPTION MIGRATION COMPLETE")
            logger.info(f"{'='*70}")
            logger.info(f"   ✅ Encrypted: {encrypted} messages")
            logger.info(f"   ⏭️  Skipped: {skipped} (already encrypted)")
            logger.info(f"   📊 Total: {total} messages processed")
            logger.info(f"{'='*70}\n")
            
            return True
            
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")
        conn.rollback()
        return False
    finally:
        release_conn(conn)

if __name__ == "__main__":
    print("\n🔒 DATABASE ENCRYPTION MIGRATION")
    print("="*70)
    print("This script will encrypt existing email subjects and content.")
    print("Safe to run multiple times (skips already-encrypted data).")
    print("="*70)
    
    response = input("\n⚠️  Continue with migration? (yes/no): ")
    
    if response.lower() in ['yes', 'y']:
        success = migrate_encrypt_columns()
        sys.exit(0 if success else 1)
    else:
        print("❌ Migration cancelled")
        sys.exit(0)
