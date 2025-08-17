import sqlite3
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import json
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def connect_db() -> sqlite3.Connection:
    """Connect to the SQLite database."""
    db_path = Path('data/security.db')
    db_path.parent.mkdir(exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    
    # Create tables if they don't exist
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            message_type TEXT NOT NULL,
            sender TEXT,
            recipient TEXT,
            subject TEXT,
            body TEXT,
            transcript TEXT,
            raw_content TEXT,
            preprocessed_text TEXT,
            timestamp TEXT,
            metadata TEXT,
            is_threat INTEGER DEFAULT 0,
            call_duration INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(message_type);
        CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
        CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
        CREATE INDEX IF NOT EXISTS idx_messages_is_threat ON messages(is_threat);
    """)
    
    return conn

def insert_message(
    conn: sqlite3.Connection,
    message_type: str,
    sender: Optional[str] = None,
    recipient: Optional[str] = None,
    subject: Optional[str] = None,
    body: Optional[str] = None,
    transcript: Optional[str] = None,
    raw_content: Optional[str] = None,
    preprocessed_text: Optional[str] = None,
    timestamp: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    is_threat: int = 0,
    call_duration: Optional[int] = None
) -> int:
    """Insert a message into the database."""
    try:
        cursor = conn.execute(
            """
            INSERT INTO messages (
                message_type, sender, recipient, subject, body,
                transcript, raw_content, preprocessed_text,
                timestamp, metadata, is_threat, call_duration
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                message_type,
                sender,
                recipient,
                subject,
                body,
                transcript,
                raw_content,
                preprocessed_text,
                timestamp or datetime.now().isoformat(),
                json.dumps(metadata) if metadata else None,
                is_threat,
                call_duration
            )
        )
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        logger.error(f"Error inserting message: {e}")
        conn.rollback()
        raise

def get_messages(
    conn: sqlite3.Connection,
    message_type: Optional[str] = None,
    sender: Optional[str] = None,
    is_threat: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 100
) -> list[Dict[str, Any]]:
    """Get messages from the database with optional filters."""
    query = "SELECT * FROM messages WHERE 1=1"
    params = []
    
    if message_type:
        query += " AND message_type = ?"
        params.append(message_type)
    
    if sender:
        query += " AND sender = ?"
        params.append(sender)
    
    if is_threat is not None:
        query += " AND is_threat = ?"
        params.append(is_threat)
    
    if start_date:
        query += " AND timestamp >= ?"
        params.append(start_date)
    
    if end_date:
        query += " AND timestamp <= ?"
        params.append(end_date)
    
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    cursor = conn.execute(query, params)
    columns = [description[0] for description in cursor.description]
    
    messages = []
    for row in cursor.fetchall():
        message = dict(zip(columns, row))
        if message.get('metadata'):
            message['metadata'] = json.loads(message['metadata'])
        messages.append(message)
    
    return messages

def update_message(
    conn: sqlite3.Connection,
    message_id: int,
    updates: Dict[str, Any]
) -> bool:
    """Update a message in the database."""
    try:
        set_clause = ", ".join(f"{key} = ?" for key in updates.keys())
        query = f"UPDATE messages SET {set_clause} WHERE id = ?"
        
        values = list(updates.values())
        if 'metadata' in updates and isinstance(updates['metadata'], dict):
            values[values.index(updates['metadata'])] = json.dumps(updates['metadata'])
        
        values.append(message_id)
        
        conn.execute(query, values)
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error updating message: {e}")
        conn.rollback()
        return False

def delete_message(conn: sqlite3.Connection, message_id: int) -> bool:
    """Delete a message from the database."""
    try:
        conn.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error deleting message: {e}")
        conn.rollback()
        return False 