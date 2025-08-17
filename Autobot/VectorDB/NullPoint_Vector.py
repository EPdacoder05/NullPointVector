import psycopg2
from psycopg2.extensions import register_adapter, AsIs
import numpy as np
from sentence_transformers import SentenceTransformer
import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import base64
import logging
import json 

# Add logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# Configure database connection parameters
DB_CONFIG = {
    'dbname': os.getenv('DB_NAME', 'NullPointVector'),
    'user': os.getenv('DB_USER', 'EPNP'),
    'password': os.getenv('DB_PASSWORD'),
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': os.getenv('DB_PORT', '5432')
}

# Initialize the embedding model
model = SentenceTransformer('all-MiniLM-L6-v2')

def generate_embedding(text):
    """Generate an embedding for the given text using the SentenceTransformer model."""
    if text is None or not isinstance(text, str):
        logger.warning("Attempted to generate embedding for None or non-string text. Returning zero vector.")
        return np.zeros(model.get_sentence_embedding_dimension(), dtype=np.float32)
    return model.encode(text)

def adapt_numpy_array(np_array):
    """Convert numpy array to format suitable for PostgreSQL vector type"""
    return AsIs(str(np_array.tolist()))

# Register the numpy array adapter
register_adapter(np.ndarray, adapt_numpy_array)

def connect_db():
    """Connect to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except psycopg2.Error as e:
        logging.error(f"Error connecting to database: {e}")
        raise

# Initialize encryption
def get_encryption_key():
    """Get or generate encryption key."""
    key = os.getenv('ENCRYPTION_KEY')
    if not key:
        key = Fernet.generate_key()
        logger.info("Generated new encryption key")
    else:
        # Ensure the key is properly formatted
        try:
            # Try to decode the key to ensure it's valid
            key_bytes = base64.urlsafe_b64decode(key)
            # Re-encode to ensure proper format
            key = base64.urlsafe_b64encode(key_bytes).decode()
        except Exception as e:
            logger.error(f"Invalid encryption key format: {e}")
            key = Fernet.generate_key()
            logger.info("Generated new encryption key due to invalid format")
    return key

FERNET_KEY = get_encryption_key()
cipher_suite = Fernet(FERNET_KEY)

def encrypt_data(text):
    """Encrypt text data with UTF-8 encoding."""
    try:
        if text is None:
            return None
        return cipher_suite.encrypt(text.encode('utf-8'))
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        raise

def decrypt_data(encrypted_data):
    """Decrypt data with UTF-8 decoding."""
    try:
        if encrypted_data is None:
            return None
        return cipher_suite.decrypt(encrypted_data).decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        raise

def create_tables(conn):
    """Create the necessary tables and extensions."""
    try:
        with conn.cursor() as cursor:
            # Create pgvector extension
            cursor.execute('CREATE EXTENSION IF NOT EXISTS vector;')
            
            # Create emails table with vector support
            # Updated table schema from 'emails' to 'messages' with new fields
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id SERIAL PRIMARY KEY,
                    message_type TEXT NOT NULL,
                    sender TEXT,
                    recipient TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    subject TEXT,
                    raw_content BYTEA,
                    preprocessed_text TEXT,
                    embedding vector(384),
                    is_threat INTEGER DEFAULT 0,
                    confidence FLOAT DEFAULT 0.0,
                    metadata JSONB,
                    label INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            
            # Create index for vector similarity search
            # Updated index name from 'email_embedding_idx' to 'message_embedding_idx'
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS message_embedding_idx
                ON messages USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100);
            ''')
            
        conn.commit()
        logger.info("Database tables and extensions created successfully")
    except psycopg2.Error as e:
        logger.error(f"Error creating tables: {e}")
        conn.rollback()
        raise

def insert_message(conn, message_type, sender, raw_content, preprocessed_text, 
                   subject=None, recipient=None, timestamp=None, 
                   is_threat=0, confidence=0.0, metadata=None, label=None):
    """Insert a message with all its components into the database."""
    try:
        embedding = generate_embedding(preprocessed_text)
        encrypted_raw_content = encrypt_data(raw_content)
        
        with conn.cursor() as cursor:
            cursor.execute('''
                INSERT INTO messages (
                    message_type, sender, recipient, timestamp, subject,
                    raw_content, preprocessed_text, embedding,
                    is_threat, confidence, metadata, label
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id;
            ''', (
                message_type, sender, recipient, timestamp, subject,
                encrypted_raw_content, preprocessed_text, embedding,
                is_threat, confidence, json.dumps(metadata) if metadata else None, label
            ))
            
            message_id = cursor.fetchone()[0]
            conn.commit()
            logger.info(f"Message ({message_type}) inserted successfully with ID: {message_id}")
            return message_id
    except psycopg2.Error as e:
        logger.error(f"Error inserting message: {e}")
        conn.rollback()
        return None

def find_similar_messages(conn, query_text, message_type=None, limit=5):
    """Find similar messages with optional message type filter."""
    try:
        query_embedding = generate_embedding(query_text)
        
        with conn.cursor() as cursor:
            if message_type:
                cursor.execute('''
                    SELECT id, message_type, subject, sender, raw_content, is_threat,
                           embedding <-> %s as distance, preprocessed_text, metadata
                    FROM messages
                    WHERE message_type = %s
                    ORDER BY embedding <-> %s
                    LIMIT %s;
                ''', (query_embedding, message_type, query_embedding, limit))
            else:
                cursor.execute('''
                    SELECT id, message_type, subject, sender, raw_content, is_threat,
                           embedding <-> %s as distance, preprocessed_text, metadata
                    FROM messages
                    ORDER BY embedding <-> %s
                    LIMIT %s;
                ''', (query_embedding, query_embedding, limit))
                
            results = cursor.fetchall()
            decrypted_results = []
            for row in results:
                id, msg_type, subject, sender, encrypted_raw_content, is_threat, distance, preprocessed_text, metadata = row
                decrypted_raw_content = decrypt_data(encrypted_raw_content) if encrypted_raw_content else None
                decrypted_results.append((id, msg_type, subject, sender, decrypted_raw_content, is_threat, distance, preprocessed_text, metadata))
            return decrypted_results
    except psycopg2.Error as e:
        logger.error(f"Error searching similar messages: {e}")
        return []

if __name__ == "__main__":
    conn = connect_db()
    create_tables(conn)
    conn.close()