import psycopg2
from psycopg2.extensions import register_adapter, AsIs
import numpy as np
from sentence_transformers import SentenceTransformer
import os
from dotenv import load_dotenv, dotenv_values
from cryptography.fernet import Fernet
import base64
import logging
import json 
from pathlib import Path
from psycopg2 import pool
from functools import lru_cache

# Add logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    # PostgreSQL pgvector expects format: '[val1,val2,val3]'
    # No spaces, just commas between values
    return AsIs(f"'[{','.join(map(str, np_array.tolist()))}]'")

# Register the numpy array adapter
register_adapter(np.ndarray, adapt_numpy_array)

# ============================================================================
# CONNECTION POOLING
# ============================================================================

# Global connection pool (initialized on first use)
_connection_pool = None

def _init_pool():
    """Initialize connection pool with database credentials."""
    global _connection_pool
    
    if _connection_pool is not None:
        return _connection_pool
    
    # Load .env configuration
    project_root = Path(__file__).resolve().parent.parent.parent
    env_path = project_root / '.env'
    config = dotenv_values(env_path)
    
    # Manual fallback for DB_PORT
    if not config or 'DB_PORT' not in config:
        if env_path.exists():
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('DB_PORT='):
                        config = dict(config) if config else {}
                        config['DB_PORT'] = line.split('=')[1].strip()
    
    # Extract credentials
    host = config.get('DB_HOST') or os.getenv('DB_HOST', 'localhost')
    port = config.get('DB_PORT') or os.getenv('DB_PORT', '5432')
    user = config.get('DB_USER') or os.getenv('DB_USER', 'EPNP')
    password = config.get('DB_PASSWORD') or os.getenv('DB_PASSWORD')
    dbname = config.get('DB_NAME') or os.getenv('DB_NAME', 'NullPointVector')
    
    try:
        _connection_pool = pool.SimpleConnectionPool(
            minconn=1,
            maxconn=10,
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )
        logger.info(f"✅ Connection pool initialized ({host}:{port})")
        return _connection_pool
    except Exception as e:
        logger.error(f"❌ Failed to create connection pool: {e}")
        return None


def get_conn():
    """Get a connection from the pool."""
    pool_instance = _init_pool()
    if pool_instance is None:
        logger.error("Connection pool not initialized")
        return None
    
    try:
        conn = pool_instance.getconn()
        return conn
    except Exception as e:
        logger.error(f"Failed to get connection from pool: {e}")
        return None


def release_conn(conn):
    """Release a connection back to the pool."""
    if conn is None:
        return
    
    pool_instance = _init_pool()
    if pool_instance is not None:
        try:
            pool_instance.putconn(conn)
        except Exception as e:
            logger.error(f"Failed to release connection: {e}")


def _load_env_explicitly():
    """Helper to force load .env from project root."""
    try:
        # Calculate path to .env relative to this file
        # File: Yahoo_Phish/Autobot/VectorDB/NullPoint_Vector.py
        # Root: Yahoo_Phish/
        project_root = Path(__file__).resolve().parent.parent.parent
        env_path = project_root / '.env'
        
        if env_path.exists():
            load_dotenv(dotenv_path=env_path, override=True)
            return True
        else:
            logger.warning(f"⚠️ .env file NOT found at {env_path}")
            return False
    except Exception as e:
        logger.error(f"Error loading .env: {e}")
        return False

def connect_db():
    """Connect to the PostgreSQL database."""
    
    # 1. Calculate path to .env
    project_root = Path(__file__).resolve().parent.parent.parent
    env_path = project_root / '.env'
    
    # 2. Load values DIRECTLY from file (Bypassing shell cache)
    config = dotenv_values(env_path)
    
    # 3. MANUAL FALLBACK: If dotenv failed to parse, read file manually
    if not config or 'DB_PORT' not in config:
        logger.warning("⚠️ Standard parser failed to find DB_PORT. Attempting manual read...")
        try:
            if env_path.exists():
                with open(env_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('DB_PORT='):
                            manual_port = line.split('=')[1].strip()
                            config = dict(config) if config else {}
                            config['DB_PORT'] = manual_port
                            logger.info(f"✅ Manually extracted DB_PORT: {manual_port}")
        except Exception as e:
            logger.error(f"Manual read failed: {e}")

    # 4. Set config variables
    host = config.get('DB_HOST') or os.getenv('DB_HOST', 'localhost')
    port = config.get('DB_PORT') or os.getenv('DB_PORT', '5432')
    user = config.get('DB_USER') or os.getenv('DB_USER', 'EPNP')
    password = config.get('DB_PASSWORD') or os.getenv('DB_PASSWORD')
    dbname = config.get('DB_NAME') or os.getenv('DB_NAME', 'NullPointVector')

    db_config = {
        'dbname': dbname,
        'user': user,
        'password': password,
        'host': host,
        'port': port
    }

    try:
        if __name__ == "__main__":
            logger.info(f"Attempting connection to: {db_config['host']}:{db_config['port']} as {db_config['user']}")
            
        conn = psycopg2.connect(**db_config)
        return conn
    except psycopg2.Error as e:
        logger.error(f"Database connection failed: {e}")
        return None

# Initialize encryption
def get_encryption_key():
    """Get or generate encryption key."""
    key = os.getenv('ENCRYPTION_KEY')
    if not key:
        # Try loading from file if env var is missing
        project_root = Path(__file__).resolve().parent.parent.parent
        env_path = project_root / '.env'
        config = dotenv_values(env_path)
        key = config.get('ENCRYPTION_KEY')

    if not key:
        key = Fernet.generate_key()
        logger.info("Generated new encryption key")
    else:
        try:
            key_bytes = base64.urlsafe_b64decode(key)
            key = base64.urlsafe_b64encode(key_bytes).decode()
        except Exception as e:
            logger.error(f"Invalid encryption key format: {e}")
            key = Fernet.generate_key()
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
    if conn is None:
        logger.error("Cannot create tables: No database connection.")
        return

    try:
        with conn.cursor() as cursor:
            cursor.execute('CREATE EXTENSION IF NOT EXISTS vector;')
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
    """Insert a message with all its components into the database.
    
    SECURITY: Encrypts sensitive fields at rest:
    - raw_content: Full email body (BYTEA encrypted)
    - subject: Email subject line (TEXT encrypted)
    - preprocessed_text: Sanitized content for ML (TEXT encrypted)
    
    Unencrypted fields (for querying/analysis):
    - sender, recipient: Needed for threat intelligence lookups
    - timestamp: Needed for time-series analysis
    - embedding: ML vector (not sensitive)
    - metadata: Already sanitized by input_validator
    """
    try:
        embedding = generate_embedding(preprocessed_text)
        
        # SECURITY: Encrypt all sensitive content fields
        encrypted_raw_content = encrypt_data(raw_content)
        encrypted_subject = encrypt_data(subject) if subject else None
        encrypted_preprocessed = encrypt_data(preprocessed_text)
        
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
                message_type, sender, recipient, timestamp, encrypted_subject,
                encrypted_raw_content, encrypted_preprocessed, embedding,
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
                id, msg_type, encrypted_subject, sender, encrypted_raw_content, is_threat, distance, encrypted_preprocessed, metadata = row
                
                # SECURITY: Decrypt all encrypted fields for application use
                decrypted_raw_content = decrypt_data(encrypted_raw_content) if encrypted_raw_content else None
                decrypted_subject = decrypt_data(encrypted_subject) if encrypted_subject else None
                decrypted_preprocessed = decrypt_data(encrypted_preprocessed) if encrypted_preprocessed else None
                
                decrypted_results.append((id, msg_type, decrypted_subject, sender, decrypted_raw_content, is_threat, distance, decrypted_preprocessed, metadata))
            return decrypted_results
    except psycopg2.Error as e:
        logger.error(f"Error searching similar messages: {e}")
        return []

# ============================================================================
# API WRAPPER FUNCTIONS
# ============================================================================

def search_similar_threats(content: str, threat_type: str = None, top_k: int = 5):
    """
    API-friendly wrapper for threat similarity search.
    
    Args:
        content: Text content to search for similar threats
        threat_type: Optional filter (phishing, smishing, vishing)
        top_k: Number of similar threats to return
        
    Returns:
        List of dictionaries containing threat information
    """
    conn = get_conn()
    if not conn:
        logger.error("Failed to connect to database")
        return []
    
    try:
        results = find_similar_messages(conn, content, threat_type, top_k)
        
        threats = []
        for row in results:
            id, msg_type, subject, sender, raw_content, is_threat, distance, preprocessed_text, metadata = row
            
            # Convert distance to similarity score (0-1 scale)
            similarity = max(0, 1 - distance)
            
            threats.append({
                "id": id,
                "threat_type": msg_type,
                "subject": subject,
                "sender": sender,
                "content": preprocessed_text,
                "is_threat": bool(is_threat),
                "similarity": round(similarity, 4),
                "metadata": metadata or {}
            })
        
        return threats
    except Exception as e:
        logger.error(f"Error searching threats: {e}")
        return []
    finally:
        release_conn(conn)


def store_threat(content: str, threat_type: str, sender: str = "unknown", metadata: dict = None):
    """
    API-friendly wrapper to store a new threat in the database.
    
    Args:
        content: Message content
        threat_type: Type of threat (phishing, smishing, vishing)
        sender: Sender identifier
        metadata: Additional metadata
        
    Returns:
        Dictionary with threat ID and status
    """
    conn = get_conn()
    if not conn:
        logger.error("Failed to connect to database")
        return {"error": "Database connection failed"}
    
    try:
        from datetime import datetime
        
        threat_id = insert_message(
            conn=conn,
            message_type=threat_type,
            sender=sender,
            raw_content=content,
            preprocessed_text=content,
            subject=metadata.get("subject") if metadata else None,
            recipient=metadata.get("recipient") if metadata else None,
            timestamp=datetime.now(),
            is_threat=1,
            confidence=metadata.get("confidence", 0.0) if metadata else 0.0,
            metadata=metadata
        )
        
        return {
            "id": threat_id,
            "status": "stored",
            "threat_type": threat_type,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error storing threat: {e}")
        return {"error": str(e)}
    finally:
        release_conn(conn)


def get_threat_by_id(threat_id: str):
    """
    API-friendly wrapper to retrieve a specific threat by ID.
    
    Args:
        threat_id: The threat ID to retrieve
        
    Returns:
        Dictionary with threat details or None
    """
    conn = get_conn()
    if not conn:
        return None
    
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                SELECT id, message_type, sender, recipient, timestamp, subject,
                       raw_content, preprocessed_text, is_threat, confidence, metadata
                FROM messages
                WHERE id = %s
            ''', (threat_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            id, msg_type, sender, recipient, timestamp, encrypted_subject, encrypted_raw, encrypted_preprocessed, is_threat, confidence, metadata = row
            
            # SECURITY: Decrypt all encrypted fields
            decrypted_content = decrypt_data(encrypted_raw) if encrypted_raw else None
            decrypted_subject = decrypt_data(encrypted_subject) if encrypted_subject else None
            decrypted_preprocessed = decrypt_data(encrypted_preprocessed) if encrypted_preprocessed else None
            
            return {
                "id": id,
                "threat_type": msg_type,
                "sender": sender,
                "recipient": recipient,
                "timestamp": timestamp.isoformat() if timestamp else None,
                "subject": decrypted_subject,
                "content": decrypted_content,
                "preprocessed_text": decrypted_preprocessed,
                "is_threat": bool(is_threat),
                "confidence": confidence,
                "metadata": metadata or {}
            }
    except Exception as e:
        logger.error(f"Error retrieving threat {threat_id}: {e}")
        return None
    finally:
        release_conn(conn)


def get_all_threats(threat_type: str = None, limit: int = 100):
    """
    API-friendly wrapper to list all threats.
    
    Args:
        threat_type: Optional filter by threat type
        limit: Maximum number of threats to return
        
    Returns:
        List of threat dictionaries
    """
    conn = get_conn()
    if not conn:
        return []
    
    try:
        with conn.cursor() as cursor:
            if threat_type:
                cursor.execute('''
                    SELECT id, message_type, sender, timestamp, subject, 
                           is_threat, confidence, metadata
                    FROM messages
                    WHERE message_type = %s
                    ORDER BY timestamp DESC
                    LIMIT %s
                ''', (threat_type, limit))
            else:
                cursor.execute('''
                    SELECT id, message_type, sender, timestamp, subject,
                           is_threat, confidence, metadata
                    FROM messages
                    ORDER BY timestamp DESC
                    LIMIT %s
                ''', (limit,))
            
            results = cursor.fetchall()
            threats = []
            
            for row in results:
                id, msg_type, sender, timestamp, encrypted_subject, is_threat, confidence, metadata = row
                
                # SECURITY: Decrypt subject field
                decrypted_subject = decrypt_data(encrypted_subject) if encrypted_subject else None
                
                threats.append({
                    "id": id,
                    "threat_type": msg_type,
                    "sender": sender,
                    "timestamp": timestamp.isoformat() if timestamp else None,
                    "subject": decrypted_subject,
                    "is_threat": bool(is_threat),
                    "confidence": confidence,
                    "metadata": metadata or {}
                })
            
            return threats
    except Exception as e:
        logger.error(f"Error listing threats: {e}")
        return []
    finally:
        release_conn(conn)


if __name__ == "__main__":
    logger.info("🔌 INITIALIZING DATABASE CONNECTION TEST...")
    
    # Debug: Print where we are looking for .env
    project_root = Path(__file__).resolve().parent.parent.parent
    env_path = project_root / '.env'
    logger.info(f"Looking for .env at: {env_path}")
    
    conn = connect_db()
    
    if conn:
        logger.info("✅ CONNECTION SUCCESSFUL!")
        try:
            create_tables(conn)
            logger.info("✅ Tables Verified/Created.")
        except Exception as e:
            logger.error(f"❌ Database Operation Failed: {e}")
        finally:
            conn.close()
    else:
        logger.critical("❌ CONNECTION FAILED.")
        # Print the actual values being used to help debug
        logger.info(f"DEBUG: DB_HOST={os.getenv('DB_HOST')}")
        logger.info(f"DEBUG: DB_PORT={os.getenv('DB_PORT')}")
        logger.info("TROUBLESHOOTING STEPS:")
        logger.info("1. Ensure Docker Desktop is RUNNING.")
        logger.info("2. Run 'docker-compose up -d db'.")
        logger.info("3. Verify .env file exists and has DB_PORT=5433.")
    
    # Note: 'processed' column added via migration script