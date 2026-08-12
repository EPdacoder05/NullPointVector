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
import sys
from datetime import datetime
from pathlib import Path
from psycopg2 import pool
from functools import lru_cache
from time import time

# Add logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Embedding model is loaded lazily (singleton) on first use rather than at import
# time. This keeps `import` side-effect-free and offline-safe: the API can boot,
# serve /health, and validate config even if the model cache/network is cold —
# the (one-time) download/load is deferred to the first embedding call.
_model = None


def _get_model():
    global _model
    if _model is None:
        _model = SentenceTransformer('all-MiniLM-L6-v2')
    return _model


def generate_embedding(text):
    """Generate an embedding for the given text using the SentenceTransformer model.

    Set ENABLE_MESSAGE_EMBEDDINGS=0 to skip (stores a zero vector). MiniLM load +
    encode on every ingest was OOM-killing the app → nginx 502 Bad Gateway.
    """
    if os.environ.get("ENABLE_MESSAGE_EMBEDDINGS", "0").strip().lower() in (
        "0", "false", "no", "off", ""
    ):
        return np.zeros(384, dtype=np.float32)
    m = _get_model()
    if text is None or not isinstance(text, str):
        logger.warning("Attempted to generate embedding for None or non-string text. Returning zero vector.")
        return np.zeros(m.get_sentence_embedding_dimension(), dtype=np.float32)
    return m.encode(text)

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
_last_db_error_log = 0.0
_reported_host_fallbacks = set()


def _throttled_db_error(message, interval_seconds=30):
    """Avoid spamming identical DB errors every callback tick."""
    global _last_db_error_log
    now = time()
    if now - _last_db_error_log >= interval_seconds:
        logger.error(message)
        _last_db_error_log = now


def _candidate_db_hosts(configured_host):
    """Return host candidates, falling back to local host when docker host is unavailable."""
    host = configured_host or 'localhost'
    candidates = [host]

    # In local runs, DB_HOST is often a docker service name ("db"/"pgbouncer")
    # that doesn't resolve on the host. Fall back to loopback (both are bound to
    # 127.0.0.1 in docker-compose) so app-on-host + stack-in-docker still works.
    if host in {'db', 'postgres', 'postgresql', 'pgbouncer'}:
        candidates.extend(['localhost', '127.0.0.1'])

    # De-duplicate while preserving order.
    seen = set()
    ordered = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def _log_host_fallback_once(original_host, fallback_host):
    """Log host fallback a single time to keep callback logs readable."""
    key = (original_host, fallback_host)
    if key in _reported_host_fallbacks:
        return
    _reported_host_fallbacks.add(key)
    logger.warning(f"⚠️ DB host fallback active: {original_host} -> {fallback_host}")

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
    
    # Prefer process env (Docker Compose) over .env file so container DB_HOST wins.
    host = os.getenv('DB_HOST') or config.get('DB_HOST') or 'localhost'
    port = os.getenv('DB_PORT') or config.get('DB_PORT') or '5432'
    user = os.getenv('DB_USER') or config.get('DB_USER') or 'EPNP'
    password = os.getenv('DB_PASSWORD') or config.get('DB_PASSWORD')
    dbname = os.getenv('DB_NAME') or config.get('DB_NAME') or 'NullPointVector'
    
    for candidate_host in _candidate_db_hosts(host):
        try:
            _connection_pool = pool.SimpleConnectionPool(
                minconn=1,
                maxconn=10,
                dbname=dbname,
                user=user,
                password=password,
                host=candidate_host,
                port=port,
                connect_timeout=10,
                application_name="yahoo_phish",
            )
            if candidate_host != host:
                _log_host_fallback_once(host, candidate_host)
            logger.info(f"✅ Connection pool initialized ({candidate_host}:{port})")
            return _connection_pool
        except Exception as e:
            _throttled_db_error(f"❌ Failed to create connection pool on host '{candidate_host}': {e}")

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
    try:
        from common.tenant_rls import clear_tenant
        clear_tenant(conn)
    except Exception:
        pass
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
            load_dotenv(dotenv_path=env_path, override=False)
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

    # 4. Prefer process env (Docker) over .env file values
    host = os.getenv('DB_HOST') or config.get('DB_HOST') or 'localhost'
    port = os.getenv('DB_PORT') or config.get('DB_PORT') or '5432'
    user = os.getenv('DB_USER') or config.get('DB_USER') or 'EPNP'
    password = os.getenv('DB_PASSWORD') or config.get('DB_PASSWORD')
    dbname = os.getenv('DB_NAME') or config.get('DB_NAME') or 'NullPointVector'

    base_config = {
        'dbname': dbname,
        'user': user,
        'password': password,
        'port': port,
        'connect_timeout': 10,
        'application_name': 'yahoo_phish',
    }

    for candidate_host in _candidate_db_hosts(host):
        db_config = dict(base_config)
        db_config['host'] = candidate_host
        try:
            if __name__ == "__main__":
                logger.info(
                    f"Attempting connection to: {db_config['host']}:{db_config['port']} as {db_config['user']}"
                )

            conn = psycopg2.connect(**db_config)
            if candidate_host != host:
                _log_host_fallback_once(host, candidate_host)
            return conn
        except psycopg2.Error as e:
            _throttled_db_error(f"Database connection failed on host '{candidate_host}': {e}")

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
        # In production, an ephemeral key is a data-loss bug: every restart would
        # generate a fresh key and orphan all previously-encrypted rows. Fail loud
        # so the key is provisioned via secret manager / env. Dev keeps ephemeral.
        if os.getenv("ENV", "development").lower() == "production":
            raise RuntimeError(
                "ENCRYPTION_KEY is not set. Refusing to start in production with an "
                "ephemeral key (would orphan all previously-encrypted data). "
                "Provision ENCRYPTION_KEY via your secret manager."
            )
        key = Fernet.generate_key()
        logger.warning("ENCRYPTION_KEY unset — generated an EPHEMERAL key (dev only). "
                       "Data encrypted now will be unreadable after restart.")
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
    """Decrypt data with UTF-8 decoding.

    Tolerates both storage formats found in the messages table:
      * str Fernet token ("gAAAA…") — token decoded to text before insert
      * bytea hex literal ("\\x6741…") — bytes token inserted into a TEXT
        column, which Postgres renders as a hex string on read
    """
    try:
        if encrypted_data is None:
            return None
        if isinstance(encrypted_data, memoryview):
            encrypted_data = bytes(encrypted_data)
        if isinstance(encrypted_data, str) and encrypted_data.startswith("\\x"):
            encrypted_data = bytes.fromhex(encrypted_data[2:]).decode("utf-8", "ignore")
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
    except psycopg2.IntegrityError as e:
        # Unique idx on rfc_message_id / ingest_fp — race-safe dedup
        logger.info("ingest dedup conflict (already stored): %s", e)
        conn.rollback()
        return None
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


def get_threats_by_sender(sender: str, limit: int = 50):
    """Return confirmed threats previously seen from a given sender / caller-id.

    Powers the local (always-on, zero-cost) reputation provider: a number that
    burned one user is instantly known for the next. Matches on the exact stored
    `sender` value (CallKit caller_id / SMS from). Fail-safe → [] on any error.
    """
    if not sender:
        return []
    conn = get_conn()
    if not conn:
        return []
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                SELECT id, message_type, sender, timestamp, is_threat, confidence, metadata
                FROM messages
                WHERE sender = %s AND is_threat = 1
                ORDER BY timestamp DESC
                LIMIT %s
            ''', (sender, limit))
            rows = cursor.fetchall()
            out = []
            for row in rows:
                _id, msg_type, snd, ts, is_threat, confidence, metadata = row
                out.append({
                    "id": _id,
                    "threat_type": msg_type,
                    "sender": snd,
                    "timestamp": ts.isoformat() if ts else None,
                    "is_threat": bool(is_threat),
                    "confidence": confidence,
                    "metadata": metadata or {},
                })
            return out
    except Exception as e:
        logger.error(f"Error fetching threats by sender: {e}")
        return []
    finally:
        release_conn(conn)


def get_vish_directory(limit: int = 5000):
    """Build Call Directory block/label lists from confirmed vishing/smishing threats.

    Returns (updated_at_iso, block_numbers, label_entries).
    Fail-safe → empty lists on any error. `is_threat` is integer (1/0) in Postgres.
    """
    from common.reputation.base import normalize_number
    import os
    conn = get_conn()
    block, label, seen = [], [], set()
    updated = None

    def _add_number(snd, metadata, ts):
        nonlocal updated
        if not snd:
            return
        num = normalize_number(str(snd))
        if not num or not num.startswith("+") or num in seen:
            return
        seen.add(num)
        meta = metadata or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        action = str(meta.get("action", "")).lower()
        risk = float(meta.get("risk_score", 0) or 0)
        if ts and updated is None:
            updated = ts
        if action == "block" or risk >= 0.85 or meta.get("is_threat") in (True, 1, "1"):
            block.append(num)
        elif action in ("label", "silence") or risk >= 0.4:
            lbl = str(meta.get("label") or meta.get("verdict") or "Suspicious caller")
            if isinstance(lbl, (int, float)):
                lbl = "Suspicious caller"
            label.append({"number": num, "label": str(lbl).replace("_", " ").title()})
        else:
            # Confirmed threat row without fine-grained action → block
            block.append(num)

    if conn:
        try:
            with conn.cursor() as cursor:
                # is_threat is INTEGER (1/0), never compare to TRUE boolean.
                cursor.execute(
                    '''
                    SELECT sender, metadata, timestamp
                    FROM messages
                    WHERE message_type IN (%s, %s) AND is_threat = 1
                    ORDER BY timestamp DESC
                    LIMIT %s
                    ''',
                    ("vishing", "smishing", max(1, min(int(limit), 10000))),
                )
                for snd, metadata, ts in cursor.fetchall():
                    _add_number(snd, metadata, ts)
        except Exception as e:
            logger.error(f"Error building vish directory: {e}")
        finally:
            release_conn(conn)

    # Hot vendor numbers (IPQS enrich cron). Raw SQL only — no import of
    # common.number_reputation (avoids Autobot↔common cycle).
    if conn:
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT to_regclass('public.number_reputation')
                    """
                )
                if cursor.fetchone()[0]:
                    cursor.execute(
                        """
                        SELECT e164, risk, verdict
                        FROM number_reputation
                        WHERE risk >= 0.4
                        ORDER BY risk DESC
                        LIMIT 2000
                        """
                    )
                    for e164, risk, verdict in cursor.fetchall():
                        num = normalize_number(str(e164 or ""))
                        if not num or num in seen:
                            continue
                        seen.add(num)
                        r = float(risk or 0)
                        if r >= 0.85:
                            block.append(num)
                        else:
                            lbl = str(verdict or "Suspicious caller").replace("_", " ").title()
                            label.append({"number": num, "label": lbl})
        except Exception as e:
            logger.debug("number_reputation directory sql: %s", e)

    # Pilot seed so TestFlight sync is never empty before live call grades exist.
    seed = os.getenv(
        "VISH_DIRECTORY_SEED",
        "+18005550199,+18885550100,+12125551212",
    )
    for raw in seed.split(","):
        raw = raw.strip()
        if not raw:
            continue
        num = normalize_number(raw)
        if num and num.startswith("+") and num not in seen:
            seen.add(num)
            block.append(num)

    # Campaign packs (tax-resolution robocalls, etc.) — versioned JSON under data/vish_campaigns/.
    try:
        from pathlib import Path
        import json
        pack_dir = Path(__file__).resolve().parents[2] / "data" / "vish_campaigns"
        if pack_dir.is_dir():
            for path in sorted(pack_dir.glob("*.json")):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except Exception as e:
                    logger.warning("vish campaign pack %s: %s", path.name, e)
                    continue
                for raw in data.get("block") or []:
                    num = normalize_number(str(raw))
                    if num and num.startswith("+") and num not in seen:
                        seen.add(num)
                        block.append(num)
                for entry in data.get("label") or []:
                    if isinstance(entry, dict):
                        num = normalize_number(str(entry.get("number") or ""))
                        lbl = str(entry.get("label") or data.get("label") or "Suspicious caller")
                    else:
                        num = normalize_number(str(entry))
                        lbl = str(data.get("label") or "Suspicious caller")
                    if num and num.startswith("+") and num not in seen:
                        seen.add(num)
                        label.append({"number": num, "label": lbl})
    except Exception as e:
        logger.warning("vish campaign packs: %s", e)

    if updated is None:
        updated_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        updated_at = updated.isoformat() if hasattr(updated, "isoformat") else str(updated)
        if not updated_at.endswith("Z") and "+" not in updated_at:
            updated_at = updated_at.replace("+00:00", "Z")
    return updated_at, block, label


def get_threats_page(threat_type: str = None, after_id: int = None, limit: int = 50,
                     *, max_confidence: float = None, min_confidence: float = None):
    """
    Keyset (cursor) pagination over threats, ordered by descending id.

    max_confidence / min_confidence segment streams from Quarantine:
      Inbox/Dashboard/feed: max_confidence=0.85 (below hard hold)
      Quarantine uses get_review_queue (conf >= 0.70) separately
    """
    conn = get_conn()
    if not conn:
        return [], None

    limit = max(1, min(int(limit), 500))  # clamp page size (DoS guard)
    cursor_id = after_id if after_id and int(after_id) > 0 else None

    cols = ("id, message_type, sender, timestamp, subject, "
            "is_threat, confidence, metadata, label")
    clauses, params = [], []
    if threat_type:
        clauses.append("message_type = %s")
        params.append(threat_type)
    if cursor_id is not None:
        clauses.append("id < %s")
        params.append(cursor_id)
    # Hide human-graded mail from live triage (inbox + dashboard).
    # Safe (0) and Block (1) both leave the stream; Quarantine still uses label IS NULL.
    clauses.append("label IS NULL")
    if max_confidence is not None:
        clauses.append("confidence < %s")
        params.append(float(max_confidence))
    if min_confidence is not None:
        clauses.append("confidence >= %s")
        params.append(float(min_confidence))
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit + 1)  # fetch one extra to know if a next page exists

    try:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {cols} FROM messages {where} ORDER BY id DESC LIMIT %s",
                tuple(params),
            )
            rows = cur.fetchall()
            has_more = len(rows) > limit
            rows = rows[:limit]
            threats = []
            for row in rows:
                _id, msg_type, sender, ts, enc_subject, is_threat, conf, meta, label = row
                threats.append({
                    "id": _id,
                    "threat_type": msg_type,
                    "sender": sender,
                    "timestamp": ts.isoformat() if ts else None,
                    "subject": decrypt_data(enc_subject) if enc_subject else None,
                    "is_threat": bool(is_threat),
                    "confidence": conf,
                    "metadata": meta or {},
                    "label": label,
                })
            next_cursor = threats[-1]["id"] if (threats and has_more) else None
            return threats, next_cursor
    except Exception as e:
        logger.error(f"Error paginating threats: {e}")
        return [], None
    finally:
        release_conn(conn)


def get_review_queue(limit: int = 100):
    """Ungraded hard holds for Quarantine (confidence >= 0.85).

    Inbox/Dashboard use max_confidence=0.85 so rows never duplicate.
    Returns (rows, counts). Fail-safe → ([], zeroed counts).
    """
    counts = {"total": 0, "quarantined": 0, "potential": 0, "unsure": 0}
    conn = get_conn()
    if not conn:
        return [], counts
    try:
        with conn.cursor() as cur:
            cur.execute('''
                SELECT id, message_type, sender, timestamp, subject, confidence, metadata,
                       preprocessed_text
                FROM messages
                WHERE label IS NULL AND confidence >= 0.85
                ORDER BY confidence DESC, id DESC
                LIMIT %s
            ''', (max(1, min(int(limit), 500)),))
            rows = []
            for _id, msg_type, sender, ts, enc_subject, conf, meta, enc_body in cur.fetchall():
                conf = float(conf or 0)
                band = "quarantined"
                counts["total"] += 1
                counts[band] += 1
                body = ""
                try:
                    body = decrypt_data(enc_body) if enc_body else ""
                except Exception:
                    body = ""
                rows.append({
                    "id": _id,
                    "channel": msg_type or "phishing",
                    "sender": sender or "unknown",
                    "timestamp": ts.isoformat() if ts else None,
                    "subject": decrypt_data(enc_subject) if enc_subject else None,
                    "body": body or "",
                    "confidence": conf,
                    "band": band,
                    "metadata": meta or {},
                })
            return rows, counts
    except Exception as e:
        logger.error(f"Error building review queue: {e}")
        return [], counts
    finally:
        release_conn(conn)


def list_sender_siblings(msg_id: int, limit: int = 80):
    """Ungraded messages from the same sender (for cascade confirm UI)."""
    conn = get_conn()
    if not conn:
        return {"sender": "", "siblings": []}
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT sender FROM messages WHERE id = %s LIMIT 1",
                (int(msg_id),),
            )
            row = cur.fetchone()
            if not row or not row[0]:
                return {"sender": "", "siblings": []}
            sender = row[0]
            cur.execute(
                '''
                SELECT DISTINCT ON (
                    COALESCE(NULLIF(metadata->>'rfc_message_id', ''), subject)
                )
                    id, subject, timestamp, confidence
                FROM messages
                WHERE sender = %s AND id <> %s AND label IS NULL
                ORDER BY COALESCE(NULLIF(metadata->>'rfc_message_id', ''), subject),
                         id DESC
                LIMIT %s
                ''',
                (sender, int(msg_id), int(limit)),
            )
            out = []
            for mid, enc_subject, ts, conf in cur.fetchall():
                try:
                    subj = decrypt_data(enc_subject) if enc_subject else ""
                except Exception:
                    subj = ""
                out.append({
                    "id": int(mid),
                    "subject": (subj or "")[:120],
                    "timestamp": ts.isoformat() if ts else None,
                    "confidence": float(conf or 0),
                })
            return {"sender": sender, "siblings": out}
    except Exception as e:
        logger.error("list_sender_siblings failed: %s", e)
        return {"sender": "", "siblings": []}
    finally:
        release_conn(conn)


def set_message_grade(msg_id: int, label=None, status: str = "", *,
                      cascade_sender: bool = True,
                      also_ids=None):
    """Persist a human verdict on one message (Quarantine/Inbox grading).

    label: 1 = confirmed threat, 0 = confirmed safe, None = still unsure
    status: free-form status string stored in metadata (blocked/safe/unsure).
    Also flips is_threat so inbox/dashboard stop showing cleared mail as threats.
    When also_ids is a list, only those extra ids (same sender, still ungraded)
    are cascaded. When also_ids is None and cascade_sender, cascade all same-sender.
    Returns the graded record (for the feedback buffer) or None on failure.
    """
    conn = get_conn()
    if not conn:
        return None
    try:
        # Align is_threat with the human verdict so UI lists stay consistent.
        if label == 0:
            threat_flag = 0
            conf_override = 0.0
        elif label == 1:
            threat_flag = 1
            conf_override = None  # keep model confidence
        else:
            threat_flag = None
            conf_override = None
        with conn.cursor() as cur:
            if conf_override is not None:
                cur.execute('''
                    UPDATE messages
                    SET label = %s,
                        is_threat = %s,
                        confidence = %s,
                        metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                                             '{review_status}', to_jsonb(%s::text))
                    WHERE id = %s
                    RETURNING message_type, sender, subject, preprocessed_text, confidence
                ''', (label, threat_flag, conf_override, status or "ungraded", int(msg_id)))
            elif threat_flag is not None:
                cur.execute('''
                    UPDATE messages
                    SET label = %s,
                        is_threat = %s,
                        metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                                             '{review_status}', to_jsonb(%s::text))
                    WHERE id = %s
                    RETURNING message_type, sender, subject, preprocessed_text, confidence
                ''', (label, threat_flag, status or "ungraded", int(msg_id)))
            else:
                cur.execute('''
                    UPDATE messages
                    SET label = %s,
                        metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                                             '{review_status}', to_jsonb(%s::text))
                    WHERE id = %s
                    RETURNING message_type, sender, subject, preprocessed_text, confidence
                ''', (label, status or "ungraded", int(msg_id)))
            row = cur.fetchone()
            if not row:
                conn.commit()
                return None
            msg_type, sender, enc_subject, enc_text, conf = row
            cascaded_ids = [int(msg_id)]

            # Same mailbox still ungraded → same verdict (all, or selected also_ids).
            if label in (0, 1) and sender:
                extra = None
                if also_ids is not None:
                    try:
                        extra = sorted({int(x) for x in also_ids if int(x) != int(msg_id)})
                    except (TypeError, ValueError):
                        extra = []
                elif cascade_sender:
                    extra = None  # means: all matching sender
                else:
                    extra = []

                if extra is None or extra:
                    if conf_override is not None:
                        if extra is None:
                            cur.execute('''
                                UPDATE messages
                                SET label = %s, is_threat = %s, confidence = %s,
                                    metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                                                         '{review_status}', to_jsonb(%s::text))
                                WHERE sender = %s AND id <> %s AND label IS NULL
                                RETURNING id
                            ''', (label, threat_flag, conf_override, status or "ungraded",
                                  sender, int(msg_id)))
                        else:
                            cur.execute('''
                                UPDATE messages
                                SET label = %s, is_threat = %s, confidence = %s,
                                    metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                                                         '{review_status}', to_jsonb(%s::text))
                                WHERE sender = %s AND id = ANY(%s) AND label IS NULL
                                RETURNING id
                            ''', (label, threat_flag, conf_override, status or "ungraded",
                                  sender, extra))
                    else:
                        if extra is None:
                            cur.execute('''
                                UPDATE messages
                                SET label = %s, is_threat = %s,
                                    metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                                                         '{review_status}', to_jsonb(%s::text))
                                WHERE sender = %s AND id <> %s AND label IS NULL
                                RETURNING id
                            ''', (label, threat_flag, status or "ungraded",
                                  sender, int(msg_id)))
                        else:
                            cur.execute('''
                                UPDATE messages
                                SET label = %s, is_threat = %s,
                                    metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                                                         '{review_status}', to_jsonb(%s::text))
                                WHERE sender = %s AND id = ANY(%s) AND label IS NULL
                                RETURNING id
                            ''', (label, threat_flag, status or "ungraded",
                                  sender, extra))
                    cascaded_ids.extend(int(r[0]) for r in cur.fetchall())

            conn.commit()

            def _safe(enc):
                try:
                    return decrypt_data(enc) or "" if enc else ""
                except Exception:
                    return ""

            # Learn domain for future ingest short-circuit when marked safe.
            if label == 0 and sender:
                try:
                    from utils.safe_sender_manager import SafeSenderManager
                    SafeSenderManager(conn).add_safe_sender(
                        sender, reason="console-grade-safe", auto_learned=True)
                except Exception as e:
                    logger.debug("safe_sender learn skipped: %s", e)

            return {
                "id": int(msg_id),
                "channel": msg_type or "phishing",
                "sender": sender or "",
                "subject": _safe(enc_subject),
                "text": _safe(enc_text),
                "confidence": float(conf or 0),
                "cascaded_ids": cascaded_ids,
                "cascaded": max(0, len(cascaded_ids) - 1),
            }
    except Exception as e:
        logger.error(f"Error grading message {msg_id}: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return None
    finally:
        release_conn(conn)


def get_message_detail(msg_id: int):
    """Decrypt one message for the analyst message view (console only)."""
    conn = get_conn()
    if not conn:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute('''
                SELECT id, message_type, sender, recipient, timestamp, subject,
                       raw_content, preprocessed_text, is_threat, confidence,
                       metadata, label
                FROM messages WHERE id = %s
            ''', (int(msg_id),))
            row = cur.fetchone()
            if not row:
                return None
            (_id, msg_type, sender, recipient, ts, enc_subj, enc_raw, enc_pre,
             is_threat, conf, meta, label) = row

            def _safe(enc):
                try:
                    return decrypt_data(enc) or "" if enc else ""
                except Exception:
                    return ""

            body = _safe(enc_raw) or _safe(enc_pre)
            return {
                "id": int(_id),
                "channel": msg_type or "phishing",
                "sender": sender or "",
                "recipient": recipient or "",
                "timestamp": ts.isoformat() if ts else None,
                "subject": _safe(enc_subj),
                "body": body,
                "is_threat": bool(is_threat),
                "confidence": float(conf or 0),
                "metadata": meta if isinstance(meta, dict) else {},
                "label": label,
            }
    except Exception as e:
        logger.error("Error loading message %s: %s", msg_id, e)
        return None
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
            conn.close()
            # Exit non-zero so the launcher's retry loop can react instead of
            # booting the API against a DB with no schema.
            sys.exit(1)
        finally:
            if not conn.closed:
                conn.close()
    else:
        logger.critical("❌ CONNECTION FAILED.")
        # Print the actual values being used to help debug
        logger.info(f"DEBUG: DB_HOST={os.getenv('DB_HOST')}")
        logger.info(f"DEBUG: DB_PORT={os.getenv('DB_PORT')}")
        logger.info("TROUBLESHOOTING STEPS:")
        logger.info("1. Ensure the database/PgBouncer containers are RUNNING.")
        logger.info("2. Run 'docker compose up -d db pgbouncer'.")
        logger.info("3. Verify .env has DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_NAME.")
        sys.exit(1)

    # Note: 'processed' column added via migration script