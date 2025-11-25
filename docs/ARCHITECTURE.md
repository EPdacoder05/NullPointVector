# Yahoo_Phish Architecture (High-level)

## 1. Core Storage & Vector DB

- Primary database: **PostgreSQL + pgvector**
- Connection & schema owned by: `Autobot/VectorDB/NullPoint_Vector.py`
  - `connect_db()` – single source of truth for DB connections
  - `create_tables(conn)` – ensures `messages` table and pgvector index exist
  - `insert_message(...)` – canonical way to write any message / threat record
  - `find_similar_messages(...)` – vector similarity search helper

## 2. Message Table Contract

Logical `messages` table fields (used across email/SMS/voice/intel):

- `id` – primary key
- `message_type` – `email | sms | voice | sender | url | ...`
- `sender`, `recipient`
- `timestamp` – when message was sent/received
- `subject` (email), `raw_content` (body/URL/etc), `preprocessed_text`
- `embedding` – pgvector(384) from SentenceTransformer
- `is_threat` (0/1), `confidence` (0.0–1.0)
- `metadata` – JSONB for channel-specific extras
- `label` – ML ground‑truth label for training

All producers (fetchers, intel loaders) and consumers (ML detectors, threat intel) must respect this contract.

## 3. Ingestion

- **Email**: `PhishGuard/providers/email_fetcher/*`
- **SMS (iPhone)**: `SmishGuard/sms_fetch/*`
- **Voice (iPhone)**: `VishGuard/voice_fetch/*`

Each fetcher is responsible for:

1. Normalizing raw source data into a standard email/SMS/voice dict
2. Persisting to DB using `insert_message()` from `NullPoint_Vector`
3. Optionally returning a simplified view for UI/testing

## 4. ML Detectors

- Email: `PhishGuard/phish_mlm/phishing_detector.py`
- SMS: `SmishGuard/smish_mlm/smishing_detector.py`
- Voice: `VishGuard/vish_mlm/vishing_detector.py`

Detectors:

- Read labeled rows from `messages`
- Train models (LogReg/NN) using embeddings + engineered features
- Write back predictions (`is_threat`, `confidence`) to `messages`

## 5. Threat Intelligence

- `utils/threat_intelligence.py`
  - Uses `connect_db`, `insert_message`, `find_similar_messages`
  - Adds derived threats (e.g., bad senders/URLs) directly into `messages`

---

This document is intentionally high-level. When refactoring, keep this as the north star: everything that wants persistence or memory goes through `Autobot/VectorDB/NullPoint_Vector.py` and the `messages` table contract.
