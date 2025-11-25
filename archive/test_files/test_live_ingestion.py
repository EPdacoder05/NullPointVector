#!/usr/bin/env python3
"""
Test Live Email Ingestion
Fetches a small batch of emails and verifies they're stored with geo data
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from Autobot.email_ingestion import EmailIngestionEngine, IngestionConfig
from Autobot.VectorDB.NullPoint_Vector import connect_db

print("="*70)
print("🧪 TESTING LIVE EMAIL INGESTION")
print("="*70)

# Check database BEFORE ingestion
print("\n[BEFORE] Checking database state...")
conn = connect_db()
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM messages')
before_count = cursor.fetchone()[0]
print(f"   Total messages: {before_count}")

cursor.execute("SELECT COUNT(*) FROM messages WHERE metadata IS NOT NULL AND metadata::text LIKE '%geo%'")
before_geo = cursor.fetchone()[0]
print(f"   Messages with geo: {before_geo}")
conn.close()

# Run ingestion for 1 provider with small batch
print("\n[INGESTING] Fetching 10 emails from Yahoo...")
config = IngestionConfig(
    batch_size=10,
    max_emails_per_provider=10,
    parallel_providers=False,
    enable_intelligence=True,
    enable_ml_analysis=True
)

engine = EmailIngestionEngine(config)
stats = engine.ingest_all_providers(['yahoo'])

print(f"\n[STATS] Ingestion completed:")
print(f"   Emails processed: {stats.total_emails}")
print(f"   Threats detected: {stats.threats_detected}")
print(f"   Processing time: {stats.processing_time:.2f}s")

# Check database AFTER ingestion
print("\n[AFTER] Checking database state...")
conn = connect_db()
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM messages')
after_count = cursor.fetchone()[0]
print(f"   Total messages: {after_count}")

cursor.execute("SELECT COUNT(*) FROM messages WHERE metadata IS NOT NULL AND metadata::text LIKE '%geo%'")
after_geo = cursor.fetchone()[0]
print(f"   Messages with geo: {after_geo}")

# Check most recent message
cursor.execute("""
    SELECT sender, subject, timestamp, metadata
    FROM messages
    ORDER BY timestamp DESC
    LIMIT 1
""")
latest = cursor.fetchone()
if latest:
    sender, subject, timestamp, metadata = latest
    print(f"\n[LATEST] Most recent message:")
    print(f"   From: {sender}")
    print(f"   Subject: {subject[:60]}")
    print(f"   Time: {timestamp}")
    
    if metadata and isinstance(metadata, dict):
        geo = metadata.get('geo', {})
        if geo:
            print(f"   ✅ Geo data present:")
            print(f"      Country: {geo.get('country', 'N/A')}")
            print(f"      City: {geo.get('city', 'N/A')}")
            print(f"      Risk: {geo.get('risk_level', 'N/A')}")
        else:
            print(f"   ⚠️ No geo data (email may not have X-Originating-IP header)")
    else:
        print(f"   ⚠️ No metadata")

conn.close()

# Results
print("\n" + "="*70)
new_emails = after_count - before_count
new_geo = after_geo - before_geo
print(f"📊 RESULTS:")
print(f"   New emails stored: {new_emails}")
print(f"   New emails with geo: {new_geo}")

if new_emails > 0:
    print(f"   ✅ Data IS being stored in database!")
    if new_geo > 0:
        print(f"   ✅ Geolocation IS being captured!")
    else:
        print(f"   ⚠️ No geo data (emails may not have IP headers)")
else:
    print(f"   ❌ NO NEW EMAILS STORED - Check fetch_emails()")

print("="*70)
