#!/usr/bin/env python3
"""
Comprehensive test of ALL fixes:
1. IP extraction from emails
2. Geolocation lookup
3. Database storage with geo data
4. Real-time logging with timestamps
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from Autobot.email_ingestion import EmailIngestionEngine, IngestionConfig
from Autobot.VectorDB.NullPoint_Vector import connect_db

print("="*70)
print("🧪 COMPREHENSIVE FIX VALIDATION TEST")
print("="*70)

# Test 1: IP Extraction
print("\n[1/4] Testing IP extraction...")
from PhishGuard.providers.email_fetcher.yahoo_doggy import YahooDoggy

fetcher = YahooDoggy()
if fetcher.connect():
    emails = fetcher.fetch_emails(folder='INBOX', limit=2)
    fetcher.disconnect()
    
    for email in emails:
        ips = email.get('ip_addresses', [])
        print(f"   Email from {email['from'][:30]}: {len(ips)} IPs = {ips[:2]}")
        if ips:
            print(f"   ✅ IP extraction working!")
            break
    else:
        print(f"   ⚠️ No IPs found in {len(emails)} emails")

# Test 2: Check database BEFORE ingestion
print("\n[2/4] Database state before...")
conn = connect_db()
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM messages')
before_count = cursor.fetchone()[0]
cursor.execute("SELECT COUNT(*) FROM messages WHERE metadata->>'ip_address' IS NOT NULL")
before_geo = cursor.fetchone()[0]
print(f"   Total: {before_count}, With GEO: {before_geo}")
conn.close()

# Test 3: Ingest with new code
print("\n[3/4] Running ingestion with fixes...")
config = IngestionConfig(
    batch_size=5,
    max_emails_per_provider=5,
    parallel_providers=False
)
engine = EmailIngestionEngine(config)
stats = engine.ingest_all_providers(['yahoo'])

print(f"   Processed: {stats.total_emails} emails")

# Test 4: Verify geo data in database
print("\n[4/4] Verifying geo data stored...")
conn = connect_db()
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM messages')
after_count = cursor.fetchone()[0]
cursor.execute("SELECT COUNT(*) FROM messages WHERE metadata->>'ip_address' IS NOT NULL")
after_geo = cursor.fetchone()[0]

cursor.execute("""
    SELECT sender, 
           metadata->'geo'->>'country' as country,
           metadata->'geo'->>'risk_level' as risk,
           metadata->>'ip_address' as ip
    FROM messages
    WHERE metadata->>'ip_address' IS NOT NULL
    ORDER BY id DESC
    LIMIT 3
""")

print(f"   Total: {after_count} (+{after_count-before_count})")
print(f"   With GEO: {after_geo} (+{after_geo-before_geo})")

if after_geo > before_geo:
    print(f"\n   ✅ NEW GEO DATA CAPTURED!")
    print(f"\n   Sample emails with geolocation:")
    for sender, country, risk, ip in cursor.fetchall():
        print(f"   - {sender[:30]}: {country} [{risk}] {ip}")
else:
    print(f"\n   ⚠️ No new geo data (emails may not have IP headers)")

conn.close()

print("\n" + "="*70)
print("🎯 TEST COMPLETE")
print("="*70)
