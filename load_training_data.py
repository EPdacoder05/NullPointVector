#!/usr/bin/env python3
"""Load all Phishy_Bizz folder emails as training data"""

from PhishGuard.providers.email_fetcher.yahoo_doggy import YahooDoggy
from Autobot.VectorDB.NullPoint_Vector import store_threat
import email as email_module

print("📧 Connecting to Yahoo...")
fetcher = YahooDoggy()
if not fetcher.connect():
    print("❌ Connection failed")
    exit(1)

print('📂 Fetching from "Phishy bizz" folder...')
fetcher.connection.select('"Phishy bizz"')
_, msg_ids = fetcher.connection.search(None, 'ALL')
ids = msg_ids[0].split()

print(f'✅ Found {len(ids)} phishing emails\n')

stored = 0
failed = 0

for i, email_id in enumerate(ids, 1):
    try:
        _, msg_data = fetcher.connection.fetch(email_id, '(RFC822)')
        msg = email_module.message_from_bytes(msg_data[0][1])
        
        subject = str(msg.get('Subject', ''))
        sender = str(msg.get('From', ''))
        
        # Extract body
        body = ''
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
                    except:
                        pass
        else:
            try:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                body = str(msg.get_payload())
        
        # Store in Vector DB
        result = store_threat(
            content=(body or subject)[:3000],  # Limit size
            threat_type='phishing',
            sender=sender[:150],
            metadata={
                'subject': subject[:200],
                'label': 1,  # Confirmed phishing
                'source': 'Phishy_bizz',
                'date': str(msg.get('Date', ''))
            }
        )
        
        if result.get('id'):
            stored += 1
            print(f"  [{i:2d}] ✅ ID={result['id']:4d} | {subject[:50]}")
        else:
            failed += 1
            print(f"  [{i:2d}] ❌ {result.get('error', 'Unknown')[:50]}")
    
    except Exception as e:
        failed += 1
        print(f"  [{i:2d}] ❌ Exception: {str(e)[:60]}")

fetcher.disconnect()

print(f"\n{'='*70}")
print(f"🎉 Training Data Loaded:")
print(f"   ✅ Stored: {stored}/{len(ids)}")
print(f"   ❌ Failed: {failed}/{len(ids)}")
print(f"{'='*70}")
print(f"\n📊 Vector DB now has {stored} labeled phishing samples")
print(f"🔁 Ready to retrain ML model with: python -m PhishGuard.phish_mlm.phishing_detector")
