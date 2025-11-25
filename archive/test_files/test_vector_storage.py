#!/usr/bin/env python3
"""Test vector DB storage after fixing array formatting"""

from Autobot.VectorDB.NullPoint_Vector import store_threat

# Test single insert
print("🧪 Testing vector storage...")
result = store_threat(
    content='URGENT: Verify your account now or it will be suspended!',
    threat_type='phishing',
    sender='noreply@phishing-site.com',
    metadata={'subject': 'Account Verification Required', 'label': 1, 'test': True}
)

if result.get('id'):
    print(f"✅ SUCCESS! Threat ID: {result['id']}")
    print(f"   Type: {result['threat_type']}")
    print(f"   Timestamp: {result['timestamp']}")
else:
    print(f"❌ FAILED: {result.get('error')}")
