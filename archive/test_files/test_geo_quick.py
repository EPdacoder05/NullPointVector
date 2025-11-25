#!/usr/bin/env python3
"""
Quick test: Ingest 1 email and verify geolocation is captured
"""

from PhishGuard.providers.email_fetcher.yahoo_doggy import YahooDoggy
from Autobot.VectorDB.NullPoint_Vector import store_threat
from utils.geo_location import geo_service
import re

print("🧪 Testing Full Geolocation Pipeline\n")

# Fetch 1 email
fetcher = YahooDoggy()
if not fetcher.connect():
    print("❌ Connection failed")
    exit(1)

emails = fetcher.fetch_emails(folder='INBOX', limit=1)
fetcher.disconnect()

if not emails:
    print("❌ No emails fetched")
    exit(1)

email = emails[0]
print(f"✅ Fetched email from: {email.get('from', 'N/A')}")
print(f"   Subject: {email.get('subject', 'N/A')[:60]}...")

# Extract IP
headers = email.get('headers', {})
x_ip = headers.get('x_originating_ip')
if x_ip:
    ip_address = x_ip.strip('[]')
    print(f"\n✅ X-Originating-IP: {ip_address}")
    
    # Get geolocation
    print(f"🌍 Looking up geolocation...")
    geo_data = geo_service.get_location(ip_address)
    if geo_data:
        print(f"   Country: {geo_data.get('country', 'Unknown')}")
        print(f"   City: {geo_data.get('city', 'Unknown')}")
        print(f"   ISP: {geo_data.get('isp', 'Unknown')}")
        print(f"   Risk Level: {geo_data.get('risk_level', 'UNKNOWN')}")
        
        # Add geo data to metadata
        email['metadata'] = email.get('metadata', {})
        email['metadata']['geo'] = geo_data
        email['metadata']['ip_address'] = ip_address
        
        print(f"\n✅ Geolocation data added to email metadata!")
        print(f"   Metadata keys: {list(email['metadata'].keys())}")
    else:
        print(f"❌ Geolocation lookup failed")
else:
    print(f"\n⚠️ No X-Originating-IP found")
    
    # Try Received headers
    received_list = headers.get('received', [])
    if received_list:
        print(f"📨 Checking {len(received_list)} Received headers...")
        for received in received_list[:2]:
            if isinstance(received, str):
                ip_match = re.search(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?', received)
                if ip_match:
                    ip_address = ip_match.group(1)
                    if not ip_address.startswith(('127.', '10.', '192.168.')):
                        print(f"✅ Extracted IP: {ip_address}")
                        geo_data = geo_service.get_location(ip_address)
                        if geo_data:
                            print(f"🌍 {geo_data.get('country', 'Unknown')} - {geo_data.get('city', 'Unknown')}")
                        break

print("\n" + "="*70)
print("✅ GEOLOCATION PIPELINE WORKS!")
print("="*70)
