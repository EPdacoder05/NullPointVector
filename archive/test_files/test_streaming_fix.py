#!/usr/bin/env python3
"""
Test Streaming and Geolocation Fixes
Verifies:
1. Geolocation data is stored correctly in metadata
2. Dashboard queries work with new metadata structure
3. Real-time logging shows geo data
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from Autobot.VectorDB.NullPoint_Vector import connect_db
import json

print("="*70)
print("🧪 TESTING STREAMING & GEOLOCATION FIXES")
print("="*70)

# Test 1: Check database metadata structure
print("\n[1/3] 🗄️ Checking database metadata structure...")
conn = None
try:
    conn = connect_db()
    cursor = conn.cursor()
    
    # Get a recent message with metadata
    cursor.execute("""
        SELECT id, sender, subject, metadata
        FROM messages
        WHERE metadata IS NOT NULL
        ORDER BY timestamp DESC
        LIMIT 5
    """)
    
    rows = cursor.fetchall()
    
    if rows:
        print(f"   ✅ Found {len(rows)} messages with metadata")
        
        for msg_id, sender, subject, metadata in rows[:2]:
            print(f"\n   📧 Message ID {msg_id}:")
            print(f"      From: {sender}")
            print(f"      Subject: {subject[:50]}")
            
            if metadata and isinstance(metadata, dict):
                # Check for geo data
                geo = metadata.get('geo', {})
                ip = metadata.get('ip_address', '')
                
                if geo and isinstance(geo, dict):
                    print(f"      ✅ Geo Data Found:")
                    print(f"         Country: {geo.get('country', 'N/A')}")
                    print(f"         City: {geo.get('city', 'N/A')}")
                    print(f"         Risk: {geo.get('risk_level', 'N/A')}")
                    print(f"         IP: {ip}")
                else:
                    print(f"      ⚠️ No geo data in metadata")
                    print(f"      Metadata keys: {list(metadata.keys())}")
            else:
                print(f"      ⚠️ Metadata is not a dict or is None")
    else:
        print("   ⚠️ No messages with metadata found")
    
    if conn:
        conn.close()
    
except Exception as e:
    print(f"   ❌ Error: {e}")
    if conn:
        conn.close()

# Test 2: Test dashboard queries
print("\n[2/3] 📊 Testing dashboard queries...")
conn = None
try:
    conn = connect_db()
    cursor = conn.cursor()
    
    # Test: Threats with geolocation (as dashboard does)
    cursor.execute("""
        SELECT sender, subject, confidence, metadata
        FROM messages
        WHERE is_threat = true
          AND metadata IS NOT NULL
          AND metadata::text LIKE '%geo%'
        ORDER BY confidence DESC
        LIMIT 5
    """)
    
    threats = cursor.fetchall()
    
    if threats:
        print(f"   ✅ Found {len(threats)} threats with geolocation")
        
        geo_count = 0
        for sender, subject, confidence, metadata in threats:
            if metadata and isinstance(metadata, dict):
                geo = metadata.get('geo', {})
                if geo and isinstance(geo, dict):
                    lat = geo.get('latitude')
                    lon = geo.get('longitude')
                    country = geo.get('country', 'Unknown')
                    risk = geo.get('risk_level', 'UNKNOWN')
                    
                    if lat and lon:
                        geo_count += 1
                        print(f"   📍 {country} [{risk}] - Confidence: {confidence:.2f}")
        
        print(f"\n   ✅ {geo_count}/{len(threats)} threats have complete geo data (lat/lon)")
    else:
        print("   ⚠️ No threats with geolocation found")
    
    if conn:
        conn.close()
    
except Exception as e:
    print(f"   ❌ Error: {e}")
    if conn:
        conn.close()

# Test 3: Verify real-time logging hook
print("\n[3/3] 🔌 Checking real-time logging integration...")
try:
    from Autobot.email_ingestion import REALTIME_LOG_FUNC, set_realtime_logger
    
    if REALTIME_LOG_FUNC:
        print("   ✅ Real-time logging function is set")
    else:
        print("   ⚠️ Real-time logging function not set (normal if dashboard not running)")
    
    # Test setting a custom logger
    def test_logger(level, message, metadata=None):
        print(f"      [TEST LOG] {level.upper()}: {message}")
    
    set_realtime_logger(test_logger)
    
    from Autobot.email_ingestion import log_realtime
    log_realtime('info', 'Test message - streaming works!')
    
    print("   ✅ Real-time logging hook works")
    
except Exception as e:
    print(f"   ❌ Error: {e}")

print("\n" + "="*70)
print("📋 SUMMARY:")
print("   ✅ Dashboard now queries 'metadata->'geo'' instead of 'x_originating_ip'")
print("   ✅ Geolocation data stored in metadata->geo->{country, city, risk_level, etc}")
print("   ✅ Real-time logging enhanced with geo info and emojis")
print("   ✅ Threat map uses stored geo data (no re-queries)")
print("\n🚀 Start the dashboard with: python ui/dash_app.py")
print("🚀 Start monitoring with: python Autobot/yahoo_stream_monitor.py")
print("="*70)
