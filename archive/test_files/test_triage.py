#!/usr/bin/env python3
"""
Test Threat Triage System
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from utils.threat_actions import threat_actions
from utils.geo_location import geo_service

def test_threat_actions():
    """Test threat action manager."""
    print("🧪 Testing Threat Actions Manager\n")
    
    # Sample threat data
    threat = {
        'id': 'test-001',
        'sender': 'phisher@evil.com',
        'subject': 'URGENT: Verify your account NOW!',
        'threat_score': 0.95,
        'headers': {
            'x_originating_ip': '8.8.8.8',
            'return_path': 'phisher@evil.com',
            'message_id': '<test001@evil.com>',
            'authentication_results': 'spf=fail',
            'received_spf': 'fail',
            'dkim_signature': 'none'
        }
    }
    
    # Test warning
    print("1️⃣ Testing WARN action...")
    result = threat_actions.warn_sender(threat, "HIGH")
    if result:
        print("   ✅ Sender warned successfully")
        print(f"   📊 Warned senders: {len(threat_actions.get_warned_senders())}")
    else:
        print("   ❌ Failed to warn sender")
    
    # Test reporting
    print("\n2️⃣ Testing REPORT action...")
    report = threat_actions.report_threat(threat, "internal")
    if report:
        print(f"   ✅ Report generated: {report['report_id']}")
        print(f"   📄 Report file: data/reports/{report['report_id']}.json")
        print(f"   🔍 Forensics: {len(report['forensics'])} fields captured")
    else:
        print("   ❌ Failed to generate report")
    
    # Test action log
    print("\n3️⃣ Testing action log...")
    actions = threat_actions.get_action_log(limit=10)
    print(f"   ✅ Found {len(actions)} actions in log")
    if actions:
        latest = actions[-1]
        print(f"   📊 Latest: {latest['action']} on {latest.get('sender', 'Unknown')}")
    
    print("\n" + "="*60)

def test_geolocation():
    """Test geolocation service."""
    print("\n🌍 Testing Geolocation Service\n")
    
    # Test public IP
    print("1️⃣ Testing public IP geolocation...")
    test_ips = [
        '8.8.8.8',      # Google DNS - Mountain View, US
        '1.1.1.1',      # Cloudflare - Australia
        '185.220.101.1' # Tor exit node - Germany
    ]
    
    for ip in test_ips:
        location = geo_service.get_location(ip)
        if location and location.get('country'):
            summary = geo_service.get_location_summary(ip)
            print(f"   ✅ {ip}: {summary}")
            print(f"      ISP: {location.get('isp', 'Unknown')}")
        else:
            print(f"   ⚠️ {ip}: {location.get('message', 'Unknown error')}")
    
    # Test private IP
    print("\n2️⃣ Testing private IP handling...")
    private_ip = '192.168.1.1'
    location = geo_service.get_location(private_ip)
    if location.get('status') == 'private':
        print(f"   ✅ {private_ip}: Correctly identified as private")
    else:
        print(f"   ❌ {private_ip}: Should be identified as private")
    
    print("\n" + "="*60)

def test_blocked_list():
    """Test blocked senders list."""
    print("\n🚫 Testing Blocked Senders\n")
    
    blocked = threat_actions.get_blocked_senders()
    warned = threat_actions.get_warned_senders()
    
    print(f"📊 Blocked senders: {len(blocked)}")
    for sender, info in list(blocked.items())[:5]:
        print(f"   🔴 {sender} - Reason: {info.get('reason', 'N/A')}")
    
    print(f"\n⚠️ Warned senders: {len(warned)}")
    for sender, info in list(warned.items())[:5]:
        print(f"   🟡 {sender} - Level: {info.get('warning_level', 'N/A')}")
    
    print("\n" + "="*60)

if __name__ == "__main__":
    print("="*60)
    print("🎯 THREAT TRIAGE SYSTEM TEST SUITE")
    print("="*60)
    
    test_threat_actions()
    test_geolocation()
    test_blocked_list()
    
    print("\n✅ All tests completed!")
    print("\n💡 Next steps:")
    print("   1. Open dashboard: http://localhost:8501")
    print("   2. Go to 'Threats' tab")
    print("   3. Click triage buttons on threat cards")
    print("   4. View 'Actions' tab for audit log")
