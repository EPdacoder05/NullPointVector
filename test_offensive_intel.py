#!/usr/bin/env python3
"""
Offensive Intelligence Test - Scalable Email Ingestion
"""

import sys
import os
sys.path.append('.')

def fetch_scalable_emails():
    """Fetch emails with scalable limits."""
    print("🚀 Fetching emails for offensive intelligence...")
    
    all_emails = []
    
    # Yahoo - fetch 50 emails
    try:
        from PhishGuard.providers.email_fetcher.yahoo_doggy import YahooDoggy
        yahoo = YahooDoggy()
        yahoo_emails = yahoo.fetch_emails(limit=50)
        print(f"✅ Yahoo: {len(yahoo_emails)} emails")
        all_emails.extend(yahoo_emails)
    except Exception as e:
        print(f"❌ Yahoo failed: {e}")
    
    # Gmail - fetch 50 emails  
    try:
        from PhishGuard.providers.email_fetcher.gmail_doggy import GmailDoggy
        gmail = GmailDoggy()
        gmail_emails = gmail.fetch_emails(limit=50)
        print(f"✅ Gmail: {len(gmail_emails)} emails")
        all_emails.extend(gmail_emails)
    except Exception as e:
        print(f"❌ Gmail failed: {e}")
    
    # Outlook - fetch 50 emails
    try:
        from PhishGuard.providers.email_fetcher.outlook_doggy import OutlookDoggy
        outlook = OutlookDoggy()
        outlook_emails = outlook.fetch_emails(limit=50)
        print(f"✅ Outlook: {len(outlook_emails)} emails")
        all_emails.extend(outlook_emails)
    except Exception as e:
        print(f"❌ Outlook failed: {e}")
    
    print(f"\n📊 Total emails ingested: {len(all_emails)}")
    return all_emails

def build_intelligence_profiles(emails):
    """Build intelligence profiles from emails."""
    print("\n🔍 Building intelligence profiles...")
    
    from utils.offensive_intel import OffensiveIntelligence
    intel = OffensiveIntelligence()
    
    # Group emails by sender
    sender_emails = {}
    for email in emails:
        sender = email.get('from', 'unknown@unknown.com')
        if sender not in sender_emails:
            sender_emails[sender] = []
        sender_emails[sender].append(email)
    
    print(f"📧 Unique senders found: {len(sender_emails)}")
    
    # Build profiles for each sender
    profiles = []
    for sender, sender_email_list in sender_emails.items():
        try:
            profile = intel.build_profile(sender, sender_email_list)
            profiles.append(profile)
            print(f"  📋 {sender}: {profile.threat_score:.2f} threat score")
        except Exception as e:
            print(f"  ❌ Failed to build profile for {sender}: {e}")
    
    return profiles, intel

def analyze_threats(profiles, intel):
    """Analyze threats and generate report."""
    print("\n🎯 Threat Analysis:")
    
    # Get high-threat profiles
    high_threats = [p for p in profiles if p.threat_score > 0.7]
    medium_threats = [p for p in profiles if 0.4 <= p.threat_score <= 0.7]
    low_threats = [p for p in profiles if p.threat_score < 0.4]
    
    print(f"  🔴 High threat: {len(high_threats)}")
    print(f"  🟡 Medium threat: {len(medium_threats)}")
    print(f"  🟢 Low threat: {len(low_threats)}")
    
    # Show top threats
    if high_threats:
        print("\n🚨 TOP THREATS:")
        for i, profile in enumerate(sorted(high_threats, key=lambda x: x.threat_score, reverse=True)[:5]):
            print(f"  {i+1}. {profile.email} (Score: {profile.threat_score:.2f})")
            print(f"     Domain: {profile.domain}")
            print(f"     Country: {profile.geolocation.get('country', 'Unknown')}")
            print(f"     Patterns: {', '.join(profile.patterns[:3])}")
    
    # Generate intelligence report
    report = intel.generate_intelligence_report()
    print(f"\n📈 Intelligence Report:")
    print(f"  Total profiles: {report['total_profiles']}")
    print(f"  Threat profiles: {report['threat_profiles']}")
    print(f"  High risk: {report['reputation_summary']['high_risk']}")
    print(f"  Medium risk: {report['reputation_summary']['medium_risk']}")
    
    return report

def main():
    """Main offensive intelligence test."""
    print("🎯 OFFENSIVE INTELLIGENCE TEST - SCALABLE INGESTION\n")
    
    # Step 1: Fetch emails (scalable)
    emails = fetch_scalable_emails()
    
    if not emails:
        print("❌ No emails fetched. Exiting.")
        return
    
    # Step 2: Build intelligence profiles
    profiles, intel = build_intelligence_profiles(emails)
    
    # Step 3: Analyze threats
    report = analyze_threats(profiles, intel)
    
    print(f"\n🎉 Offensive Intelligence Complete!")
    print(f"📊 Data ingested: {len(emails)} emails from {len(profiles)} senders")
    print(f"🎯 Threat detection: {report['threat_profiles']} suspicious senders")

if __name__ == "__main__":
    main()
