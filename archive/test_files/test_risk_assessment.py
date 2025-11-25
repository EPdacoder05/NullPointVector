#!/usr/bin/env python3
"""
Test Risk Assessment Integration
Tests that risk_score field is properly extracted and displayed
"""

from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
from Autobot.email_ingestion import EmailIngestionEngine
import json

def test_risk_in_database():
    """Check if existing messages have risk_score in their geo data"""
    conn = get_conn()
    if not conn:
        print("❌ Database connection failed")
        return
    
    try:
        cursor = conn.cursor()
        
        # Check messages with geo data
        query = """
        SELECT 
            sender,
            metadata->'geo'->>'country' as country,
            metadata->'geo'->>'risk_score' as risk_score,
            metadata->'geo' as full_geo
        FROM messages 
        WHERE metadata->'geo' IS NOT NULL
        LIMIT 10
        """
        
        cursor.execute(query)
        rows = cursor.fetchall()
        
        print(f"\n=== Database Risk Assessment Check ===")
        print(f"Messages with geo data: {len(rows)}\n")
        
        if rows:
            for sender, country, risk, geo_json in rows:
                print(f"Sender: {sender[:40]}")
                print(f"  Country: {country}")
                print(f"  Risk: {risk}")
                if risk:
                    emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(risk, '⚪')
                    print(f"  Status: {emoji} {risk}")
                else:
                    print(f"  ⚠️ Risk score missing!")
                print()
        else:
            print("⚠️ No messages with geo data found\n")
            print("Running quick ingestion to generate test data...")
            
            # Run quick ingestion
            engine = EmailIngestionEngine()
            result = engine.ingest(max_emails=5, batch_size=5)
            
            print(f"\n✅ Ingested {result.get('total_ingested', 0)} emails")
            
            # Check again
            cursor.execute(query)
            rows = cursor.fetchall()
            
            print(f"\nAfter ingestion - Messages with geo data: {len(rows)}\n")
            for sender, country, risk, geo_json in rows:
                print(f"Sender: {sender[:40]}")
                print(f"  Country: {country}")
                print(f"  Risk: {risk}")
                emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(risk, '⚪')
                print(f"  Status: {emoji} {risk if risk else 'MISSING'}")
                print()
        
        cursor.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        release_conn(conn)

if __name__ == "__main__":
    test_risk_in_database()
