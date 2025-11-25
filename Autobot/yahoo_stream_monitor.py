#!/usr/bin/env python3
"""
Yahoo Stream Monitor - Continuous Ingestion + Auto-Triage

AUTONOMOUS OPERATION:
- Fetches Yahoo (primary) + Gmail (secondary) emails every 5 minutes
- ML predicts phishing/safe → Vector DB storage
- AUTO-TRIAGE: Blocks threats > 0.85 from high-risk countries
- Auto-retrains model every 50 new threats
- Runs indefinitely in background

PRODUCTION DEPLOYMENT:
- systemd service: systemctl start yahoo-monitor.service
- Docker: docker-compose up -d yahoo_monitor
- PM2 (Node.js process manager): pm2 start yahoo_stream_monitor.py
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Autobot.email_ingestion import EmailIngestionEngine, IngestionConfig
from PhishGuard.phish_mlm.phishing_detector import PhishingDetector
from Autobot.VectorDB.NullPoint_Vector import get_all_threats, connect_db
from utils.threat_actions import threat_actions
from utils.geo_location import geo_service

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/yahoo_stream_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class YahooStreamMonitor:
    """Continuous ingestion, analysis, and auto-triage loop."""
    
    def __init__(self, 
                 interval_minutes: int = 5, 
                 retrain_threshold: int = 50,
                 enable_auto_triage: bool = True,
                 auto_triage_threshold: float = 0.85):
        """
        Args:
            interval_minutes: How often to fetch emails (default: 5 min)
            retrain_threshold: Auto-retrain after N new threats (default: 50)
            enable_auto_triage: Auto-block high-risk threats (default: True)
            auto_triage_threshold: Block threats above this score (default: 0.85)
        """
        self.interval = interval_minutes * 60  # Convert to seconds
        self.retrain_threshold = retrain_threshold
        self.enable_auto_triage = enable_auto_triage
        self.auto_triage_threshold = auto_triage_threshold
        self.last_threat_count = 0
        
        # Initialize components
        config = IngestionConfig(
            batch_size=50,
            max_emails_per_provider=200,
            parallel_providers=True,  # Yahoo + Gmail simultaneously
            enable_intelligence=True,
            enable_ml_analysis=True
        )
        self.engine = EmailIngestionEngine(config)
        self.detector = PhishingDetector()
        
        logger.info("🛡️  Auto-triage: " + ("✅ ENABLED" if enable_auto_triage else "❌ DISABLED"))
        if enable_auto_triage:
            logger.info(f"   → Auto-blocking threats with score > {auto_triage_threshold}")
    
    async def _auto_triage_threats(self):
        """Auto-block high-risk unprocessed threats."""
        if not self.enable_auto_triage:
            return
        
        try:
            conn = connect_db()
            cursor = conn.cursor()
            
            # Find unprocessed high-risk threats
            cursor.execute("""
                SELECT id, sender, subject, confidence, metadata
                FROM messages
                WHERE is_threat = true 
                  AND processed = false 
                  AND confidence > %s
                ORDER BY confidence DESC
                LIMIT 100
            """, (self.auto_triage_threshold,))
            
            threats = cursor.fetchall()
            blocked_count = 0
            
            for threat in threats:
                threat_id, sender, subject, confidence, metadata = threat
                
                # Extract geolocation from metadata
                headers = metadata.get('headers', {}) if metadata else {}
                originating_ip = headers.get('x_originating_ip')
                
                # Check if from high-risk country
                if originating_ip:
                    geo_info = geo_service.get_location(originating_ip)
                    if geo_info and geo_info['risk_level'] == 'HIGH':
                        # Auto-block
                        threat_data = {
                            'id': threat_id,
                            'sender': sender,
                            'subject': subject,
                            'threat_score': confidence,
                            'headers': headers
                        }
                        
                        reason = f"Auto-blocked: Score {confidence:.2f}, Origin: {geo_info['country']} (HIGH risk)"
                        success = threat_actions.block_sender(threat_data, reason)
                        
                        if success:
                            blocked_count += 1
                            logger.info(f"🚨 AUTO-BLOCKED: {sender} (score: {confidence:.2f}, {geo_info['country']})")
                
                # Mark as processed regardless of action taken
                cursor.execute("UPDATE messages SET processed = true WHERE id = %s", (threat_id,))
                conn.commit()
            
            if blocked_count > 0:
                logger.info(f"✅ Auto-triaged {blocked_count} high-risk threats")
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ Auto-triage error: {e}", exc_info=True)
        
    async def run_forever(self):
        """Main loop - runs indefinitely."""
        logger.info("🚀 Yahoo Stream Monitor started")
        logger.info(f"📧 Fetching emails every {self.interval // 60} minutes")
        logger.info(f"🔁 Auto-retrain after {self.retrain_threshold} new threats")
        logger.info(f"🌍 Providers: Yahoo (primary) + Gmail (secondary, parallel)")
        
        cycle = 0
        
        while True:
            try:
                cycle += 1
                logger.info(f"\n{'='*60}")
                logger.info(f"🔄 CYCLE {cycle} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                logger.info(f"{'='*60}")
                
                # 1. Ingest from Yahoo (primary) + Gmail (parallel)
                logger.info("📥 Fetching emails from Yahoo + Gmail...")
                stats = self.engine.ingest_all_providers(['yahoo', 'gmail'])
                logger.info(f"✅ Ingested {stats.total_emails} emails, {stats.threats_detected} threats")
                
                # 2. Auto-triage high-risk threats
                if self.enable_auto_triage:
                    logger.info("🛡️  Running auto-triage...")
                    await self._auto_triage_threats()
                
                # 3. Check if retrain needed
                current_threat_count = len(get_all_threats(limit=10_000))
                new_threats = current_threat_count - self.last_threat_count
                
                if new_threats >= self.retrain_threshold:
                    logger.info(f"🔁 Retraining model ({new_threats} new threats)")
                    self.detector.detect_threats()
                    self.last_threat_count = current_threat_count
                    logger.info("✅ Model retrained successfully")
                else:
                    logger.info(f"⏳ No retrain needed ({new_threats}/{self.retrain_threshold} new threats)")
                
                # 4. Wait for next cycle
                logger.info(f"💤 Sleeping for {self.interval // 60} minutes...")
                await asyncio.sleep(self.interval)
                
            except KeyboardInterrupt:
                logger.info("⚠️ Received shutdown signal")
                break
            except Exception as e:
                logger.error(f"❌ Error in cycle {cycle}: {e}", exc_info=True)
                logger.info("⏳ Waiting 60 seconds before retry...")
                await asyncio.sleep(60)
        
        logger.info("👋 Yahoo Stream Monitor stopped")

async def main():
    """Entry point for async execution."""
    # Parse command-line arguments
    import argparse
    parser = argparse.ArgumentParser(description='Yahoo Stream Monitor - Continuous Email Ingestion + Auto-Triage')
    parser.add_argument('--interval', type=int, default=5, help='Fetch interval in minutes (default: 5)')
    parser.add_argument('--retrain-threshold', type=int, default=50, help='Retrain after N new threats (default: 50)')
    parser.add_argument('--disable-auto-triage', action='store_true', help='Disable automatic threat blocking')
    parser.add_argument('--triage-threshold', type=float, default=0.85, help='Auto-block threshold (default: 0.85)')
    args = parser.parse_args()
    
    # Create and run monitor
    monitor = YahooStreamMonitor(
        interval_minutes=args.interval,
        retrain_threshold=args.retrain_threshold,
        enable_auto_triage=not args.disable_auto_triage,
        auto_triage_threshold=args.triage_threshold
    )
    
    await monitor.run_forever()

if __name__ == "__main__":
    # Ensure logs directory exists
    Path('logs').mkdir(exist_ok=True)
    
    # Run async event loop
    asyncio.run(main())
