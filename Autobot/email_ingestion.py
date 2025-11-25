#!/usr/bin/env python3
"""
Advanced Email Ingestion System
Optimized for performance and analysis with configurable batch sizes.
"""

import asyncio
import time
import sys
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

from PhishGuard.providers.email_fetcher.registry import EmailFetcherRegistry
from PhishGuard.phish_mlm.phishing_detector import PhishingDetector, detector as SHARED_DETECTOR
from utils.threat_intelligence import threat_intel
from utils.security.input_validator import input_validator
from utils.security.url_analyzer import url_analyzer  # NEW: URL analysis with zero-trust
from utils.geo_location import geo_service
from Autobot.VectorDB.NullPoint_Vector import connect_db, insert_message

# Configure logger with timestamps
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s.%(msecs)03d] %(levelname)s %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Global reference to real-time log function (set by dashboard)
REALTIME_LOG_FUNC = None

def set_realtime_logger(log_func):
    """Set the real-time logging function from dashboard."""
    global REALTIME_LOG_FUNC
    REALTIME_LOG_FUNC = log_func

def log_realtime(level, message):
    """Log to real-time dashboard if available."""
    if REALTIME_LOG_FUNC:
        try:
            REALTIME_LOG_FUNC(level, message)
        except Exception as e:
            logger.debug(f"Realtime logging failed: {e}")
    # Force flush to show logs immediately in terminal
    sys.stdout.flush()

@dataclass
class IngestionConfig:
    """Configuration for email ingestion."""
    batch_size: int = 75  # Sweet spot for performance
    max_emails_per_provider: int = 200
    parallel_providers: bool = True
    enable_intelligence: bool = True
    enable_ml_analysis: bool = True
    save_raw_data: bool = True
    rate_limit_delay: float = 0.1  # 100ms between requests

@dataclass
class IngestionStats:
    """Statistics for ingestion run."""
    start_time: datetime
    end_time: Optional[datetime] = None
    total_emails: int = 0
    providers_processed: int = 0
    threats_detected: int = 0
    intelligence_profiles: int = 0
    processing_time: float = 0.0
    errors: List[str] = None
    # Performance metrics
    ml_inference_time: float = 0.0
    db_insert_time: float = 0.0
    geo_lookup_time: float = 0.0
    emails_per_second: float = 0.0
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
    
    # Aliases for compatibility
    @property
    def total_fetched(self) -> int:
        return self.total_emails
    
    @property
    def total_threats(self) -> int:
        return self.threats_detected
    
    @property
    def total_profiles(self) -> int:
        return self.intelligence_profiles

class EmailIngestionEngine:
    """High-performance email ingestion engine."""
    
    def __init__(self, config: IngestionConfig = None):
        self.config = config or IngestionConfig()
        self.intelligence = threat_intel if self.config.enable_intelligence else None
        # Reuse shared global detector to avoid duplicate model instances in memory
        self.ml_detector = SHARED_DETECTOR if self.config.enable_ml_analysis else None
        self.stats = None
        self.data_dir = Path('data/ingestion')
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
    def ingest_all_providers(self, providers: List[str] = None) -> IngestionStats:
        """Ingest emails from all providers with performance optimization."""
        self.stats = IngestionStats(start_time=datetime.now())
        
        if not providers:
            providers = EmailFetcherRegistry.get_available_providers()
        
        logger.info(f"🚀 Starting ingestion from {len(providers)} providers")
        logger.info(f"📊 Config: batch_size={self.config.batch_size}, max_emails={self.config.max_emails_per_provider}")
        
        if self.config.parallel_providers:
            return self._ingest_parallel(providers)
        else:
            return self._ingest_sequential(providers)
    
    def _ingest_parallel(self, providers: List[str]) -> IngestionStats:
        """Ingest from multiple providers in parallel."""
        with ThreadPoolExecutor(max_workers=len(providers)) as executor:
            futures = []
            for provider in providers:
                future = executor.submit(self._ingest_provider, provider)
                futures.append(future)
            
            # Collect results
            for future in futures:
                try:
                    result = future.result()
                    self.stats.total_emails += result.get('emails_processed', 0)
                    self.stats.threats_detected += result.get('threats_detected', 0)
                    self.stats.intelligence_profiles += result.get('profiles_created', 0)
                    self.stats.providers_processed += 1
                except Exception as e:
                    self.stats.errors.append(f"Provider ingestion failed: {e}")
                    logger.error(f"Provider ingestion error: {e}")
        
        self._finalize_stats()
        return self.stats
    
    def _ingest_sequential(self, providers: List[str]) -> IngestionStats:
        """Ingest from providers sequentially."""
        for provider in providers:
            try:
                result = self._ingest_provider(provider)
                self.stats.total_emails += result.get('emails_processed', 0)
                self.stats.threats_detected += result.get('threats_detected', 0)
                self.stats.intelligence_profiles += result.get('profiles_created', 0)
                self.stats.providers_processed += 1
            except Exception as e:
                self.stats.errors.append(f"{provider} failed: {e}")
                logger.error(f"{provider} ingestion error: {e}")
        
        self._finalize_stats()
        return self.stats
    
    def _ingest_provider(self, provider: str) -> Dict[str, Any]:
        """Ingest emails from a single provider - GENERATOR version for streaming."""
        logger.info(f"📥 Ingesting from {provider}")
        log_realtime('info', f'🚀 Starting ingestion from {provider.upper()}...')
        sys.stdout.flush()
        start_time = time.time()
        
        # Get fetcher
        fetcher = EmailFetcherRegistry.get_fetcher(provider)
        
        # Fetch emails in batches
        all_emails = []
        batch_count = 0
        threats_detected = 0
        profiles_created = 0
        progress_events = []  # collect events for GUI streaming
        
        while len(all_emails) < self.config.max_emails_per_provider:
            try:
                # Fetch batch
                batch = fetcher.fetch_emails(limit=self.config.batch_size)
                if not batch:
                    break
                
                all_emails.extend(batch)
                batch_count += 1
                
                # Show individual emails like terminal does
                logger.info(f"  📦 Batch {batch_count}: {len(batch)} emails")
                log_realtime('info', f'📦 {provider}: Batch {batch_count} - {len(batch)} emails fetched')
                sys.stdout.flush()  # Force immediate output
                
                for idx, email in enumerate(batch, 1):
                    email_id = email.get('id', 'unknown')
                    subject = email.get('subject', 'No Subject')[:45]
                    sender = email.get('from', 'unknown')[:25]
                    logger.info(f"  [{idx:2d}] ✅ ID={email_id:4s} | {subject}")
                    # Stream each email to dashboard
                    log_realtime('info', f'📧 {sender}: {subject}...')
                    sys.stdout.flush()  # Force immediate output
                    # Longer delay to allow dashboard to poll and display logs
                    time.sleep(0.2)  # 200ms between emails for visible streaming
                
                progress_events.append({"batch": batch_count, "count": len(batch), "provider": provider, "emails": batch})
                
                # Process batch
                batch_result = self._process_batch(batch, provider)
                threats_detected += batch_result.get('threats', 0)
                profiles_created += batch_result.get('profiles', 0)
                
                # Rate limiting
                time.sleep(self.config.rate_limit_delay)
                
            except Exception as e:
                logger.error(f"Batch {batch_count} failed: {e}")
                break
        
        processing_time = time.time() - start_time
        
        # Save raw data
        if self.config.save_raw_data:
            self._save_raw_data(all_emails, provider)
        
        logger.info(f"✅ {provider}: {len(all_emails)} emails in {processing_time:.2f}s")
        log_realtime('success', f'✅ {provider.upper()}: {len(all_emails)} emails processed in {processing_time:.1f}s | Threats: {threats_detected}')
        sys.stdout.flush()
        
        result = {
            'emails_processed': len(all_emails),
            'threats_detected': threats_detected,
            'profiles_created': profiles_created,
            'processing_time': processing_time,
            'progress_events': progress_events
        }
        return result
    
    def _process_batch_streaming(self, emails: List[Dict[str, Any]], provider: str):
        """Process a batch of emails - GENERATOR version for streaming."""
        threats = 0
        profiles = 0
        
        yield {'type': 'batch_processing', 'message': f"      🔍 Analyzing {len(emails)} emails..."}
        
        # Group emails by sender for intelligence analysis
        sender_emails = {}
        for email in emails:
            sender = email.get('from', 'unknown')
            if sender not in sender_emails:
                sender_emails[sender] = []
            sender_emails[sender].append(email)
        
        # Build intelligence profiles
        if self.intelligence:
            yield {'type': 'building_profiles', 'message': f"      👤 Building profiles for {len(sender_emails)} senders..."}
            for sender, sender_email_list in sender_emails.items():
                try:
                    # Get first email for profiling (or aggregate all)
                    first_email = sender_email_list[0]
                    subject = first_email.get('subject', '')
                    content = first_email.get('body', '') or first_email.get('snippet', '')
                    
                    profile = self.intelligence.build_profile(sender, subject, content)
                    profiles += 1
                    
                    # Check if high threat
                    if profile.get('threat_score', 0) > 0.7:
                        threats += 1
                        yield {'type': 'threat_found', 'message': f"      🚨 HIGH THREAT: {sender} (score: {profile['threat_score']:.2f})"}
                    
                except Exception as e:
                    logger.error(f"Profile building failed for {sender}: {e}")
        
        # ML analysis
        if self.ml_detector:
            yield {'type': 'ml_analysis', 'message': f"      🤖 Running ML analysis..."}
            for email in emails:
                try:
                    # Simple ML analysis
                    result = self.ml_detector.predict(email)
                    if result and result[0] == 1:  # Threat detected
                        threats += 1
                except Exception as e:
                    logger.error(f"ML analysis failed: {e}")
        
        yield {'type': 'batch_processed', 'threats': threats, 'profiles': profiles}
    
    def _process_batch(self, emails: List[Dict[str, Any]], provider: str) -> Dict[str, int]:
        """Process a batch of emails (non-streaming version for backward compat)."""
        threats = 0
        profiles = 0
        
        # Group emails by sender for intelligence analysis
        sender_emails = {}
        for email in emails:
            sender = email.get('from', 'unknown')
            if sender not in sender_emails:
                sender_emails[sender] = []
            sender_emails[sender].append(email)
        
        # Process each email with security validation
        for email in emails:
            try:
                # SECURITY: Validate all inputs before processing
                email_data = {
                    'sender': email.get('from', ''),
                    'recipient': email.get('to', ''),
                    'subject': email.get('subject', ''),
                    'body': email.get('body', '') or email.get('snippet', ''),
                    'headers': email.get('headers', {}),
                    'metadata': {
                        'source': provider,
                        'timestamp': email.get('date', datetime.now().isoformat())
                    }
                }
                
                # Validate with input_validator (prevents SQL injection, XSS, etc.)
                try:
                    is_valid, validation_errors = input_validator.validate_email_data(email_data)
                    
                    if not is_valid:
                        logger.warning(f"⚠️ Email rejected (validation failed): {validation_errors}")
                        continue
                except ValueError as ve:
                    # Strict validation failed (likely false positive on legitimate HTML emails)
                    logger.debug(f"Validation warning for {email.get('from', 'unknown')}: {ve}")
                    # Continue processing - body already sanitized by base_fetcher
                except Exception as e:
                    logger.error(f"Validation error: {e}")
                    continue
                
                # SECURITY: Extract and analyze URLs (zero-trust, no code execution)
                url_analysis = []
                try:
                    body_text = email.get('body', '') or email.get('snippet', '')
                    html_content = email.get('html', None)  # Some providers give HTML separately
                    
                    # Extract URLs safely (no rendering, no JS execution)
                    urls = url_analyzer.extract_urls(body_text, html_content)
                    
                    if urls:
                        # Analyze URLs in parallel (multithreading for efficiency)
                        url_analysis = url_analyzer.analyze_urls_parallel(urls, max_workers=3)
                        
                        # Log high-risk URLs
                        high_risk_urls = [u for u in url_analysis if u['risk_score'] >= 70]
                        if high_risk_urls:
                            log_realtime('warning', f"🔗 {len(high_risk_urls)} high-risk URLs detected")
                            time.sleep(0.05)
                except Exception as url_e:
                    logger.error(f"URL analysis failed: {url_e}")
                    url_analysis = []  # Continue processing even if URL analysis fails
                
                # Use pre-validated IPs from base_fetcher (already sanitized & validated)
                ip_addresses = email.get('ip_addresses', [])
                
                if ip_addresses:
                    # Use first IP (most likely originating IP)
                    ip_address = ip_addresses[0]
                    geo_data = geo_service.get_location(ip_address)
                    
                    if geo_data:
                        email['metadata'] = email.get('metadata', {})
                        email['metadata']['geo'] = geo_data
                        email['metadata']['ip_address'] = ip_address  # Store for dashboard
                        country = geo_data.get('country', 'Unknown')
                        city = geo_data.get('city', 'Unknown')
                        risk = geo_data.get('risk_score', 'UNKNOWN')  # Fixed: was 'risk_level', should be 'risk_score'
                        logger.info(f"📍 Geolocation: {city}, {country} (Risk: {risk})")
                        # Stream geo data with visual indicators
                        risk_emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'UNKNOWN': '⚪'}
                        log_realtime('info', f"{risk_emoji.get(risk, '⚪')} {city}, {country} [{risk}] - {sender[:25]}")
                        sys.stdout.flush()
                else:
                    logger.debug(f"No IP addresses found for email from {email.get('from', 'unknown')}")
                
            except ValueError as e:
                logger.error(f"🔒 SECURITY: Malicious content detected - {e}")
                continue
            except Exception as e:
                logger.error(f"Email processing error: {e}")
                continue
        
        # Build intelligence profiles
        if self.intelligence:
            for sender, sender_email_list in sender_emails.items():
                try:
                    first_email = sender_email_list[0]
                    subject = first_email.get('subject', '')
                    content = first_email.get('body', '') or first_email.get('snippet', '')
                    
                    profile = self.intelligence.build_profile(sender, subject, content)
                    profiles += 1
                    
                    if profile.get('threat_score', 0) > 0.7:
                        threats += 1
                        logger.warning(f"🚨 HIGH THREAT: {sender} (score: {profile['threat_score']:.2f})")
                    
                except Exception as e:
                    logger.error(f"Profile building failed for {sender}: {e}")
        
        # ML analysis and DB storage
        # Open single DB connection for batch persistence
        conn = None
        try:
            conn = connect_db()
            for email in emails:
                try:
                    if not isinstance(email, dict):
                        logger.error(f"Email skipped (not dict): {type(email)}")
                        continue

                    metadata = email.get('metadata', {}) or {}
                    geo = metadata.get('geo')
                    ip_address = metadata.get('ip_address')

                    is_threat = 0
                    confidence = 0.0

                    # Run ML prediction only if enabled
                    if self.ml_detector:
                        try:
                            result = self.ml_detector.predict(email)
                            if result:
                                is_threat = 1 if result[0] == 1 else 0
                                confidence = result[1] if len(result) > 1 else 0.0
                            if is_threat:
                                threats += 1
                                # Stream threat detection to dashboard
                                threat_emoji = '🚨' if confidence > 0.85 else '⚠️'
                                sender = email.get('from', 'unknown')[:25]
                                subject = email.get('subject', '')[:40]
                                log_realtime('warning', f"{threat_emoji} THREAT {confidence:.2f} | {sender}: {subject}")
                                time.sleep(0.03)  # Brief pause for streaming
                        except Exception as ml_e:
                            logger.error(f"ML prediction failed: {ml_e}")

                    # Build unified metadata for storage
                    full_metadata = {
                        **metadata,
                        'source': provider,
                        'timestamp': email.get('date', datetime.now().isoformat()),
                        'geo': geo,
                        'ip_address': ip_address,
                        'url_analysis': url_analysis  # Add URL analysis results
                    }
                    
                    # SECURITY: Boost threat score if high-risk URLs detected
                    if url_analysis:
                        high_risk_count = sum(1 for u in url_analysis if u['risk_score'] >= 70)
                        if high_risk_count > 0:
                            is_threat = 1  # Force threat classification
                            confidence = max(confidence, 0.85)  # Boost confidence
                            full_metadata['url_threat_boost'] = True
                            full_metadata['high_risk_urls'] = high_risk_count

                    # Insert message using vector DB helper
                    try:
                        msg_id = insert_message(
                            conn=conn,
                            message_type='email',
                            sender=email.get('from', 'unknown'),
                            raw_content=email.get('body', ''),
                            preprocessed_text=email.get('body', ''),
                            subject=email.get('subject', ''),
                            recipient=email.get('to', ''),
                            timestamp=datetime.now(),
                            is_threat=is_threat,
                            confidence=confidence,
                            metadata=full_metadata,
                            label=1 if is_threat else 0
                        )
                        # Real-time logging of DB persistence with geo info
                        if msg_id:
                            sender = email.get('from', 'unknown')[:25]
                            subject_preview = email.get('subject','')[:35]
                            status = '🚨 THREAT' if is_threat else '✅ SAFE'
                            conf_display = f"{confidence:.2f}" if is_threat else ""
                            
                            # Add geo info if available
                            geo_display = ""
                            if geo and isinstance(geo, dict):
                                country = geo.get('country', '')[:15]
                                if country:
                                    geo_display = f" 📍{country}"
                            
                            log_realtime(
                                'warning' if is_threat else 'success',
                                f"💾 DB→{msg_id} {status} {conf_display} | {sender}: {subject_preview}{geo_display}"
                            )
                    except Exception as store_e:
                        logger.error(f"Insert failed: {store_e}")
                except Exception as process_e:
                    logger.error(f"Email finalization error: {process_e}")
        finally:
            if conn:
                conn.close()

        return {'threats': threats, 'profiles': profiles}
    
    def _save_raw_data(self, emails: List[Dict[str, Any]], provider: str):
        """Save raw email data for analysis."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = self.data_dir / f"{provider}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(emails, f, indent=2)
            logger.info(f"💾 Raw data saved: {filename}")
        except Exception as e:
            logger.error(f"Failed to save raw data: {e}")
    
    def _finalize_stats(self):
        """Finalize ingestion statistics."""
        self.stats.end_time = datetime.now()
        self.stats.processing_time = (self.stats.end_time - self.stats.start_time).total_seconds()
        
        # Log summary
        logger.info(f"🎯 INGESTION COMPLETE:")
        logger.info(f"   📧 Total emails: {self.stats.total_emails}")
        logger.info(f"   🚨 Threats detected: {self.stats.threats_detected}")
        logger.info(f"   👤 Intelligence profiles: {self.stats.intelligence_profiles}")
        logger.info(f"   ⏱️  Processing time: {self.stats.processing_time:.2f}s")
        logger.info(f"   📊 Emails/second: {self.stats.total_emails / self.stats.processing_time:.1f}")
        
        if self.stats.errors:
            logger.warning(f"   ⚠️  Errors: {len(self.stats.errors)}")
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for optimization."""
        if not self.stats:
            return {}
        
        return {
            'total_emails': self.stats.total_emails,
            'processing_time': self.stats.processing_time,
            'emails_per_second': self.stats.total_emails / self.stats.processing_time,
            'threat_detection_rate': self.stats.threats_detected / max(self.stats.total_emails, 1),
            'providers_processed': self.stats.providers_processed,
            'errors': len(self.stats.errors)
        }

if __name__ == "__main__":
    # Test the ingestion engine
    config = IngestionConfig(
        batch_size=50,  # Start with 50 for testing
        max_emails_per_provider=150,
        parallel_providers=True,
        enable_intelligence=True,
        enable_ml_analysis=True
    )
    
    engine = EmailIngestionEngine(config)
    stats = engine.ingest_all_providers()
    
    print(f"\n📊 Performance Metrics:")
    metrics = engine.get_performance_metrics()
    for key, value in metrics.items():
        print(f"   {key}: {value}")
