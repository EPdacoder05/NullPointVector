#!/usr/bin/env python3
"""
Advanced Email Ingestion System
Optimized for performance and analysis with configurable batch sizes.
"""

import asyncio
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

from PhishGuard.providers.email_fetcher.registry import EmailFetcherRegistry
from utils.offensive_intel import OffensiveIntelligence
from PhishGuard.phish_mlm.phishing_detector import PhishingDetector

logger = logging.getLogger(__name__)

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
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []

class EmailIngestionEngine:
    """High-performance email ingestion engine."""
    
    def __init__(self, config: IngestionConfig = None):
        self.config = config or IngestionConfig()
        self.intelligence = OffensiveIntelligence() if self.config.enable_intelligence else None
        self.ml_detector = PhishingDetector() if self.config.enable_ml_analysis else None
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
        """Ingest emails from a single provider."""
        logger.info(f"📥 Ingesting from {provider}")
        start_time = time.time()
        
        # Get fetcher
        fetcher = EmailFetcherRegistry.get_fetcher(provider)
        
        # Fetch emails in batches
        all_emails = []
        batch_count = 0
        threats_detected = 0
        profiles_created = 0
        
        while len(all_emails) < self.config.max_emails_per_provider:
            try:
                # Fetch batch
                batch = fetcher.fetch_emails(limit=self.config.batch_size)
                if not batch:
                    break
                
                all_emails.extend(batch)
                batch_count += 1
                
                logger.info(f"  📦 Batch {batch_count}: {len(batch)} emails")
                
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
        
        return {
            'emails_processed': len(all_emails),
            'threats_detected': threats_detected,
            'profiles_created': profiles_created,
            'processing_time': processing_time
        }
    
    def _process_batch(self, emails: List[Dict[str, Any]], provider: str) -> Dict[str, int]:
        """Process a batch of emails."""
        threats = 0
        profiles = 0
        
        # Group emails by sender for intelligence analysis
        sender_emails = {}
        for email in emails:
            sender = email.get('from', 'unknown')
            if sender not in sender_emails:
                sender_emails[sender] = []
            sender_emails[sender].append(email)
        
        # Build intelligence profiles
        if self.intelligence:
            for sender, sender_email_list in sender_emails.items():
                try:
                    profile = self.intelligence.build_profile(sender, sender_email_list)
                    profiles += 1
                    
                    # Check if high threat
                    if profile.threat_score > 0.7:
                        threats += 1
                        logger.warning(f"🚨 HIGH THREAT: {sender} (score: {profile.threat_score:.2f})")
                    
                except Exception as e:
                    logger.error(f"Profile building failed for {sender}: {e}")
        
        # ML analysis
        if self.ml_detector:
            for email in emails:
                try:
                    # Simple ML analysis
                    result = self.ml_detector.predict(email)
                    if result and result[0] == 1:  # Threat detected
                        threats += 1
                except Exception as e:
                    logger.error(f"ML analysis failed: {e}")
        
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
