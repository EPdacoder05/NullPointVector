from datetime import datetime
import logging
import os
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('guard_logs.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

# Import guards
from PhishGuard.providers.email_fetcher.registry import EmailFetcherRegistry
from PhishGuard.providers.email_analyzer import EmailAnalyzer
from PhishGuard.phish_mlm.phishing_detector import PhishingDetector
from SmishGuard.sms_fetch.iphone_fetcher import IPhoneSMSFetcher
from SmishGuard.smish_mlm.smishing_detector import SmishingDetector

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Run security guards for different communication channels')
    parser.add_argument('--email-providers', nargs='+', 
                      choices=EmailFetcherRegistry.get_available_providers(),
                      help='Email providers to check (default: all)')
    parser.add_argument('--skip-sms', action='store_true',
                      help='Skip SMS checking')
    parser.add_argument('--skip-voice', action='store_true',
                      help='Skip voice checking')
    parser.add_argument('--skip-threat-intel', action='store_true',
                      help='Skip threat intelligence analysis')
    return parser.parse_args()

def preflight_check():
    """Check for required environment variables and dependencies."""
    required_env = ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_PORT']
    missing = [var for var in required_env if not os.getenv(var)]
    if missing:
        logger.error(f"Missing required environment variables: {missing}")
        sys.exit(1)

def run_guard(fetch_func, detect_func, guard_name, threat_analyzer=None):
    """Run a specific guard's fetch and detect operations."""
    try:
        logger.info(f"Starting {guard_name} operations...")
        
        # Fetch emails
        emails = fetch_func()
        
        # Run threat intelligence analysis if enabled
        if threat_analyzer and emails:
            logger.info(f"Running threat intelligence analysis for {guard_name}...")
            for email in emails:
                analysis = threat_analyzer.analyze_email(email)
                if analysis['recommendation'] == 'block':
                    logger.warning(f"Blocked email from {analysis['from']}: {analysis['threats']}")
                    continue
                elif analysis['recommendation'] == 'quarantine':
                    logger.warning(f"Quarantined email from {analysis['from']}: {analysis['threats']}")
                    continue
        
        # Run ML detection
        detect_func()
        logger.info(f"{guard_name} operations completed successfully")
        return True
    except Exception as e:
        logger.error(f"Error in {guard_name}: {e}", exc_info=True)
        return False

def main():
    """Main function to run all guards."""
    args = parse_args()
    preflight_check()
    start_time = datetime.now()
    logger.info("Starting security guard operations...")

    # Initialize threat analyzer if not skipped
    threat_analyzer = None if args.skip_threat_intel else EmailAnalyzer()

    # Define guard operations
    guards = []
    
    # Add email guards based on selected providers
    email_providers = args.email_providers or EmailFetcherRegistry.get_available_providers()
    for provider in email_providers:
        fetcher = EmailFetcherRegistry.get_fetcher(provider)
        detector = PhishingDetector()
        guards.append((f"PhishGuard-{provider}", fetcher.fetch_emails, detector.detect_threats, threat_analyzer))
    
    # SMS/Voice guards disabled - need iOS CallKit implementation
    # TODO: Implement iOS CallKit for real-time SMS/Voice monitoring

    # Run guards in parallel
    with ThreadPoolExecutor(max_workers=len(guards)) as executor:
        results = list(executor.map(
            lambda g: run_guard(g[1], g[2], g[0], g[3]),
            guards
        ))

    # Report results
    successful = sum(results)
    failed = len(guards) - successful
    duration = (datetime.now() - start_time).total_seconds()

    logger.info(f"""
    Guard Operations Summary:
    ------------------------
    Total Guards: {len(guards)}
    Successful: {successful}
    Failed: {failed}
    Duration: {duration:.2f} seconds
    """)

    if failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Interrupted by user. Shutting down gracefully.")
        sys.exit(130)