#!/usr/bin/env python3
import argparse
import logging
from datetime import datetime
from typing import Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from dotenv import load_dotenv

from PhishGuard.providers.email_fetcher.registry import EmailFetcherRegistry

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
console = Console()

class PhishGuardCLI:
    def __init__(self):
        load_dotenv()
        self.console = Console()
        
    def analyze_email(self, provider: str, limit: int = 100) -> List[Dict]:
        """Analyze emails for phishing attempts."""
        try:
            fetcher = EmailFetcherRegistry.get_fetcher(provider)
            emails = fetcher.fetch_emails(limit=limit)
            
            suspicious_emails = []
            for email in emails:
                # Check for suspicious patterns
                suspicious = False
                reasons = []
                
                # Check sender
                sender = email.get('from', '').lower()
                if 'noreply' in sender or 'no-reply' in sender:
                    suspicious = True
                    reasons.append("Uses no-reply address")
                
                # Check subject for urgency
                subject = email.get('subject', '').lower()
                urgency_words = ['urgent', 'immediate', 'action required', 'verify', 'confirm', 
                               'suspended', 'locked', 'expired']
                if any(word in subject for word in urgency_words):
                    suspicious = True
                    reasons.append("Contains urgency in subject")
                
                # Check body for suspicious links
                body = email.get('body', '').lower()
                if 'click here' in body or 'verify your account' in body:
                    suspicious = True
                    reasons.append("Contains suspicious call-to-action")
                
                # Check for financial institutions
                financial_institutions = ['chase', 'bank of america', 'wells fargo', 
                                       'citibank', 'american express']
                if any(bank in sender for bank in financial_institutions):
                    if 'verify' in body or 'confirm' in body:
                        suspicious = True
                        reasons.append("Suspicious financial institution email")
                
                if suspicious:
                    suspicious_emails.append({
                        'from': email.get('from', 'N/A'),
                        'subject': email.get('subject', 'N/A'),
                        'date': email.get('date', 'N/A'),
                        'reasons': reasons
                    })
            
            return suspicious_emails
            
        except Exception as e:
            logger.error(f"Email analysis failed: {e}")
            return []

    def display_results(self, results: List[Dict], source: str):
        """Display analysis results in a formatted table."""
        if not results:
            self.console.print(Panel("No suspicious content found", style="green"))
            return

        table = Table(title=f"Suspicious {source} Analysis Results")
        table.add_column("From", style="cyan")
        table.add_column("Subject", style="magenta")
        table.add_column("Date", style="green")
        table.add_column("Reasons", style="red")

        for item in results:
            table.add_row(
                item['from'],
                item['subject'],
                item['date'],
                "\n".join(item['reasons'])
            )

        self.console.print(table)

def main():
    parser = argparse.ArgumentParser(description='PhishGuard - Phishing Detection Tool')
    parser.add_argument('--email', choices=['yahoo', 'gmail', 'outlook'], 
                      help='Analyze emails from specific provider')
    parser.add_argument('--sms', action='store_true', help='Analyze SMS messages')
    parser.add_argument('--voice', action='store_true', help='Analyze voice calls')
    parser.add_argument('--limit', type=int, default=100, 
                      help='Limit number of items to analyze (default: 100)')
    
    args = parser.parse_args()
    
    cli = PhishGuardCLI()
    
    if args.email:
        with Progress() as progress:
            task = progress.add_task("[cyan]Analyzing emails...", total=1)
            results = cli.analyze_email(args.email, args.limit)
            progress.update(task, completed=1)
        cli.display_results(results, f"{args.email.capitalize()} Emails")
    
    if args.sms:
        console.print("[yellow]SMS analysis not yet implemented[/yellow]")
    
    if args.voice:
        console.print("[yellow]Voice call analysis not yet implemented[/yellow]")

if __name__ == "__main__":
    main() 