#!/usr/bin/env python3
import logging
import time
from typing import Dict, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from iphone_fetcher import IPhoneSMSFetcher

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
console = Console()

class SMSMonitor:
    def __init__(self):
        self.fetcher = IPhoneSMSFetcher()
        self.last_messages = set()
        
    def analyze_message(self, message: Dict) -> List[str]:
        """Analyze a message for suspicious content.
        
        Args:
            message: Dictionary containing message data
            
        Returns:
            List of reasons why the message is suspicious
        """
        reasons = []
        text = message['text'].lower()
        
        # Check for common phishing patterns
        phishing_patterns = [
            ('verify your account', 'Account verification request'),
            ('click here', 'Suspicious link'),
            ('urgent action required', 'Urgency in message'),
            ('your account has been suspended', 'Account suspension threat'),
            ('unusual activity detected', 'Suspicious activity claim'),
            ('confirm your identity', 'Identity verification request'),
            ('your payment has failed', 'Payment failure claim'),
            ('you have won', 'Prize/winning claim'),
            ('your package is delayed', 'Package delivery claim'),
            ('your subscription is expiring', 'Subscription expiration claim')
        ]
        
        for pattern, reason in phishing_patterns:
            if pattern in text:
                reasons.append(reason)
                
        # Check for suspicious numbers
        if message['sender'].startswith('+') and not message['sender'].startswith('+1'):
            reasons.append('International number')
            
        return reasons
        
    def display_message(self, message: Dict, reasons: List[str]):
        """Display a message and its analysis results."""
        if reasons:
            console.print(Panel(
                f"[red]Suspicious Message Detected![/red]\n\n"
                f"From: {message['sender']}\n"
                f"Date: {message['date']}\n"
                f"Text: {message['text']}\n\n"
                f"Reasons:\n" + "\n".join(f"- {reason}" for reason in reasons),
                title="⚠️ Phishing Alert",
                border_style="red"
            ))
        else:
            console.print(Panel(
                f"From: {message['sender']}\n"
                f"Date: {message['date']}\n"
                f"Text: {message['text']}",
                title="📱 New Message",
                border_style="green"
            ))
            
    def check_new_messages(self):
        """Check for and analyze new messages."""
        messages = self.fetcher.fetch_sms(limit=10)
        current_messages = {(m['text'], m['date']) for m in messages}
        
        # Find new messages
        new_messages = current_messages - self.last_messages
        if new_messages:
            for msg in messages:
                if (msg['text'], msg['date']) in new_messages:
                    reasons = self.analyze_message(msg)
                    self.display_message(msg, reasons)
                    
        self.last_messages = current_messages
        
    def start(self):
        """Start monitoring SMS messages."""
        console.print("[bold green]Starting SMS monitoring...[/bold green]")
        self.fetcher.start_monitoring(self.check_new_messages)
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Stopping SMS monitoring...[/bold yellow]")
            self.fetcher.stop_monitoring()
            
if __name__ == "__main__":
    monitor = SMSMonitor()
    monitor.start() 