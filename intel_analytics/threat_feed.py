import logging
from datetime import datetime
import requests
from urllib.parse import urlparse
import psycopg2
from typing import Set, Optional

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    def __init__(self, db_config: dict):
        self.db_config = db_config
        self.blocked_senders: Set[str] = set()
        self.blocked_urls: Set[str] = set()
        self.last_update = None
        self.update_interval = 3600  # 1 hour in seconds
        self.load_blocklists()

    def load_blocklists(self) -> None:
        """Load blocklists from database."""
        try:
            with psycopg2.connect(**self.db_config) as conn:
                with conn.cursor() as cursor:
                    # Load blocked senders
                    cursor.execute("SELECT sender FROM blocked_senders")
                    self.blocked_senders = {row[0] for row in cursor.fetchall()}

                    # Load blocked URLs
                    cursor.execute("SELECT url FROM blocked_urls")
                    self.blocked_urls = {row[0] for row in cursor.fetchall()}

            self.last_update = datetime.now()
            logger.info(f"Loaded {len(self.blocked_senders)} blocked senders and {len(self.blocked_urls)} blocked URLs")
        except Exception as e:
            logger.error(f"Error loading blocklists: {e}")

    def is_blocked_sender(self, sender: str) -> bool:
        """Check if sender is blocked."""
        self._check_update()
        return sender in self.blocked_senders

    def is_blocked_url(self, url: str) -> bool:
        """Check if URL is blocked."""
        self._check_update()
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            return domain in self.blocked_urls
        except Exception as e:
            logger.error(f"Error checking URL {url}: {e}")
            return False

    def add_blocked_sender(self, sender: str) -> bool:
        """Add a sender to the blocklist."""
        try:
            with psycopg2.connect(**self.db_config) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO blocked_senders (sender) VALUES (%s) ON CONFLICT DO NOTHING",
                        (sender,)
                    )
                conn.commit()
            self.blocked_senders.add(sender)
            return True
        except Exception as e:
            logger.error(f"Error adding blocked sender {sender}: {e}")
            return False

    def add_blocked_url(self, url: str) -> bool:
        """Add a URL to the blocklist."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            with psycopg2.connect(**self.db_config) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO blocked_urls (url) VALUES (%s) ON CONFLICT DO NOTHING",
                        (domain,)
                    )
                conn.commit()
            self.blocked_urls.add(domain)
            return True
        except Exception as e:
            logger.error(f"Error adding blocked URL {url}: {e}")
            return False

    def _check_update(self) -> None:
        """Check if blocklists need updating."""
        if (not self.last_update or 
            (datetime.now() - self.last_update).total_seconds() > self.update_interval):
            self.load_blocklists()

def fetch_blocklist(url):
    resp = requests.get(url)
    return [line.strip() for line in resp.text.splitlines() if line and not line.startswith('#')]

def update_blocklist_in_db(conn, blocklist):
    with conn.cursor() as cursor:
        for entry in blocklist:
            cursor.execute("INSERT INTO blocklist (sender) VALUES (%s) ON CONFLICT DO NOTHING", (entry,))
    conn.commit()