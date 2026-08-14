from typing import Dict, Type
from .base_fetcher import EmailFetcher
from .yahoo_doggy import YahooDoggy
from .gmail_doggy import GmailDoggy
from .outlook_doggy import OutlookDoggy

class EmailFetcherRegistry:
    """Registry for email fetcher implementations."""
    
    _fetchers: Dict[str, Type[EmailFetcher]] = {
        'yahoo': YahooDoggy,
        'gmail': GmailDoggy,
        'outlook': OutlookDoggy,
        # Add more providers here as needed
        # 'custom_provider': CustomEmailFetcher,
    }
    
    @classmethod
    def get_fetcher(cls, provider: str, *, account_sub: str = "",
                    mailbox_id: int | None = None) -> EmailFetcher:
        """Get a fetcher, optionally pinned to one tenant mailbox.

        Mutating callers must provide both values; unpinned instances are only
        for the background poller, whose fetched records retain their owners.
        """
        if provider not in cls._fetchers:
            raise ValueError(f"Unknown email provider: {provider}. Available providers: {list(cls._fetchers.keys())}")
        return cls._fetchers[provider](account_sub=account_sub, mailbox_id=mailbox_id)
    
    @classmethod
    def get_available_providers(cls) -> list[str]:
        """Get list of available email providers."""
        return list(cls._fetchers.keys())
    
    @classmethod
    def register_fetcher(cls, provider: str, fetcher_class: Type[EmailFetcher]) -> None:
        """Register a new email fetcher implementation."""
        if not issubclass(fetcher_class, EmailFetcher):
            raise TypeError(f"Fetcher class must implement EmailFetcher interface")
        cls._fetchers[provider] = fetcher_class
