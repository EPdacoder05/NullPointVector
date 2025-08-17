from typing import Dict, Type
from .base import EmailFetcher
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
    def get_fetcher(cls, provider: str) -> EmailFetcher:
        """Get an instance of the specified email fetcher."""
        if provider not in cls._fetchers:
            raise ValueError(f"Unknown email provider: {provider}. Available providers: {list(cls._fetchers.keys())}")
        return cls._fetchers[provider]()
    
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