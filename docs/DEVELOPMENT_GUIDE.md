# Development Guide

## Overview

This guide is for developers who want to contribute to the IDPS project or extend its functionality. It covers the development workflow, code standards, testing procedures, and extension points.

## Development Environment Setup

### 1. Prerequisites
```bash
# Install development tools
pip install black flake8 pytest pytest-cov mypy
pip install pre-commit

# Setup pre-commit hooks
pre-commit install
```

### 2. IDE Configuration
**VS Code Settings** (`.vscode/settings.json`):
```json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.terminal.activateEnvironment": true,
    "python.analysis.extraPaths": ["."],
    "python.analysis.autoImportCompletions": true,
    "python.formatting.provider": "black",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": ["test/"]
}
```

### 3. Development Database
```bash
# Create development database
createdb NullPointVector_dev

# Run migrations
python -c "
from Autobot.VectorDB.NullPoint_Vector import init_db
init_db('NullPointVector_dev')
"
```

## Code Standards

### 1. Python Style Guide
We follow PEP 8 with some modifications:

```python
# Use type hints for all functions
def process_email(email_data: Dict[str, Any]) -> Tuple[bool, float]:
    """Process email and return threat detection result.
    
    Args:
        email_data: Dictionary containing email information
        
    Returns:
        Tuple of (is_threat, confidence_score)
    """
    pass

# Use dataclasses for data structures
@dataclass
class EmailResult:
    sender: str
    subject: str
    threat_score: float
    confidence: float
    timestamp: datetime
```

### 2. Import Organization
```python
# Standard library imports
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Third-party imports
import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer

# Local imports
from utils.offensive_intel import OffensiveIntelligence
from PhishGuard.phish_mlm.phishing_detector import PhishingDetector
```

### 3. Error Handling
```python
def safe_operation(func):
    """Decorator for safe operation with proper error handling."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Operation failed: {e}")
            # Return safe default or re-raise based on context
            return None
    return wrapper

@safe_operation
def fetch_emails(provider: str) -> List[Dict]:
    """Fetch emails with error handling."""
    pass
```

## Testing Strategy

### 1. Unit Tests
Create tests for each component:

```python
# test/test_email_fetchers.py
import pytest
from unittest.mock import Mock, patch
from PhishGuard.providers.email_fetcher.yahoo_doggy import YahooDoggy

class TestYahooDoggy:
    def setup_method(self):
        self.fetcher = YahooDoggy()
    
    @patch('imaplib.IMAP4_SSL')
    def test_fetch_emails_success(self, mock_imap):
        # Mock successful email fetch
        mock_imap.return_value.login.return_value = ('OK', [b'Logged in'])
        mock_imap.return_value.search.return_value = ('OK', [b'1 2 3'])
        
        emails = self.fetcher.fetch_emails(limit=3)
        assert len(emails) == 3
    
    def test_fetch_emails_no_credentials(self):
        # Test error handling for missing credentials
        with pytest.raises(ValueError):
            fetcher = YahooDoggy()
            fetcher.imap_user = None
            fetcher.fetch_emails()
```

### 2. Integration Tests
Test component interactions:

```python
# test/test_integration.py
class TestEmailIngestion:
    def test_full_ingestion_pipeline(self):
        """Test complete email ingestion pipeline."""
        from Autobot.email_ingestion import EmailIngestionEngine
        
        engine = EmailIngestionEngine()
        stats = engine.ingest_all_providers()
        
        assert stats.total_emails > 0
        assert stats.profiles_built > 0
        assert stats.avg_speed > 0
```

### 3. Performance Tests
```python
# test/test_performance.py
import time
import pytest

class TestPerformance:
    def test_ingestion_speed(self):
        """Test that ingestion meets performance requirements."""
        start_time = time.time()
        
        engine = EmailIngestionEngine()
        stats = engine.ingest_all_providers()
        
        duration = time.time() - start_time
        speed = stats.total_emails / duration
        
        assert speed >= 1.0  # Minimum 1 email/second
        assert stats.avg_speed >= 1.0
```

### 4. Security Tests
```python
# test/test_security.py
class TestSecurity:
    def test_input_sanitization(self):
        """Test that malicious input is properly sanitized."""
        from utils.content_sanitizer import sanitize_email_content
        
        malicious_content = "<script>alert('xss')</script>Hello"
        sanitized = sanitize_email_content(malicious_content)
        
        assert "<script>" not in sanitized
        assert "Hello" in sanitized
    
    def test_encryption(self):
        """Test that sensitive data is properly encrypted."""
        from Autobot.VectorDB.NullPoint_Vector import encrypt_content, decrypt_content
        
        original = "sensitive data"
        encrypted = encrypt_content(original)
        decrypted = decrypt_content(encrypted)
        
        assert encrypted != original
        assert decrypted == original
```

## Extension Points

### 1. Adding New Email Providers

Create a new provider by extending the base class:

```python
# PhishGuard/providers/email_fetcher/protonmail_doggy.py
from .base import EmailFetcher
import imaplib
from email.header import decode_header
import os
from dotenv import load_dotenv

class ProtonMailDoggy(EmailFetcher):
    def __init__(self):
        load_dotenv()
        self.imap_host = '127.0.0.1'  # ProtonMail Bridge
        self.imap_user = os.getenv('PROTONMAIL_USER')
        self.imap_pass = os.getenv('PROTONMAIL_PASS')
        
        if not all([self.imap_user, self.imap_pass]):
            raise ValueError("Missing ProtonMail credentials")
    
    def connect(self) -> bool:
        try:
            self.mail = imaplib.IMAP4_SSL(self.imap_host, 1025)
            self.mail.login(self.imap_user, self.imap_pass)
            return True
        except Exception as e:
            logger.error(f"ProtonMail connection failed: {e}")
            return False
    
    def fetch_emails(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch emails from ProtonMail."""
        if not self.connect():
            return []
        
        try:
            self.mail.select('INBOX')
            status, data = self.mail.search(None, 'ALL')
            email_ids = data[0].split()
            
            emails = []
            for email_id in email_ids[-limit:]:
                status, data = self.mail.fetch(email_id, '(RFC822)')
                for response_part in data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        emails.append({
                            'subject': self._decode_header(msg['Subject']),
                            'sender': msg.get('From'),
                            'date': msg.get('Date'),
                            'body': self._extract_body(msg)
                        })
            
            return emails
        finally:
            self.mail.logout()
    
    def _decode_header(self, header: str) -> str:
        if header is None:
            return ""
        decoded_header = decode_header(header)
        return " ".join(
            text.decode(charset or 'utf-8') if isinstance(text, bytes) else text
            for text, charset in decoded_header
        )
    
    def _extract_body(self, msg) -> str:
        if msg.is_multipart():
            body = ""
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
            return body
        return msg.get_payload(decode=True).decode('utf-8', errors='ignore')
```

Register the new provider:

```python
# PhishGuard/providers/email_fetcher/registry.py
from .protonmail_doggy import ProtonMailDoggy

class EmailFetcherRegistry:
    _fetchers = {
        'yahoo': YahooDoggy,
        'gmail': GmailDoggy,
        'outlook': OutlookDoggy,
        'protonmail': ProtonMailDoggy  # Add new provider
    }
```

### 2. Adding New ML Models

Create a custom model by extending the base detector:

```python
# PhishGuard/phish_mlm/custom_detector.py
from .phishing_detector import PhishingDetector
import torch
import torch.nn as nn

class CustomNeuralNetwork(nn.Module):
    def __init__(self, input_size=384):
        super().__init__()
        self.layers = nn.Sequential(
            nn.Linear(input_size, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 2)
        )
    
    def forward(self, x):
        return self.layers(x)

class CustomPhishingDetector(PhishingDetector):
    def __init__(self):
        super().__init__()
        self.model = CustomNeuralNetwork()
    
    def train_model(self, X, y):
        """Train custom neural network."""
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        X_tensor = torch.FloatTensor(X_scaled)
        y_tensor = torch.LongTensor(y)
        
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        
        self.model.train()
        for epoch in range(50):  # More epochs for complex model
            optimizer.zero_grad()
            outputs = self.model(X_tensor)
            loss = criterion(outputs, y_tensor)
            loss.backward()
            optimizer.step()
```

### 3. Adding New Intelligence Sources

Extend the offensive intelligence module:

```python
# utils/custom_intelligence.py
from .offensive_intel import OffensiveIntelligence
import requests
from typing import Dict, Any

class CustomIntelligence(OffensiveIntelligence):
    def __init__(self):
        super().__init__()
        self.custom_api_key = os.getenv('CUSTOM_API_KEY')
    
    def custom_reputation_check(self, domain: str) -> Dict[str, Any]:
        """Custom reputation checking service."""
        if not self.custom_api_key:
            return {}
        
        try:
            response = requests.get(
                f"https://api.customservice.com/check/{domain}",
                headers={'Authorization': f'Bearer {self.custom_api_key}'},
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Custom API returned {response.status_code}")
                return {}
        except Exception as e:
            logger.error(f"Custom reputation check failed: {e}")
            return {}
    
    def build_profile(self, sender_email: str, email_list: List[Dict]) -> SenderProfile:
        """Build profile with custom intelligence."""
        profile = super().build_profile(sender_email, email_list)
        
        # Add custom intelligence
        domain = sender_email.split('@')[1]
        custom_data = self.custom_reputation_check(domain)
        
        if custom_data:
            profile.reputation_data['custom'] = custom_data
        
        return profile
```

### 4. Adding New Dashboard Widgets

Extend the Streamlit dashboard:

```python
# ui/custom_widgets.py
import streamlit as st
import plotly.graph_objects as go

def custom_threat_timeline(data):
    """Custom timeline widget for threat visualization."""
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=data['timestamp'],
        y=data['threat_score'],
        mode='lines+markers',
        name='Threat Score',
        line=dict(color='red', width=2)
    ))
    
    fig.update_layout(
        title='Threat Timeline',
        xaxis_title='Time',
        yaxis_title='Threat Score',
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)

def custom_geolocation_map(profiles):
    """Custom map widget for threat geolocation."""
    # Implementation for interactive map
    pass
```

## Debugging and Development Tools

### 1. Debug Configuration
**VS Code Launch Configuration** (`.vscode/launch.json`):
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug Email Ingestion",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/Autobot/email_ingestion.py",
            "console": "integratedTerminal",
            "env": {
                "PYTHONPATH": "${workspaceFolder}"
            }
        },
        {
            "name": "Debug Dashboard",
            "type": "python",
            "request": "launch",
            "module": "streamlit",
            "args": ["run", "ui/dashboard.py"],
            "console": "integratedTerminal"
        }
    ]
}
```

### 2. Logging Configuration
```python
# utils/logger_config.py
import logging
import sys
from pathlib import Path

def setup_logging(level=logging.INFO):
    """Setup comprehensive logging for development."""
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # File handler for detailed logs
    file_handler = logging.FileHandler(log_dir / 'development.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    
    # Console handler for simple logs
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(simple_formatter)
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
```

### 3. Performance Profiling
```python
# utils/profiler.py
import cProfile
import pstats
import io
from functools import wraps

def profile_function(func):
    """Decorator to profile function performance."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        profiler = cProfile.Profile()
        profiler.enable()
        
        result = func(*args, **kwargs)
        
        profiler.disable()
        s = io.StringIO()
        ps = pstats.Stats(profiler, stream=s).sort_stats('cumulative')
        ps.print_stats(20)  # Top 20 functions
        
        logger.info(f"Profile for {func.__name__}:\n{s.getvalue()}")
        return result
    return wrapper

# Usage
@profile_function
def slow_function():
    # Function to profile
    pass
```

## Code Quality Tools

### 1. Pre-commit Hooks
**.pre-commit-config.yaml**:
```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
        language_version: python3.9
  
  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: [--max-line-length=88]
  
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.3.0
    hooks:
      - id: mypy
        additional_dependencies: [types-requests]
  
  - repo: local
    hooks:
      - id: pytest
        name: pytest
        entry: pytest
        language: system
        pass_filenames: false
        always_run: true
```

### 2. Type Checking
```python
# mypy.ini
[mypy]
python_version = 3.9
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = True
disallow_incomplete_defs = True
check_untyped_defs = True
disallow_untyped_decorators = True
no_implicit_optional = True
warn_redundant_casts = True
warn_unused_ignores = True
warn_no_return = True
warn_unreachable = True
strict_equality = True

[mypy.plugins.numpy.*]
ignore_missing_imports = True
```

## Documentation Standards

### 1. Docstring Format
```python
def complex_function(param1: str, param2: int = 10) -> Dict[str, Any]:
    """Perform complex operation with detailed documentation.
    
    This function performs a complex operation that requires multiple steps.
    It handles various edge cases and provides comprehensive error handling.
    
    Args:
        param1: Description of the first parameter. Must be a valid string.
        param2: Description of the second parameter. Defaults to 10.
        
    Returns:
        Dictionary containing the results of the operation with keys:
        - 'status': Success/failure status
        - 'data': Processed data
        - 'metadata': Additional information
        
    Raises:
        ValueError: If param1 is empty or invalid
        ConnectionError: If external service is unavailable
        
    Example:
        >>> result = complex_function("test", 5)
        >>> print(result['status'])
        'success'
    """
    pass
```

### 2. README Updates
When adding new features, update:
- Main README.md with feature description
- Architecture documentation
- Setup guide if new dependencies
- Development guide for new extension points

## Contribution Workflow

### 1. Feature Development
```bash
# Create feature branch
git checkout -b feature/new-email-provider

# Make changes
# Add tests
# Update documentation

# Run quality checks
pre-commit run --all-files

# Run tests
pytest test/ -v --cov

# Commit changes
git add .
git commit -m "feat: Add ProtonMail email provider

- Implement ProtonMailDoggy class
- Add integration tests
- Update documentation
- Fixes #123"
```

### 2. Pull Request Process
1. Create PR with descriptive title
2. Fill out PR template
3. Ensure all tests pass
4. Get code review
5. Address feedback
6. Merge when approved

### 3. Release Process
```bash
# Update version
bump2version patch  # or minor/major

# Create release notes
git log --oneline $(git describe --tags --abbrev=0)..HEAD

# Tag release
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin v1.2.0
```

## Advanced Development Topics

### 1. Database Migrations
```python
# utils/migrations.py
import psycopg2
from pathlib import Path

def run_migrations():
    """Run database migrations."""
    migrations_dir = Path('migrations')
    
    for migration_file in sorted(migrations_dir.glob('*.sql')):
        with open(migration_file) as f:
            sql = f.read()
        
        with connect_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql)
            conn.commit()
```

### 2. Configuration Management
```python
# config/settings.py
from dataclasses import dataclass
from typing import Dict, Any
import os

@dataclass
class Settings:
    """Application settings."""
    database_url: str
    email_providers: Dict[str, Any]
    ml_models: Dict[str, Any]
    security: Dict[str, Any]
    
    @classmethod
    def from_env(cls):
        """Load settings from environment variables."""
        return cls(
            database_url=os.getenv('DATABASE_URL'),
            email_providers={
                'yahoo': {
                    'enabled': os.getenv('YAHOO_ENABLED', 'true').lower() == 'true',
                    'user': os.getenv('YAHOO_USER'),
                    'pass': os.getenv('YAHOO_PASS')
                }
            },
            ml_models={
                'use_nn': os.getenv('USE_NEURAL_NETWORK', 'false').lower() == 'true',
                'model_path': os.getenv('MODEL_PATH', 'models/')
            },
            security={
                'encryption_key': os.getenv('ENCRYPTION_KEY'),
                'rate_limit': int(os.getenv('RATE_LIMIT', '100'))
            }
        )
```

This development guide provides the foundation for extending and maintaining the IDPS system. Follow these standards to ensure code quality, maintainability, and consistency across the project.
