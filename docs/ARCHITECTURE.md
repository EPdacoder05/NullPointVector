# IDPS Architecture Documentation

## System Overview

The IDPS (Intrusion Detection and Prevention System) is a multi-layered security platform that combines email fetching, machine learning analysis, and offensive intelligence gathering to detect and prevent phishing, smishing, and vishing attacks.

## Core Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    IDPS Security Platform                    │
├─────────────────────────────────────────────────────────────┤
│  🛡️  Security Layer                                        │
│  ├── Encryption (Fernet)                                   │
│  ├── Rate Limiting                                         │
│  ├── Input Validation                                      │
│  └── Audit Logging                                         │
├─────────────────────────────────────────────────────────────┤
│  📥  Data Ingestion Layer                                  │
│  ├── Email Providers (Yahoo, Gmail, Outlook)              │
│  ├── Batch Processing (50-75 emails/batch)                │
│  ├── Parallel Processing                                   │
│  └── Raw Data Storage                                      │
├─────────────────────────────────────────────────────────────┤
│  🤖  Machine Learning Layer                                │
│  ├── Sentence Transformers (all-MiniLM-L6-v2)             │
│  ├── Feature Engineering (Pandas)                         │
│  ├── Logistic Regression                                   │
│  ├── Neural Networks (PyTorch)                            │
│  └── Threat Scoring                                        │
├─────────────────────────────────────────────────────────────┤
│  🕵️  Intelligence Layer                                    │
│  ├── DNS Reconnaissance                                    │
│  ├── WHOIS Analysis                                        │
│  ├── Geolocation Mapping                                   │
│  ├── Reputation Checking                                   │
│  └── Pattern Recognition                                   │
├─────────────────────────────────────────────────────────────┤
│  💾  Data Storage Layer                                    │
│  ├── PostgreSQL with pgvector                             │
│  ├── Vector Embeddings                                     │
│  ├── Sender Profiles                                       │
│  └── Threat Intelligence                                   │
├─────────────────────────────────────────────────────────────┤
│  📊  Presentation Layer                                    │
│  ├── Streamlit Dashboard                                   │
│  ├── Real-time Metrics                                     │
│  ├── Interactive Charts                                    │
│  └── Performance Monitoring                                │
└─────────────────────────────────────────────────────────────┘
```

## Component Breakdown

### 1. Email Providers (`PhishGuard/providers/email_fetcher/`)

**Purpose**: Fetch emails from multiple providers with standardized interface

**Key Files**:
- `base.py` - Abstract base class for all email fetchers
- `yahoo_doggy.py` - Yahoo Mail implementation
- `gmail_doggy.py` - Gmail implementation  
- `outlook_doggy.py` - Outlook implementation
- `registry.py` - Dynamic provider selection

**Dependencies**:
```python
import imaplib
import email.message
from email.header import decode_header
from abc import ABC, abstractmethod
from typing import List, Dict, Any
import logging
from dotenv import load_dotenv
```

**Usage**:
```python
from PhishGuard.providers.email_fetcher.registry import EmailFetcherRegistry

# Get specific provider
fetcher = EmailFetcherRegistry.get_fetcher('yahoo')
emails = fetcher.fetch_emails(limit=50)

# Get all providers
providers = EmailFetcherRegistry.get_available_providers()
```

### 2. Machine Learning Engine (`PhishGuard/phish_mlm/`)

**Purpose**: Analyze emails using ML models for threat detection

**Key Files**:
- `phishing_detector.py` - Main ML pipeline
- `FeatureEngineering` class - Extract features from emails
- `SimpleNN` class - PyTorch neural network
- `PhishingDetector` class - Orchestrates ML analysis

**Dependencies**:
```python
import torch
import torch.nn as nn
from sentence_transformers import SentenceTransformer
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
import joblib
```

**Usage**:
```python
from PhishGuard.phish_mlm.phishing_detector import PhishingDetector

detector = PhishingDetector(use_nn=False)  # Use Logistic Regression
result = detector.predict(email_data)
```

### 3. Offensive Intelligence (`utils/offensive_intel.py`)

**Purpose**: Build comprehensive profiles of email senders

**Key Features**:
- DNS reconnaissance
- WHOIS analysis
- IP geolocation
- Reputation checking
- Pattern recognition

**Dependencies**:
```python
import dns.resolver
import whois
import requests
from dataclasses import dataclass
from typing import Dict, List, Any
import json
from pathlib import Path
```

**Usage**:
```python
from utils.offensive_intel import OffensiveIntelligence

intel = OffensiveIntelligence()
profile = intel.build_profile(sender_email, email_list)
threat_score = profile.threat_score
```

### 4. Email Ingestion Engine (`Autobot/email_ingestion.py`)

**Purpose**: High-performance email ingestion with batch processing

**Key Features**:
- Configurable batch sizes (25-100 emails)
- Parallel provider processing
- Performance optimization
- Raw data storage

**Dependencies**:
```python
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, List, Any
import time
import json
from pathlib import Path
```

**Usage**:
```python
from Autobot.email_ingestion import EmailIngestionEngine, IngestionConfig

config = IngestionConfig(
    batch_size=75,
    max_emails_per_provider=200,
    parallel_providers=True
)
engine = EmailIngestionEngine(config)
stats = engine.ingest_all_providers()
```

### 5. Vector Database (`Autobot/VectorDB/NullPoint_Vector.py`)

**Purpose**: Store and query vector embeddings for similarity search

**Key Features**:
- PostgreSQL with pgvector extension
- Encrypted data storage
- Semantic similarity search
- Message deduplication

**Dependencies**:
```python
import psycopg2
from psycopg2.extensions import register_adapter, AsIs
import numpy as np
from sentence_transformers import SentenceTransformer
from cryptography.fernet import Fernet
```

**Usage**:
```python
from Autobot.VectorDB.NullPoint_Vector import connect_db, insert_message

conn = connect_db()
insert_message(conn, 'email', sender, content, embedding)
```

### 6. Dashboard (`ui/dashboard.py`)

**Purpose**: Real-time monitoring and analysis interface

**Key Features**:
- Streamlit-based web interface
- Interactive charts and metrics
- Real-time threat monitoring
- Performance analytics

**Dependencies**:
```python
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
```

**Usage**:
```bash
streamlit run ui/dashboard.py
```

## Data Flow

1. **Ingestion**: Email providers fetch emails in batches
2. **Processing**: Emails are parsed and normalized
3. **ML Analysis**: Sentence transformers generate embeddings
4. **Feature Engineering**: Extract metadata and behavioral features
5. **Intelligence**: Build sender profiles with reconnaissance
6. **Storage**: Save to PostgreSQL with vector embeddings
7. **Visualization**: Display results in dashboard

## Performance Characteristics

- **Batch Size**: 50-75 emails optimal for performance
- **Processing Speed**: 1.5-2.5 emails/second
- **Memory Usage**: ~10-20MB per batch
- **Storage**: ~1KB per email with embeddings
- **Concurrency**: Parallel processing for multiple providers

## Security Features

- **Encryption**: Fernet encryption for sensitive data
- **Rate Limiting**: Prevents API abuse
- **Input Validation**: Sanitizes all inputs
- **Audit Logging**: Tracks all operations
- **Access Control**: Environment-based credentials

## Configuration

All configuration is managed through environment variables:

```bash
# Database
DB_NAME=NullPointVector
DB_USER=your_user
DB_PASSWORD=your_password

# Email Providers
YAHOO_USER=your_yahoo_email
YAHOO_PASS=your_app_password
GMAIL_USER=your_gmail_email
GMAIL_PASS=your_app_password

# Security
ENCRYPTION_KEY=your_encryption_key
SECRET_KEY=your_secret_key

# APIs
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

## Extension Points

### Adding New Email Providers

1. Create new fetcher class inheriting from `EmailFetcher`
2. Implement required methods: `connect()`, `fetch_emails()`, `disconnect()`
3. Register in `EmailFetcherRegistry`

### Adding New ML Models

1. Extend `PhishingDetector` class
2. Implement `predict()` method
3. Add model loading and training logic

### Adding New Intelligence Sources

1. Extend `OffensiveIntelligence` class
2. Implement new reconnaissance methods
3. Update threat scoring algorithm

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure PYTHONPATH includes project root
2. **Database Connection**: Check PostgreSQL is running and credentials are correct
3. **API Limits**: Implement rate limiting for external APIs
4. **Memory Issues**: Reduce batch size or enable garbage collection

### Performance Optimization

1. **Increase Batch Size**: Up to 100 emails per batch
2. **Enable Parallel Processing**: Use ThreadPoolExecutor
3. **Optimize Database Queries**: Use indexes on frequently queried columns
4. **Cache Intelligence Results**: Store API responses locally

## Future Enhancements

1. **Real-time Monitoring**: WebSocket-based live updates
2. **Advanced ML Models**: BERT, GPT-based analysis
3. **Threat Intelligence**: Integration with STIX/TAXII
4. **Automated Response**: Block/quarantine suspicious emails
5. **Mobile App**: iOS/Android companion app
6. **API Gateway**: RESTful API for external integrations
