# NullPointVector: AI-Powered IDPS Security Platform

> **From Yahoo_Phish to NullPointVector: The Evolution of a Security Architecture**

A comprehensive **Intrusion Detection and Prevention System (IDPS)** that combines advanced machine learning, offensive intelligence gathering, and real-time monitoring to defend against phishing, smishing, and vishing attacks across multiple channels.

## 🛡️ **What We Built**

This isn't just another security tool - it's a **complete security platform** that evolved from a simple email checker into a production-ready IDPS capable of processing hundreds of emails per minute while building comprehensive threat intelligence profiles.

### **Core Capabilities**

- **🚀 High-Performance Ingestion**: Process 200+ emails per provider with 75-email batch optimization
- **🤖 Multi-Layered ML Pipeline**: Sentence Transformers + Logistic Regression + Neural Networks
- **🕵️ Offensive Intelligence**: DNS reconnaissance, WHOIS analysis, geolocation mapping, reputation checking
- **💾 Vector Database**: PostgreSQL with pgvector for semantic similarity search and pattern recognition
- **📊 Real-Time Dashboard**: Streamlit-based monitoring with interactive analytics
- **🔒 Enterprise Security**: End-to-end encryption, rate limiting, audit logging, input validation
- **🏗️ Modular Architecture**: Extensible design supporting dynamic provider integration

## 🚀 **Key Features**

### **Advanced Email Processing**
- **Multi-Provider Support**: Yahoo, Gmail, Outlook with extensible registry pattern
- **Batch Optimization**: 50-75 emails per batch for optimal performance (1.5-2.5 emails/sec)
- **Parallel Processing**: Concurrent provider processing for maximum efficiency
- **Raw Data Storage**: Complete audit trail with encrypted storage

### **Machine Learning Engine**
- **Sentence Transformers**: 384-dimensional embeddings for semantic understanding
- **Feature Engineering**: Time-based, content-based, and structural feature extraction
- **Dual Model Support**: Interpretable Logistic Regression + Complex Neural Networks
- **Confidence Scoring**: Probability-based threat assessment with explainable results

### **Offensive Intelligence**
- **DNS Reconnaissance**: Complete domain infrastructure analysis
- **WHOIS Analysis**: Registration pattern identification and domain age tracking
- **IP Geolocation**: Attack origin mapping and geographic threat analysis
- **Reputation Checking**: VirusTotal, AbuseIPDB, and custom API integration
- **Sender Profiling**: Comprehensive threat actor intelligence building

### **Production-Ready Infrastructure**
- **Vector Database**: PostgreSQL with pgvector for similarity search
- **Encryption**: Fernet encryption for all sensitive data
- **Rate Limiting**: DDoS protection and API abuse prevention
- **Audit Logging**: Complete operation trail for compliance
- **Error Handling**: Graceful degradation and robust error recovery

## 📊 **Performance Metrics**

- **Processing Speed**: 1.5-2.5 emails/second
- **Memory Efficiency**: 10-20MB per batch
- **Storage Optimization**: ~1KB per email with embeddings
- **Accuracy**: 85%+ on semantic similarity tasks
- **Scalability**: Parallel processing for unlimited providers

## 🏗️ **Architecture Overview**

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

## 🛠️ **Quick Start**

### **Prerequisites**
- Python 3.9+ (3.11 recommended)
- PostgreSQL 13+ with pgvector extension
- Git for version control
- Docker (optional, for containerized deployment)

### **Installation**

1. **Clone the Repository**
```bash
git clone https://github.com/EPdacoder05/NullPointVector.git
cd NullPointVector
```

2. **Setup Environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. **Configure Database**
```bash
# Install pgvector extension
CREATE EXTENSION vector;

# Create database
CREATE DATABASE NullPointVector;
```

4. **Environment Configuration**
```bash
cp .env.example .env
# Edit .env with your credentials
```

5. **Test the System**
```bash
# Test email providers
python test_email_providers.py

# Test ML components
python test_ml_components.py

# Run full ingestion
python Autobot/email_ingestion.py

# Start dashboard
streamlit run ui/dashboard.py
```

## ⚙️ **Configuration**

### **Required Environment Variables**
```bash
# Database
DB_NAME=NullPointVector
DB_USER=your_username
DB_PASSWORD=your_password

# Email Providers
YAHOO_USER=your_yahoo_email@yahoo.com
YAHOO_PASS=your_app_password
GMAIL_USER=your_gmail@gmail.com
GMAIL_PASS=your_app_password
OUTLOOK_EMAIL=your_outlook@outlook.com
OUTLOOK_PASSWORD=your_app_password

# Security
ENCRYPTION_KEY=your_32_byte_encryption_key
SECRET_KEY=your_secret_key_for_sessions
```

### **Optional Intelligence APIs**
```bash
# Threat Intelligence
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key
```

## 📁 **Project Structure**

```
NullPointVector/
├── Autobot/                    # Core orchestration and database
│   ├── email_ingestion.py     # High-performance ingestion engine
│   ├── run_all.py             # Main orchestrator
│   └── VectorDB/              # PostgreSQL with pgvector
│       └── NullPoint_Vector.py
├── PhishGuard/                # Email security engine
│   ├── providers/             # Email provider integrations
│   │   ├── email_fetcher/     # Yahoo, Gmail, Outlook
│   │   └── email_analyzer.py  # Email analysis
│   └── phish_mlm/            # ML models and feature engineering
├── SmishGuard/               # SMS security (iOS integration pending)
├── VishGuard/                # Voice security (iOS integration pending)
├── utils/                    # Shared utilities and intelligence
│   ├── offensive_intel.py    # Offensive intelligence gathering
│   ├── security/             # Security components
│   └── threat_intelligence.py
├── ui/                       # User interfaces
│   └── dashboard.py          # Streamlit dashboard
├── docs/                     # Comprehensive documentation
│   ├── ARCHITECTURE.md       # System architecture
│   ├── ML_ENGINEERING.md     # ML pipeline details
│   ├── SETUP_GUIDE.md        # Installation guide
│   ├── DEVELOPMENT_GUIDE.md  # Contributor guide
│   └── JOURNEY.md           # Project evolution story
├── hackbook/                 # Security testing environment
│   └── vps-lab/             # VPS reconnaissance tools
├── test/                     # Testing infrastructure
└── requirements.txt          # Dependencies
```

## 🚀 **Usage Examples**

### **Command Line Interface**
```bash
# Run complete system
python Autobot/run_all.py

# Run specific providers
python Autobot/run_all.py --email-providers yahoo gmail

# High-performance ingestion
python Autobot/email_ingestion.py
```

### **Dashboard Interface**
```bash
# Start real-time dashboard
streamlit run ui/dashboard.py
```

### **Testing and Validation**
```bash
# Test email providers
python test_email_providers.py

# Test ML components
python test_ml_components.py

# Test offensive intelligence
python test_offensive_intel.py
```

## 🔧 **Development**

### **Adding New Email Providers**
```python
from PhishGuard.providers.email_fetcher.base import EmailFetcher

class NewProviderDoggy(EmailFetcher):
    def __init__(self):
        # Provider-specific initialization
        pass
    
    def fetch_emails(self, limit: int = 100):
        # Implementation
        pass
```

### **Extending ML Models**
```python
from PhishGuard.phish_mlm.phishing_detector import PhishingDetector

class CustomDetector(PhishingDetector):
    def __init__(self):
        super().__init__()
        # Custom model initialization
```

### **Adding Intelligence Sources**
```python
from utils.offensive_intel import OffensiveIntelligence

class CustomIntelligence(OffensiveIntelligence):
    def custom_reputation_check(self, domain: str):
        # Custom intelligence implementation
        pass
```

## 🐳 **Docker Deployment**

### **Quick Deployment**
```bash
# Build and run with Docker Compose
docker-compose up -d

# Check logs
docker-compose logs -f
```

### **Production Deployment**
```bash
# Build production image
docker build -t nullpointvector .

# Run with environment variables
docker run -d \
  -p 8501:8501 \
  --env-file .env \
  nullpointvector
```

## 🔒 **Security Features**

- **🔐 Encryption**: Fernet encryption for all sensitive data
- **🛡️ Rate Limiting**: DDoS protection and API abuse prevention
- **✅ Input Validation**: Comprehensive sanitization and validation
- **📝 Audit Logging**: Complete operation trail for compliance
- **🔑 Access Control**: Environment-based credential management
- **🛡️ Content Sanitization**: XSS and injection attack prevention

## 📊 **Monitoring and Analytics**

### **Real-Time Dashboard**
- **Ingestion Statistics**: Emails processed per provider
- **Threat Analysis**: Real-time threat detection results
- **Intelligence Reports**: Sender profiles and patterns
- **Performance Metrics**: Processing speed and efficiency

### **Logging and Debugging**
```bash
# Check system logs
tail -f logs/idps.log

# Monitor database size
psql -U your_username -d NullPointVector -c "SELECT pg_size_pretty(pg_database_size('NullPointVector'));"
```

## 🤝 **Contributing**

We welcome contributions! Please see our [Development Guide](docs/DEVELOPMENT_GUIDE.md) for detailed instructions.

### **Development Setup**
```bash
# Install development tools
pip install black flake8 pytest pytest-cov mypy
pip install pre-commit

# Setup pre-commit hooks
pre-commit install

# Run tests
pytest test/ -v --cov
```

## 📚 **Documentation**

- **[Architecture Guide](docs/ARCHITECTURE.md)**: Complete system architecture
- **[ML Engineering Guide](docs/ML_ENGINEERING.md)**: Machine learning pipeline details
- **[Setup Guide](docs/SETUP_GUIDE.md)**: Installation and configuration
- **[Development Guide](docs/DEVELOPMENT_GUIDE.md)**: Contributor guidelines
- **[Journey Documentation](docs/JOURNEY.md)**: Project evolution story

## 🎯 **Roadmap**

### **Immediate Next Steps**
- [ ] iOS CallKit integration for real-time SMS/voice monitoring
- [ ] Advanced ML models (BERT, GPT-based analysis)
- [ ] Threat intelligence integration (STIX/TAXII)
- [ ] Automated response actions

### **Long-term Vision**
- [ ] Federated learning for privacy-preserving model training
- [ ] Graph neural networks for sender relationship modeling
- [ ] Reinforcement learning for adaptive threat detection
- [ ] Mobile app (iOS/Android companion)

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- **PhishTank** for phishing data
- **AbuseIPDB** for IP reputation
- **VirusTotal** for threat intelligence
- **pgvector** for vector similarity search
- **Sentence Transformers** for semantic understanding

## 📞 **Support**

- **Documentation**: Check the [docs/](docs/) directory
- **Issues**: Create an issue on GitHub
- **Discussions**: Use GitHub Discussions for questions
- **Journey**: Read [docs/JOURNEY.md](docs/JOURNEY.md) for the full story

---

**Built with ❤️ by a security engineer who started with a simple email checker and ended up with a complete IDPS platform.**

*"From Yahoo_Phish to NullPointVector: The journey of building something that actually works."*
