# PhishGuard: Multi-Channel Threat Detection System

A comprehensive AI-powered security platform that detects and blocks phishing, smishing, and vishing attempts across email, SMS, and voice channels in real-time.

## 🚀 Features

### Core Capabilities
- **Multi-Channel Monitoring**: Email (Yahoo, Gmail, Outlook), SMS, and Voice call analysis
- **AI/ML Detection**: Multi-layered ML pipeline combining Logistic Regression, Neural Networks, and Pandas feature engineering
- **Threat Intelligence**: Integration with PhishTank, AbuseIPDB, and local threat databases
- **Vector Database**: PostgreSQL with pgvector for semantic similarity search and pattern matching
- **Real-time Processing**: Continuous monitoring with immediate threat detection and response
- **Modular Architecture**: Extensible design supporting dynamic provider integration

### Security Features
- **Encryption**: End-to-end data encryption using Fernet
- **Rate Limiting**: Protection against DDoS and abuse
- **Input Validation**: Comprehensive sanitization and validation
- **Audit Logging**: Complete audit trail for compliance and debugging
- **Access Control**: Role-based permissions and secure credential management

## 📋 Prerequisites

- Python 3.8+
- PostgreSQL 12+ with pgvector extension
- Git
- macOS (for iPhone backup access)

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/Yahoo_Phish.git
   cd Yahoo_Phish
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # macOS/Linux
   # or
   venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up PostgreSQL database**
   ```bash
   # Install pgvector extension
   CREATE EXTENSION vector;
   
   # Create database
   CREATE DATABASE NullPointVector;
   ```

5. **Configure environment**
   ```bash
   cp env.template .env
   # Edit .env with your credentials
   ```

## ⚙️ Configuration

Copy `env.template` to `.env` and configure the following:

### Required Variables
```env
# Database
DB_NAME=NullPointVector
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=localhost
DB_PORT=5432

# Email Providers (configure at least one)
YAHOO_USER=your_yahoo_email@yahoo.com
YAHOO_PASS=your_yahoo_app_password
GMAIL_USER=your_gmail_email@gmail.com
GMAIL_PASS=your_gmail_app_password
OUTLOOK_USER=your_outlook_email@outlook.com
OUTLOOK_PASSWORD=your_outlook_password

# Security
SECRET_KEY=your_secret_key_here
ENCRYPTION_KEY=your_encryption_key_here
```

### Optional Variables
```env
# iPhone Monitoring
IPHONE_NUMBER=your_phone_number
IPHONE_BACKUP_PATH=/path/to/your/iphone/backup

# Threat Intelligence APIs
PHISHTANK_API_KEY=your_phishtank_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key

# Twilio (for SMS/Voice)
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
```

## 🚀 Usage

### Command Line Interface

**Run all security guards:**
```bash
python Autobot/run_all.py
```

**Run specific components:**
```bash
# Email only
python Autobot/run_all.py --email-providers yahoo gmail

# Skip SMS/Voice
python Autobot/run_all.py --skip-sms --skip-voice

# Skip threat intelligence
python Autobot/run_all.py --skip-threat-intel
```

**Test security features:**
```bash
python test/test_security.py
```

### Web Interface

**Flask Web UI:**
```bash
python ui/app.py
```

**Streamlit Dashboard:**
```bash
streamlit run ui/admin.py
```

## 📁 Project Structure

```
Yahoo_Phish/
├── Autobot/                    # Main orchestrator and monitoring
│   ├── run_all.py             # Main entry point
│   ├── real_time_monitor.py   # Real-time monitoring
│   └── VectorDB/              # Vector database operations
├── PhishGuard/                # Email threat detection
│   ├── providers/             # Email provider integrations
│   └── phish_mlm/            # ML models for phishing detection
├── SmishGuard/               # SMS threat detection
│   ├── providers/            # SMS provider integrations
│   └── smish_mlm/           # ML models for smishing detection
├── VishGuard/                # Voice threat detection
│   ├── voice_fetch/          # Voice provider integrations
│   └── vish_mlm/            # ML models for vishing detection
├── utils/                    # Shared utilities
│   ├── security/            # Security components
│   ├── database.py          # Database operations
│   └── threat_intelligence.py # Threat intelligence
├── ui/                      # Web interfaces
├── test/                    # Test suite
├── docs/                    # Documentation
├── hackbook/               # Security lab environment
└── requirements.txt        # Dependencies
```

## 🔧 Development

### Setting up Development Environment

1. **Install development dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up pre-commit hooks**
   ```bash
   pre-commit install
   ```

3. **Run tests**
   ```bash
   python -m pytest test/
   ```

### Adding New Email Providers

1. Create a new fetcher class in `PhishGuard/providers/email_fetcher/`
2. Inherit from `EmailFetcher` base class
3. Implement required methods
4. Register in `EmailFetcherRegistry`

Example:
```python
from .base import EmailFetcher

class NewProviderDoggy(EmailFetcher):
    def __init__(self):
        super().__init__()
        # Provider-specific initialization
    
    def connect(self) -> bool:
        # Implementation
        pass
    
    def fetch_emails(self, folder: str = 'INBOX', limit: int = 100):
        # Implementation
        pass
```

## 🐳 Docker Deployment

**Build and run with Docker Compose:**
```bash
docker-compose up -d
```

**Individual services:**
```bash
# Build image
docker build -t phishguard .

# Run container
docker run -p 8501:8501 phishguard
```

## 🔒 Security Considerations

- **Credential Management**: Use app-specific passwords for email providers
- **Network Security**: Deploy behind a reverse proxy with SSL/TLS
- **Access Control**: Implement proper authentication and authorization
- **Data Privacy**: Ensure compliance with relevant privacy regulations
- **Monitoring**: Set up comprehensive logging and alerting

## 📊 Monitoring and Logging

- **Log Files**: Check `guard_logs.log` for detailed operation logs
- **Database**: Monitor threat detection patterns and false positives
- **Performance**: Track processing times and resource usage
- **Alerts**: Configure notifications for critical security events

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation as needed
- Ensure security best practices

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [PhishTank](https://www.phishtank.com/) for phishing data
- [AbuseIPDB](https://www.abuseipdb.com/) for IP reputation
- [Twilio](https://www.twilio.com/) for SMS/Voice integration
- [pgvector](https://github.com/pgvector/pgvector) for vector similarity search

## 📞 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation in `docs/`
- Review the technical journey in `docs/TECHNICAL_JOURNEY.md`

---

**Note**: SMS and Voice monitoring for iPhone requires CallKit integration and production app deployment due to Apple's terms of service. The current implementation focuses on email threat detection with SMS/Voice capabilities in development.
