# IDPS Setup Guide

## Quick Start

This guide will get you from zero to a fully operational IDPS system in under 30 minutes.

## Prerequisites

- **Python 3.9+** (3.11 recommended)
- **PostgreSQL 13+** with pgvector extension
- **Git** for version control
- **Docker** (optional, for containerized deployment)

## Step 1: Environment Setup

### 1.1 Clone the Repository
```bash
git clone https://github.com/yourusername/Yahoo_Phish.git
cd Yahoo_Phish
```

### 1.2 Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 1.3 Install Dependencies
```bash
pip install -r requirements.txt
```

## Step 2: Database Setup

### 2.1 Install PostgreSQL
**macOS (Homebrew):**
```bash
brew install postgresql
brew services start postgresql
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**Windows:**
Download from [PostgreSQL official site](https://www.postgresql.org/download/windows/)

### 2.2 Install pgvector Extension
```bash
# Install pgvector
git clone https://github.com/pgvector/pgvector.git
cd pgvector
make
sudo make install

# Connect to PostgreSQL and create extension
psql -U postgres
CREATE EXTENSION vector;
\q
```

### 2.3 Create Database and User
```bash
# Connect as postgres user
sudo -u postgres psql

# Create database and user
CREATE DATABASE NullPointVector;
CREATE USER your_username WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE NullPointVector TO your_username;
\q
```

## Step 3: Environment Configuration

### 3.1 Create Environment File
```bash
cp .env.example .env
```

### 3.2 Configure Environment Variables
Edit `.env` with your actual credentials:

```bash
# Database Configuration
DB_NAME=NullPointVector
DB_USER=your_username
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432

# Email Provider Credentials
YAHOO_USER=your_yahoo_email@yahoo.com
YAHOO_PASS=your_app_password
GMAIL_USER=your_gmail@gmail.com
GMAIL_PASS=your_app_password
OUTLOOK_EMAIL=your_outlook@outlook.com
OUTLOOK_PASSWORD=your_app_password

# Security Keys
ENCRYPTION_KEY=your_32_byte_encryption_key
SECRET_KEY=your_secret_key_for_sessions

# Threat Intelligence APIs (Optional)
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key

# iPhone Configuration (Future)
IPHONE_BACKUP_PATH=/path/to/iphone/backup
```

### 3.3 Generate Security Keys
```python
# Run this in Python to generate encryption key
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print(f"ENCRYPTION_KEY={key.decode()}")
```

## Step 4: Email Provider Setup

### 4.1 Yahoo Mail
1. Enable 2-factor authentication
2. Generate app password:
   - Go to Account Security
   - App passwords
   - Generate new app password
3. Use app password in `.env`

### 4.2 Gmail
1. Enable 2-factor authentication
2. Generate app password:
   - Go to Google Account settings
   - Security → App passwords
   - Generate for "Mail"
3. Use app password in `.env`

### 4.3 Outlook
1. Enable 2-factor authentication
2. Generate app password:
   - Go to Account settings
   - Security → Advanced security options
   - App passwords
3. Use app password in `.env`

## Step 5: Initial Testing

### 5.1 Test Database Connection
```bash
python -c "
from Autobot.VectorDB.NullPoint_Vector import connect_db
conn = connect_db()
if conn:
    print('✅ Database connection successful')
else:
    print('❌ Database connection failed')
"
```

### 5.2 Test Email Providers
```bash
python test_email_providers.py
```

Expected output:
```
🔍 Testing Yahoo email fetching...
✅ Yahoo: Fetched 5 emails
🔍 Testing Gmail email fetching...
✅ Gmail: Fetched 5 emails
🔍 Testing Outlook email fetching...
✅ Outlook: Fetched 5 emails
```

### 5.3 Test ML Components
```bash
python test_ml_components.py
```

Expected output:
```
🔍 Testing Sentence Transformer...
✅ Sentence Transformer: Generated embedding of shape (384,)
🔍 Testing Feature Engineering...
✅ Feature Engineering: Extracted 9 features
🔍 Testing Rule-based Prediction...
✅ Rule-based Prediction: Generated threat score
```

## Step 6: Run the System

### 6.1 Start Email Ingestion
```bash
python Autobot/email_ingestion.py
```

Expected output:
```
🚀 Starting email ingestion...
📥 Processing Yahoo: 150 emails
📥 Processing Gmail: 150 emails
📥 Processing Outlook: 150 emails
🕵️ Building intelligence profiles: 171 profiles
📊 Ingestion complete: 450 emails processed
```

### 6.2 Start Dashboard
```bash
streamlit run ui/dashboard.py
```

Open browser to `http://localhost:8501`

## Step 7: Production Deployment

### 7.1 Docker Deployment (Recommended)
```bash
# Build and run with Docker Compose
docker-compose up -d

# Check logs
docker-compose logs -f
```

### 7.2 Systemd Service (Linux)
```bash
# Create service file
sudo nano /etc/systemd/system/idps.service

[Unit]
Description=IDPS Security System
After=network.target

[Service]
Type=simple
User=your_user
WorkingDirectory=/path/to/Yahoo_Phish
Environment=PATH=/path/to/Yahoo_Phish/venv/bin
ExecStart=/path/to/Yahoo_Phish/venv/bin/python Autobot/run_all.py
Restart=always

[Install]
WantedBy=multi-user.target

# Enable and start service
sudo systemctl enable idps
sudo systemctl start idps
```

## Troubleshooting

### Common Issues

#### 1. Database Connection Failed
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check pgvector extension
psql -U your_username -d NullPointVector -c "SELECT * FROM pg_extension WHERE extname = 'vector';"

# Reset database
sudo -u postgres dropdb NullPointVector
sudo -u postgres createdb NullPointVector
psql -U postgres -d NullPointVector -c "CREATE EXTENSION vector;"
```

#### 2. Email Provider Authentication Failed
```bash
# Test individual providers
python -c "
from PhishGuard.providers.email_fetcher.yahoo_doggy import YahooDoggy
yahoo = YahooDoggy()
emails = yahoo.fetch_emails(limit=1)
print(f'Fetched {len(emails)} emails')
"
```

#### 3. Import Errors
```bash
# Check Python path
python -c "import sys; print('\n'.join(sys.path))"

# Reinstall dependencies
pip uninstall -r requirements.txt
pip install -r requirements.txt
```

#### 4. Memory Issues
```bash
# Reduce batch size in Autobot/email_ingestion.py
config = IngestionConfig(
    batch_size=25,  # Reduce from 75
    max_emails_per_provider=100  # Reduce from 200
)
```

#### 5. Performance Issues
```bash
# Enable parallel processing
config = IngestionConfig(
    parallel_providers=True,
    enable_intelligence=True,
    enable_ml_analysis=True
)
```

### Performance Optimization

#### 1. Database Optimization
```sql
-- Create indexes for better performance
CREATE INDEX idx_messages_sender ON messages(sender);
CREATE INDEX idx_messages_created_at ON messages(created_at);
CREATE INDEX idx_messages_type ON messages(message_type);
```

#### 2. Memory Optimization
```python
# In Autobot/email_ingestion.py
import gc

def process_batch(self, emails):
    # Process batch
    results = self._analyze_emails(emails)
    
    # Force garbage collection
    gc.collect()
    
    return results
```

#### 3. Caching
```python
# Cache intelligence results
import pickle
from pathlib import Path

def cache_intelligence(self, domain, data):
    cache_file = Path(f'cache/{domain}.pkl')
    cache_file.parent.mkdir(exist_ok=True)
    
    with open(cache_file, 'wb') as f:
        pickle.dump(data, f)
```

## Security Considerations

### 1. Environment Variables
- Never commit `.env` files to version control
- Use strong, unique passwords
- Rotate API keys regularly

### 2. Database Security
```sql
-- Create read-only user for dashboard
CREATE USER dashboard_user WITH PASSWORD 'dashboard_password';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO dashboard_user;
```

### 3. Network Security
```bash
# Firewall rules (Ubuntu)
sudo ufw allow 8501/tcp  # Streamlit dashboard
sudo ufw allow 5432/tcp  # PostgreSQL (if remote)
sudo ufw enable
```

### 4. File Permissions
```bash
# Secure sensitive files
chmod 600 .env
chmod 600 config/security_config.py
chmod 700 data/
```

## Monitoring and Maintenance

### 1. Log Monitoring
```bash
# Check system logs
tail -f logs/idps.log

# Monitor database size
psql -U your_username -d NullPointVector -c "SELECT pg_size_pretty(pg_database_size('NullPointVector'));"
```

### 2. Performance Monitoring
```bash
# Monitor system resources
htop
iotop
nethogs
```

### 3. Backup Strategy
```bash
# Database backup
pg_dump -U your_username NullPointVector > backup_$(date +%Y%m%d).sql

# Configuration backup
tar -czf config_backup_$(date +%Y%m%d).tar.gz .env config/ data/
```

### 4. Update Strategy
```bash
# Update dependencies
pip install --upgrade -r requirements.txt

# Update models
python -c "
from PhishGuard.phish_mlm.phishing_detector import PhishingDetector
detector = PhishingDetector()
detector.retrain_models()
"
```

## Next Steps

### 1. Customization
- Add new email providers
- Implement custom ML models
- Extend intelligence gathering

### 2. Integration
- Connect to SIEM systems
- Integrate with ticketing systems
- Add webhook notifications

### 3. Scaling
- Deploy to cloud infrastructure
- Implement load balancing
- Add monitoring and alerting

### 4. Advanced Features
- iOS CallKit integration
- Real-time threat intelligence
- Automated response actions

## Support

### Documentation
- [Architecture Guide](ARCHITECTURE.md)
- [ML Engineering Guide](ML_ENGINEERING.md)
- [Journey Documentation](JOURNEY.md)

### Community
- GitHub Issues for bug reports
- GitHub Discussions for questions
- Pull requests for contributions

### Professional Support
For enterprise deployments and custom development, contact the development team.

---

**Congratulations!** You now have a fully operational IDPS system. The system is designed to be self-improving - the more data it processes, the better it becomes at detecting threats.
