# VPS Security Testing Lab

## Overview
This VPS-based lab provides a cost-effective alternative to expensive networking equipment for security testing and reconnaissance.

## VPS Setup Options

### 1. **DigitalOcean Droplet** ($5-10/month)
- **Pros**: Reliable, good performance, easy setup
- **Cons**: Limited bandwidth for heavy testing
- **Best for**: Basic security testing, small-scale reconnaissance

### 2. **Linode** ($5-10/month)
- **Pros**: Good performance, reliable, good support
- **Cons**: Limited locations
- **Best for**: General security testing

### 3. **Vultr** ($2.50-10/month)
- **Pros**: Very cheap, good performance, many locations
- **Cons**: Less reliable than others
- **Best for**: Budget testing, multiple locations

### 4. **AWS EC2** (Free tier available)
- **Pros**: Free tier, scalable, many services
- **Cons**: Complex pricing, can get expensive
- **Best for**: Learning, small projects

## Recommended Setup

### Basic VPS ($5/month)
```
OS: Ubuntu 22.04 LTS
RAM: 1GB
CPU: 1 vCPU
Storage: 25GB SSD
Bandwidth: 1TB
```

### Enhanced VPS ($10/month)
```
OS: Ubuntu 22.04 LTS
RAM: 2GB
CPU: 2 vCPU
Storage: 50GB SSD
Bandwidth: 2TB
```

## Security Testing Tools

### Network Reconnaissance
- **Nmap**: Port scanning and network discovery
- **Masscan**: Fast port scanning
- **Wireshark**: Packet analysis
- **tcpdump**: Command-line packet capture

### Web Application Testing
- **OWASP ZAP**: Web application security scanner
- **Nikto**: Web server scanner
- **Dirb**: Directory brute forcing
- **SQLMap**: SQL injection testing

### Vulnerability Assessment
- **OpenVAS**: Vulnerability scanner
- **Nessus**: Commercial vulnerability scanner
- **Vulners**: Vulnerability database integration

### Exploitation Framework
- **Metasploit**: Exploitation framework
- **Cobalt Strike**: Advanced penetration testing

## Setup Instructions

### 1. VPS Initial Setup
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo apt install -y git curl wget vim htop

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

### 2. Security Tools Installation
```bash
# Install network tools
sudo apt install -y nmap masscan wireshark tcpdump

# Install web testing tools
sudo apt install -y nikto dirb sqlmap

# Install Python tools
pip3 install requests beautifulsoup4 selenium
```

### 3. Docker-based Tools
```bash
# OWASP ZAP
docker pull owasp/zap2docker-stable

# Metasploit
docker pull metasploitframework/metasploit-framework

# Kali Linux (full toolset)
docker pull kalilinux/kali-rolling
```

## Testing Scenarios

### 1. Network Discovery
```bash
# Basic network scan
nmap -sS -sV -O 192.168.1.0/24

# Fast port scan
masscan -p1-65535 192.168.1.0/24 --rate=1000

# Service enumeration
nmap -sS -sV -sC -A -p- target.com
```

### 2. Web Application Testing
```bash
# Directory enumeration
dirb http://target.com

# Vulnerability scan
nikto -h http://target.com

# SQL injection test
sqlmap -u "http://target.com/page?id=1"
```

### 3. IDPS Testing
```bash
# Test our PhishGuard system
python3 test_email_providers.py

# Load testing
ab -n 1000 -c 10 http://target.com/

# Stress testing
siege -c 100 -t 60S http://target.com/
```

## Cost Optimization

### 1. **Use Free Tiers**
- AWS Free Tier (12 months)
- Google Cloud Free Tier
- Oracle Cloud Free Tier

### 2. **Spot Instances**
- Use spot/preemptible instances for testing
- 60-90% cost savings
- Good for non-critical testing

### 3. **Shared Resources**
- Use one VPS for multiple projects
- Schedule testing during off-peak hours
- Use lightweight tools

### 4. **Local Testing**
- Test basic functionality locally
- Use VPS only for network-level testing
- Minimize bandwidth usage

## Security Considerations

### 1. **Legal Compliance**
- Only test your own systems
- Get written permission for testing
- Follow responsible disclosure

### 2. **VPS Security**
- Use SSH keys, not passwords
- Configure firewall (UFW)
- Regular security updates
- Monitor logs

### 3. **Data Protection**
- Encrypt sensitive data
- Use VPN for connections
- Regular backups
- Secure credential storage

## Monitoring and Logging

### 1. **System Monitoring**
```bash
# Install monitoring tools
sudo apt install -y htop iotop nethogs

# Monitor system resources
htop
iotop
nethogs
```

### 2. **Log Analysis**
```bash
# View system logs
sudo journalctl -f

# Monitor auth logs
sudo tail -f /var/log/auth.log

# Monitor web server logs
sudo tail -f /var/log/nginx/access.log
```

### 3. **Alerting**
```bash
# Set up email alerts
sudo apt install -y mailutils

# Configure log monitoring
sudo apt install -y fail2ban
```

## Next Steps

1. **Choose a VPS provider** based on your budget
2. **Set up the basic environment** with security tools
3. **Configure monitoring and logging**
4. **Test your IDPS system** against real threats
5. **Document findings** and improve the system

## Budget Breakdown

### Monthly Costs
- **Basic VPS**: $5-10/month
- **Domain name**: $1-2/month (optional)
- **SSL certificate**: Free (Let's Encrypt)
- **Total**: $6-12/month

### One-time Costs
- **Domain registration**: $10-15/year
- **Security tools**: Free (open source)
- **Training materials**: Free (online resources)

This setup provides a professional-grade security testing environment at a fraction of the cost of dedicated hardware.
