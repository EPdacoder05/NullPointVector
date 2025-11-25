# Threat Triage System

## Overview

The threat triage system enables security analysts to take action on detected threats through:
- **Blocking & Reporting**: Programmatic sender blocking with email folder management
- **Warning System**: Flag senders requiring careful review
- **Forensic Reporting**: Generate detailed threat reports with IP geolocation
- **Action Logging**: Complete audit trail of all triage decisions

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Dashboard (ui/dashboard.py)               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   Threats    │  │  Intelligence │  │   Actions    │       │
│  │   Tab        │  │     Tab       │  │     Log      │       │
│  └──────┬───────┘  └──────────────┘  └──────┬───────┘       │
│         │                                     │               │
└─────────┼─────────────────────────────────────┼───────────────┘
          │                                     │
          ▼                                     ▼
┌─────────────────────────────────────────────────────────────┐
│          Threat Actions Manager (utils/threat_actions.py)   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │    Block     │  │     Warn     │  │    Report    │       │
│  │   Sender     │  │    Sender    │  │   Threat     │       │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘       │
│         │                  │                  │               │
│         ▼                  ▼                  ▼               │
│  ┌─────────────────────────────────────────────────┐        │
│  │         Action Log (data/threat_actions.json)   │        │
│  └─────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│      Geolocation Service (utils/geo_location.py)            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ IP → Location│  │ Risk Scoring │  │   ISP Info   │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│                                                               │
│  Cache: 7-day TTL (data/geo_cache.json)                     │
│  API: ip-api.com (45 req/min free tier)                     │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. Threat Actions Manager (`utils/threat_actions.py`)

Manages all threat triage actions with persistent storage.

#### Key Methods:

```python
from utils.threat_actions import threat_actions

# Block a sender and move to spam
threat_actions.block_sender(threat_data, reason="High threat detected")
# → Moves email to "Phishy bizz" folder
# → Adds sender to blocked list
# → Logs action for audit

# Mark sender for caution
threat_actions.warn_sender(threat_data, warning_level="MEDIUM")
# → Flags sender in warned list
# → Displays warning icon in future emails

# Generate forensic report
report = threat_actions.report_threat(threat_data, report_to="internal")
# → Extracts all IPs from headers
# → Captures SPF/DKIM/authentication results
# → Saves to data/reports/{report_id}.json
```

#### Data Storage:

- `data/blocked_senders.json`: Blocked sender registry
- `data/warned_senders.json`: Warned sender registry
- `data/threat_actions.json`: Complete action log (append-only)
- `data/reports/{report_id}.json`: Individual threat reports

### 2. Geolocation Service (`utils/geo_location.py`)

Provides IP → Location mapping with risk scoring.

#### Key Methods:

```python
from utils.geo_location import geo_service

# Get location data
location = geo_service.get_location('123.45.67.89')
# Returns:
# {
#     'ip': '123.45.67.89',
#     'country': 'Russia',
#     'city': 'Moscow',
#     'latitude': 55.7558,
#     'longitude': 37.6173,
#     'isp': 'Example Telecom',
#     'risk_score': 'HIGH'  # HIGH/MEDIUM/LOW
# }

# Get human-readable summary
summary = geo_service.get_location_summary('123.45.67.89')
# → "Moscow, Russia 🔴 (HIGH Risk)"
```

#### Risk Scoring:

- **HIGH**: Origin from high-risk countries (CN, RU, NG, PK, etc.)
- **MEDIUM**: VPN/hosting/cloud providers
- **LOW**: Regular ISPs in low-risk countries

#### Caching:

- 7-day TTL per IP
- Cache stored in `data/geo_cache.json`
- Automatic cache invalidation

### 3. Enhanced Dashboard (`ui/dashboard.py`)

#### New Threat Tab Features:

```
┌─────────────────────────────────────────────────────────┐
│ 🚨 Threat Analysis                                      │
├─────────────────────────────────────────────────────────┤
│ 🔴 Blocked: 12  |  🟡 Warned: 8  |  📊 Total Actions: 45│
├─────────────────────────────────────────────────────────┤
│ Filter: [All Types ▼] [Confidence: 50% ──────●──] ☐ Hide│
│                                                 blocked  │
├─────────────────────────────────────────────────────────┤
│ 🚨 NEW | URGENT: Verify your account NOW!              │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Sender: phisher@evil.com                            │ │
│ │ Type: phishing                                       │ │
│ │ Confidence: 95.3%                                    │ │
│ │ Location: Moscow, Russia 🔴 (HIGH Risk)             │ │
│ │ ISP: Evil Telecom                                    │ │
│ │                                                       │ │
│ │ 🎯 Triage Actions:                                   │ │
│ │ [🔴 Block & Report] [🟡 Mark as Caution]            │ │
│ │ [📋 Generate Report]                                 │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

#### New Actions Tab:

Displays complete audit log:
- Timestamp of each action
- Action type (BLOCK/WARN/REPORT)
- Sender details
- Threat score
- Reason for action

## Usage

### Dashboard Workflow

1. **View Threats**:
   ```
   Dashboard → Threats Tab → Browse detected threats
   ```

2. **Triage Threat**:
   - Click **Block & Report**: Blocks sender, moves email to spam
   - Click **Mark as Caution**: Flags sender for warning
   - Click **Generate Report**: Creates forensic report

3. **Review Actions**:
   ```
   Dashboard → Actions Tab → View audit log
   ```

### Programmatic Usage

```python
from utils.threat_actions import threat_actions
from utils.geo_location import geo_service

# Process a threat
threat = {
    'id': 'THR-001',
    'sender': 'phisher@evil.com',
    'subject': 'Reset your password',
    'threat_score': 0.89,
    'headers': {
        'x_originating_ip': '123.45.67.89',
        'authentication_results': 'spf=fail',
        'dkim_signature': 'none'
    }
}

# Get geolocation
ip = threat['headers']['x_originating_ip']
location = geo_service.get_location(ip)
print(f"Origin: {location['city']}, {location['country']}")
print(f"Risk: {location['risk_score']}")

# Take action based on risk
if location['risk_score'] == 'HIGH' and threat['threat_score'] > 0.8:
    # Block high-risk threats
    threat_actions.block_sender(threat, "High-risk origin + high threat score")
    print("✅ Sender blocked and email moved to spam")
elif threat['threat_score'] > 0.5:
    # Warn on medium threats
    threat_actions.warn_sender(threat, "MEDIUM")
    print("⚠️ Sender flagged for caution")

# Generate report for escalation
if threat['threat_score'] > 0.9:
    report = threat_actions.report_threat(threat, "abuse@provider.com")
    print(f"📋 Report generated: {report['report_id']}")
```

## Email Folder Management

### Moving to "Phishy bizz" Folder

When blocking a sender, the system:

1. Connects to Yahoo IMAP server
2. Copies email to "Phishy bizz" folder
3. Deletes from original folder
4. Expunges (permanent delete)

**Note**: The "Phishy bizz" folder must exist in your Yahoo account. Create it manually if needed.

### Prerequisites:

```bash
# .env file
YAHOO_USER=your@yahoo.com
YAHOO_PASS=your_app_password
```

## Forensic Reporting

### Report Structure

```json
{
  "report_id": "THR-20250122-143052",
  "timestamp": "2025-01-22T14:30:52",
  "sender": "phisher@evil.com",
  "subject": "URGENT: Verify your account",
  "threat_score": 0.95,
  "recipient": "internal",
  "forensics": {
    "originating_ips": ["123.45.67.89", "98.76.54.32"],
    "return_path": "bounce@evil.com",
    "message_id": "<abc123@evil.com>",
    "authentication": "spf=fail dkim=none",
    "spf_result": "fail",
    "dkim": "none"
  },
  "indicators": {
    "suspicious_links": ["http://evil-site.com/phish"],
    "phishing_keywords": ["urgent", "verify", "account"],
    "ml_confidence": 0.95
  }
}
```

### Reports Location

All reports saved to: `data/reports/{report_id}.json`

## Geolocation API

### Provider: ip-api.com

- **Free tier**: 45 requests/minute
- **Fields returned**: Country, city, lat/lon, ISP, organization, AS number
- **No API key required**

### Rate Limiting

To avoid rate limits:
- 7-day caching per IP
- Private IPs not queried
- Batch lookups available

### Alternative Providers

If you exceed free tier, consider:
- **ipapi.co**: 1000 req/day free
- **ipgeolocation.io**: 1000 req/day free
- **MaxMind GeoLite2**: Offline database (free)

## Security Considerations

### Action Logging

All actions logged with:
- Timestamp
- Action type
- User/system identifier
- Threat details
- Reason

### Data Privacy

- Action logs contain email metadata (not content)
- Reports include headers (may contain IPs)
- Geolocation cached locally
- No external data sharing

### Access Control

Currently:
- Single-user system
- File-based storage

Future considerations:
- Multi-user role-based access
- Database-backed storage
- API authentication

## Monitoring

### Action Statistics

```python
from utils.threat_actions import threat_actions

# Get blocked senders
blocked = threat_actions.get_blocked_senders()
print(f"Blocked: {len(blocked)}")

# Get warned senders
warned = threat_actions.get_warned_senders()
print(f"Warned: {len(warned)}")

# Get recent actions
actions = threat_actions.get_action_log(limit=100)
print(f"Recent actions: {len(actions)}")

# Check if sender is blocked
if threat_actions.is_blocked('phisher@evil.com'):
    print("Sender is blocked")
```

### Dashboard Metrics

The **Actions** tab shows:
- Total actions taken
- Action type distribution (BLOCK/WARN/REPORT)
- Timeline of actions
- Sender breakdown

## Troubleshooting

### Issue: "Failed to move email to Phishy bizz"

**Cause**: Folder doesn't exist or IMAP credentials invalid

**Solution**:
1. Create "Phishy bizz" folder in Yahoo web interface
2. Verify YAHOO_USER and YAHOO_PASS in `.env`
3. Use Yahoo app password (not regular password)

### Issue: "Geolocation timeout"

**Cause**: Rate limit exceeded or network issues

**Solution**:
1. Check internet connection
2. Wait for rate limit reset (1 minute)
3. System uses cache for repeated IPs

### Issue: "Actions not showing in dashboard"

**Cause**: Dashboard data not refreshed

**Solution**:
1. Click action button
2. Dashboard auto-refreshes every 2 seconds
3. Or manually refresh browser (F5)

## Performance

### Benchmarks

- **Block action**: ~2-3 seconds (IMAP operation)
- **Warn action**: <50ms (file I/O)
- **Report generation**: <100ms (no network calls)
- **Geolocation lookup**: ~500ms (first time), <10ms (cached)

### Optimization

- Geolocation: 7-day cache reduces API calls by 95%
- Action log: Append-only, no database queries
- Batch operations: Process multiple threats at once

## Future Enhancements

### Planned Features

1. **Automated Triage**:
   - Auto-block threats above threshold
   - Auto-warn based on sender reputation

2. **Email Provider Integration**:
   - Gmail: Use Gmail API for folder management
   - Outlook: Use Microsoft Graph API

3. **Enhanced Reporting**:
   - PDF report generation
   - Email reports to security team
   - Integration with SIEM systems

4. **Machine Learning**:
   - Learn from triage decisions
   - Improve threat scoring based on actions

5. **Multi-Provider Support**:
   - Block across all email providers
   - Centralized block list

## API Reference

See source code for complete API:
- `utils/threat_actions.py`: ThreatActionManager class
- `utils/geo_location.py`: GeoLocationService class

## Support

For issues or questions:
1. Check logs: `logs/`
2. Review action log: `data/threat_actions.json`
3. Verify credentials in `.env`

## License

Part of Yahoo_Phish IDPS project.
