# Dash Deployment Guide

## ✅ COMPLETED SETUP

### Phase 1: Dependencies ✅
- ✅ Installed: `dash`, `plotly`, `dash-bootstrap-components`
- ✅ Updated: `requirements.txt` (removed Streamlit, added Dash)
- ✅ Docker: Updated `Dockerfile` and `docker-compose.yml` for port 8050

### Phase 2: Background Worker ✅
- ✅ Refactored: `Autobot/yahoo_stream_monitor.py` with:
  - Auto-triage logic (blocks threats > 0.85 from HIGH risk countries)
  - Parallel provider support (Yahoo primary + Gmail secondary)
  - Configurable thresholds via command-line args
  - Auto-marks threats as `processed` in database

### Phase 3: Dash Dashboard ✅
- ✅ Created: `ui/dash_app.py` (replaced Streamlit)
- ✅ Deleted: `ui/dashboard.py` (old Streamlit version)
- ✅ Updated: `start.sh` to launch Dash on port 8050

### Phase 4: Database Schema ✅
- ✅ Added column: `messages.processed BOOLEAN DEFAULT false`
- ✅ Purpose: Track which threats have been auto-triaged

---

## 🚀 DEPLOYMENT STEPS

### Step 1: Start Background Worker (Terminal 1)

```bash
cd /Users/ep/DevProjects/Yahoo_Phish

# Activate virtual environment
source .venv/bin/activate

# Start continuous ingestion with auto-triage
python Autobot/yahoo_stream_monitor.py \
  --interval 5 \
  --retrain-threshold 50 \
  --triage-threshold 0.85
```

**What this does:**
- Fetches Yahoo + Gmail emails every 5 minutes (parallel)
- Runs ML analysis on each email
- AUTO-BLOCKS threats with:
  - Confidence > 0.85 AND
  - Originating from HIGH risk country (CN, RU, NG, etc.)
- Moves blocked emails to "Phishy bizz" folder via IMAP
- Logs all actions to `data/threat_actions.json`
- Auto-retrains ML model after 50 new threats
- Runs indefinitely (Ctrl+C to stop)

**Command-line options:**
- `--interval 5`: Fetch every 5 minutes (default)
- `--retrain-threshold 50`: Retrain after 50 threats (default)
- `--triage-threshold 0.85`: Auto-block threshold (default 0.85)
- `--disable-auto-triage`: Disable automatic blocking (manual only)

**Example output:**
```
🚀 Yahoo Stream Monitor started
📧 Fetching emails every 5 minutes
🔁 Auto-retrain after 50 new threats
🌍 Providers: Yahoo (primary) + Gmail (secondary, parallel)
🛡️  Auto-triage: ✅ ENABLED
   → Auto-blocking threats with score > 0.85

============================================================
🔄 CYCLE 1 - 2025-11-22 15:30:00
============================================================
📥 Fetching emails from Yahoo + Gmail...
✅ Ingested 23 emails, 5 threats
🛡️  Running auto-triage...
🚨 AUTO-BLOCKED: phisher@evil.ru (score: 0.92, Russia)
🚨 AUTO-BLOCKED: scam@fraud.cn (score: 0.88, China)
✅ Auto-triaged 2 high-risk threats
⏳ No retrain needed (5/50 new threats)
💤 Sleeping for 5 minutes...
```

---

### Step 2: Start Dash Dashboard (Terminal 2)

```bash
cd /Users/ep/DevProjects/Yahoo_Phish
source .venv/bin/activate

# Start Dash UI
python ui/dash_app.py
```

**What this does:**
- Starts Dash server on http://localhost:8050
- Auto-refreshes every 2 seconds
- Shows live ingestion logs (last 50 emails)
- Geographic threat map (scatter plot)
- Active threats with Block/Warn/Report buttons
- Action log (recent triage decisions)

**Example output:**
```
======================================================================
🛡️  YAHOO_PHISH IDPS DASHBOARD
======================================================================
🌐 Starting Dash server...
📍 URL: http://localhost:8050
🔄 Auto-refresh: Every 2 seconds
======================================================================
Dash is running on http://0.0.0.0:8050/

 * Serving Flask app 'dash_app'
 * Debug mode: on
```

---

### Step 3: Open Dashboard

Open browser to: **http://localhost:8050**

You should see:
- **Live Stats**: Total emails, threats, blocked senders, threat rate
- **Live Logs**: Terminal-style stream with emoji indicators
  - 🚨 Red: High-risk threat (> 0.85)
  - ⚠️ Orange: Medium threat (0.7-0.85)
  - ✅ Green: Safe email
- **Threat Map**: World map with colored dots showing threat origins
  - 🔴 Red: HIGH risk countries (China, Russia, etc.)
  - 🟠 Orange: MEDIUM risk (VPNs, hosting providers)
  - 🟢 Green: LOW risk
- **Active Threats**: Cards with sender, subject, score, geolocation
  - 🔴 Block: Moves to "Phishy bizz" + blocks sender
  - ⚠️ Warn: Flags sender for review
  - 📋 Report: Generates forensic report
- **Action Log**: Recent Block/Warn/Report actions

---

## 🧪 TESTING END-TO-END

### Test 1: Verify Background Worker
```bash
# In Terminal 1 (background worker)
# You should see logs like:
# "📥 Fetching emails from Yahoo + Gmail..."
# "✅ Ingested X emails, Y threats"
# "🚨 AUTO-BLOCKED: sender@domain (score: 0.XX, Country)"
```

### Test 2: Verify Dash Dashboard
```bash
# Open http://localhost:8050
# Check that stats are updating every 2 seconds
# Verify "Last updated" timestamp changes
# Check live logs show recent emails
```

### Test 3: Manual Triage
```bash
# In dashboard, find a threat card
# Click "🔴 Block" button
# Button should change to "✅ Blocked"
# Check Terminal 1 logs for:
#   "✅ Moved email {id} to Phishy bizz"
# Check Action Log section for new entry
```

### Test 4: Auto-Triage
```bash
# Trigger auto-triage by ingesting high-risk email
# In Terminal 1, wait for next cycle (5 min)
# Look for: "🚨 AUTO-BLOCKED: sender (score: 0.XX, Country)"
# Check Yahoo webmail: Email should be in "Phishy bizz" folder
# Check dashboard Action Log: Should show BLOCK action
```

---

## 📊 DASHBOARD FEATURES EXPLAINED

### 1. Live Log Stream
- **Line-by-line explanation:**
  ```python
  # Each log entry shows:
  [15:30:45]     # Timestamp when email was processed
  🚨             # Emoji: 🚨 threat, ✅ safe
  0.92           # ML confidence score (0.0-1.0)
  sender@...     # Sender email address (truncated)
  Subject...     # Email subject (truncated)
  ```

### 2. Geographic Threat Map
- **Purpose:** Visualize where threats are coming from
- **Data source:** IP addresses from email headers (`X-Originating-IP`)
- **Risk coloring:**
  - 🔴 RED: HIGH risk countries (CN, RU, NG, PK, IN, BR, RO, VN)
  - 🟠 ORANGE: MEDIUM risk (VPN, proxy, datacenter, hosting)
  - 🟢 GREEN: LOW risk (regular ISPs)
- **Hover:** Shows city, country, sender, risk level

### 3. Auto-Triage Logic
```python
# Pseudo-code of auto-triage:
if threat.confidence > 0.85:
    ip = threat.headers['x_originating_ip']
    geo = get_location(ip)
    
    if geo.risk_level == 'HIGH':
        # AUTO-BLOCK
        block_sender(threat)
        move_to_phishy_bizz(threat)
        log_action("BLOCK", threat, "Auto-blocked: HIGH risk")
    
    # Mark as processed regardless
    threat.processed = True
```

### 4. Pattern-Matching Callbacks
- **How Block/Warn/Report buttons work:**
  ```python
  # Dash uses pattern-matching for dynamic buttons
  # Each threat card has 3 buttons with IDs:
  {"type": "btn-block", "index": threat_id}
  {"type": "btn-warn", "index": threat_id}
  {"type": "btn-report", "index": threat_id}
  
  # Callbacks use MATCH to respond to specific button:
  @app.callback(
      Output({"type": "btn-block", "index": MATCH}, "children"),
      Input({"type": "btn-block", "index": MATCH}, "n_clicks"),
      ...
  )
  # When clicked, button ID contains threat_id
  # Callback queries database for full threat data
  # Executes threat_actions.block_sender(threat_data)
  # Returns "✅ Blocked" to update button text
  ```

---

## 🛠️ TROUBLESHOOTING

### Issue: Terminal not working
**Solution:** Terminal commands can still be run via Python tools. All critical operations completed using `mcp_pylance_mcp_s_pylanceRunCodeSnippet`.

### Issue: "Column 'processed' does not exist"
**Solution:** Already fixed! Column added successfully:
```sql
ALTER TABLE messages ADD COLUMN processed BOOLEAN DEFAULT false
```

### Issue: Dashboard shows "No data"
**Check:**
1. Is background worker running? (Terminal 1)
2. Has it completed at least one cycle? (Wait 5 min)
3. Check database: `SELECT COUNT(*) FROM messages;`
4. Check API health: http://localhost:8000/health

### Issue: Auto-triage not blocking threats
**Check:**
1. Confidence score > 0.85? (Lower threshold with `--triage-threshold 0.7`)
2. Geolocation available? (Check `data/geo_cache.json`)
3. Risk level HIGH? (Only auto-blocks HIGH risk countries)
4. Background worker logs: Look for "🚨 AUTO-BLOCKED" messages

### Issue: "Phishy bizz" folder not found
**Solution:** Create folder in Yahoo webmail:
1. Log into Yahoo Mail
2. Create new folder: "Phishy bizz" (exact name, no quotes)
3. Restart background worker

---

## 🔄 WHY COPY → DELETE → EXPUNGE?

**Your question:** "Why not directly move email?"

**Answer:** Yahoo IMAP doesn't support native `MOVE` command. The 3-step pattern is the standard IMAP workaround:

```python
# Step 1: COPY email to destination folder
result = mail.copy(email_id, 'Phishy bizz')

# Step 2: Mark original as deleted (doesn't remove yet)
mail.store(email_id, '+FLAGS', '\\Deleted')

# Step 3: Permanently remove deleted messages
mail.expunge()
```

**Why this works:**
- `COPY`: Creates duplicate in "Phishy bizz"
- `+FLAGS \\Deleted`: Marks INBOX copy for deletion
- `EXPUNGE`: Permanently removes marked messages

**Alternative (if supported):**
```python
# RFC 6851 MOVE extension (not reliable on Yahoo)
mail.move(email_id, 'Phishy bizz')  # One command
```

Most IMAP servers (including Yahoo, Gmail, Outlook) require the 3-step approach for compatibility.

---

## 📈 NEXT STEPS

### Optional Enhancements:
1. **WebSocket streaming:** Replace 2-second polling with instant updates
2. **Redis queue:** Decouple ingestion from triage for scalability
3. **Systemd service:** Auto-start background worker on boot
4. **Multi-user support:** Add authentication to dashboard
5. **Email notifications:** Alert on high-risk threats
6. **SMS integration:** SmishGuard + iPhone backup parsing
7. **Voice call analysis:** VishGuard + CallKit integration

### Production Deployment:
1. Set environment variables for production DB
2. Run with `gunicorn` instead of Flask dev server
3. Add nginx reverse proxy for HTTPS
4. Deploy to AWS/Azure/GCP with Docker Compose
5. Set up monitoring (Prometheus + Grafana)

---

## 🎉 SUMMARY

**What we built:**
- ✅ Real-time IDPS with Dash + Plotly (replaced Streamlit)
- ✅ Continuous ingestion (Yahoo primary + Gmail secondary)
- ✅ Automatic threat blocking (ML + geolocation)
- ✅ Live log streaming (terminal in browser)
- ✅ Geographic threat visualization (world map)
- ✅ Manual triage controls (Block/Warn/Report)
- ✅ Complete audit trail (action logging)

**Key improvements over Streamlit:**
- ✅ Real-time updates (2-second auto-refresh)
- ✅ Live log streaming (shows processing as it happens)
- ✅ Pattern-matching callbacks (dynamic buttons)
- ✅ No data loss on restart (PostgreSQL persistence)
- ✅ Production-ready (can scale with Redis + WebSockets)

**Let's go! 🚀**
