# 🚀 QUICK START GUIDE

## ⚠️ PREREQUISITES

### 1. Start Docker Desktop
```bash
# Open Docker Desktop application
# Wait for "Docker Desktop is running" indicator
```

### 2. Start PostgreSQL Database
```bash
cd /Users/ep/DevProjects/Yahoo_Phish
docker-compose up -d db
```

**Verify database is running:**
```bash
docker ps | grep postgres
# Should show: ankane/pgvector on port 5433
```

---

## ✅ What's Ready

1. **Database:** `processed` column added for auto-triage tracking
2. **Dependencies:** Dash/Plotly installed, Streamlit removed
3. **Background Worker:** `yahoo_stream_monitor.py` enhanced with auto-triage
4. **Dashboard:** `ui/dash_app.py` with real-time updates (2-second refresh)
5. **Cleanup:** All Streamlit code removed

---

## 🏃 RUN IT NOW

### 🎯 EASIEST WAY (Automated Startup):
```bash
cd /Users/ep/DevProjects/Yahoo_Phish
./startup.sh
```

**What it does:**
1. Checks Docker Desktop is running
2. Starts PostgreSQL container
3. Verifies virtual environment
4. Checks dependencies installed
5. Tests database connection
6. Asks which service to start (Worker/Dashboard/Both)

---

### 🔧 MANUAL WAY (Two Terminals):

#### Terminal 1: Background Worker
```bash
cd /Users/ep/DevProjects/Yahoo_Phish
source .venv/bin/activate
python Autobot/yahoo_stream_monitor.py
```

**What it does:**
- Fetches Yahoo + Gmail every 5 minutes (parallel)
- AUTO-BLOCKS threats > 0.85 from HIGH risk countries (CN, RU, NG, etc.)
- Moves blocked emails to "Phishy bizz" folder
- Auto-retrains ML after 50 new threats
- Logs everything

### Terminal 2: Dash Dashboard
```bash
cd /Users/ep/DevProjects/Yahoo_Phish
source .venv/bin/activate
python ui/dash_app.py
```

**What it does:**
- Serves dashboard on http://localhost:8050
- Auto-refreshes every 2 seconds
- Shows live logs, threat map, triage buttons
- Pattern-matching callbacks for Block/Warn/Report

### Browser
**Open:** http://localhost:8050

---

## 📊 Dashboard Features

- **Live Stats:** Emails, threats, blocked senders, threat rate
- **Live Logs:** Last 50 emails with emoji indicators
  - 🚨 Red = High threat (> 0.85)
  - ⚠️ Orange = Medium threat (0.7-0.85)
  - ✅ Green = Safe
- **Threat Map:** World map showing threat origins (color-coded by risk)
- **Threat Cards:** Block/Warn/Report buttons (pattern-matching callbacks)
- **Action Log:** Recent triage decisions with timestamps

---

## ❓ FAQ

### Q: Why COPY → DELETE → EXPUNGE instead of MOVE?
**A:** Yahoo IMAP doesn't support native `MOVE` command. The 3-step pattern is the standard IMAP workaround:
1. `COPY`: Duplicates email to "Phishy bizz"
2. `+FLAGS \\Deleted`: Marks original for deletion
3. `EXPUNGE`: Permanently removes

### Q: How does auto-triage work?
**A:** Background worker queries unprocessed threats, checks:
```python
if confidence > 0.85 AND geo_risk == 'HIGH':
    block_sender()
    move_to_phishy_bizz()
    log_action("BLOCK", "Auto-blocked: HIGH risk")
    mark_processed()
```

### Q: Can I disable auto-triage?
**A:** Yes! Add `--disable-auto-triage` flag:
```bash
python Autobot/yahoo_stream_monitor.py --disable-auto-triage
```

### Q: Can I change the auto-block threshold?
**A:** Yes! Use `--triage-threshold`:
```bash
python Autobot/yahoo_stream_monitor.py --triage-threshold 0.90
```

---

## 🧪 Quick Test

1. Start both services (see commands above)
2. Open http://localhost:8050
3. Wait for background worker cycle (5 min)
4. Watch Terminal 1 for: "🚨 AUTO-BLOCKED: sender (score: X, Country)"
5. Dashboard logs should show new emails
6. Click "🔴 Block" on a threat → button changes to "✅ Blocked"
7. Check Action Log for new BLOCK entry

---

## 📖 Full Docs

See `docs/DASH_DEPLOYMENT.md` for:
- Complete deployment steps
- Line-by-line code explanations
- Troubleshooting guide
- Production deployment

---

## 🔧 TROUBLESHOOTING

### Error: "Bind for 0.0.0.0:5433 failed: port is already allocated"
**Problem:** Old container still using port 5433

**Solution:**
```bash
# 1. Archive old container config
mkdir -p archive/docker_configs
docker inspect <container_name> > archive/docker_configs/<container_name>_config_$(date +%Y%m%d_%H%M%S).json

# 2. Stop and remove old container
docker stop <container_name>
docker rm <container_name>

# 3. Start fresh
docker-compose up -d db
```

### Error: "Connection refused" on port 5433
**Problem:** PostgreSQL Docker container not running

**Solution:**
```bash
# 1. Start Docker Desktop app
# 2. Start database container
docker-compose up -d db

# 3. Verify it's running
docker ps | grep postgres
```

### Error: "PhishingDetector() got unexpected keyword argument"
**Problem:** Already fixed! `PhishingDetector()` takes no arguments

**Solution:** Code updated - just restart background worker

### Error: "Cannot connect to Docker daemon"
**Problem:** Docker Desktop not running

**Solution:**
```bash
# Open Docker Desktop from Applications
# Wait for "Docker Desktop is running" status
# Then run: docker-compose up -d db
```

### Database shows 0 emails
**Problem:** Background worker needs to complete first cycle (5 minutes)

**Solution:** Wait 5 minutes and check dashboard again

---

## 🎉 Done!

Your IDPS is production-ready:
- ✅ Real-time monitoring (Dash + Plotly)
- ✅ Automated response (auto-block HIGH risk)
- ✅ Live log streaming (terminal in browser)
- ✅ Geographic intelligence (threat map)
- ✅ Complete audit trail (action logging)
- ✅ Zero Streamlit bloat

**LET'S GO! 🚀**
