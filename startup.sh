#!/bin/bash
# Startup Script for Yahoo_Phish IDPS
# Run this to start everything in the correct order

set -e

echo "🚀 Yahoo_Phish IDPS Startup"
echo "="*70

# Check 1: Docker Desktop
echo "📋 Step 1/5: Checking Docker Desktop..."
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker Desktop is not running!"
    echo "   → Open Docker Desktop from Applications"
    echo "   → Wait for 'Docker Desktop is running' indicator"
    echo "   → Then run this script again"
    exit 1
fi
echo "✅ Docker Desktop is running"

# Check 2: Start PostgreSQL
echo ""
echo "📋 Step 2/5: Starting PostgreSQL..."
docker-compose up -d db
sleep 3

# Verify PostgreSQL
if docker ps | grep -q postgres; then
    echo "✅ PostgreSQL running on port 5433"
else
    echo "❌ PostgreSQL failed to start"
    exit 1
fi

# Check 3: Virtual Environment
echo ""
echo "📋 Step 3/5: Activating Python environment..."
if [ ! -d ".venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "   → Run: python -m venv .venv"
    exit 1
fi
source .venv/bin/activate
echo "✅ Virtual environment activated"

# Check 4: Dependencies
echo ""
echo "📋 Step 4/5: Checking dependencies..."
python -c "import dash, plotly, psycopg2" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed"
else
    echo "❌ Missing dependencies!"
    echo "   → Run: pip install -r requirements.txt"
    exit 1
fi

# Check 5: Database Schema
echo ""
echo "📋 Step 5/5: Verifying database schema..."
python -c "from Autobot.VectorDB.NullPoint_Vector import connect_db; conn = connect_db(); print('✅ Database connection successful')" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Database connection failed!"
    echo "   → Check Docker logs: docker logs nullpoint-postgres"
    exit 1
fi

echo ""
echo "="*70
echo "✅ ALL CHECKS PASSED!"
echo "="*70
echo ""
echo "🚀 Starting services..."
echo ""
echo "📍 Terminal 1 (Background Worker):"
echo "   python Autobot/yahoo_stream_monitor.py"
echo ""
echo "📍 Terminal 2 (Dashboard):"
echo "   python ui/dash_app.py"
echo ""
echo "📍 Browser:"
echo "   http://localhost:8050"
echo ""
echo "="*70

# Ask user which service to start
echo ""
echo "Which service do you want to start?"
echo "1) Background Worker"
echo "2) Dashboard"
echo "3) Both (split terminal required)"
echo "4) Exit"
read -p "Choice [1-4]: " choice

case $choice in
    1)
        echo "Starting Background Worker..."
        python Autobot/yahoo_stream_monitor.py
        ;;
    2)
        echo "Starting Dashboard..."
        python ui/dash_app.py
        ;;
    3)
        echo "Starting both services..."
        echo "Background Worker running in background..."
        python Autobot/yahoo_stream_monitor.py > logs/background_worker.log 2>&1 &
        WORKER_PID=$!
        echo "PID: $WORKER_PID"
        sleep 2
        echo "Starting Dashboard..."
        python ui/dash_app.py
        ;;
    4)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid choice. Exiting..."
        exit 1
        ;;
esac
