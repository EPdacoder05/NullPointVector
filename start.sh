#!/bin/bash
set -e

echo "🚀 Starting Yahoo_Phish IDPS..."

# Start FastAPI in background
echo "📡 Starting FastAPI API server..."
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload &
API_PID=$!

# Start Dash UI
echo "🎨 Starting Dash UI..."
python ui/dash_app.py &
UI_PID=$!

# Wait for both processes
echo "✅ Services started!"
echo "   - API: http://localhost:8000/docs"
echo "   - UI:  http://localhost:8050"

# Trap SIGTERM and SIGINT to cleanly shutdown
trap "kill $API_PID $UI_PID 2>/dev/null; exit 0" SIGTERM SIGINT

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?
