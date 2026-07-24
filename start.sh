#!/bin/bash
set -e

echo "🚀 Starting Yahoo_Phish IDPS..."

# Initialize database schema FIRST (before starting services).
# PgBouncer/Postgres may still be coming up, so retry with backoff instead of a
# single best-effort attempt. `if cmd` does not trip `set -e` on failure.
echo "🛠️  Ensuring database schema exists (waiting for DB via PgBouncer)..."
SCHEMA_READY=false
for i in $(seq 1 30); do
  if python Autobot/VectorDB/NullPoint_Vector.py --init-db; then
    echo "✅ Schema ready."
    SCHEMA_READY=true
    break
  fi
  echo "⏳ DB not ready (attempt ${i}/30); retrying in 2s..."
  sleep 2
done
if [ "${SCHEMA_READY}" != "true" ]; then
  echo "⚠️  Schema init did not confirm after retries; starting services anyway."
fi

# API: gunicorn + uvicorn workers in production (USE_GUNICORN=true, default).
# Each worker loads ML models once at fork — memory × workers, but parallel CPU.
API_WORKERS="${API_WORKERS:-2}"
if [ "${USE_GUNICORN:-true}" = "true" ] && command -v gunicorn >/dev/null 2>&1; then
  echo "📡 Starting FastAPI (gunicorn, ${API_WORKERS} workers)..."
  gunicorn api.main:app \
    -k uvicorn.workers.UvicornWorker \
    -w "${API_WORKERS}" \
    -b 0.0.0.0:8000 \
    --timeout 120 \
    --graceful-timeout 30 \
    --access-logfile - &
else
  echo "📡 Starting FastAPI (uvicorn)..."
  uvicorn api.main:app --host 0.0.0.0 --port 8000 &
fi
API_PID=$!

echo "📧 Starting Yahoo Stream Monitor (5-min polling)..."
python Autobot/yahoo_stream_monitor.py &
MONITOR_PID=$!

echo "🎨 Starting Dash UI..."
DASH_DEBUG="${DASH_DEBUG:-false}" DASH_HOST="${DASH_HOST:-0.0.0.0}" python ui/dash_app.py &
UI_PID=$!

echo "✅ Services started!"
echo "   - Ingress: http://localhost:8088/  (proxy → UI + API)"
echo "   - API direct: http://localhost:8000/docs"
echo "   - UI direct:  http://localhost:8050"
echo "   - Workers: ${API_WORKERS:-2}  Redis: ${REDIS_URL:-disabled}"

trap "kill $API_PID $MONITOR_PID $UI_PID 2>/dev/null; exit 0" SIGTERM SIGINT
wait -n
exit $?
