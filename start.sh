#!/bin/bash
set -Eeuo pipefail

ROLE="${1:-${PROCESS_ROLE:-web}}"

run_migrations() {
  echo "Waiting for database migration readiness..."
  for attempt in $(seq 1 30); do
    if python Autobot/VectorDB/NullPoint_Vector.py --init-db; then
      echo "Database migration completed."
      return 0
    fi
    echo "Database migration attempt ${attempt}/30 failed; retrying in 2s..."
    sleep 2
  done
  echo "Database migration failed; refusing to start an incompatible release."
  return 1
}

case "${ROLE}" in
  migrate)
    run_migrations
    ;;
  web)
    API_WORKERS="${API_WORKERS:-2}"
    if [ "${USE_GUNICORN:-true}" = "true" ] && command -v gunicorn >/dev/null 2>&1; then
      echo "Starting web process with ${API_WORKERS} worker(s)."
      exec gunicorn api.main:app \
        -k uvicorn.workers.UvicornWorker \
        -w "${API_WORKERS}" \
        -b 0.0.0.0:8000 \
        --timeout 120 \
        --graceful-timeout 30 \
        --access-logfile -
    fi
    echo "Starting single-worker web process."
    exec uvicorn api.main:app --host 0.0.0.0 --port 8000
    ;;
  monitor)
    echo "Starting mailbox monitor process."
    exec python Autobot/yahoo_stream_monitor.py
    ;;
  *)
    echo "Unknown PROCESS_ROLE '${ROLE}'. Expected web, monitor, or migrate."
    exit 2
    ;;
esac
