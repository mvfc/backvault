#!/bin/bash
set -euo pipefail

echo "Initializing Backvault container..."
BACKUP_INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
CRON_EXPRESSION=${CRON_EXPRESSION:-"0 */$BACKUP_INTERVAL_HOURS * * *"}
UI_HOST="${SETUP_UI_HOST:-0.0.0.0}"
UI_PORT="${SETUP_UI_PORT:-8080}"
DB_FILE="/app/db/backvault.db"

# Prepare wrapper that runs backup
cat > /app/run_wrapper.sh <<EOF
#!/bin/bash
set -euo pipefail
export PATH="/usr/local/bin:\$PATH"
$(printenv | grep -E 'BW_|BACKUP_' | sed 's/^/export /')
/usr/local/bin/python /app/run.py 2>&1 | tee -a /app/logs/cron.log
EOF

chmod +x /app/run_wrapper.sh

# Create supercronic schedule file
cat > /app/crontab <<EOF
# Backvault scheduled backup
$CRON_EXPRESSION /app/run_wrapper.sh
# Cleanup job every midnight
0 0 * * * /app/cleanup.sh 2>&1 | tee -a /app/logs/cron.log
EOF

if [ ! -f "${DB_FILE}" ]; then
  echo "Secure DB not found; starting one-time setup UI at http://${UI_HOST}:${UI_PORT}"
  uvicorn init:app --host "${UI_HOST}" --port "${UI_PORT}" &
  UI_PID=$!

  # Wait for the DB to be created before continuing
  while [ ! -f "${DB_FILE}" ]; do
    sleep 3
  done

  echo "Setup complete detected, stopping UI..."
  kill ${UI_PID} || true
  sleep 1
fi

echo "Running initial backup..."

/usr/local/bin/python /app/run.py 2>&1 | tee -a /app/logs/cron.log

echo "Starting supercronic scheduler..."
exec /usr/local/bin/supercronic /app/crontab
