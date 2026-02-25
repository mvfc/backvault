#!/bin/bash
set -euo pipefail

# If no arguments are passed, start the service. Otherwise, execute the arguments.
if [ $# -eq 0 ]; then
    echo "Initializing Backvault container..."
    INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
    if [ -z "${CRON_EXPRESSION:-}" ]; then
        if ! [[ "$INTERVAL_HOURS" =~ ^[1-9][0-9]*$ ]]; then
            echo "BACKUP_INTERVAL_HOURS must be a positive integer." >&2
            exit 1
        fi

        if (( INTERVAL_HOURS <= 23 )); then
            CRON_EXPRESSION="0 */${INTERVAL_HOURS} * * *"
        elif (( INTERVAL_HOURS % 24 == 0 )) && (( INTERVAL_HOURS / 24 <= 31 )); then
            CRON_EXPRESSION="0 0 */$((INTERVAL_HOURS / 24)) * *"
        else
            echo "INTERVAL_HOURS=${INTERVAL_HOURS} cannot be represented exactly with cron. Set CRON_EXPRESSION explicitly." >&2
            exit 1
        fi
    fi
    UI_HOST="${SETUP_UI_HOST:-0.0.0.0}"
    UI_PORT="${SETUP_UI_PORT:-8080}"
    DB_FILE="/app/db/backvault.db"

    # Prepare wrapper that runs backup
    cat > /app/run_wrapper.sh <<EOF
#!/bin/bash
set -euo pipefail
export PATH="/usr/local/bin:\$PATH"
$(printenv | grep -E 'BW_|BACKUP_' | sed 's/^/export /')
/usr/local/bin/python /app/src/run.py 2>&1 | tee -a /app/logs/cron.log
EOF

    chmod +x /app/run_wrapper.sh
# Cleanup pre-existing crontab
    rm -f /app/crontab
    # Create supercronic schedule file
    cat > /app/crontab <<EOF
# Backvault scheduled backup
$CRON_EXPRESSION /app/run_wrapper.sh
# Cleanup job every midnight
0 0 * * * /app/cleanup.sh 2>&1 | tee -a /app/logs/cron.log
EOF

    if [ ! -f "${DB_FILE}" ]; then
      echo "Secure DB not found; starting one-time setup UI at http://${UI_HOST}:${UI_PORT}"
      cd /app/src
      uvicorn init:app --host "${UI_HOST}" --port "${UI_PORT}" &
      UI_PID=$!
      # Wait for the DB to be created before continuing
      while [ ! -f "${DB_FILE}" ]; do
        sleep 3
      done

      sleep 1
      # Give some time for UI to gracefully shutdown

      echo "Setup complete detected, stopping UI..."
      kill ${UI_PID} || true
      sleep 1
      cd /app
    fi

    BACKUP_DIR=${BACKUP_DIR:-"/app/backups"}
    if [ -d "$BACKUP_DIR" ] && [ "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
        echo "Found existing backups in $BACKUP_DIR, skipping initial backup."
    else
        echo "Running initial backup..."
        ./run_wrapper.sh
    fi

    echo "Starting supercronic scheduler..."
    exec /usr/local/bin/supercronic /app/crontab
else
    case "$1" in
        bw)
            exec "$@"
            ;;
        *)
            echo "Error: Unknown or disallowed command: $1"
            echo "Allowed commands: bw, uvicorn, supercronic, bash, sh"
            exit 1
            ;;
    esac
fi
