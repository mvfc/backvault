#!/bin/bash
set -euo pipefail

echo "Initializing Backvault container..."
BACKUP_INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
CRON_EXPRESSION=${CRON_EXPRESSION:-"0 */$BACKUP_INTERVAL_HOURS * * *"}

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

echo "Running initial backup..."
/usr/local/bin/python /app/run.py 2>&1 | tee -a /app/logs/cron.log

echo "Starting supercronic scheduler..."
exec /usr/local/bin/supercronic /app/crontab
