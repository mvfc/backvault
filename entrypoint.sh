#!/bin/bash
echo "Initializing container and setting up cron job"
BACKUP_INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
CRON_EXPRESSION=${CRON_EXPRESSION:-"0 */$BACKUP_INTERVAL_HOURS * * *"}
echo "$CRON_EXPRESSION python /app/run.py >> /var/log/cron.log 2>&1" | crontab -
echo "Cron setup complete, starting cron in foreground"
exec cron -f
