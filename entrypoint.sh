#!/bin/bash
echo "Initializing container and setting up cron job"
BACKUP_INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
CRON_EXPRESSION=${CRON_EXPRESSION:-"* */$BACKUP_INTERVAL_HOURS * * *"}

cat > /app/run_wrapper.sh <<EOF
#!/bin/bash
export PATH="/usr/local/bin:\$PATH"
$(printenv | grep -E 'BW_|BACKUP_' | sed 's/^/export /')
/usr/local/bin/python /app/run.py 2>&1 | tee -a /var/log/cron.log > /proc/1/fd/1
EOF

chmod +x /app/run_wrapper.sh

echo "$CRON_EXPRESSION /app/run_wrapper.sh" | crontab -

echo "Cron setup complete, starting cron on foreground"
exec cron -f
