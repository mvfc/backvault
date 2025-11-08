#!/bin/bash
set -euo pipefail

echo "Initializing container and setting up cron job"

# Validate BACKUP_INTERVAL_HOURS
BACKUP_INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
if ! [[ "$BACKUP_INTERVAL_HOURS" =~ ^[1-9][0-9]*$ ]] || [ "$BACKUP_INTERVAL_HOURS" -gt 8760 ]; then
    echo "ERROR: BACKUP_INTERVAL_HOURS must be a positive integer between 1 and 8760 (1 year)"
    exit 1
fi

# Validate CRON_EXPRESSION if provided, otherwise use interval
if [ -n "${CRON_EXPRESSION:-}" ]; then
    # Validate cron expression format (5 fields, allowed characters)
    if ! echo "$CRON_EXPRESSION" | grep -qE '^[0-9*/,-]+[[:space:]]+[0-9*/,-]+[[:space:]]+[0-9*/,-]+[[:space:]]+[0-9*/,-]+[[:space:]]+[0-9*/,-]+$'; then
        echo "ERROR: Invalid CRON_EXPRESSION format. Must be 5 space-separated fields with allowed characters: 0-9 * / , -"
        exit 1
    fi
    # Additional check for field ranges (basic validation)
    if ! echo "$CRON_EXPRESSION" | grep -qE '^([0-9*,/-]+\s+){4}[0-9*,/-]+$'; then
        echo "ERROR: CRON_EXPRESSION contains invalid characters"
        exit 1
    fi
else
    CRON_EXPRESSION="0 */$BACKUP_INTERVAL_HOURS * * *"
fi

# Create wrapper script using printf with proper quoting to avoid command injection
# Whitelist only necessary environment variables
{
    echo '#!/bin/bash'
    echo 'set -euo pipefail'
    echo 'export PATH="/usr/local/bin:$PATH"'

    # Whitelist of allowed environment variables
    for var in BW_CLIENT_ID BW_CLIENT_SECRET BW_PASSWORD BW_SERVER BW_FILE_PASSWORD \
               BACKUP_DIR BACKUP_ENCRYPTION_MODE RETAIN_DAYS LOG_FILE \
               NODE_TLS_REJECT_UNAUTHORIZED; do
        # Use printf %q for safe shell quoting
        if [ -n "${!var:-}" ]; then
            printf 'export %s=%q\n' "$var" "${!var}"
        fi
    done

    echo '/usr/local/bin/python /app/run.py 2>&1 | tee -a /var/log/cron.log > /proc/1/fd/1'
} > /app/run_wrapper.sh

# Set restrictive permissions (owner read/write/execute only)
chmod 700 /app/run_wrapper.sh

# Use printf to safely create crontab (prevents interpretation of escape sequences)
{
    printf '%s /app/run_wrapper.sh\n' "$CRON_EXPRESSION"
    printf '0 0 * * * /app/cleanup.sh 2>&1 | tee -a /var/log/cron.log > /proc/1/fd/1\n'
} | crontab -

echo "Cron setup complete, starting cron on foreground."
exec cron -f
