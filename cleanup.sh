#!/bin/sh
set -e

# cleanup.sh - Deletes old backup files based on a retention policy.

# Default to 7 days if RETAIN_DAYS is not set, empty, or zero.
RETAIN_DAYS=${RETAIN_DAYS:-7}

# Default backup directory, consistent with run.py
BACKUP_DIR=${BACKUP_DIR:-/app/backups}

# A value of 0 or a non-integer means "keep forever".
if ! echo "$RETAIN_DAYS" | grep -qE '^[1-9][0-9]*$'; then
  echo "INFO: RETAIN_DAYS is set to '$RETAIN_DAYS'. Skipping cleanup."
  exit 0
fi

# Validate upper bound to prevent issues with large values
if [ "$RETAIN_DAYS" -gt 3650 ]; then
  echo "ERROR: RETAIN_DAYS must be between 1 and 3650 (10 years)"
  exit 1
fi

echo "INFO: Starting cleanup of backups older than $RETAIN_DAYS days in $BACKUP_DIR..."

# Use find to delete files with security improvements:
# -maxdepth 1: prevent recursive traversal (defense against symlink attacks)
# -xdev: don't cross filesystem boundaries
# -type f: only files (not directories or symlinks)
# -name "*.enc": only encrypted backup files
# -mtime +N: files modified more than N*24 hours ago
find "$BACKUP_DIR" -maxdepth 1 -xdev -type f -name "*.enc" -mtime "+$RETAIN_DAYS" -print -delete

echo "INFO: Cleanup finished."