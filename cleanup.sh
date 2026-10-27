#!/bin/sh
set -eu

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

echo "INFO: Starting cleanup of backups older than $RETAIN_DAYS days in $BACKUP_DIR..."

# Use find to delete files.
# -mtime +N means files modified more than N*24 hours ago.
# We use RETAIN_DAYS directly. For example, if RETAIN_DAYS=7, files older than 7 days will be deleted.
find "$BACKUP_DIR" -type f \( -name "*.enc" -o -name "*_attachments.7z" \) -mtime "+$RETAIN_DAYS" -print -delete -xdev -maxdepth 1

# If no .enc backup files remain, remove .complete success marker to prevent stale status
if [ -f "$BACKUP_DIR/.complete" ]; then
  has_enc=0
  for f in "$BACKUP_DIR"/*.enc; do
    if [ -e "$f" ]; then
      has_enc=1
      break
    fi
  done
  if [ "$has_enc" -eq 0 ]; then
    echo "INFO: No backup files remaining in $BACKUP_DIR; removing stale .complete marker."
    rm -f "$BACKUP_DIR/.complete"
  fi
fi

echo "INFO: Cleanup finished."