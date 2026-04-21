#!/bin/sh

# Allow custom UID/GID (PUID + PGID) at runtime
PUID=${PUID:-1000}
PGID=${PGID:-1000}

# Modify group if PGID provided
if [ "$(id -g appuser)" != "$PGID" ]; then
    echo "Changing appuser group to PGID $PGID"
    delgroup appuser >/dev/null 2>&1 || true
    addgroup -g "$PGID" appgroup 2>/dev/null || true
    addgroup appuser appgroup 2>/dev/null || true
fi

# Modify user if PUID provided
if [ "$(id -u appuser)" != "$PUID" ]; then
    echo "Changing appuser UID to $PUID"
    deluser appuser >/dev/null 2>&1 || true
    adduser -S -u "$PUID" -G appgroup appuser
fi

# Ensure permissions on mounted volumes
chown -R "$PUID":"$PGID" /app

# Execute the actual application
exec su-exec "$PUID":"$PGID" "$@"
