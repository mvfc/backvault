#!/bin/sh

# Allow custom UID/GID (PUID + PGID) at runtime
PUID=${PUID:-1000}
PGID=${PGID:-1000}

# Modify group if PGID provided
if [ "$(id -g appuser)" != "$PGID" ]; then
    echo "Changing appuser group to PGID $PGID"
    delgroup appuser >/dev/null 2>&1 || true
    if ! addgroup -g "$PGID" appgroup 2>&1; then
        echo "Error: Failed to create group appgroup with GID $PGID" >&2
        exit 1
    fi
    if ! addgroup appuser appgroup 2>&1; then
        echo "Error: Failed to add user appuser to group appgroup" >&2
        exit 1
    fi
fi

# Modify user if PUID provided
if [ "$(id -u appuser)" != "$PUID" ]; then
    echo "Changing appuser UID to $PUID"
    deluser appuser >/dev/null 2>&1 || true
    if ! adduser -S -u "$PUID" -G appgroup appuser 2>&1; then
        echo "Error: Failed to create user appuser with UID $PUID" >&2
        exit 1
    fi
fi

# Ensure permissions on mounted volumes
chown -R "$PUID":"$PGID" /app

# Execute the actual application
exec su-exec "$PUID":"$PGID" "$@"
