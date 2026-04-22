#!/bin/sh

# Allow custom UID/GID (PUID + PGID) at runtime
PUID=${PUID:-1000}
PGID=${PGID:-1000}

# Modify group if PGID provided
if [ "$(id -g appuser)" != "$PGID" ]; then
    echo "Changing appuser group to PGID $PGID"
    delgroup appuser >/dev/null 2>&1 || true
    if getent group appgroup >/dev/null 2>&1; then
        current_gid=$(getent group appgroup | cut -d: -f3)
        if [ "$current_gid" != "$PGID" ]; then
            echo "Warning: appgroup exists with GID $current_gid, using existing group"
        fi
    else
        addgroup -g "$PGID" appgroup
    fi
    addgroup appuser appgroup 2>/dev/null || true
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
