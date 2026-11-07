#!/bin/sh

# Allow custom UID/GID (PUID + PGID) at runtime
PUID=${PUID:-1000}
PGID=${PGID:-1000}

# Validate PUID and PGID are positive integers
case "$PGID" in
    ''|*[!0-9]*)
        echo "Error: PGID must be a non-negative integer" >&2
        exit 1
        ;;
esac

case "$PUID" in
    ''|*[!0-9]*)
        echo "Error: PUID must be a non-negative integer" >&2
        exit 1
        ;;
esac

if ! [ "$PGID" -le 2147483647 ] 2>/dev/null; then
    echo "Error: PGID must be between 0 and 2147483647" >&2
    exit 1
fi

if ! [ "$PUID" -le 2147483647 ] 2>/dev/null; then
    echo "Error: PUID must be between 0 and 2147483647" >&2
    exit 1
fi

CURRENT_PGID=$(id -g appuser 2>/dev/null || echo "")
CURRENT_PUID=$(id -u appuser 2>/dev/null || echo "")

# Modify user/group if PUID or PGID differs from current appuser
if [ "$CURRENT_PGID" != "$PGID" ] || [ "$CURRENT_PUID" != "$PUID" ]; then
    if [ -z "$CURRENT_PGID" ]; then
        echo "Creating appuser with UID $PUID and PGID $PGID"
    else
        if [ "$CURRENT_PGID" != "$PGID" ]; then
            echo "Changing appuser group to PGID $PGID"
        fi
        if [ "$CURRENT_PUID" != "$PUID" ]; then
            echo "Changing appuser UID to $PUID"
        fi
    fi

    # Determine or create group for PGID
    GROUP_NAME=$(getent group "$PGID" | head -n1 | cut -d: -f1)
    if [ -z "$GROUP_NAME" ]; then
        # Group with this GID does not exist; create it.
        # If appgroup already exists with another GID, remove appuser and appgroup first.
        deluser appuser >/dev/null 2>&1 || true
        delgroup appgroup >/dev/null 2>&1 || true
        if ! addgroup -g "$PGID" appgroup; then
            echo "Error: Failed to create group appgroup with GID $PGID" >&2
            exit 1
        fi
        GROUP_NAME="appgroup"
    fi

    # Determine if PUID belongs to an existing system user (e.g. root for PUID=0)
    EXISTING_USER=$(getent passwd "$PUID" | head -n1 | cut -d: -f1)
    if [ -z "$EXISTING_USER" ] || [ "$EXISTING_USER" = "appuser" ]; then
        # Recreate appuser with target PUID and GROUP_NAME
        deluser appuser >/dev/null 2>&1 || true
        if ! adduser -S -u "$PUID" -G "$GROUP_NAME" appuser 2>&1; then
            echo "Error: Failed to create user appuser with UID $PUID" >&2
            exit 1
        fi
    fi
fi

# Ensure permissions on mounted volumes and configuration directories
chown -R "$PUID":"$PGID" /app
[ -d /home/appuser ] && chown -R "$PUID":"$PGID" /home/appuser
[ -d /.config ] && chown -R "$PUID":"$PGID" /.config

# Execute the actual application
exec su-exec "$PUID":"$PGID" "$@"
