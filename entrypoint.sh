#!/bin/sh

# Allow custom UID/GID (PUID + PGID) at runtime
PUID=${PUID:-1000}
PGID=${PGID:-1000}

# Validate PUID and PGID are non-negative integers
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

# Normalize PUID and PGID to remove leading zeros
PGID=$(echo "$PGID" | sed 's/^0*\([0-9]\)/\1/')
PUID=$(echo "$PUID" | sed 's/^0*\([0-9]\)/\1/')

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
        # Group with this GID does not exist; verify it can be created before modifying existing accounts
        delgroup appgrouptmp >/dev/null 2>&1 || true
        if ! ERR=$(addgroup -g "$PGID" appgrouptmp 2>&1); then
            delgroup appgrouptmp >/dev/null 2>&1 || true
            if [ -n "$ERR" ]; then
                echo "$ERR" | sed 's/appgrouptmp/appgroup/g' >&2
            fi
            echo "Error: Failed to create group appgroup with GID $PGID" >&2
            exit 1
        fi
        delgroup appgrouptmp >/dev/null 2>&1 || true
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
    else
        # Provide writable CLI storage for existing accounts with an unsuitable home directory
        if [ -z "$BITWARDENCLI_APPDATA_DIR" ]; then
            USER_HOME=$(getent passwd "$PUID" | head -n1 | cut -d: -f6)
            if [ -z "$USER_HOME" ] || [ ! -d "$USER_HOME" ] || ! su-exec "$PUID":"$PGID" test -w "$USER_HOME" 2>/dev/null; then
                export BITWARDENCLI_APPDATA_DIR="/.config"
            fi
        fi
    fi
fi

# Ensure permissions on mounted volumes and configuration directories
chown -R "$PUID":"$PGID" /app
for d in /home/appuser /.config "$BITWARDENCLI_APPDATA_DIR"; do
    if [ -n "$d" ] && [ -d "$d" ]; then
        chown -R "$PUID":"$PGID" "$d"
    fi
done

# Execute the actual application
exec su-exec "$PUID":"$PGID" "$@"
