#!/usr/bin/env sh
set -eu

DATA_DIR="${DATA_DIR:-/var/lib/messenger}"
SERVICE_NAME="${SERVICE_NAME:-messenger.service}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo DATA_DIR=$DATA_DIR sh deploy/ubuntu-server/reset-accounts.sh"
    exit 1
fi

if systemctl list-unit-files "$SERVICE_NAME" >/dev/null 2>&1; then
    systemctl stop "$SERVICE_NAME" || true
fi

mkdir -p "$DATA_DIR"
printf '{}\n' > "$DATA_DIR/users.json"
printf '{}\n' > "$DATA_DIR/prekey_bundles.json"
printf '{}\n' > "$DATA_DIR/offline_messages.json"

if id messenger >/dev/null 2>&1; then
    chown messenger:messenger "$DATA_DIR/users.json" "$DATA_DIR/prekey_bundles.json" "$DATA_DIR/offline_messages.json"
fi
chmod 600 "$DATA_DIR/users.json" "$DATA_DIR/prekey_bundles.json" "$DATA_DIR/offline_messages.json"

if systemctl list-unit-files "$SERVICE_NAME" >/dev/null 2>&1; then
    systemctl start "$SERVICE_NAME"
fi

echo "All accounts, prekeys, and offline messages were removed from $DATA_DIR."
