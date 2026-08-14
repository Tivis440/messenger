#!/usr/bin/env sh
set -eu

DATA_DIR="${DATA_DIR:-/var/lib/messenger}"
SERVICE_NAME="${SERVICE_NAME:-messenger.service}"
DB_NAME="${DB_NAME:-messenger}"
DB_USER="${DB_USER:-messenger}"
DB_PASSWORD_FILE="${DB_PASSWORD_FILE:-$DATA_DIR/postgres_password}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo DATA_DIR=$DATA_DIR sh deploy/ubuntu-server/reset-accounts.sh"
    exit 1
fi

if [ ! -f "$DB_PASSWORD_FILE" ]; then
    echo "PostgreSQL password file not found: $DB_PASSWORD_FILE"
    exit 1
fi

if systemctl list-unit-files "$SERVICE_NAME" >/dev/null 2>&1; then
    systemctl stop "$SERVICE_NAME" || true
fi

DB_PASSWORD="$(cat "$DB_PASSWORD_FILE")"
export PGPASSWORD="$DB_PASSWORD"
psql "postgresql://$DB_USER@127.0.0.1:5432/$DB_NAME" -v ON_ERROR_STOP=1 <<SQL
TRUNCATE TABLE offline_messages, prekey_bundles, users RESTART IDENTITY CASCADE;
SQL
unset PGPASSWORD

if systemctl list-unit-files "$SERVICE_NAME" >/dev/null 2>&1; then
    systemctl start "$SERVICE_NAME"
fi

echo "All accounts, prekeys, and offline messages were removed from PostgreSQL database $DB_NAME."
