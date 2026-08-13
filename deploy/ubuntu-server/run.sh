#!/usr/bin/env sh
set -eu

APP_DIR="${APP_DIR:-/opt/messenger}"
DATA_DIR="${DATA_DIR:-/var/lib/messenger}"
PORT="${PORT:-5555}"
DB_NAME="${DB_NAME:-messenger}"
DB_USER="${DB_USER:-messenger}"
DB_PASSWORD_FILE="${DB_PASSWORD_FILE:-$DATA_DIR/postgres_password}"

if [ -z "${MESSENGER_DATABASE_URL:-}" ] && [ -f "$DB_PASSWORD_FILE" ]; then
    DB_PASSWORD="$(cat "$DB_PASSWORD_FILE")"
    export MESSENGER_DATABASE_URL="postgres://$DB_USER:$DB_PASSWORD@127.0.0.1:5432/$DB_NAME"
fi

exec "$APP_DIR/server/server" --port "$PORT" --data-dir "$DATA_DIR"
