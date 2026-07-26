#!/usr/bin/env sh
set -eu

APP_DIR="${APP_DIR:-/opt/messenger}"
DATA_DIR="${DATA_DIR:-/var/lib/messenger}"
PORT="${PORT:-5555}"

exec "$APP_DIR/server/server" --port "$PORT" --data-dir "$DATA_DIR"
