#!/usr/bin/env sh
set -eu

APP_DIR="${APP_DIR:-/opt/messenger}"
DATA_DIR="${DATA_DIR:-/var/lib/messenger}"
PORT="${PORT:-5555}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo APP_DIR=$APP_DIR DATA_DIR=$DATA_DIR PORT=$PORT sh deploy/ubuntu-server/install.sh"
    exit 1
fi

apt-get update
apt-get install -y build-essential qt6-base-dev libargon2-dev openssl pkg-config

mkdir -p "$APP_DIR" "$DATA_DIR"
cp -R protocol.h server "$APP_DIR/"

cd "$APP_DIR/server"
qmake6 server.pro
make -j"$(nproc)"

[ -f "$DATA_DIR/users.json" ] || cp -f "$APP_DIR/server/data/users.json" "$DATA_DIR/users.json" 2>/dev/null || printf '{}\n' > "$DATA_DIR/users.json"
[ -f "$DATA_DIR/prekey_bundles.json" ] || cp -f "$APP_DIR/server/data/prekey_bundles.json" "$DATA_DIR/prekey_bundles.json" 2>/dev/null || printf '{}\n' > "$DATA_DIR/prekey_bundles.json"
[ -f "$DATA_DIR/offline_messages.json" ] || cp -f "$APP_DIR/server/data/offline_messages.json" "$DATA_DIR/offline_messages.json" 2>/dev/null || printf '{}\n' > "$DATA_DIR/offline_messages.json"

if [ ! -f "$DATA_DIR/tls_server.crt" ] || [ ! -f "$DATA_DIR/tls_server.key" ]; then
    if [ -f "$APP_DIR/server/data/tls_server.crt" ] && [ -f "$APP_DIR/server/data/tls_server.key" ]; then
        cp -f "$APP_DIR/server/data/tls_server.crt" "$DATA_DIR/tls_server.crt"
        cp -f "$APP_DIR/server/data/tls_server.key" "$DATA_DIR/tls_server.key"
    else
        openssl req -x509 -newkey rsa:4096 -nodes \
            -keyout "$DATA_DIR/tls_server.key" \
            -out "$DATA_DIR/tls_server.crt" \
            -days 365 \
            -subj "/CN=messenger.local"
    fi
fi

chmod 600 "$DATA_DIR/tls_server.key"
chmod 600 "$DATA_DIR"/*.json

FINGERPRINT="$(openssl x509 -in "$DATA_DIR/tls_server.crt" -outform der | openssl dgst -sha256 -hex | awk '{print toupper($NF)}')"
printf '%s\n' "$FINGERPRINT" > "$DATA_DIR/tls_server.sha256"
chmod 644 "$DATA_DIR/tls_server.crt" "$DATA_DIR/tls_server.sha256"

echo "Server built: $APP_DIR/server/server"
echo "Run: $APP_DIR/server/server --port $PORT --data-dir $DATA_DIR"
echo "Certificate fingerprint for client pinning:"
echo "$FINGERPRINT"
echo "Fingerprint file: $DATA_DIR/tls_server.sha256"
