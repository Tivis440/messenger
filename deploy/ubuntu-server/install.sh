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

if ! id messenger >/dev/null 2>&1; then
    useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin messenger
fi

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

FINGERPRINT="$(openssl x509 -in "$DATA_DIR/tls_server.crt" -outform der | openssl dgst -sha256 -hex | awk '{print toupper($NF)}')"
printf '%s\n' "$FINGERPRINT" > "$DATA_DIR/tls_server.sha256"
chown -R messenger:messenger "$DATA_DIR"
chmod 700 "$DATA_DIR"
chmod 600 "$DATA_DIR/tls_server.key"
chmod 600 "$DATA_DIR"/*.json
chmod 644 "$DATA_DIR/tls_server.crt" "$DATA_DIR/tls_server.sha256"

cat > /etc/systemd/system/messenger.service <<EOF
[Unit]
Description=Messenger TLS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR/server
ExecStart=$APP_DIR/server/server --port $PORT --data-dir $DATA_DIR
Restart=on-failure
RestartSec=3
User=messenger
Group=messenger
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now messenger.service

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow "$PORT/tcp"
fi

echo "Server built: $APP_DIR/server/server"
echo "Service: messenger.service"
echo "Status: systemctl status messenger.service --no-pager"
echo "Certificate fingerprint for client pinning:"
echo "$FINGERPRINT"
echo "Fingerprint file: $DATA_DIR/tls_server.sha256"
