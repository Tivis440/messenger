#!/usr/bin/env sh
set -eu

APP_DIR="${APP_DIR:-/opt/messenger}"
DATA_DIR="${DATA_DIR:-/var/lib/messenger}"
PORT="${PORT:-5555}"
DB_NAME="${DB_NAME:-messenger}"
DB_USER="${DB_USER:-messenger}"
DB_PASSWORD_FILE="${DB_PASSWORD_FILE:-$DATA_DIR/postgres_password}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo APP_DIR=$APP_DIR DATA_DIR=$DATA_DIR PORT=$PORT sh deploy/ubuntu-server/install.sh"
    exit 1
fi

apt-get update
apt-get install -y build-essential qt6-base-dev libqt6sql6-psql libargon2-dev openssl pkg-config postgresql postgresql-client

if ! id messenger >/dev/null 2>&1; then
    useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin messenger
fi

mkdir -p "$APP_DIR" "$DATA_DIR"
cp -R protocol.h server "$APP_DIR/"

if [ -n "${DB_PASSWORD:-}" ]; then
    printf '%s\n' "$DB_PASSWORD" > "$DB_PASSWORD_FILE"
elif [ -f "$DB_PASSWORD_FILE" ]; then
    DB_PASSWORD="$(cat "$DB_PASSWORD_FILE")"
else
    DB_PASSWORD="$(openssl rand -hex 24)"
    printf '%s\n' "$DB_PASSWORD" > "$DB_PASSWORD_FILE"
fi
chmod 600 "$DB_PASSWORD_FILE"

SQL_PASSWORD="$(printf "%s" "$DB_PASSWORD" | sed "s/'/''/g")"
runuser -u postgres -- psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$DB_USER') THEN
        CREATE ROLE $DB_USER LOGIN PASSWORD '$SQL_PASSWORD';
    ELSE
        ALTER ROLE $DB_USER WITH LOGIN PASSWORD '$SQL_PASSWORD';
    END IF;
END
\$\$;
SQL

if ! runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1; then
    runuser -u postgres -- createdb -O "$DB_USER" "$DB_NAME"
fi
runuser -u postgres -- psql -d "$DB_NAME" -v ON_ERROR_STOP=1 <<SQL
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
GRANT ALL ON SCHEMA public TO $DB_USER;
SQL

cd "$APP_DIR/server"
qmake6 server.pro
make -j"$(nproc)"

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
chmod 600 "$DB_PASSWORD_FILE"
chmod 644 "$DATA_DIR/tls_server.crt" "$DATA_DIR/tls_server.sha256"

cat > /etc/systemd/system/messenger.service <<EOF
[Unit]
Description=Messenger TLS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR/server
Environment=MESSENGER_DATABASE_URL=postgres://$DB_USER:$DB_PASSWORD@127.0.0.1:5432/$DB_NAME
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
ReadWritePaths=/var/run/postgresql

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
echo "PostgreSQL database: $DB_NAME"
echo "Status: systemctl status messenger.service --no-pager"
echo "Certificate fingerprint for client pinning:"
echo "$FINGERPRINT"
echo "Fingerprint file: $DATA_DIR/tls_server.sha256"
