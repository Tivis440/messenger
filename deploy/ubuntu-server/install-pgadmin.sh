#!/usr/bin/env sh
set -eu

DATA_DIR="${DATA_DIR:-/var/lib/messenger}"
PGADMIN_PORT="${PGADMIN_PORT:-5050}"
PGADMIN_EMAIL="${PGADMIN_EMAIL:-admin@messenger.local}"
PGADMIN_PASSWORD_FILE="${PGADMIN_PASSWORD_FILE:-$DATA_DIR/pgadmin_password}"
CONTAINER_NAME="${CONTAINER_NAME:-messenger-pgadmin}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo sh deploy/ubuntu-server/install-pgadmin.sh"
    exit 1
fi

apt-get update
apt-get install -y docker.io openssl
systemctl enable --now docker

mkdir -p "$DATA_DIR"
if [ -n "${PGADMIN_PASSWORD:-}" ]; then
    printf '%s\n' "$PGADMIN_PASSWORD" > "$PGADMIN_PASSWORD_FILE"
elif [ -f "$PGADMIN_PASSWORD_FILE" ]; then
    PGADMIN_PASSWORD="$(cat "$PGADMIN_PASSWORD_FILE")"
else
    PGADMIN_PASSWORD="$(openssl rand -base64 24 | tr -d '\n')"
    printf '%s\n' "$PGADMIN_PASSWORD" > "$PGADMIN_PASSWORD_FILE"
fi
chmod 600 "$PGADMIN_PASSWORD_FILE"

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    --network host \
    -e "PGADMIN_DEFAULT_EMAIL=$PGADMIN_EMAIL" \
    -e "PGADMIN_DEFAULT_PASSWORD=$PGADMIN_PASSWORD" \
    -e "PGADMIN_LISTEN_ADDRESS=127.0.0.1" \
    -e "PGADMIN_LISTEN_PORT=$PGADMIN_PORT" \
    dpage/pgadmin4:latest

echo "pgAdmin is running on server localhost:$PGADMIN_PORT"
echo "Open it through an SSH tunnel:"
echo "  ssh -L $PGADMIN_PORT:127.0.0.1:$PGADMIN_PORT root@144.31.113.35"
echo "Then open: http://127.0.0.1:$PGADMIN_PORT"
echo "Login: $PGADMIN_EMAIL"
echo "Password file: $PGADMIN_PASSWORD_FILE"
