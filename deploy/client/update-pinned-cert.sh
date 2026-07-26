#!/usr/bin/env sh
set -eu

CERT_FILE=""
SSH_TARGET=""
REMOTE_DATA_DIR="${REMOTE_DATA_DIR:-/var/lib/messenger}"
CLIENT_SOURCE="${CLIENT_SOURCE:-untitled/mainwindow.cpp}"

usage() {
    cat <<EOF
Usage:
  sh deploy/client/update-pinned-cert.sh --cert /path/to/tls_server.crt
  sh deploy/client/update-pinned-cert.sh --ssh user@server [--remote-data-dir /var/lib/messenger]

The script computes the server certificate SHA-256 fingerprint and updates the client pin in:
  $CLIENT_SOURCE
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --cert)
            CERT_FILE="${2:-}"
            shift 2
            ;;
        --ssh)
            SSH_TARGET="${2:-}"
            shift 2
            ;;
        --remote-data-dir)
            REMOTE_DATA_DIR="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

if [ -n "$CERT_FILE" ] && [ -n "$SSH_TARGET" ]; then
    echo "Use either --cert or --ssh, not both."
    exit 1
fi

if [ -n "$SSH_TARGET" ]; then
    TMP_CERT="$(mktemp /tmp/messenger-tls-cert.XXXXXX)"
    trap 'rm -f "$TMP_CERT"' EXIT
    scp "$SSH_TARGET:$REMOTE_DATA_DIR/tls_server.crt" "$TMP_CERT"
    CERT_FILE="$TMP_CERT"
fi

if [ -z "$CERT_FILE" ]; then
    usage
    exit 1
fi

if [ ! -f "$CERT_FILE" ]; then
    echo "Certificate not found: $CERT_FILE"
    exit 1
fi

if [ ! -f "$CLIENT_SOURCE" ]; then
    echo "Client source not found: $CLIENT_SOURCE"
    exit 1
fi

FINGERPRINT="$(openssl x509 -in "$CERT_FILE" -outform der | openssl dgst -sha256 -hex | awk '{print toupper($NF)}')"

if ! printf '%s' "$FINGERPRINT" | grep -Eq '^[0-9A-F]{64}$'; then
    echo "Could not compute certificate fingerprint."
    exit 1
fi

perl -0pi -e 's/QByteArray::fromHex\("[0-9A-Fa-f]{64}"\)/QByteArray::fromHex("'"$FINGERPRINT"'")/' "$CLIENT_SOURCE"

echo "Updated client pinned certificate fingerprint:"
echo "$FINGERPRINT"
