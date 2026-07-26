# Ubuntu server deploy

This folder contains helper files for running the server on Ubuntu.

## Install

From the project root:

```sh
sudo sh deploy/ubuntu-server/install.sh
```

The script builds the Qt server, creates an empty data directory, and generates a development TLS certificate if one is missing.
At the end it prints the certificate SHA-256 fingerprint and writes it to `/var/lib/messenger/tls_server.sha256`.
The client uses trust on first use: on the first connection it stores the server certificate fingerprint automatically, then blocks unexpected certificate changes.

Default paths:

- app: `/opt/messenger`
- data: `/var/lib/messenger`
- port: `5555`

Override them when needed:

```sh
sudo APP_DIR=/opt/messenger DATA_DIR=/var/lib/messenger PORT=5555 sh deploy/ubuntu-server/install.sh
```

## Run manually

```sh
sudo sh deploy/ubuntu-server/run.sh
```

## Run through systemd

```sh
sudo cp deploy/ubuntu-server/messenger.service.example /etc/systemd/system/messenger.service
sudo systemctl daemon-reload
sudo systemctl enable --now messenger
```

Open TCP port `5555` on the Ubuntu firewall/router. The clients should use the server IP or DNS name in the login window.

After changing the TLS certificate, reset the saved server certificate in the client menu: `Справка -> Сбросить сертификат сервера`.
