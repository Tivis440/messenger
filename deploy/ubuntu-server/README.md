# Ubuntu server deploy

This folder contains helper files for running the server on Ubuntu.

## Install

From the project root:

```sh
sudo sh deploy/ubuntu-server/install.sh
```

The script builds the Qt server, creates an empty data directory, generates a development TLS certificate if one is missing, installs `messenger.service`, and starts it.
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

## Check systemd

```sh
sudo systemctl status messenger.service --no-pager
sudo journalctl -u messenger.service -n 80 --no-pager
```

The installer opens TCP port `5555` automatically when `ufw` is active. If the VPS provider has a separate firewall panel, allow TCP `5555` there too. The clients should use the server IP or DNS name in the login window.

## Run manually

```sh
sudo sh deploy/ubuntu-server/run.sh
```

After changing the TLS certificate, reset the saved server certificate in the client menu: `Справка -> Сбросить сертификат сервера`.
