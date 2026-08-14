# Ubuntu server deploy

This folder contains helper files for running the server on Ubuntu.

## Install

From the project root:

```sh
sudo sh deploy/ubuntu-server/install.sh
```

The script installs PostgreSQL, creates the `messenger` database/user, builds the Qt server, creates the data directory for TLS files, generates a development TLS certificate if one is missing, installs `messenger.service`, and starts it.
At the end it prints the certificate SHA-256 fingerprint and writes it to `/var/lib/messenger/tls_server.sha256`.
The client uses trust on first use: on the first connection it stores the server certificate fingerprint automatically, then blocks unexpected certificate changes.
Server data is stored in PostgreSQL. The data directory is used for TLS files and local service secrets.

Default paths:

- app: `/opt/messenger`
- data: `/var/lib/messenger`
- port: `5555`
- database: `messenger`
- database user: `messenger`

Override them when needed:

```sh
sudo APP_DIR=/opt/messenger DATA_DIR=/var/lib/messenger PORT=5555 DB_NAME=messenger DB_USER=messenger sh deploy/ubuntu-server/install.sh
```

The generated PostgreSQL password is stored in `/var/lib/messenger/postgres_password` and injected into systemd through `MESSENGER_DATABASE_URL`.

## Check systemd

```sh
sudo systemctl status messenger.service --no-pager
sudo journalctl -u messenger.service -n 80 --no-pager
```

The installer opens TCP port `5555` automatically when `ufw` is active. If the VPS provider has a separate firewall panel, allow TCP `5555` there too. The clients are pinned to the production server endpoint.

## Reset accounts

```sh
sudo sh deploy/ubuntu-server/reset-accounts.sh
```

This truncates the PostgreSQL tables `offline_messages`, `prekey_bundles`, and `users`.

## Optional pgAdmin panel

For visual database inspection:

```sh
sudo sh deploy/ubuntu-server/install-pgadmin.sh
```

The panel is bound to `127.0.0.1:5050` on the server and is not exposed publicly. Open it through an SSH tunnel:

```sh
ssh -L 5050:127.0.0.1:5050 root@144.31.113.35
```

Then open `http://127.0.0.1:5050` locally.

Default pgAdmin login:

- email: `admin@messenger.local`
- password file on server: `/var/lib/messenger/pgadmin_password`

Add PostgreSQL server inside pgAdmin:

- host: `127.0.0.1`
- port: `5432`
- database: `messenger`
- username: `messenger`
- password file on server: `/var/lib/messenger/postgres_password`

## Run manually

```sh
sudo sh deploy/ubuntu-server/run.sh
```

After changing the TLS certificate, reset the saved server certificate in the client menu: `Справка -> Сбросить сертификат сервера`.
