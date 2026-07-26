# Мессенджер

Qt/C++ мессенджер с TLS-транспортом, локальной книгой контактов, офлайн-сообщениями и экспериментальной интеграцией `libsignal-protocol-c`.

## Быстрый запуск сервера на Ubuntu

```bash
sudo apt update
sudo apt install -y git
git clone <REPO_URL> messenger
cd messenger
sudo sh deploy/ubuntu-server/install.sh
sudo sh deploy/ubuntu-server/run.sh
```

По умолчанию сервер ставится в `/opt/messenger`, данные хранятся в `/var/lib/messenger`, порт `5555`.

Для запуска как сервис:

```bash
sudo useradd --system --home /var/lib/messenger --shell /usr/sbin/nologin messenger
sudo chown -R messenger:messenger /var/lib/messenger
sudo cp deploy/ubuntu-server/messenger.service.example /etc/systemd/system/messenger.service
sudo systemctl daemon-reload
sudo systemctl enable --now messenger
```

## Клиент

macOS-клиент собирается в `messenger.app`, Windows-клиент в `messenger.exe`.
Подробности сборки лежат в `BUILD_RELEASE.md`.

## Важно про TLS

Сертификат сервера не коммитится в git. При установке на Ubuntu `install.sh` создаст новый dev-сертификат, если его нет.
После замены сертификата нужно обновить pinned SHA-256 fingerprint в клиенте перед сборкой клиента.
