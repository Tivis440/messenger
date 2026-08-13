# Сборка и запуск проекта

Проект состоит из двух частей:

- `server` - консольный TLS relay-сервер.
- `untitled` - Qt Widgets клиент.

## Общие зависимости

- Qt 6 с модулями `Core`, `Network`, `Widgets`, `Sql`.
- OpenSSL crypto library для клиента.
- `libsignal-protocol-c` для клиента.
- `libargon2` для сервера.
- PostgreSQL и Qt PostgreSQL driver для сервера.

## Сервер: папка данных

Сервер больше не обязан хранить данные рядом с бинарником. Папку можно передать аргументом:

```bash
server --port 5555 --data-dir /path/to/server-data
```

В этом рабочем проекте уже подготовлена локальная папка:

```bash
cd server
./server --port 5555 --data-dir ./data
```

Или переменной окружения:

```bash
MESSENGER_SERVER_DATA_DIR=/path/to/server-data server
```

В этой папке должны лежать TLS-файлы:

- `tls_server.crt`
- `tls_server.key`

Серверные данные хранятся в PostgreSQL. Перед запуском нужно задать `MESSENGER_DATABASE_URL`, например:

```bash
export MESSENGER_DATABASE_URL=postgres://messenger:password@127.0.0.1:5432/messenger
```

Старые `users.json`, `prekey_bundles.json` и `offline_messages.json` из data-dir импортируются один раз, если они существуют.

## Адрес сервера в клиенте

Клиент фиксированно подключается к `144.31.113.35:5555`.
Поля выбора сервера в окне входа удалены.
Если сервер меняется, нужно обновить `FIXED_SERVER_HOST` / `FIXED_SERVER_PORT` в `untitled/mainwindow.cpp` и пересобрать клиент.

Важно: клиент проверяет TLS-сертификат по встроенному SHA-256 fingerprint. Если заменить `tls_server.crt`, нужно обновить fingerprint в клиентском коде и пересобрать приложение.

## Ubuntu Server

Готовый пакет исходников для переноса лежит здесь:

```bash
dist/ubuntu-server-package.zip
```

На Ubuntu распаковать пакет и выполнить из корня проекта:

```bash
sudo sh deploy/ubuntu-server/install.sh
sudo sh deploy/ubuntu-server/run.sh
```

Для постоянного запуска через `systemd` см. `deploy/ubuntu-server/README.md`.

Пример пакетов:

```bash
sudo apt update
sudo apt install build-essential qt6-base-dev libargon2-dev pkg-config
```

Сборка:

```bash
cd server
qmake6 server.pro
make -j"$(nproc)"
```

Запуск:

```bash
mkdir -p ./data
cp tls_server.crt tls_server.key ./data/
export MESSENGER_DATABASE_URL=postgres://messenger:password@127.0.0.1:5432/messenger
./server --port 5555 --data-dir ./data
```

## Windows Server

Установить:

- Qt 6 для MSVC или MinGW.
- `libargon2`.
- PostgreSQL client libraries and Qt SQL PostgreSQL driver.

Если Argon2 лежит не в `C:/argon2`, передать путь в qmake:

```bat
cd server
qmake server.pro "ARGON2_DIR=C:/libs/argon2"
nmake
```

Для MinGW вместо `nmake` использовать:

```bat
mingw32-make
```

Запуск:

```bat
set MESSENGER_DATABASE_URL=postgres://messenger:password@127.0.0.1:5432/messenger
server.exe --port 5555 --data-dir C:\messenger-server-data
```

## macOS клиент

Сборка:

```bash
cd untitled
/Users/kirill/Qt/6.11.1/macos/bin/qmake untitled.pro
make -j"$(sysctl -n hw.ncpu)"
```

Упаковка `.app`:

```bash
/Users/kirill/Qt/6.11.1/macos/bin/macdeployqt messenger.app
```

Для распространения дальше нужны подпись и notarization.

## Windows клиент

Готовый пакет исходников для второго пользователя лежит здесь:

```bash
dist/windows-client-package.zip
```

На Windows распаковать пакет, открыть `x64 Native Tools Command Prompt for VS` и выполнить:

```bat
deploy\windows-client\build.bat
```

Установить:

- Qt 6 для MSVC или MinGW.
- OpenSSL.
- `libsignal-protocol-c`.

Если библиотеки лежат не в стандартных папках из `.pro`, передать пути:

```bat
cd untitled
qmake untitled.pro "SIGNAL_DIR=C:/libs/signal-protocol-c" "OPENSSL_DIR=C:/libs/OpenSSL-Win64"
nmake
```

Для MinGW:

```bat
mingw32-make
```

Упаковка рядом с `.exe`:

```bat
windeployqt release\messenger.exe
```

После `windeployqt` рядом с `.exe` также нужно положить DLL от OpenSSL и `libsignal-protocol-c`, если они не находятся в системном `PATH`.
