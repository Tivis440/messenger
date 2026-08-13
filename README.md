# Мессенджер

Современный кроссплатформенный мессенджер на Qt/C++ с обычными именами пользователей, единым поиском пользователей и диалогов, обязательным TLS-транспортом, офлайн-доставкой, статусами сообщений и экспериментальной end-to-end моделью на базе `libsignal-protocol-c`.

Проект собирается как desktop-клиент для macOS и Windows, а серверная часть разворачивается на Ubuntu/VPS или другом Linux-хосте с Qt 6.

> Важно: это инженерный pet/project-прототип с серьезной архитектурной базой, но без независимого криптографического аудита. Для реальной приватной коммуникации промышленного уровня нужны аудит, threat modeling, hardening инфраструктуры и воспроизводимые релизы.

## Что уже умеет

- Отдельное окно входа и регистрации.
- Регистрация по обычному имени пользователя.
- Единый поиск по пользователям и локальным диалогам.
- Отправка сообщений конкретному выбранному собеседнику по username, а не broadcast всем пользователям.
- Сохранение истории диалогов на клиенте.
- Offline-сообщения: сервер хранит зашифрованные blobs для пользователя не в сети.
- Статусы сообщений: отправляется, отправлено, не отправлено, прочитано.
- TLS как обязательный транспорт между клиентом и сервером.
- Pinning SHA-256 fingerprint TLS-сертификата сервера.
- Проверка срока действия TLS-сертификата.
- Argon2id для новых паролей на сервере.
- Rate limits на вход, регистрацию, сообщения и prekey-запросы.
- Серверная учетная запись привязана к читаемому username; приватность проекта фокусируется на шифровании содержимого сообщений.
- Шифрование локального Signal state через AES-256-GCM.
- macOS Keychain для ключа локального Signal state.
- Windows DPAPI для ключа локального Signal state.
- GitHub Actions сборка Windows-клиента с готовым artifact.
- Ubuntu install-скрипт, который собирает сервер, ставит `systemd`-службу и запускает ее.

## Архитектура

```text
┌──────────────────────────┐
│ macOS / Windows client   │
│ Qt Widgets + QSslSocket  │
│ Local contacts/history   │
│ Signal state storage     │
└─────────────┬────────────┘
              │
              │ TLS 1.2+
              │ pinned server certificate
              ▼
┌──────────────────────────┐
│ Ubuntu / Linux server    │
│ Qt Core + QTcpServer     │
│ Auth + rate limits       │
│ Prekey relay             │
│ Offline encrypted queue  │
└──────────────────────────┘
```

Клиент отвечает за пользовательский интерфейс, локальные контакты, историю диалогов и криптографическое состояние. Сервер выполняет роль защищенного relay: принимает TLS-подключения, аутентифицирует пользователей, хранит prekey bundles и доставляет offline-сообщения.

Сервер знает username аккаунтов и маршруты доставки сообщений. Содержимое сообщений должно оставаться защищенным клиентским шифрованием, а транспорт между клиентом и сервером всегда идет через TLS.

## Стек

| Слой | Технологии | Зачем |
| --- | --- | --- |
| Desktop UI | Qt Widgets, C++17 | Нативное приложение для macOS и Windows без браузерной оболочки |
| Сеть | `QSslSocket`, `QTcpServer`, `QDataStream` | Бинарный протокол поверх обязательного TLS |
| TLS | Qt SSL backend, OpenSSL-compatible runtime | Защищенный транспорт и pinning сертификата |
| Пароли | Argon2id, legacy migration | Более устойчивое хранение новых password records |
| E2EE-слой | `libsignal-protocol-c` | Double Ratchet/prekey primitives для защищенных диалогов |
| Локальные ключи | AES-256-GCM, macOS Keychain, Windows DPAPI | Приватные состояния не лежат на диске открытым текстом |
| Сервер | Qt Core/Network, C++17, libargon2 | Минимальный relay-сервер без GUI |
| CI/CD | GitHub Actions, MSVC, Qt 6.7.2 | Автоматическая сборка Windows artifact |
| Deploy | shell scripts, systemd | Быстрый запуск Ubuntu-сервера |

## Структура репозитория

```text
.
├── protocol.h                         # Общие типы и константы сетевого протокола
├── untitled/                           # Qt Widgets клиент
│   ├── mainwindow.*                    # Главное окно, сеть, сообщения, контакты
│   ├── authdialog.*                    # Окно входа/регистрации
│   ├── signalmanager.*                 # Signal state, prekeys, шифрование сообщений
│   ├── designtokens.*                  # Визуальные токены/стили
│   └── untitled.pro                    # qmake-проект клиента
├── server/                             # Серверная часть
│   ├── main.cpp                        # CLI entrypoint
│   ├── server.*                        # TLS server, auth, queues, limits
│   └── server.pro                      # qmake-проект сервера
├── deploy/
│   ├── ubuntu-server/                  # Установка сервера на Ubuntu
│   ├── windows-client/                 # Ручная сборка клиента на Windows
│   └── client/                         # Вспомогательные клиентские скрипты
├── .github/workflows/windows-client.yml # Windows CI сборка
├── BUILD_RELEASE.md                    # Подробные заметки по сборке
└── SECURITY_HARDENING.md               # Состояние и план безопасности
```

## Модель аккаунтов

При регистрации пользователь сам выбирает читаемое имя аккаунта:

```text
kirill
```

Имя используется для входа и поиска собеседников. Допустимы буквы, цифры и символы:

```text
_ - .
```

Примеры:

```text
alice
user.name
team_dev
```

Любое имя, которое проходит эти правила и еще не занято на сервере, можно зарегистрировать и использовать для переписки.

## Безопасность

В проекте уже реализованы несколько важных защитных слоев.

### Transport security

- Обычный TCP fallback убран.
- Клиент использует TLS через `QSslSocket`.
- Сервер принимает только TLS-сессию.
- Клиент проверяет SHA-256 fingerprint сертификата сервера.
- Клиент отклоняет просроченный или еще не действительный сертификат.
- При смене сертификата клиент блокирует соединение, пока пользователь явно не подтвердит новый fingerprint.

### Password security

- Новые пароли хранятся через Argon2id.
- Старые PBKDF2/SHA-256 записи мигрируют после успешного входа.
- Есть rate limit на логин и регистрацию.
- Логи не должны содержать пароли.

### Local key security

- Signal state хранится в зашифрованном виде.
- Формат шифрования: AES-256-GCM.
- macOS хранит ключ state encryption в Keychain.
- Windows хранит ключ через DPAPI.
- Это сохраняет кроссплатформенный формат данных и меняет только backend хранения ключа.

### Metadata model

- Сервер знает username отправителя и получателя, потому что маршрутизирует сообщения.
- Контакты и история диалогов хранятся на клиенте.
- Online-статусы и список пользователей можно развивать как обычную продуктовую функцию.
- Offline queue хранит зашифрованные blobs с TTL и лимитами.

### Что еще нужно для production-grade уровня

- Независимый аудит криптографии и протокола.
- Защита от replay на уровне протокольных сценариев.
- Перенос server storage с JSON на SQLite/PostgreSQL.
- Более строгая защита метаданных при необходимости отдельного privacy-режима.
- Reproducible builds.
- Code signing и notarization для macOS.
- Подпись Windows-бинарников.
- Политика ротации TLS pin с двумя активными fingerprint.

Подробный security backlog лежит в [SECURITY_HARDENING.md](SECURITY_HARDENING.md).

## Быстрый запуск сервера на Ubuntu

На чистом сервере:

```bash
sudo apt update
sudo apt install -y git
git clone https://github.com/Tivis440/messenger.git
cd messenger
sudo sh deploy/ubuntu-server/install.sh
```

Скрипт сделает основную работу:

- установит системные зависимости;
- создаст пользователя `messenger`;
- соберет сервер в `/opt/messenger/server/server`;
- создаст data-dir `/var/lib/messenger`;
- создаст dev TLS-сертификат, если его еще нет;
- запишет fingerprint в `/var/lib/messenger/tls_server.sha256`;
- установит и запустит `messenger.service`;
- включит автозапуск через `systemd`;
- откроет порт через `ufw`, если `ufw` активен.

Проверить состояние:

```bash
sudo systemctl status messenger.service --no-pager
sudo journalctl -u messenger.service -n 80 --no-pager
sudo ss -lntp | grep 5555
```

Очистить аккаунты, prekeys и offline-очереди на сервере:

```bash
cd messenger
git pull
sudo sh deploy/ubuntu-server/reset-accounts.sh
```

Скрипт очищает только account/message state. TLS-сертификат и ключ сервера остаются на месте.

По умолчанию:

| Параметр | Значение |
| --- | --- |
| App dir | `/opt/messenger` |
| Data dir | `/var/lib/messenger` |
| Port | `5555` |
| Service | `messenger.service` |

Если нужен другой порт или путь:

```bash
sudo APP_DIR=/opt/messenger DATA_DIR=/var/lib/messenger PORT=5555 sh deploy/ubuntu-server/install.sh
```

Если у VPS-провайдера есть отдельный firewall/security group, открой входящий TCP-порт `5555` в панели провайдера.

## Сборка Windows-клиента через GitHub Actions

Самый удобный путь - GitHub Actions.

1. Открой вкладку `Actions`.
2. Выбери workflow `Build Windows Client`.
3. Запусти `Run workflow` или просто запушь изменения в `main`.
4. После успешной сборки скачай artifact `messenger-windows`.
5. Распакуй архив и запусти `messenger.exe`.

Workflow делает все сам:

- ставит Qt `6.7.2` для MSVC;
- скачивает OpenSSL ZIP;
- проверяет SHA-256 архива OpenSSL;
- собирает `libsignal-protocol-c`;
- применяет небольшой MSVC patch для старой C-библиотеки;
- собирает `messenger.exe`;
- запускает `windeployqt`;
- упаковывает готовый runtime в ZIP.

Последний успешный artifact можно брать из актуального run в GitHub Actions.

## Ручная сборка Windows-клиента

Нужны:

- Visual Studio Build Tools с MSVC;
- Qt 6 под MSVC;
- OpenSSL x64;
- `libsignal-protocol-c`.

В `x64 Native Tools Command Prompt for VS`:

```bat
deploy\windows-client\build.bat
```

Если зависимости лежат не в стандартных местах:

```bat
cd untitled
qmake untitled.pro "SIGNAL_DIR=C:/libs/signal-protocol-c" "OPENSSL_DIR=C:/libs/OpenSSL-Win64"
nmake
windeployqt release\messenger.exe
```

## Сборка macOS-клиента

Нужны:

- Qt 6;
- OpenSSL/libcrypto;
- `libsignal-protocol-c`;
- Apple Command Line Tools.

Пример:

```bash
cd untitled
/Users/kirill/Qt/6.11.1/macos/bin/qmake untitled.pro
make -j"$(sysctl -n hw.ncpu)"
/Users/kirill/Qt/6.11.1/macos/bin/macdeployqt messenger.app
```

Для распространения за пределами локальной машины нужны подпись и notarization.

## Настройка клиента

Клиент фиксированно подключается к серверу `144.31.113.35:5555`.
В окне входа больше нет выбора адреса сервера: пользователь вводит только username и пароль.

После регистрации пользователь получает username. Его можно передать другому пользователю, чтобы тот нашел вас через поиск и начал диалог.

## Диагностика подключения

На Windows:

```powershell
Test-NetConnection 144.31.113.35 -Port 5555
```

На сервере:

```bash
sudo journalctl -u messenger.service -f
```

Частые ошибки:

| Ошибка | Что значит | Что проверить |
| --- | --- | --- |
| `Connection refused` | По адресу/порту никто не принимает TCP | Запущен ли `messenger.service`, открыт ли порт, правильный ли IP |
| `wrong version number` в server log | На TLS-порт пришел не-TLS клиент | Обычно это `nc`, браузер, порт-скан или старый клиент |
| `сертификат сервера изменился` | Fingerprint не совпал с сохраненным | Это нормально после переустановки сертификата, но требует ручного подтверждения |
| `host name did not match` | Qt CA/hostname warning для self-signed сертификата | Trust решается fingerprint pinning, hostname warning логируется отдельно |

Проверить порт с любой Unix/macOS машины:

```bash
nc -vz 144.31.113.35 5555
```

Проверить TLS:

```bash
openssl s_client -connect 144.31.113.35:5555 -tls1_2
```

## Данные сервера

Data-dir сервера содержит:

```text
/var/lib/messenger
├── users.json
├── prekey_bundles.json
├── offline_messages.json
├── tls_server.crt
├── tls_server.key
└── tls_server.sha256
```

`tls_server.key` должен быть доступен только системному пользователю сервиса. JSON-хранилища подходят для прототипа, но для длительной эксплуатации лучше перейти на SQLite/PostgreSQL.

## Roadmap

- SQLite/PostgreSQL вместо JSON storage.
- Миграции схемы базы данных.
- Более строгая offline queue: TTL jobs, per-user quotas, transactional delivery.
- Полная модель safety number с явной ручной верификацией собеседника.
- Предупреждение при смене identity key контакта.
- Sealed Sender-like envelope.
- Более приватный contact discovery.
- macOS code signing и notarization.
- Windows signing.
- Linux desktop client.
- Автотесты security-сценариев.

## Лицензии и зависимости

Проект использует сторонние библиотеки, у каждой из которых есть собственная лицензия:

- Qt
- OpenSSL
- libsignal-protocol-c
- Argon2/libargon2

Перед публичным распространением бинарников нужно проверить лицензионные условия конкретных версий и способа линковки.

## Коротко

Это компактный, нативный и достаточно серьезно устроенный desktop messenger: Qt-клиент, TLS relay-сервер, username-аккаунты, единый поиск пользователей/диалогов, offline delivery, статусы сообщений и фокус на шифровании содержимого переписки.
