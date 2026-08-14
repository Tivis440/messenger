#include "server.h"
#include <QDebug>
#include <QDateTime>
#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QRandomGenerator>
#include <QDir>
#include <QSqlError>
#include <QSqlQuery>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslKey>
#include <QUrl>

#include <argon2.h>

static constexpr int PASSWORD_HASH_ITERATIONS = 210000;
static constexpr int PASSWORD_SALT_BYTES = 16;
static constexpr int PASSWORD_HASH_BYTES = 32;
static constexpr int PASSWORD_MIN_LENGTH = 8;
static constexpr int ARGON2_TIME_COST = 3;
static constexpr int ARGON2_MEMORY_KIB = 64 * 1024;
static constexpr int ARGON2_PARALLELISM = 1;
static constexpr int MAX_WIRE_CONTENT_BYTES = 65536;
static constexpr int MAX_READ_BUFFER_BYTES = 262144;
static constexpr int OFFLINE_MESSAGE_TTL_SECONDS = 30 * 24 * 60 * 60;
static constexpr int MAX_OFFLINE_MESSAGES_PER_USER = 500;
static constexpr int AUTH_WINDOW_MS = 15 * 60 * 1000;
static constexpr int AUTH_MAX_FAILURES = 6;
static constexpr int AUTH_LOCK_MS = 15 * 60 * 1000;
static constexpr int REGISTER_WINDOW_MS = 60 * 60 * 1000;
static constexpr int REGISTER_MAX_ATTEMPTS = 10;
static constexpr int MESSAGE_WINDOW_MS = 60 * 1000;
static constexpr int MESSAGE_MAX_PER_WINDOW = 90;
static constexpr int PREKEY_WINDOW_MS = 60 * 1000;
static constexpr int PREKEY_MAX_PER_WINDOW = 30;

static QString normalizedDataDir(const QString &requestedDir)
{
    QString dataDir = requestedDir.trimmed();
    if (dataDir.isEmpty())
        dataDir = QString::fromLocal8Bit(qgetenv("MESSENGER_SERVER_DATA_DIR")).trimmed();
    if (dataDir.isEmpty())
        dataDir = QCoreApplication::applicationDirPath();

    QDir dir(dataDir);
    if (!dir.exists() && !dir.mkpath("."))
        qWarning() << "Не удалось создать папку данных сервера:" << dataDir;

    return dir.absolutePath();
}

// ==================== ClientSession ====================

ClientSession::ClientSession(qintptr socketDescriptor,
                             const QString &certificatePath,
                             const QString &privateKeyPath,
                             QObject *parent)
    : QObject(parent),
      m_socket(new QSslSocket(this)),
      m_authenticated(false),
      m_dataStream(m_socket)
{
    m_dataStream.setVersion(QDataStream::Qt_6_0);

    if (!m_socket->setSocketDescriptor(socketDescriptor))
    {
        qWarning() << "Ошибка установки сокета";
        m_socket->deleteLater();
        return;
    }

    QFile keyFile(privateKeyPath);
    if (!keyFile.open(QIODevice::ReadOnly))
    {
        qWarning() << "TLS ключ не найден:" << privateKeyPath;
        m_socket->close();
        return;
    }

    const QList<QSslCertificate> certificates = QSslCertificate::fromPath(certificatePath);
    const QSslKey privateKey(&keyFile, QSsl::Rsa);
    keyFile.close();
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const bool certificateInDate = !certificates.isEmpty() &&
                                   certificates.first().effectiveDate().toUTC() <= now &&
                                   certificates.first().expiryDate().toUTC() >= now;
    if (certificates.isEmpty() || !certificateInDate || privateKey.isNull())
    {
        qWarning() << "Некорректный, просроченный или еще не действительный TLS сертификат/ключ";
        m_socket->close();
        return;
    }

    QSslConfiguration tlsConfig = m_socket->sslConfiguration();
    tlsConfig.setProtocol(QSsl::TlsV1_2OrLater);
    tlsConfig.setLocalCertificate(certificates.first());
    tlsConfig.setPrivateKey(privateKey);
    m_socket->setSslConfiguration(tlsConfig);

    connect(m_socket, &QSslSocket::encrypted, this, &ClientSession::onEncrypted);
    connect(m_socket, &QSslSocket::disconnected, this, &ClientSession::onDisconnected);
    connect(m_socket, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::errorOccurred),
            this, &ClientSession::onError);
    connect(m_socket, QOverload<const QList<QSslError> &>::of(&QSslSocket::sslErrors),
            this, &ClientSession::onSslErrors);

    m_socket->startServerEncryption();
    qDebug() << "Новое TLS подключение:" << socketDescriptor;
}

// ---------------- PostgreSQL storage helpers (Server) ----------------

static QString databaseUrlFromEnvironment()
{
    QString url = QString::fromLocal8Bit(qgetenv("MESSENGER_DATABASE_URL")).trimmed();
    if (url.isEmpty())
        url = QString::fromLocal8Bit(qgetenv("DATABASE_URL")).trimmed();
    return url;
}

bool Server::openDatabase()
{
    const QString databaseUrl = databaseUrlFromEnvironment();
    if (databaseUrl.isEmpty())
    {
        qCritical() << "PostgreSQL не настроен: задайте MESSENGER_DATABASE_URL.";
        return false;
    }

    const QUrl url(databaseUrl);
    if (!url.isValid() || (url.scheme() != "postgres" && url.scheme() != "postgresql"))
    {
        qCritical() << "Некорректный MESSENGER_DATABASE_URL. Ожидается postgres://user:password@host:5432/database";
        return false;
    }

    const QString connectionName = "messenger-postgres";
    if (QSqlDatabase::contains(connectionName))
        m_db = QSqlDatabase::database(connectionName);
    else
        m_db = QSqlDatabase::addDatabase("QPSQL", connectionName);

    m_db.setHostName(url.host());
    m_db.setPort(url.port(5432));
    m_db.setDatabaseName(url.path().mid(1));
    m_db.setUserName(url.userName(QUrl::FullyDecoded));
    m_db.setPassword(url.password(QUrl::FullyDecoded));
    if (url.query().contains("sslmode=require") || QString::fromLocal8Bit(qgetenv("MESSENGER_DATABASE_SSLMODE")) == "require")
        m_db.setConnectOptions("requiressl=1");

    if (!m_db.open())
    {
        qCritical() << "Не удалось подключиться к PostgreSQL:" << m_db.lastError().text();
        return false;
    }

    qInfo() << "PostgreSQL подключен:" << url.host() << url.path();
    return true;
}

static bool execSql(QSqlQuery &query, const QString &sql)
{
    if (query.exec(sql))
        return true;

    qCritical() << "SQL ошибка:" << query.lastError().text() << "query=" << sql;
    return false;
}

bool Server::migrateDatabase()
{
    QSqlQuery query(m_db);
    if (!execSql(query, "CREATE TABLE IF NOT EXISTS users ("
                        "username TEXT PRIMARY KEY,"
                        "password_json TEXT NOT NULL,"
                        "created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
                        "updated_at TIMESTAMPTZ NOT NULL DEFAULT now())"))
        return false;

    if (!execSql(query, "CREATE TABLE IF NOT EXISTS prekey_bundles ("
                        "username TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,"
                        "bundle_json TEXT NOT NULL,"
                        "updated_at TIMESTAMPTZ NOT NULL DEFAULT now())"))
        return false;

    if (!execSql(query, "CREATE TABLE IF NOT EXISTS offline_messages ("
                        "id BIGSERIAL PRIMARY KEY,"
                        "receiver TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,"
                        "message_type INTEGER NOT NULL,"
                        "sender TEXT NOT NULL,"
                        "content TEXT NOT NULL,"
                        "message_id TEXT,"
                        "message_timestamp BIGINT NOT NULL,"
                        "response_code INTEGER NOT NULL DEFAULT 0,"
                        "created_at TIMESTAMPTZ NOT NULL DEFAULT now())"))
        return false;

    if (!execSql(query, "CREATE INDEX IF NOT EXISTS offline_messages_receiver_id_idx "
                        "ON offline_messages(receiver, id)"))
        return false;

    return true;
}

bool Server::userExists(const QString &username) const
{
    QSqlQuery query(m_db);
    query.prepare("SELECT 1 FROM users WHERE username = :username");
    query.bindValue(":username", username);
    return query.exec() && query.next();
}

QJsonObject Server::passwordEntryForUser(const QString &username) const
{
    QSqlQuery query(m_db);
    query.prepare("SELECT password_json FROM users WHERE username = :username");
    query.bindValue(":username", username);
    if (!query.exec() || !query.next())
        return {};

    const QJsonDocument document = QJsonDocument::fromJson(query.value(0).toString().toUtf8());
    return document.isObject() ? document.object() : QJsonObject();
}

bool Server::savePasswordEntry(const QString &username, const QJsonObject &entry)
{
    QSqlQuery query(m_db);
    query.prepare("UPDATE users SET password_json = :password_json, updated_at = now() WHERE username = :username");
    query.bindValue(":username", username);
    query.bindValue(":password_json", QString::fromUtf8(QJsonDocument(entry).toJson(QJsonDocument::Compact)));
    if (!query.exec())
    {
        qWarning() << "Не удалось обновить пароль пользователя:" << query.lastError().text();
        return false;
    }
    return query.numRowsAffected() == 1;
}

QStringList Server::registeredUsers() const
{
    QStringList users;
    QSqlQuery query(m_db);
    if (!query.exec("SELECT username FROM users ORDER BY username"))
    {
        qWarning() << "Не удалось получить пользователей:" << query.lastError().text();
        return users;
    }

    while (query.next())
        users.append(query.value(0).toString());

    return users;
}

static bool isValidUsername(const QString &username)
{
    if (username.isEmpty() || username != username.trimmed() || username.size() > 64)
        return false;

    for (const QChar ch : username)
    {
        const bool allowed = ch.isLetterOrNumber() || ch == '_' || ch == '-' || ch == '.';
        if (!allowed)
            return false;
    }

    return true;
}

static QString auditSubject(const QString &value)
{
    const QByteArray digest = QCryptographicHash::hash(value.toUtf8(), QCryptographicHash::Sha256).toHex();
    return QString::fromLatin1(digest.left(12));
}

static bool allowWindow(ServerRateWindow &window, qint64 now, int limit, int intervalMs)
{
    if (window.windowStart == 0 || now - window.windowStart > intervalMs)
    {
        window.windowStart = now;
        window.count = 0;
    }

    ++window.count;
    return window.count <= limit;
}

static QByteArray randomBytes(int size)
{
    QByteArray bytes;
    bytes.resize(size);
    for (int i = 0; i < size; ++i)
        bytes[i] = static_cast<char>(QRandomGenerator::global()->generate() & 0xff);
    return bytes;
}

static QByteArray pbkdf2Sha256(const QByteArray &password, const QByteArray &salt, int iterations, int outputBytes)
{
    QByteArray result;
    quint32 blockIndex = 1;

    while (result.size() < outputBytes)
    {
        QByteArray blockSalt = salt;
        blockSalt.append(static_cast<char>((blockIndex >> 24) & 0xff));
        blockSalt.append(static_cast<char>((blockIndex >> 16) & 0xff));
        blockSalt.append(static_cast<char>((blockIndex >> 8) & 0xff));
        blockSalt.append(static_cast<char>(blockIndex & 0xff));

        QByteArray u = QMessageAuthenticationCode::hash(blockSalt, password, QCryptographicHash::Sha256);
        QByteArray t = u;
        for (int i = 1; i < iterations; ++i)
        {
            u = QMessageAuthenticationCode::hash(u, password, QCryptographicHash::Sha256);
            for (int j = 0; j < t.size(); ++j)
                t[j] = static_cast<char>(t.at(j) ^ u.at(j));
        }

        result.append(t);
        ++blockIndex;
    }

    return result.left(outputBytes);
}

static bool constantTimeEquals(const QByteArray &left, const QByteArray &right)
{
    if (left.size() != right.size())
        return false;

    unsigned char diff = 0;
    for (int i = 0; i < left.size(); ++i)
        diff |= static_cast<unsigned char>(left.at(i) ^ right.at(i));

    return diff == 0;
}

static QJsonObject makePasswordEntry(const QString &password)
{
    const QByteArray salt = randomBytes(PASSWORD_SALT_BYTES);
    QByteArray hash(PASSWORD_HASH_BYTES, Qt::Uninitialized);
    const QByteArray passwordBytes = password.toUtf8();
    const int result = argon2id_hash_raw(ARGON2_TIME_COST,
                                         ARGON2_MEMORY_KIB,
                                         ARGON2_PARALLELISM,
                                         passwordBytes.constData(),
                                         passwordBytes.size(),
                                         salt.constData(),
                                         salt.size(),
                                         hash.data(),
                                         hash.size());
    if (result != ARGON2_OK)
        hash = pbkdf2Sha256(passwordBytes, salt, PASSWORD_HASH_ITERATIONS, PASSWORD_HASH_BYTES);

    QJsonObject entry;
    entry.insert("algorithm", result == ARGON2_OK ? "argon2id" : "pbkdf2-sha256");
    entry.insert("timeCost", ARGON2_TIME_COST);
    entry.insert("memoryKiB", ARGON2_MEMORY_KIB);
    entry.insert("parallelism", ARGON2_PARALLELISM);
    entry.insert("iterations", PASSWORD_HASH_ITERATIONS);
    entry.insert("salt", QString::fromLatin1(salt.toBase64()));
    entry.insert("hash", QString::fromLatin1(hash.toBase64()));
    return entry;
}

bool Server::verifyPassword(const QString &username, const QString &password)
{
    const QJsonObject obj = passwordEntryForUser(username);
    if (obj.isEmpty())
        return false;

    if (obj.value("algorithm").toString() == "argon2id")
    {
        const int timeCost = obj.value("timeCost").toInt(ARGON2_TIME_COST);
        const int memoryKiB = obj.value("memoryKiB").toInt(ARGON2_MEMORY_KIB);
        const int parallelism = obj.value("parallelism").toInt(ARGON2_PARALLELISM);
        const QByteArray salt = QByteArray::fromBase64(obj.value("salt").toString().toLatin1());
        const QByteArray storedHash = QByteArray::fromBase64(obj.value("hash").toString().toLatin1());
        if (timeCost < 2 || memoryKiB < 19 * 1024 || parallelism < 1 || salt.size() < PASSWORD_SALT_BYTES || storedHash.size() < PASSWORD_HASH_BYTES)
            return false;

        QByteArray hash(storedHash.size(), Qt::Uninitialized);
        const QByteArray passwordBytes = password.toUtf8();
        const int result = argon2id_hash_raw(timeCost,
                                             memoryKiB,
                                             parallelism,
                                             passwordBytes.constData(),
                                             passwordBytes.size(),
                                             salt.constData(),
                                             salt.size(),
                                             hash.data(),
                                             hash.size());
        return result == ARGON2_OK && constantTimeEquals(hash, storedHash);
    }

    if (obj.value("algorithm").toString() == "pbkdf2-sha256")
    {
        const int iterations = obj.value("iterations").toInt(PASSWORD_HASH_ITERATIONS);
        const QByteArray salt = QByteArray::fromBase64(obj.value("salt").toString().toLatin1());
        const QByteArray storedHash = QByteArray::fromBase64(obj.value("hash").toString().toLatin1());
        if (iterations < 100000 || salt.size() < PASSWORD_SALT_BYTES || storedHash.size() < PASSWORD_HASH_BYTES)
            return false;

        const QByteArray hash = pbkdf2Sha256(password.toUtf8(), salt, iterations, storedHash.size());
        const bool pbkdf2Ok = constantTimeEquals(hash, storedHash);
        if (pbkdf2Ok)
        {
            savePasswordEntry(username, makePasswordEntry(password));
        }
        return pbkdf2Ok;
    }

    return false;
}

bool Server::registerUser(const QString &username, const QString &password)
{
    if (!isValidUsername(username) || password.size() < PASSWORD_MIN_LENGTH)
        return false;
    if (userExists(username))
        return false;

    QSqlQuery query(m_db);
    query.prepare("INSERT INTO users(username, password_json) VALUES(:username, :password_json)");
    query.bindValue(":username", username);
    query.bindValue(":password_json", QString::fromUtf8(QJsonDocument(makePasswordEntry(password)).toJson(QJsonDocument::Compact)));
    if (!query.exec())
    {
        qWarning() << "Не удалось зарегистрировать пользователя:" << query.lastError().text();
        return false;
    }
    return true;
}

ClientSession::~ClientSession()
{
    if (m_socket)
    {
        m_socket->close();
    }
}

void ClientSession::sendMessage(const Message &msg)
{
    if (!m_socket || m_socket->state() != QAbstractSocket::ConnectedState)
    {
        qWarning() << "Попытка отправки в неподключенный сокет";
        return;
    }

    QByteArray buffer;
    QDataStream out(&buffer, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_0);

    Message sendMsg = msg;
    sendMsg.timestamp = QDateTime::currentSecsSinceEpoch();

    out << sendMsg;

    m_socket->write(buffer);
    m_socket->flush();
}

void ClientSession::disconnect()
{
    if (m_socket)
    {
        m_socket->close();
    }
}

void ClientSession::onReadyRead()
{
    m_readBuffer.append(m_socket->readAll());
    if (m_readBuffer.size() > MAX_READ_BUFFER_BYTES)
    {
        qWarning() << "Отключение клиента: превышен лимит входного буфера";
        sendResponse(Protocol::INVALID_FORMAT, "Слишком большой пакет", Protocol::MSG_AUTH_RESPONSE);
        m_socket->close();
        return;
    }

    while (!m_readBuffer.isEmpty())
    {
        QDataStream in(&m_readBuffer, QIODevice::ReadOnly);
        in.setVersion(QDataStream::Qt_6_0);
        in.startTransaction();

        Message msg;
        in >> msg;

        if (!in.commitTransaction())
        {
            break; // Не все данные получены
        }

        m_readBuffer.remove(0, in.device()->pos());

        if (msg.sender.size() > 64 || msg.receiver.size() > 64 || msg.id.size() > 128 || msg.content.toUtf8().size() > MAX_WIRE_CONTENT_BYTES)
        {
            qWarning() << "Отклонено слишком большое или некорректное сообщение";
            sendResponse(Protocol::INVALID_FORMAT, "Некорректный размер сообщения", Protocol::MSG_AUTH_RESPONSE);
            m_socket->close();
            return;
        }

        switch (msg.type)
        {
        case Protocol::MSG_AUTH:
            handleAuthMessage(msg);
            break;
        case Protocol::MSG_REGISTER:
            handleRegisterMessage(msg);
            break;
        case Protocol::MSG_TEXT:
        case Protocol::MSG_PRIVATE:
        case Protocol::MSG_STATUS:
        case Protocol::MSG_PREKEY_PUBLISH:
        case Protocol::MSG_PREKEY_REQUEST:
            if (m_authenticated)
            {
                Server *server = qobject_cast<Server *>(parent());
                if (server)
                {
                    if (!server->allowMessageFrom(m_username))
                    {
                        sendResponse(Protocol::SERVER_ERROR, "Слишком много сообщений. Подождите.", Protocol::MSG_AUTH_RESPONSE);
                        return;
                    }
                    if (msg.type == Protocol::MSG_PREKEY_REQUEST && !server->allowPreKeyRequestFrom(m_username))
                    {
                        sendResponse(Protocol::SERVER_ERROR, "Слишком много запросов ключей. Подождите.", Protocol::MSG_PREKEY_RESPONSE);
                        return;
                    }
                }
                handleTextMessage(msg);
            }
            break;
        case Protocol::MSG_DISCONNECT:
            handleDisconnectMessage();
            return;
            break;
        case Protocol::MSG_HEARTBEAT:
        {
            Message heartbeatReply;
            heartbeatReply.type = Protocol::MSG_HEARTBEAT;
            heartbeatReply.sender = "SERVER";
            heartbeatReply.content = "PONG";
            sendMessage(heartbeatReply);
        }
        break;
        default:
            qWarning() << "Неизвестный тип сообщения:" << msg.type;
        }
    }
}

void ClientSession::onDisconnected()
{
    qDebug() << "client_disconnected subject=" << auditSubject(m_username);
    emit userDisconnected(m_username, this);
}

void ClientSession::onEncrypted()
{
    connect(m_socket, &QSslSocket::readyRead, this, &ClientSession::onReadyRead);
    qInfo() << "TLS канал установлен";
}

void ClientSession::onError(QAbstractSocket::SocketError error)
{
    Q_UNUSED(error);
    qWarning() << "Ошибка сокета:" << m_socket->errorString();
    emit sessionError(m_socket->errorString());
}

void ClientSession::onSslErrors(const QList<QSslError> &errors)
{
    for (const QSslError &error : errors)
        qWarning() << "TLS ошибка:" << error.errorString();
    m_socket->close();
}

void ClientSession::handleAuthMessage(const Message &msg)
{
    if (m_authenticated)
    {
        sendResponse(Protocol::USER_EXISTS, "Уже аутентифицирован", Protocol::MSG_AUTH_RESPONSE);
        return;
    }

    m_username = msg.sender;

    if (!isValidUsername(m_username))
    {
        sendResponse(Protocol::INVALID_FORMAT, "Неверный формат имени", Protocol::MSG_AUTH_RESPONSE);
        return;
    }

    if (parent() && parent()->inherits("Server"))
    {
        Server *server = qobject_cast<Server *>(parent());
        if (server)
        {
            if (!server->userExists(m_username))
            {
                sendResponse(Protocol::AUTH_FAILED, "Пользователь не найден", Protocol::MSG_AUTH_RESPONSE);
                server->recordAuthFailure(m_username);
                return;
            }

            if (!server->allowAuthAttempt(m_username))
            {
                sendResponse(Protocol::AUTH_FAILED, "Слишком много попыток входа. Попробуйте позже.", Protocol::MSG_AUTH_RESPONSE);
                return;
            }

            if (!server->verifyPassword(m_username, msg.content))
            {
                sendResponse(Protocol::AUTH_FAILED, "Неверный пароль", Protocol::MSG_AUTH_RESPONSE);
                server->recordAuthFailure(m_username);
                return;
            }

            if (server->m_clients.contains(m_username))
            {
                sendResponse(Protocol::USER_EXISTS, "Пользователь уже онлайн", Protocol::MSG_AUTH_RESPONSE);
                return;
            }

            // Успешная аутентификация
            m_authenticated = true;
            server->recordAuthSuccess(m_username);
            sendResponse(Protocol::OK, "Аутентификация успешна", Protocol::MSG_AUTH_RESPONSE);
            qInfo() << "auth_ok subject=" << auditSubject(m_username);
            emit userAuthenticated(m_username, this);
            return;
        }
    }

    sendResponse(Protocol::SERVER_ERROR, "Серверная ошибка", Protocol::MSG_AUTH_RESPONSE);
}

void ClientSession::handleRegisterMessage(const Message &msg)
{
    QString username = msg.sender;
    QString password = msg.content;

    if (!isValidUsername(username) || password.size() < PASSWORD_MIN_LENGTH)
    {
        sendResponse(Protocol::INVALID_FORMAT, "Неверное имя или слишком короткий пароль", Protocol::MSG_REGISTER_RESPONSE);
        return;
    }

    if (parent() && parent()->inherits("Server"))
    {
        Server *server = qobject_cast<Server *>(parent());
        if (!server->allowRegistrationAttempt())
        {
            sendResponse(Protocol::SERVER_ERROR, "Слишком много регистраций. Попробуйте позже.", Protocol::MSG_REGISTER_RESPONSE);
            return;
        }

        if (server->userExists(username))
        {
            sendResponse(Protocol::USER_EXISTS, "Имя уже занято", Protocol::MSG_REGISTER_RESPONSE);
            return;
        }

        if (server->registerUser(username, password))
        {
            sendResponse(Protocol::OK, "Регистрация успешна", Protocol::MSG_REGISTER_RESPONSE);
        }
        else
        {
            sendResponse(Protocol::SERVER_ERROR, "Не удалось зарегистрировать", Protocol::MSG_REGISTER_RESPONSE);
        }
    }
}

void ClientSession::handleTextMessage(const Message &msg)
{
    Message broadcastMsg = msg;
    broadcastMsg.sender = m_username;
    broadcastMsg.timestamp = QDateTime::currentSecsSinceEpoch();
    emit messageReceived(broadcastMsg, this);
}

void ClientSession::handleDisconnectMessage()
{
    qDebug() << "disconnect_request subject=" << auditSubject(m_username);
    m_socket->close();
}

void ClientSession::sendResponse(quint32 code, const QString &content, quint32 msgType)
{
    Message response;
    response.type = msgType;
    response.sender = "SERVER";
    response.content = content;
    response.responseCode = code;
    response.timestamp = QDateTime::currentSecsSinceEpoch();

    sendMessage(response);
}

// ==================== Server ====================

Server::Server(const QString &dataDir, QObject *parent)
    : QTcpServer(parent),
      m_dataDir(normalizedDataDir(dataDir))
{
    m_rateClock.start();
    qInfo() << "Сервер инициализирован";
    qInfo() << "Папка данных сервера:" << m_dataDir;
    const QDir dir(m_dataDir);
    m_certificateFile = dir.filePath("tls_server.crt");
    m_privateKeyFile = dir.filePath("tls_server.key");
    m_storageReady = openDatabase() && migrateDatabase();
}

bool Server::allowAuthAttempt(const QString &username)
{
    const qint64 now = m_rateClock.elapsed();
    ServerRateWindow &window = m_authRate[username];
    return window.lockedUntil <= now;
}

void Server::recordAuthFailure(const QString &username)
{
    const qint64 now = m_rateClock.elapsed();
    ServerRateWindow &window = m_authRate[username];
    if (!allowWindow(window, now, AUTH_MAX_FAILURES, AUTH_WINDOW_MS))
    {
        window.lockedUntil = now + AUTH_LOCK_MS;
        qWarning() << "auth_lock subject=" << auditSubject(username);
    }
}

void Server::recordAuthSuccess(const QString &username)
{
    m_authRate.remove(username);
}

bool Server::allowRegistrationAttempt()
{
    return allowWindow(m_registrationRate, m_rateClock.elapsed(), REGISTER_MAX_ATTEMPTS, REGISTER_WINDOW_MS);
}

bool Server::allowMessageFrom(const QString &username)
{
    return allowWindow(m_messageRate[username], m_rateClock.elapsed(), MESSAGE_MAX_PER_WINDOW, MESSAGE_WINDOW_MS);
}

bool Server::allowPreKeyRequestFrom(const QString &username)
{
    return allowWindow(m_preKeyRate[username], m_rateClock.elapsed(), PREKEY_MAX_PER_WINDOW, PREKEY_WINDOW_MS);
}

Server::~Server()
{
    for (ClientSession *session : m_sessions)
    {
        session->deleteLater();
    }
}

bool Server::startServer(quint16 port)
{
    if (!m_storageReady)
    {
        qCritical() << "Сервер не запущен: PostgreSQL-хранилище не готово.";
        return false;
    }

    if (listen(QHostAddress::Any, port))
    {
        qInfo() << "Сервер запущен на порту" << port;
        return true;
    }
    else
    {
        qCritical() << "Ошибка запуска сервера:" << errorString();
        return false;
    }
}

void Server::incomingConnection(qintptr socketDescriptor)
{
    ClientSession *session = new ClientSession(socketDescriptor, m_certificateFile, m_privateKeyFile, this);

    connect(session, &ClientSession::userAuthenticated, this, &Server::onClientAuthenticated);
    connect(session, &ClientSession::userDisconnected, this, &Server::onClientDisconnected);
    connect(session, &ClientSession::messageReceived, this, &Server::onMessageReceived);
    connect(session, &ClientSession::sessionError, this, &Server::onSessionError);

    m_sessions.insert(session);
}

void Server::onClientAuthenticated(const QString &username, ClientSession *session)
{
    m_clients.insert(username, session);
    deliverOfflineMessages(username, session);
    broadcastUserList();

    qInfo() << "client_online count=" << m_clients.size() << "subject=" << auditSubject(username);
}

void Server::onClientDisconnected(const QString &username, ClientSession *session)
{
    m_sessions.remove(session);

    const bool wasOnline = !username.isEmpty() && m_clients.value(username) == session;
    if (wasOnline)
    {
        m_clients.remove(username);
        broadcastUserList();
    }

    session->deleteLater();

    qInfo() << "client_offline count=" << m_clients.size();
}

void Server::onMessageReceived(const Message &msg, ClientSession *sender)
{
    if (msg.type == Protocol::MSG_PRIVATE)
    {
        sendPrivateMessage(msg, sender);
        qDebug() << "private_message id=" << auditSubject(msg.id);
        return;
    }

    if (msg.type == Protocol::MSG_STATUS)
    {
        forwardStatusMessage(msg);
        return;
    }

    if (msg.type == Protocol::MSG_PREKEY_PUBLISH)
    {
        storePreKeyBundle(msg);
        return;
    }

    if (msg.type == Protocol::MSG_PREKEY_REQUEST)
    {
        sendPreKeyBundle(msg, sender);
        return;
    }

    Q_UNUSED(sender);
    qWarning() << "broadcast_rejected subject=" << auditSubject(msg.sender);
}

void Server::onSessionError(const QString &error)
{
    qWarning() << "Ошибка сессии:" << error;
}

void Server::broadcastMessage(const Message &msg, ClientSession *exclude)
{
    for (ClientSession *session : m_sessions)
    {
        if (session != exclude && session->isAuthenticated())
        {
            session->sendMessage(msg);
        }
    }
}

void Server::sendPrivateMessage(const Message &msg, ClientSession *sender)
{
    ClientSession *receiver = m_clients.value(msg.receiver, nullptr);
    if (!receiver)
    {
        Message statusMsg;
        statusMsg.type = Protocol::MSG_STATUS;
        statusMsg.sender = "SERVER";
        statusMsg.receiver = msg.sender;
        statusMsg.id = msg.id;

        if (userExists(msg.receiver))
        {
            queueOfflineMessage(msg);
            statusMsg.content = "sent";
        }
        else
        {
            statusMsg.content = "failed";
        }

        sender->sendMessage(statusMsg);
        return;
    }

    receiver->sendMessage(msg);

    Message statusMsg;
    statusMsg.type = Protocol::MSG_STATUS;
    statusMsg.sender = "SERVER";
    statusMsg.receiver = msg.sender;
    statusMsg.content = "sent";
    statusMsg.id = msg.id;
    sender->sendMessage(statusMsg);
}

void Server::forwardStatusMessage(const Message &msg)
{
    ClientSession *receiver = m_clients.value(msg.receiver, nullptr);
    if (receiver)
    {
        receiver->sendMessage(msg);
        return;
    }

    if (userExists(msg.receiver))
    {
        queueOfflineMessage(msg);
    }
}

void Server::storePreKeyBundle(const Message &msg)
{
    if (!msg.sender.isEmpty() && !msg.content.isEmpty())
    {
        QSqlQuery query(m_db);
        query.prepare("INSERT INTO prekey_bundles(username, bundle_json) VALUES(:username, :bundle_json) "
                      "ON CONFLICT(username) DO UPDATE SET bundle_json = EXCLUDED.bundle_json, updated_at = now()");
        query.bindValue(":username", msg.sender);
        query.bindValue(":bundle_json", msg.content);
        if (!query.exec())
            qWarning() << "Не удалось сохранить prekey bundle:" << query.lastError().text();
    }
}

void Server::sendPreKeyBundle(const Message &msg, ClientSession *sender)
{
    QSqlQuery query(m_db);
    query.prepare("SELECT bundle_json FROM prekey_bundles WHERE username = :username");
    query.bindValue(":username", msg.receiver);
    const QString bundleJson = query.exec() && query.next() ? query.value(0).toString() : QString();
    QJsonObject storedBundle = QJsonDocument::fromJson(bundleJson.toUtf8()).object();
    QJsonArray preKeys = storedBundle.value("preKeys").toArray();

    Message response;
    response.type = Protocol::MSG_PREKEY_RESPONSE;
    response.sender = "SERVER";
    response.receiver = msg.sender;
    response.id = msg.id;
    response.responseCode = Protocol::OK;

    if (storedBundle.isEmpty() || preKeys.isEmpty())
    {
        response.responseCode = Protocol::UNKNOWN_USER;
        sender->sendMessage(response);
        return;
    }

    const QJsonObject selectedPreKey = preKeys.takeAt(0).toObject();
    storedBundle.insert("preKeyId", selectedPreKey.value("id"));
    storedBundle.insert("preKeyPublic", selectedPreKey.value("public"));
    storedBundle.insert("preKeys", preKeys);
    response.content = QString::fromUtf8(QJsonDocument(storedBundle).toJson(QJsonDocument::Compact));

    QSqlQuery updateQuery(m_db);
    updateQuery.prepare("UPDATE prekey_bundles SET bundle_json = :bundle_json, updated_at = now() WHERE username = :username");
    updateQuery.bindValue(":username", msg.receiver);
    updateQuery.bindValue(":bundle_json", QString::fromUtf8(QJsonDocument(storedBundle).toJson(QJsonDocument::Compact)));
    if (!updateQuery.exec())
        qWarning() << "Не удалось обновить prekey bundle:" << updateQuery.lastError().text();
    sender->sendMessage(response);
}

void Server::queueOfflineMessage(const Message &msg)
{
    const quint64 now = QDateTime::currentSecsSinceEpoch();
    Message stored = msg;
    if (stored.timestamp == 0)
        stored.timestamp = now;

    QSqlQuery cleanupQuery(m_db);
    cleanupQuery.prepare("DELETE FROM offline_messages WHERE receiver = :receiver AND message_timestamp < :expires_before");
    cleanupQuery.bindValue(":receiver", msg.receiver);
    cleanupQuery.bindValue(":expires_before", static_cast<qlonglong>(now - OFFLINE_MESSAGE_TTL_SECONDS));
    if (!cleanupQuery.exec())
        qWarning() << "Не удалось очистить просроченные offline-сообщения:" << cleanupQuery.lastError().text();

    QSqlQuery insertQuery(m_db);
    insertQuery.prepare("INSERT INTO offline_messages(receiver, message_type, sender, content, message_id, message_timestamp, response_code) "
                        "VALUES(:receiver, :message_type, :sender, :content, :message_id, :message_timestamp, :response_code)");
    insertQuery.bindValue(":receiver", msg.receiver);
    insertQuery.bindValue(":message_type", static_cast<int>(stored.type));
    insertQuery.bindValue(":sender", stored.sender);
    insertQuery.bindValue(":content", stored.content);
    insertQuery.bindValue(":message_id", stored.id);
    insertQuery.bindValue(":message_timestamp", static_cast<qlonglong>(stored.timestamp));
    insertQuery.bindValue(":response_code", static_cast<int>(stored.responseCode));
    if (!insertQuery.exec())
    {
        qWarning() << "Не удалось сохранить offline-сообщение:" << insertQuery.lastError().text();
        return;
    }

    QSqlQuery trimQuery(m_db);
    trimQuery.prepare("DELETE FROM offline_messages WHERE id IN ("
                      "SELECT id FROM offline_messages WHERE receiver = :receiver ORDER BY id DESC OFFSET :keep_count)");
    trimQuery.bindValue(":receiver", msg.receiver);
    trimQuery.bindValue(":keep_count", MAX_OFFLINE_MESSAGES_PER_USER);
    if (!trimQuery.exec())
        qWarning() << "Не удалось ограничить offline-очередь:" << trimQuery.lastError().text();
}

void Server::deliverOfflineMessages(const QString &username, ClientSession *session)
{
    const quint64 now = QDateTime::currentSecsSinceEpoch();
    QSqlQuery query(m_db);
    query.prepare("SELECT message_type, sender, content, message_id, message_timestamp, response_code "
                  "FROM offline_messages WHERE receiver = :receiver ORDER BY id");
    query.bindValue(":receiver", username);
    if (!query.exec())
    {
        qWarning() << "Не удалось получить offline-сообщения:" << query.lastError().text();
        return;
    }

    while (query.next())
    {
        Message msg;
        msg.type = static_cast<quint32>(query.value(0).toInt());
        msg.sender = query.value(1).toString();
        msg.receiver = username;
        msg.content = query.value(2).toString();
        msg.id = query.value(3).toString();
        msg.timestamp = static_cast<quint64>(query.value(4).toLongLong());
        msg.responseCode = static_cast<quint32>(query.value(5).toInt());
        if (msg.timestamp != 0 && now - msg.timestamp <= OFFLINE_MESSAGE_TTL_SECONDS)
        {
            session->sendMessage(msg);
        }
    }

    QSqlQuery deleteQuery(m_db);
    deleteQuery.prepare("DELETE FROM offline_messages WHERE receiver = :receiver");
    deleteQuery.bindValue(":receiver", username);
    if (!deleteQuery.exec())
        qWarning() << "Не удалось удалить доставленные offline-сообщения:" << deleteQuery.lastError().text();
}

void Server::broadcastUserList()
{
    Message listMsg;
    listMsg.type = Protocol::MSG_USER_LIST;
    listMsg.sender = "SERVER";
    QStringList users;
    const QStringList allUsers = registeredUsers();
    for (const QString &username : allUsers)
    {
        users.append(username + "|" + (m_clients.contains(username) ? "1" : "0"));
    }
    listMsg.content = users.join(",");
    listMsg.timestamp = QDateTime::currentSecsSinceEpoch();

    for (ClientSession *session : m_sessions)
    {
        if (session->isAuthenticated())
        {
            session->sendMessage(listMsg);
        }
    }
}

QStringList Server::getOnlineUsers() const
{
    return m_clients.keys();
}
