#include "server.h"
#include <QDebug>
#include <QDateTime>
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QRandomGenerator>
#include <QDir>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslKey>

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

// ---------------- User DB helpers (Server) ----------------

bool Server::loadUsers()
{
    if (m_usersFile.isEmpty())
        m_usersFile = QCoreApplication::applicationDirPath() + QDir::separator() + "users.json";

    QFile f(m_usersFile);
    if (!f.exists())
        return true; // no users yet

    if (!f.open(QIODevice::ReadOnly))
    {
        qWarning() << "Не удалось открыть файл пользователей:" << m_usersFile;
        return false;
    }

    QByteArray data = f.readAll();
    f.close();

    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject())
        return false;

    m_userDb = doc.object();
    return true;
}

bool Server::saveUsers()
{
    if (m_usersFile.isEmpty())
        m_usersFile = QCoreApplication::applicationDirPath() + QDir::separator() + "users.json";

    QFile f(m_usersFile);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        qWarning() << "Не удалось сохранить пользователей в:" << m_usersFile << f.errorString();
        return false;
    }

    QJsonDocument doc(m_userDb);
    f.write(doc.toJson());
    f.close();
    QFile::setPermissions(m_usersFile, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return true;
}

static QJsonObject messageToJson(const Message &msg)
{
    QJsonObject object;
    object.insert("type", static_cast<int>(msg.type));
    object.insert("sender", msg.sender);
    object.insert("receiver", msg.receiver);
    object.insert("content", msg.content);
    object.insert("id", msg.id);
    object.insert("timestamp", QString::number(msg.timestamp));
    object.insert("responseCode", static_cast<int>(msg.responseCode));
    return object;
}

static Message messageFromJson(const QJsonObject &object)
{
    Message msg;
    msg.type = static_cast<quint32>(object.value("type").toInt(Protocol::MSG_PRIVATE));
    msg.sender = object.value("sender").toString();
    msg.receiver = object.value("receiver").toString();
    msg.content = object.value("content").toString();
    msg.id = object.value("id").toString();
    msg.timestamp = object.value("timestamp").toString().toULongLong();
    msg.responseCode = static_cast<quint32>(object.value("responseCode").toInt());
    return msg;
}

bool Server::loadOfflineMessages()
{
    if (m_offlineMessagesFile.isEmpty())
        m_offlineMessagesFile = QCoreApplication::applicationDirPath() + QDir::separator() + "offline_messages.json";

    QFile f(m_offlineMessagesFile);
    if (!f.exists())
        return true;

    if (!f.open(QIODevice::ReadOnly))
    {
        qWarning() << "Не удалось открыть файл офлайн-сообщений:" << m_offlineMessagesFile;
        return false;
    }

    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (!doc.isObject())
        return false;

    m_offlineDb = doc.object();
    return true;
}

bool Server::saveOfflineMessages()
{
    if (m_offlineMessagesFile.isEmpty())
        m_offlineMessagesFile = QCoreApplication::applicationDirPath() + QDir::separator() + "offline_messages.json";

    QFile f(m_offlineMessagesFile);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        qWarning() << "Не удалось сохранить офлайн-сообщения:" << m_offlineMessagesFile;
        return false;
    }

    f.write(QJsonDocument(m_offlineDb).toJson(QJsonDocument::Indented));
    f.close();
    QFile::setPermissions(m_offlineMessagesFile, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return true;
}

bool Server::loadPreKeyBundles()
{
    if (m_preKeyBundlesFile.isEmpty())
        m_preKeyBundlesFile = QCoreApplication::applicationDirPath() + QDir::separator() + "prekey_bundles.json";

    QFile f(m_preKeyBundlesFile);
    if (!f.exists())
        return true;

    if (!f.open(QIODevice::ReadOnly))
    {
        qWarning() << "Не удалось открыть файл Signal bundles:" << m_preKeyBundlesFile;
        return false;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (!doc.isObject())
        return false;

    m_preKeyBundles = doc.object();
    return true;
}

bool Server::savePreKeyBundles()
{
    if (m_preKeyBundlesFile.isEmpty())
        m_preKeyBundlesFile = QCoreApplication::applicationDirPath() + QDir::separator() + "prekey_bundles.json";

    QFile f(m_preKeyBundlesFile);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        qWarning() << "Не удалось сохранить Signal bundles:" << m_preKeyBundlesFile;
        return false;
    }

    f.write(QJsonDocument(m_preKeyBundles).toJson(QJsonDocument::Indented));
    f.close();
    QFile::setPermissions(m_preKeyBundlesFile, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return true;
}

bool Server::userExists(const QString &username) const
{
    return m_userDb.contains(username);
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

static bool isGeneratedPublicId(const QString &publicId)
{
    if (!publicId.startsWith("nlk_") || publicId.size() != 24)
        return false;

    for (int i = 4; i < publicId.size(); ++i)
    {
        if (!publicId.at(i).isLetterOrNumber())
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

static QString makeLegacyHash(const QString &password, const QString &salt)
{
    QByteArray data = (password + salt).toUtf8();
    QByteArray h = QCryptographicHash::hash(data, QCryptographicHash::Sha256);
    return QString::fromUtf8(h.toHex());
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
    if (!m_userDb.contains(username))
        return false;
    QJsonObject obj = m_userDb.value(username).toObject();

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
            m_userDb.insert(username, makePasswordEntry(password));
            saveUsers();
        }
        return pbkdf2Ok;
    }

    const QString salt = obj.value("salt").toString();
    const QString hash = obj.value("hash").toString();
    const bool legacyOk = makeLegacyHash(password, salt) == hash;
    if (legacyOk)
    {
        m_userDb.insert(username, makePasswordEntry(password));
        saveUsers();
    }
    return legacyOk;
}

bool Server::registerUser(const QString &username, const QString &password)
{
    if (!isGeneratedPublicId(username) || password.size() < PASSWORD_MIN_LENGTH)
        return false;
    if (m_userDb.contains(username))
        return false;

    m_userDb.insert(username, makePasswordEntry(password));
    return saveUsers();
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
    m_usersFile = dir.filePath("users.json");
    m_offlineMessagesFile = dir.filePath("offline_messages.json");
    m_preKeyBundlesFile = dir.filePath("prekey_bundles.json");
    m_certificateFile = dir.filePath("tls_server.crt");
    m_privateKeyFile = dir.filePath("tls_server.key");
    loadUsers();
    loadOfflineMessages();
    loadPreKeyBundles();
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

    qInfo() << "client_online count=" << m_clients.size() << "subject=" << auditSubject(username);
}

void Server::onClientDisconnected(const QString &username, ClientSession *session)
{
    m_sessions.remove(session);

    const bool wasOnline = !username.isEmpty() && m_clients.value(username) == session;
    if (wasOnline)
    {
        m_clients.remove(username);
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
        m_preKeyBundles.insert(msg.sender, msg.content);
        savePreKeyBundles();
    }
}

void Server::sendPreKeyBundle(const Message &msg, ClientSession *sender)
{
    QJsonObject storedBundle = QJsonDocument::fromJson(m_preKeyBundles.value(msg.receiver).toString().toUtf8()).object();
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

    m_preKeyBundles.insert(msg.receiver, QString::fromUtf8(QJsonDocument(storedBundle).toJson(QJsonDocument::Compact)));
    savePreKeyBundles();
    sender->sendMessage(response);
}

void Server::queueOfflineMessage(const Message &msg)
{
    QJsonArray queue = m_offlineDb.value(msg.receiver).toArray();
    const quint64 now = QDateTime::currentSecsSinceEpoch();
    QJsonArray compacted;
    for (const QJsonValue &value : queue)
    {
        const Message queued = messageFromJson(value.toObject());
        if (queued.timestamp != 0 && now - queued.timestamp <= OFFLINE_MESSAGE_TTL_SECONDS)
            compacted.append(value);
    }

    Message stored = msg;
    if (stored.timestamp == 0)
        stored.timestamp = now;
    compacted.append(messageToJson(stored));
    while (compacted.size() > MAX_OFFLINE_MESSAGES_PER_USER)
        compacted.removeAt(0);

    queue = compacted;
    m_offlineDb.insert(msg.receiver, queue);
    saveOfflineMessages();
}

void Server::deliverOfflineMessages(const QString &username, ClientSession *session)
{
    QJsonArray queue = m_offlineDb.value(username).toArray();
    if (queue.isEmpty())
    {
        return;
    }

    const quint64 now = QDateTime::currentSecsSinceEpoch();
    for (const QJsonValue &value : queue)
    {
        Message msg = messageFromJson(value.toObject());
        if (msg.timestamp != 0 && now - msg.timestamp <= OFFLINE_MESSAGE_TTL_SECONDS)
            session->sendMessage(msg);
    }

    m_offlineDb.remove(username);
    saveOfflineMessages();
}

void Server::broadcastUserList()
{
    Message listMsg;
    listMsg.type = Protocol::MSG_USER_LIST;
    listMsg.sender = "SERVER";
    QStringList users;
    for (const QString &username : m_userDb.keys())
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
