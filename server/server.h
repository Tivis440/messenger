#ifndef SERVER_H
#define SERVER_H

#include <QTcpServer>
#include <QSslSocket>
#include <QSqlDatabase>
#include <QObject>
#include <QHash>
#include <QJsonObject>
#include <QSet>
#include <QDateTime>
#include <QElapsedTimer>
#include "../protocol.h"

class ClientSession : public QObject
{
    Q_OBJECT
public:
    explicit ClientSession(qintptr socketDescriptor,
                           const QString &certificatePath,
                           const QString &privateKeyPath,
                           QObject *parent = nullptr);
    ~ClientSession();

    QString getUsername() const { return m_username; }
    bool isAuthenticated() const { return m_authenticated; }
    QSslSocket *getSocket() { return m_socket; }

    void sendMessage(const Message &msg);
    void disconnect();

private slots:
    void onReadyRead();
    void onEncrypted();
    void onDisconnected();
    void onError(QAbstractSocket::SocketError error);
    void onSslErrors(const QList<QSslError> &errors);

signals:
    void userAuthenticated(const QString &username, ClientSession *session);
    void userDisconnected(const QString &username, ClientSession *session);
    void messageReceived(const Message &msg, ClientSession *sender);
    void sessionError(const QString &error);

private:
    void handleAuthMessage(const Message &msg);
    void handleRegisterMessage(const Message &msg);
    void handleTextMessage(const Message &msg);
    void handleDisconnectMessage();
    void sendResponse(quint32 code, const QString &content, quint32 msgType = Protocol::MSG_AUTH_RESPONSE);

    QSslSocket *m_socket;
    QString m_username;
    bool m_authenticated;
    QDataStream m_dataStream;
    QByteArray m_readBuffer;
};

struct ServerRateWindow
{
    qint64 windowStart = 0;
    int count = 0;
    qint64 lockedUntil = 0;
};

class Server : public QTcpServer
{
    Q_OBJECT
    friend class ClientSession;

public:
    explicit Server(const QString &dataDir = QString(), QObject *parent = nullptr);
    ~Server();

    bool startServer(quint16 port = Protocol::DEFAULT_PORT);
    QStringList getOnlineUsers() const;
    int getClientCount() const { return m_clients.size(); }

protected:
    void incomingConnection(qintptr socketDescriptor) override;

private slots:
    void onClientAuthenticated(const QString &username, ClientSession *session);
    void onClientDisconnected(const QString &username, ClientSession *session);
    void onMessageReceived(const Message &msg, ClientSession *sender);
    void onSessionError(const QString &error);

private:
    bool allowAuthAttempt(const QString &username);
    void recordAuthFailure(const QString &username);
    void recordAuthSuccess(const QString &username);
    bool allowRegistrationAttempt();
    bool allowMessageFrom(const QString &username);
    bool allowPreKeyRequestFrom(const QString &username);
    void broadcastMessage(const Message &msg, ClientSession *exclude = nullptr);
    void sendPrivateMessage(const Message &msg, ClientSession *sender);
    void forwardStatusMessage(const Message &msg);
    void storePreKeyBundle(const Message &msg);
    void sendPreKeyBundle(const Message &msg, ClientSession *sender);
    void queueOfflineMessage(const Message &msg);
    void deliverOfflineMessages(const QString &username, ClientSession *session);
    void broadcastUserList();
    bool openDatabase();
    bool migrateDatabase();
    void migrateLegacyJsonFiles();
    bool legacyJsonHasBeenImported() const;
    void markLegacyJsonImported();
    QJsonObject passwordEntryForUser(const QString &username) const;
    bool savePasswordEntry(const QString &username, const QJsonObject &entry);
    QStringList registeredUsers() const;

    QHash<QString, ClientSession *> m_clients; // username -> session
    QSet<ClientSession *> m_sessions;
    QSqlDatabase m_db;
    QElapsedTimer m_rateClock;
    QHash<QString, ServerRateWindow> m_authRate;
    QHash<QString, ServerRateWindow> m_messageRate;
    QHash<QString, ServerRateWindow> m_preKeyRate;
    ServerRateWindow m_registrationRate;
    QString m_dataDir;
    QString m_usersFile;
    QString m_offlineMessagesFile;
    QString m_preKeyBundlesFile;
    QString m_certificateFile;
    QString m_privateKeyFile;
    bool m_storageReady = false;
    bool userExists(const QString &username) const;
    bool verifyPassword(const QString &username, const QString &password);
    bool registerUser(const QString &username, const QString &password);
};

#endif // SERVER_H
