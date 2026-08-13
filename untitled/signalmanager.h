#ifndef SIGNALMANAGER_H
#define SIGNALMANAGER_H

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QString>

struct signal_context;
struct signal_protocol_store_context;
struct signal_buffer;

class SignalProtocolManager
{
public:
    SignalProtocolManager();
    ~SignalProtocolManager();

    bool initialize(const QString &username);
    bool hasSession(const QString &peer) const;
    QString localPreKeyBundleJson() const;
    bool processPreKeyBundle(const QString &peer, const QString &bundleJson);
    bool encrypt(const QString &peer, const QString &plainText, QString *wirePayload, QString *error);
    bool decrypt(const QString &peer, const QString &wirePayload, QString *plainText, QString *error);
    void removePublishedPreKey(quint32 id);

private:
public:
    struct StoreData
    {
        QHash<QString, QByteArray> sessions;
        QHash<quint32, QByteArray> preKeys;
        QHash<quint32, QByteArray> signedPreKeys;
        QHash<QString, QByteArray> identities;
        QByteArray identityPublic;
        QByteArray identityPrivate;
        quint32 registrationId = 0;
        SignalProtocolManager *owner = nullptr;
    };

    static QString addressKey(const char *name, size_t nameLen, int deviceId);
    static QByteArray bufferToByteArray(signal_buffer *buffer);
    static QString toBase64(const QByteArray &data);
    static QByteArray fromBase64(const QJsonObject &object, const QString &key);

private:
    bool setupContexts();
    bool generateLocalKeys();
    bool loadState();
    bool saveState() const;
    QString stateFilePath() const;
    void cleanup();

    QString m_username;
    signal_context *m_context = nullptr;
    signal_protocol_store_context *m_storeContext = nullptr;
    StoreData *m_store = nullptr;
    QJsonObject m_localBundle;
};

#endif // SIGNALMANAGER_H
