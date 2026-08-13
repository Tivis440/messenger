#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSslSocket>
#include <QHash>
#include <QList>
#include <QSet>
#include "signalmanager.h"
#include "../protocol.h"

QT_BEGIN_NAMESPACE
namespace Ui
{
    class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    bool showAuthDialog();

private slots:
    // Сетевые слоты
    void onConnected();
    void onEncrypted();
    void onDisconnected();
    void onReadyRead();
    void onError(QAbstractSocket::SocketError error);
    void onSslErrors(const QList<QSslError> &errors);
    void onHeartbeatTimeout();

    // UI слоты
    void on_buttonConnect_clicked();
    void on_buttonSend_clicked();
    void on_buttonDisconnect_clicked();
    void on_lineEdit_message_returnPressed();
    void on_buttonRegister_clicked();
    void onUserSelected();
    void onRemoveContact();
    void onProfile();

protected:
    void changeEvent(QEvent *event) override;

private:
    void startLogin(const QString &username, const QString &password);
    void startRegistration(const QString &username, const QString &password);
    void setupConnections();
    void setupUI();
    void setupMenus();
    void log(const QString &message, const QString &sender = "");
    void logSystem(const QString &message);
    void logError(const QString &message);

    void sendAuthMessage();
    void sendRegisterMessage();
    void sendTextMessage(const QString &text);
    void sendDisconnectMessage();
    void handleMessageReceived(const Message &msg);
    void updateUserList(const QString &userList);
    void addChatMessage(const QString &peer, const QString &sender, const QString &message, const QString &id, const QString &status);
    void updateMessageStatus(const QString &id, const QString &status);
    void sendReadStatuses(const QString &peer);
    void sendStatusMessage(const QString &peer, const QString &messageId, const QString &status);
    void publishPreKeyBundle();
    void requestPreKeyBundle(const QString &peer);
    bool sendEncryptedTextMessage(const QString &peer, const QString &text);
    void renderConversation(const QString &peer);
    void refreshChatList();
    void loadConversations();
    void saveConversations() const;
    QString contactDisplayName(const QString &contactId) const;
    QString historyFilePath() const;
    QString selectedPeer() const;
    bool verifyServerCertificate(bool allowTrustOnFirstUse, const QList<QSslError> &errors = {});
    QString serverPinSettingsKey() const;

    bool isConnected() const;

    Ui::MainWindow *ui;
    QSslSocket *m_socket;
    QByteArray m_readBuffer;
    QString m_currentUsername;
    QString m_currentPassword;
    bool m_pendingRegister = false;
    bool m_authenticated;
    QTimer *m_heartbeatTimer;
    class AuthDialog *m_authDialog = nullptr;
    QString m_lastConnectionError;
    QString m_serverHost;
    quint16 m_serverPort = 0;
    bool m_exiting = false;
    QString m_selectedPeer;
    struct ChatLine
    {
        QString sender;
        QString message;
        QString time;
        QString id;
        QString status;
        bool mine = false;
    };
    QHash<QString, QList<ChatLine>> m_conversations;
    QSet<QString> m_onlineUsers;
    QSet<QString> m_knownUsers;
    QSet<QString> m_contacts;
    QHash<QString, QString> m_contactDisplayNames;
    SignalProtocolManager m_signalManager;
    QHash<QString, QStringList> m_pendingMessages;
    QHash<QString, QString> m_preKeyRequests;
    class QLabel *m_chatTitleLabel = nullptr;
    class QLabel *m_chatStatusLabel = nullptr;
    class QListWidget *m_messageList = nullptr;
    class QLineEdit *m_contactSearchEdit = nullptr;
    class QPushButton *m_removeContactButton = nullptr;
    class QPushButton *m_profileButton = nullptr;
    class QSplitter *m_splitter = nullptr;
    bool m_applyingTheme = false;
};

#endif // MAINWINDOW_H
