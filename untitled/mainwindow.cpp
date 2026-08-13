#include "mainwindow.h"
#include "authdialog.h"
#include "chatlistdelegate.h"
#include "designtokens.h"
#include "ui_mainwindow.h"
#include <QDebug>
#include <QMessageBox>
#include <QMenu>
#include <QMenuBar>
#include <QDateTime>
#include <QCryptographicHash>
#include <QTimer>
#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFormLayout>
#include <QSettings>
#include <QHostInfo>
#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QInputDialog>
#include <QLineEdit>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QListWidgetItem>
#include <QPainter>
#include <QPushButton>
#include <QShortcut>
#include <QSplitter>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>
#include <QStandardPaths>
#include <QTextEdit>
#include <QUrl>
#include <QUuid>
#include <QVBoxLayout>
#include <algorithm>

static QString statusLabel(const QString &status)
{
    if (status == "sending")
        return "отправляется";
    if (status == "sent")
        return "отправлено";
    if (status == "read")
        return "прочитано";
    if (status == "failed")
        return "не отправлено";
    return QString();
}

static const QList<QByteArray> DEFAULT_PINNED_SERVER_CERT_SHA256 = {
    QByteArray::fromHex("903B6169F2D03CD85406D0A216CB38E46376AC8819201FEA5C531D16884E746D")
};

static const char *FIXED_SERVER_HOST = "144.31.113.35";
static constexpr quint16 FIXED_SERVER_PORT = 5555;

static QString endpointString(const QString &host, quint16 port)
{
    return host + ":" + QString::number(port);
}

static QString peerStatusText(bool online)
{
    return online ? "защищено / в сети" : "защищено / не в сети";
}

static bool isValidAccountName(const QString &username)
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

static QString certificateFingerprintHex(const QSslCertificate &certificate)
{
    return QString::fromLatin1(certificate.digest(QCryptographicHash::Sha256).toHex().toUpper());
}

static QSslConfiguration tofuTlsConfiguration(QSslSocket *socket)
{
    QSslConfiguration tlsConfig = socket->sslConfiguration();
    tlsConfig.setProtocol(QSsl::TlsV1_2OrLater);
    tlsConfig.setPeerVerifyMode(QSslSocket::VerifyNone);
    return tlsConfig;
}

static QColor avatarColor(const QString &name)
{
    return DesignTokens::avatarColor(name, QApplication::palette());
}

static QString initialsForName(const QString &name)
{
    const QString trimmed = name.trimmed();
    if (trimmed.isEmpty())
        return "?";

    const QStringList parts = trimmed.split(' ', Qt::SkipEmptyParts);
    QString initials;
    for (const QString &part : parts)
    {
        if (!part.isEmpty())
            initials.append(part.left(1).toUpper());
        if (initials.size() == 2)
            break;
    }

    return initials.isEmpty() ? trimmed.left(1).toUpper() : initials;
}

static QIcon avatarIcon(const QString &name)
{
    constexpr int size = 40;
    QPixmap pixmap(size, size);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setBrush(avatarColor(name));
    painter.setPen(Qt::NoPen);
    painter.drawEllipse(1, 1, size - 2, size - 2);

    painter.setPen(Qt::white);
    QFont font = painter.font();
    font.setBold(true);
    font.setPointSize(12);
    painter.setFont(font);
    painter.drawText(pixmap.rect(), Qt::AlignCenter, initialsForName(name));

    return QIcon(pixmap);
}

static QString makeEncryptedMessagePlaintext(const QString &text, const QString &displayName)
{
    QJsonObject object;
    object.insert("v", 1);
    object.insert("text", text);
    if (!displayName.trimmed().isEmpty())
        object.insert("name", displayName.trimmed().left(48));
    return QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Compact));
}

static QString readEncryptedMessagePlaintext(const QString &plainText, QString *displayName)
{
    const QJsonDocument document = QJsonDocument::fromJson(plainText.toUtf8());
    if (!document.isObject())
        return plainText;

    const QJsonObject object = document.object();
    if (!object.contains("text"))
        return plainText;

    if (displayName)
        *displayName = object.value("name").toString().trimmed().left(48);
    return object.value("text").toString();
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      m_socket(new QSslSocket(this)),
      m_authenticated(false),
      m_heartbeatTimer(new QTimer(this))
{
    ui->setupUi(this);
    setWindowTitle("Мессенджер");
    setUnifiedTitleAndToolBarOnMac(true);
    setupUI();
    setupConnections();
    setupMenus();
}

MainWindow::~MainWindow()
{
    m_exiting = true;
    QSettings settings;
    settings.setValue("window/geometry", saveGeometry());
    if (m_splitter)
        settings.setValue("window/splitter", m_splitter->saveState());
    saveConversations();
    if (m_socket && m_socket->state() == QAbstractSocket::ConnectedState)
    {
        sendDisconnectMessage();
        m_socket->close();
    }
    delete ui;
}

void MainWindow::changeEvent(QEvent *event)
{
    QMainWindow::changeEvent(event);
    if (event->type() == QEvent::PaletteChange || event->type() == QEvent::ApplicationPaletteChange)
    {
        if (m_applyingTheme)
            return;
        m_applyingTheme = true;
        setStyleSheet(DesignTokens::appStyleSheet(QApplication::palette()));
        refreshChatList();
        renderConversation(m_selectedPeer);
        m_applyingTheme = false;
    }
}

void MainWindow::setupUI()
{
    resize(1040, 720);
    setMinimumSize(860, 560);

    ui->lineEdit_message->setPlaceholderText("Сообщение...");
    ui->lineEdit_message->setAccessibleName("Поле ввода сообщения");
    ui->lineEdit_message->setAccessibleDescription("Введите сообщение выбранному собеседнику");
    ui->textEdit->setReadOnly(true);
    ui->textEdit->setAcceptRichText(true);
    ui->listWidget_users->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->listWidget_users->setItemDelegate(new ChatListDelegate(ui->listWidget_users));
    ui->label_online->setText("Чаты");

    ui->buttonSend->setEnabled(false);
    ui->lineEdit_message->setEnabled(false);
    ui->buttonConnect->hide();
    ui->buttonRegister->hide();
    ui->lineEdit_username->hide();
    ui->buttonSend->setObjectName("buttonSend");
    ui->buttonSend->setText("Отправить");
    ui->buttonSend->setToolTip("Отправить сообщение");
    ui->buttonSend->setAccessibleName("Отправить сообщение");

    QWidget *headerPanel = new QWidget(ui->centralwidget);
    headerPanel->setObjectName("chatHeader");
    m_chatTitleLabel = new QLabel("Выберите собеседника", headerPanel);
    m_chatTitleLabel->setObjectName("chatTitle");
    m_chatStatusLabel = new QLabel("защищенный канал готов", headerPanel);
    m_chatStatusLabel->setObjectName("chatStatus");
    QLabel *securityBadge = new QLabel("защищено", headerPanel);
    securityBadge->setObjectName("securityBadge");
    QVBoxLayout *headerTextLayout = new QVBoxLayout;
    headerTextLayout->setContentsMargins(0, 0, 0, 0);
    headerTextLayout->setSpacing(2);
    headerTextLayout->addWidget(m_chatTitleLabel);
    headerTextLayout->addWidget(m_chatStatusLabel);
    QHBoxLayout *headerLayout = new QHBoxLayout(headerPanel);
    headerLayout->setContentsMargins(22, 14, 22, 14);
    headerLayout->addLayout(headerTextLayout, 1);
    headerLayout->addWidget(securityBadge, 0, Qt::AlignVCenter);

    QWidget *chatPanel = new QWidget(ui->centralwidget);
    chatPanel->setObjectName("chatPanel");
    QVBoxLayout *chatLayout = new QVBoxLayout(chatPanel);
    chatLayout->setContentsMargins(0, 0, 0, 0);
    chatLayout->setSpacing(0);
    chatLayout->addWidget(headerPanel);
    ui->textEdit->hide();
    m_messageList = new QListWidget(chatPanel);
    m_messageList->setObjectName("messageList");
    m_messageList->setAccessibleName("История сообщений");
    m_messageList->setSelectionMode(QAbstractItemView::NoSelection);
    m_messageList->setFocusPolicy(Qt::NoFocus);
    m_messageList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    chatLayout->addWidget(m_messageList, 1);

    QWidget *composerPanel = new QWidget(chatPanel);
    composerPanel->setObjectName("composerPanel");
    QHBoxLayout *messageLayout = new QHBoxLayout;
    messageLayout->setContentsMargins(18, 12, 18, 14);
    messageLayout->setSpacing(8);
    messageLayout->addWidget(ui->lineEdit_message, 1);
    messageLayout->addWidget(ui->buttonSend);
    composerPanel->setLayout(messageLayout);
    chatLayout->addWidget(composerPanel);

    QWidget *sidePanel = new QWidget(ui->centralwidget);
    sidePanel->setObjectName("sidePanel");
    QVBoxLayout *sideLayout = new QVBoxLayout(sidePanel);
    sideLayout->setContentsMargins(0, 0, 0, 14);
    sideLayout->setSpacing(8);

    QLabel *brandLabel = new QLabel("Чаты", sidePanel);
    brandLabel->setObjectName("brandLabel");
    m_profileButton = new QPushButton("Профиль", sidePanel);
    m_profileButton->setObjectName("profileButton");
    m_profileButton->setToolTip("Профиль");
    m_profileButton->setAccessibleName("Профиль");
    m_profileButton->setEnabled(false);
    QHBoxLayout *brandLayout = new QHBoxLayout;
    brandLayout->setContentsMargins(22, 20, 16, 4);
    brandLayout->setSpacing(10);
    brandLayout->addWidget(brandLabel, 1);
    brandLayout->addWidget(m_profileButton);
    sideLayout->addLayout(brandLayout);

    m_contactSearchEdit = new QLineEdit(sidePanel);
    m_contactSearchEdit->setObjectName("contactSearch");
    m_contactSearchEdit->setPlaceholderText("Поиск пользователей и диалогов...");
    m_contactSearchEdit->setAccessibleName("Поиск пользователей и диалогов");
    sideLayout->addWidget(m_contactSearchEdit);

    ui->label_online->setContentsMargins(20, 18, 20, 0);
    QWidget *contactsHeader = new QWidget(sidePanel);
    contactsHeader->setObjectName("contactsHeader");
    QHBoxLayout *contactsHeaderLayout = new QHBoxLayout(contactsHeader);
    contactsHeaderLayout->setContentsMargins(20, 18, 14, 2);
    contactsHeaderLayout->setSpacing(8);
    ui->label_online->setContentsMargins(0, 0, 0, 0);
    contactsHeaderLayout->addWidget(ui->label_online, 1);
    m_removeContactButton = new QPushButton("−", contactsHeader);
    m_removeContactButton->setObjectName("contactToolButton");
    m_removeContactButton->setToolTip("Убрать выбранный диалог из списка");
    m_removeContactButton->setAccessibleName("Убрать выбранный диалог из списка");
    m_removeContactButton->setEnabled(false);
    contactsHeaderLayout->addWidget(m_removeContactButton);
    sideLayout->addWidget(contactsHeader);
    ui->listWidget_users->setIconSize(QSize(40, 40));
    ui->listWidget_users->setAccessibleName("Диалоги и пользователи");
    ui->listWidget_users->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    sideLayout->addWidget(ui->listWidget_users, 1);
    m_splitter = new QSplitter(ui->centralwidget);
    m_splitter->addWidget(sidePanel);
    m_splitter->addWidget(chatPanel);
    m_splitter->setSizes({320, 720});
    m_splitter->setStretchFactor(0, 0);
    m_splitter->setStretchFactor(1, 1);
    m_splitter->setCollapsible(0, false);
    m_splitter->setCollapsible(1, false);

    QVBoxLayout *rootLayout = new QVBoxLayout(ui->centralwidget);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->addWidget(m_splitter);


    setStyleSheet(DesignTokens::appStyleSheet(QApplication::palette()));

    QSettings settings;
    restoreGeometry(settings.value("window/geometry").toByteArray());
    if (m_splitter)
        m_splitter->restoreState(settings.value("window/splitter").toByteArray());

    renderConversation(QString());
}

void MainWindow::setupConnections()
{
    connect(m_socket, &QSslSocket::connected, this, &MainWindow::onConnected);
    connect(m_socket, &QSslSocket::encrypted, this, &MainWindow::onEncrypted);
    connect(m_socket, &QSslSocket::disconnected, this, &MainWindow::onDisconnected);
    connect(m_socket, &QSslSocket::readyRead, this, &MainWindow::onReadyRead);
    connect(m_socket, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::errorOccurred),
            this, &MainWindow::onError);
    connect(m_socket, QOverload<const QList<QSslError> &>::of(&QSslSocket::sslErrors),
            this, &MainWindow::onSslErrors);

    connect(m_heartbeatTimer, &QTimer::timeout, this, &MainWindow::onHeartbeatTimeout);
    m_heartbeatTimer->setInterval(30000);

    connect(ui->listWidget_users, &QListWidget::itemClicked, this, &MainWindow::onUserSelected);
    connect(m_removeContactButton, &QPushButton::clicked, this, &MainWindow::onRemoveContact);
    connect(m_profileButton, &QPushButton::clicked, this, &MainWindow::onProfile);
    connect(m_contactSearchEdit, &QLineEdit::textChanged, this, [this]() {
        refreshChatList();
    });
}

void MainWindow::setupMenus()
{
    QMenu *fileMenu = menuBar()->addMenu("Файл");
    QAction *closeAction = fileMenu->addAction("Закрыть окно");
    closeAction->setShortcut(QKeySequence::Close);
    connect(closeAction, &QAction::triggered, this, &QWidget::close);

    QMenu *editMenu = menuBar()->addMenu("Правка");
    QAction *copyAction = editMenu->addAction("Копировать");
    copyAction->setShortcut(QKeySequence::Copy);
    connect(copyAction, &QAction::triggered, this, []() {
        if (auto *lineEdit = qobject_cast<QLineEdit *>(QApplication::focusWidget()))
            lineEdit->copy();
        else if (auto *textEdit = qobject_cast<QTextEdit *>(QApplication::focusWidget()))
            textEdit->copy();
    });
    QAction *pasteAction = editMenu->addAction("Вставить");
    pasteAction->setShortcut(QKeySequence::Paste);
    connect(pasteAction, &QAction::triggered, this, []() {
        if (auto *lineEdit = qobject_cast<QLineEdit *>(QApplication::focusWidget()))
            lineEdit->paste();
        else if (auto *textEdit = qobject_cast<QTextEdit *>(QApplication::focusWidget()))
            textEdit->paste();
    });
    QAction *selectAllAction = editMenu->addAction("Выбрать все");
    selectAllAction->setShortcut(QKeySequence::SelectAll);
    connect(selectAllAction, &QAction::triggered, this, []() {
        if (auto *lineEdit = qobject_cast<QLineEdit *>(QApplication::focusWidget()))
            lineEdit->selectAll();
        else if (auto *textEdit = qobject_cast<QTextEdit *>(QApplication::focusWidget()))
            textEdit->selectAll();
    });

    QMenu *viewMenu = menuBar()->addMenu("Вид");
    QAction *focusSearchAction = viewMenu->addAction("Поиск пользователей и диалогов");
    focusSearchAction->setShortcut(QKeySequence("Meta+K"));
    connect(focusSearchAction, &QAction::triggered, this, [this]() {
        if (m_contactSearchEdit)
            m_contactSearchEdit->setFocus();
    });

    QMenu *conversationMenu = menuBar()->addMenu("Диалог");
    QAction *profileAction = conversationMenu->addAction("Мой профиль");
    profileAction->setShortcut(QKeySequence("Meta+,"));
    connect(profileAction, &QAction::triggered, this, &MainWindow::onProfile);
    QAction *removeContactAction = conversationMenu->addAction("Убрать из списка");
    connect(removeContactAction, &QAction::triggered, this, &MainWindow::onRemoveContact);

    QMenu *windowMenu = menuBar()->addMenu("Окно");
    QAction *minimizeAction = windowMenu->addAction("Свернуть");
    minimizeAction->setShortcut(QKeySequence("Meta+M"));
    connect(minimizeAction, &QAction::triggered, this, &QWidget::showMinimized);

    QMenu *helpMenu = menuBar()->addMenu("Справка");
    QAction *securityAction = helpMenu->addAction("Безопасность");
    connect(securityAction, &QAction::triggered, this, [this]() {
        QMessageBox::information(this,
                                 "Безопасность",
                                 "Транспорт: TLS с автоматической привязкой сертификата при первом подключении\nСообщения: Signal-сессии\nЛокальные ключи: зашифрованное хранилище состояния");
    });
    QAction *resetServerCertificateAction = helpMenu->addAction("Сбросить сертификат сервера");
    connect(resetServerCertificateAction, &QAction::triggered, this, [this]() {
        const QString key = serverPinSettingsKey();
        QSettings settings;
        const QString storedFingerprint = settings.value(key).toString();
        if (storedFingerprint.isEmpty())
        {
            QMessageBox::information(this, "Сертификат сервера", "Для текущего сервера еще нет сохраненного сертификата.");
            return;
        }

        const QMessageBox::StandardButton answer = QMessageBox::warning(
            this,
            "Сбросить сертификат сервера?",
            "При следующем подключении приложение снова автоматически доверит первому сертификату этого сервера. Делайте это только если вы переустановили сервер или сознательно заменили TLS-сертификат.",
            QMessageBox::Reset | QMessageBox::Cancel,
            QMessageBox::Cancel);

        if (answer == QMessageBox::Reset)
        {
            settings.remove(key);
            ui->statusbar->showMessage("Сохраненный сертификат сервера сброшен", 4000);
        }
    });
}

bool MainWindow::showAuthDialog()
{
    AuthDialog dialog(this);
    m_authDialog = &dialog;

    connect(&dialog, &AuthDialog::loginRequested, this, &MainWindow::startLogin);
    connect(&dialog, &AuthDialog::registerRequested, this, &MainWindow::startRegistration);

    const bool accepted = dialog.exec() == QDialog::Accepted;
    m_authDialog = nullptr;
    return accepted;
}

void MainWindow::startLogin(const QString &username, const QString &password)
{
    if (username.isEmpty() || password.isEmpty())
    {
        if (m_authDialog)
        {
            m_authDialog->showError("Введите имя пользователя и пароль.");
        }
        return;
    }

    if (m_socket->state() != QAbstractSocket::UnconnectedState)
    {
        m_socket->abort();
    }

    m_pendingRegister = false;
    m_currentUsername = username;
    m_currentPassword = password;
    m_signalManager.initialize(username);

    QSettings settings;
    settings.setValue("username", username);

    m_serverHost = QString::fromLatin1(FIXED_SERVER_HOST);
    m_serverPort = FIXED_SERVER_PORT;
    m_socket->setSslConfiguration(tofuTlsConfiguration(m_socket));

    logSystem("Защищенное подключение к " + endpointString(m_serverHost, m_serverPort) + "...");
    m_socket->connectToHostEncrypted(m_serverHost, m_serverPort);
}

void MainWindow::startRegistration(const QString &username, const QString &password)
{
    if (username.isEmpty() || password.isEmpty())
    {
        if (m_authDialog)
        {
            m_authDialog->showError("Введите имя пользователя и пароль.");
        }
        return;
    }

    if (m_socket->state() != QAbstractSocket::UnconnectedState)
    {
        m_socket->abort();
    }

    m_pendingRegister = true;
    m_currentUsername = username;
    m_currentPassword = password;
    m_signalManager.initialize(username);

    QSettings settings;
    settings.setValue("username", username);

    m_serverHost = QString::fromLatin1(FIXED_SERVER_HOST);
    m_serverPort = FIXED_SERVER_PORT;
    m_socket->setSslConfiguration(tofuTlsConfiguration(m_socket));

    logSystem("Защищенное подключение к " + endpointString(m_serverHost, m_serverPort) + " для регистрации...");
    m_socket->connectToHostEncrypted(m_serverHost, m_serverPort);
}

void MainWindow::on_buttonConnect_clicked()
{
    startLogin(ui->lineEdit_username->text().trimmed(), QString());
}

void MainWindow::on_buttonSend_clicked()
{
    QString message = ui->lineEdit_message->text().trimmed();
    if (!message.isEmpty())
    {
        sendTextMessage(message);
        ui->lineEdit_message->clear();
        ui->lineEdit_message->setFocus();
    }
}

void MainWindow::on_buttonRegister_clicked()
{
    startRegistration(ui->lineEdit_username->text().trimmed(), QString());
}

void MainWindow::onUserSelected()
{
    QListWidgetItem *item = ui->listWidget_users->currentItem();
    if (!item)
    {
        return;
    }

    m_selectedPeer = item->data(Qt::UserRole).toString();
    const bool online = item->data(Qt::UserRole + 1).toBool();
    if (!m_contacts.contains(m_selectedPeer))
    {
        m_contacts.insert(m_selectedPeer);
        saveConversations();
    }
    if (m_contactSearchEdit && !m_contactSearchEdit->text().isEmpty())
    {
        m_contactSearchEdit->clear();
    }
    m_chatTitleLabel->setText(contactDisplayName(m_selectedPeer));
    m_chatStatusLabel->setText(peerStatusText(online));
    ui->lineEdit_message->setEnabled(m_authenticated);
    ui->buttonSend->setEnabled(m_authenticated);
    if (m_removeContactButton)
    {
        m_removeContactButton->setEnabled(true);
    }
    renderConversation(m_selectedPeer);
    sendReadStatuses(m_selectedPeer);
    ui->lineEdit_message->setFocus();
}

void MainWindow::on_lineEdit_message_returnPressed()
{
    on_buttonSend_clicked();
}

void MainWindow::onRemoveContact()
{
    const QString peer = selectedPeer();
    if (peer.isEmpty())
    {
        ui->statusbar->showMessage("Выберите диалог или пользователя", 3000);
        return;
    }

    m_contacts.remove(peer);
    m_contactDisplayNames.remove(peer);
    m_selectedPeer.clear();
    saveConversations();
    refreshChatList();
    renderConversation(QString());
    m_chatTitleLabel->setText("Выберите собеседника");
    m_chatStatusLabel->setText("Найдите пользователя, чтобы начать переписку");
    ui->lineEdit_message->setEnabled(false);
    ui->buttonSend->setEnabled(false);
    ui->statusbar->showMessage("Диалог убран из списка", 3000);
}

void MainWindow::onProfile()
{
    if (m_currentUsername.isEmpty())
    {
        return;
    }

    QDialog dialog(this);
    dialog.setWindowTitle("Профиль");
    dialog.setModal(true);
    dialog.setMinimumWidth(520);

    QLabel *title = new QLabel("Ваш профиль", &dialog);
    title->setObjectName("authTitle");
    QLabel *hint = new QLabel("Имя пользователя используется для входа, поиска собеседников и отображается внутри зашифрованных сообщений.", &dialog);
    hint->setObjectName("authSubtitle");
    hint->setWordWrap(true);

    QLineEdit *usernameEdit = new QLineEdit(m_currentUsername, &dialog);
    usernameEdit->setReadOnly(true);

    QPushButton *copyUsernameButton = new QPushButton("Копировать имя", &dialog);
    QDialogButtonBox *buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    buttons->button(QDialogButtonBox::Close)->setText("Закрыть");

    QFormLayout *form = new QFormLayout;
    form->setVerticalSpacing(12);
    form->addRow("Имя", usernameEdit);

    QHBoxLayout *copyLayout = new QHBoxLayout;
    copyLayout->addWidget(copyUsernameButton);
    copyLayout->addStretch(1);

    QVBoxLayout *layout = new QVBoxLayout(&dialog);
    layout->setContentsMargins(24, 22, 24, 20);
    layout->setSpacing(14);
    layout->addWidget(title);
    layout->addWidget(hint);
    layout->addLayout(form);
    layout->addLayout(copyLayout);
    layout->addWidget(buttons);

    dialog.setStyleSheet(DesignTokens::authStyleSheet(QApplication::palette()) +
                         "QDialogButtonBox QPushButton { min-width: 92px; }");

    connect(copyUsernameButton, &QPushButton::clicked, this, [this]() {
        QApplication::clipboard()->setText(m_currentUsername);
        ui->statusbar->showMessage("Имя пользователя скопировано", 2500);
    });
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    dialog.exec();
}

void MainWindow::onConnected()
{
    logSystem("TCP подключен, устанавливаем TLS...");
}

void MainWindow::onEncrypted()
{
    if (!verifyServerCertificate(false))
    {
        m_socket->abort();
        return;
    }

    logSystem("Защищенный канал TLS установлен.");
    if (m_pendingRegister)
    {
        logSystem("Отправка запроса регистрации...");
        sendRegisterMessage();
    }
    else
    {
        logSystem("Аутентификация...");
        sendAuthMessage();
    }
}

void MainWindow::onSslErrors(const QList<QSslError> &errors)
{
    if (verifyServerCertificate(false, errors))
        m_socket->ignoreSslErrors(errors);
    else
        m_socket->abort();
}

QString MainWindow::serverPinSettingsKey() const
{
    const QString host = m_serverHost.trimmed().isEmpty() ? QString::fromLatin1(FIXED_SERVER_HOST) : m_serverHost.trimmed();
    const quint16 port = m_serverPort > 0 ? m_serverPort : FIXED_SERVER_PORT;
    const QString endpoint = endpointString(host.toLower(), port);
    const QString endpointHash = QString::fromLatin1(QCryptographicHash::hash(endpoint.toUtf8(), QCryptographicHash::Sha256).toHex());
    return "serverPins/" + endpointHash;
}

bool MainWindow::verifyServerCertificate(bool allowTrustOnFirstUse, const QList<QSslError> &errors)
{
    m_lastConnectionError.clear();
    const QSslCertificate peerCertificate = m_socket->peerCertificate();
    if (peerCertificate.isNull())
    {
        const QString reason = "сервер не прислал TLS-сертификат";
        m_lastConnectionError = "Небезопасное подключение: " + reason + ".";
        logError("TLS ошибка: " + reason + ".");
        if (m_authDialog)
            m_authDialog->showError(m_lastConnectionError);
        return false;
    }

    const QDateTime now = QDateTime::currentDateTimeUtc();
    const bool certificateInDate = peerCertificate.effectiveDate().toUTC() <= now &&
                                   peerCertificate.expiryDate().toUTC() >= now;
    if (!certificateInDate)
    {
        const QString reason = "срок действия сертификата сервера истек или еще не начался";
        m_lastConnectionError = "Небезопасное подключение: " + reason + ".";
        logError("TLS ошибка: " + reason + ".");
        if (m_authDialog)
            m_authDialog->showError(m_lastConnectionError);
        return false;
    }

    for (const QSslError &error : errors)
        logSystem("TLS предупреждение Qt: " + error.errorString());

    const QByteArray fingerprint = peerCertificate.digest(QCryptographicHash::Sha256);
    const QString fingerprintHex = certificateFingerprintHex(peerCertificate);

    QSettings settings;
    const QString settingsKey = serverPinSettingsKey();
    const QString storedFingerprint = settings.value(settingsKey).toString().trimmed().toUpper();

    if (DEFAULT_PINNED_SERVER_CERT_SHA256.contains(fingerprint))
    {
        if (storedFingerprint != fingerprintHex)
            settings.setValue(settingsKey, fingerprintHex);
        logSystem("Сертификат сервера проверен по встроенному отпечатку.");
        return true;
    }

    if (!storedFingerprint.isEmpty())
    {
        if (storedFingerprint == fingerprintHex)
        {
            logSystem("Сертификат сервера проверен по сохраненному отпечатку.");
            return true;
        }

        const QString reason = "сертификат сервера изменился";
        logError("TLS ошибка: " + reason + ".");
        const QString message = "Сертификат сервера изменился.\n\n"
                                "Сохраненный отпечаток:\n" + storedFingerprint +
                                "\n\nНовый отпечаток:\n" + fingerprintHex +
                                "\n\nЕсли вы переустановили сервер или заменили сертификат, можно доверить новому сертификату.";
        if (QMessageBox::warning(this,
                                 "Сертификат сервера изменился",
                                 message,
                                 QMessageBox::Yes | QMessageBox::No,
                                 QMessageBox::No) == QMessageBox::Yes)
        {
            settings.setValue(settingsKey, fingerprintHex);
            logSystem("Новый TLS-сертификат сервера подтвержден пользователем и сохранен.");
            return true;
        }

        m_lastConnectionError = "Небезопасное подключение: " + reason + ".";
        if (m_authDialog)
            m_authDialog->showError(m_lastConnectionError);
        return false;
    }

    if (allowTrustOnFirstUse)
    {
        settings.setValue(settingsKey, fingerprintHex);
        logSystem("Первое подключение: отпечаток TLS-сертификата сервера сохранен локально.");
        return true;
    }

    const QString reason = "сертификат сервера еще не доверен";
    m_lastConnectionError = "Небезопасное подключение: " + reason + ".";
    logError("TLS ошибка: " + reason + ".");
    if (m_authDialog)
        m_authDialog->showError(m_lastConnectionError);
    return false;
}

void MainWindow::onDisconnected()
{
    m_authenticated = false;
    m_heartbeatTimer->stop();

    logSystem("Отключено от сервера");
    ui->statusbar->showMessage("Отключено от сервера", 5000);

    ui->lineEdit_message->setEnabled(false);
    ui->buttonSend->setEnabled(false);
    if (m_removeContactButton)
    {
        m_removeContactButton->setEnabled(false);
    }
    if (m_profileButton)
    {
        m_profileButton->setEnabled(false);
        m_profileButton->setText("Профиль");
    }

    if (m_authDialog)
    {
        m_authDialog->showError(m_lastConnectionError.isEmpty() ? "Соединение с сервером потеряно." : m_lastConnectionError);
    }
    else if (!m_exiting)
    {
        QTimer::singleShot(0, this, [this]() {
            if (!showAuthDialog())
            {
                close();
            }
        });
    }
}
void MainWindow::onReadyRead()
{
    m_readBuffer.append(m_socket->readAll());

    while (!m_readBuffer.isEmpty())
    {
        QDataStream in(&m_readBuffer, QIODevice::ReadOnly);
        in.setVersion(QDataStream::Qt_6_0);
        in.startTransaction();

        Message msg;
        in >> msg;

        if (!in.commitTransaction())
        {
            break;
        }

        handleMessageReceived(msg);
        qint64 bytesRead = in.device()->pos();
        m_readBuffer.remove(0, bytesRead);
    }
}

void MainWindow::onError(QAbstractSocket::SocketError socketError)
{
    const QString host = m_serverHost.trimmed().isEmpty() ? QString::fromLatin1(FIXED_SERVER_HOST) : m_serverHost.trimmed();
    const quint16 port = m_serverPort > 0 ? m_serverPort : FIXED_SERVER_PORT;
    const QString endpoint = endpointString(host, port);
    QString details = QString("Не удалось подключиться к %1: %2 (код %3)")
                          .arg(endpoint, m_socket->errorString())
                          .arg(static_cast<int>(socketError));

    if (socketError == QAbstractSocket::ConnectionRefusedError)
    {
        details += "\nСервер доступен только если процесс слушает этот порт и firewall VPS разрешает входящий TCP.";
    }

    m_lastConnectionError = details;
    logError("Ошибка: " + details);
    if (m_authDialog)
    {
        m_authDialog->showError(m_lastConnectionError);
    }
}

void MainWindow::onHeartbeatTimeout()
{
    if (!isConnected())
    {
        m_heartbeatTimer->stop();
        return;
    }

    Message hb;
    hb.type = Protocol::MSG_HEARTBEAT;
    hb.sender = m_currentUsername;

    QByteArray buffer;
    QDataStream out(&buffer, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_0);
    out << hb;

    m_socket->write(buffer);
}

void MainWindow::sendAuthMessage()
{
    Message authMsg;
    authMsg.type = Protocol::MSG_AUTH;
    authMsg.sender = m_currentUsername;
    authMsg.content = m_currentPassword;

    QByteArray buffer;
    QDataStream out(&buffer, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_0);
    out << authMsg;

    m_socket->write(buffer);
    m_socket->flush();
}

void MainWindow::sendRegisterMessage()
{
    Message regMsg;
    regMsg.type = Protocol::MSG_REGISTER;
    regMsg.sender = m_currentUsername;
    regMsg.content = m_currentPassword;

    QByteArray buffer;
    QDataStream out(&buffer, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_0);
    out << regMsg;

    m_socket->write(buffer);
    m_socket->flush();
}

void MainWindow::sendTextMessage(const QString &text)
{
    if (!isConnected() || !m_authenticated)
    {
        logError("Соединение потеряно!");
        return;
    }

    const QString peer = selectedPeer();
    if (peer.isEmpty())
    {
        ui->statusbar->showMessage("Выберите собеседника слева", 3000);
        return;
    }

    if (!m_signalManager.hasSession(peer))
    {
        m_pendingMessages[peer].append(text);
        requestPreKeyBundle(peer);
        ui->statusbar->showMessage("Создаем Signal-сессию с " + peer + "...", 3000);
        return;
    }

    sendEncryptedTextMessage(peer, text);
}

bool MainWindow::sendEncryptedTextMessage(const QString &peer, const QString &text)
{
    QString encryptedPayload;
    QString error;
    const QString plainPayload = makeEncryptedMessagePlaintext(text, m_currentUsername);
    if (!m_signalManager.encrypt(peer, plainPayload, &encryptedPayload, &error))
    {
        ui->statusbar->showMessage(error, 4000);
        return false;
    }

    Message msg;
    msg.type = Protocol::MSG_PRIVATE;
    msg.sender = m_currentUsername;
    msg.receiver = peer;
    msg.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    msg.content = encryptedPayload;

    addChatMessage(peer, m_currentUsername, text, msg.id, "sending");

    QByteArray buffer;
    QDataStream out(&buffer, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_0);
    out << msg;

    m_socket->write(buffer);
    m_socket->flush();
    return true;
}

void MainWindow::sendDisconnectMessage()
{
    if (!isConnected())
    {
        return;
    }

    Message disconnectMsg;
    disconnectMsg.type = Protocol::MSG_DISCONNECT;
    disconnectMsg.sender = m_currentUsername;

    QByteArray buffer;
    QDataStream out(&buffer, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_0);
    out << disconnectMsg;

    m_socket->write(buffer);
    m_socket->flush();
}

void MainWindow::handleMessageReceived(const Message &msg)
{
    switch (msg.type)
    {
    case Protocol::MSG_HEARTBEAT:
        // Сервер подтверждает, что соединение живое.
        return;

    case Protocol::MSG_AUTH_RESPONSE:
        if (msg.responseCode == Protocol::OK)
        {
            m_authenticated = true;
            loadConversations();
            refreshChatList();
            publishPreKeyBundle();
            logSystem("✓ Аутентификация успешна!");
            ui->lineEdit_message->setEnabled(true);
            ui->buttonSend->setEnabled(!m_selectedPeer.isEmpty());
            if (m_removeContactButton)
            {
                m_removeContactButton->setEnabled(!m_selectedPeer.isEmpty() && m_contacts.contains(m_selectedPeer));
            }
            if (m_profileButton)
            {
                m_profileButton->setEnabled(true);
                m_profileButton->setText(m_currentUsername);
            }
            ui->lineEdit_message->setFocus();
            ui->statusbar->showMessage("Вы вошли как " + m_currentUsername, 7000);
            m_heartbeatTimer->start();
            if (m_authDialog)
            {
                m_authDialog->accept();
            }
        }
        else
        {
            logError("Ошибка аутентификации: " + msg.content);
            if (m_authDialog)
            {
                m_authDialog->showError("Ошибка входа: " + msg.content);
            }
        }
        break;

    case Protocol::MSG_REGISTER_RESPONSE:
        if (msg.responseCode == Protocol::OK)
        {
            logSystem("Регистрация успешна — выполняется вход...");
            m_pendingRegister = false;
            // Теперь сразу пытаемся аутентифицироваться
            sendAuthMessage();
        }
        else
        {
            logError("Ошибка регистрации: " + msg.content);
            m_pendingRegister = false;
            if (m_authDialog)
            {
                m_authDialog->showError("Ошибка регистрации: " + msg.content);
            }
        }
        break;

    case Protocol::MSG_TEXT:
        logSystem(msg.content);
        break;

    case Protocol::MSG_PRIVATE:
    {
        const QString peer = msg.sender == m_currentUsername ? msg.receiver : msg.sender;
        QString plainText;
        QString error;
        if (!m_signalManager.decrypt(peer, msg.content, &plainText, &error))
        {
            ui->statusbar->showMessage(error, 4000);
            break;
        }
        QString senderDisplayName;
        const QString messageText = readEncryptedMessagePlaintext(plainText, &senderDisplayName);
        if (msg.sender != m_currentUsername && !m_contacts.contains(peer))
        {
            m_contacts.insert(peer);
        }
        if (msg.sender != m_currentUsername && !senderDisplayName.isEmpty())
        {
            m_contactDisplayNames.insert(peer, senderDisplayName);
        }
        if (msg.sender != m_currentUsername)
            refreshChatList();
        addChatMessage(peer, msg.sender, messageText, msg.id, msg.sender == m_currentUsername ? "sent" : QString());
        if (peer == m_selectedPeer && msg.sender != m_currentUsername)
        {
            sendStatusMessage(peer, msg.id, "read");
        }
        break;
    }

    case Protocol::MSG_STATUS:
        updateMessageStatus(msg.id, msg.content);
        break;

    case Protocol::MSG_PREKEY_RESPONSE:
    {
        const QString peer = m_preKeyRequests.take(msg.id);
        if (peer.isEmpty())
        {
            break;
        }

        if (msg.responseCode != Protocol::OK || !m_signalManager.processPreKeyBundle(peer, msg.content))
        {
            ui->statusbar->showMessage("Не удалось создать Signal-сессию с " + peer + ". Возможна смена ключа личности.", 6000);
            m_pendingMessages.remove(peer);
            break;
        }

        if (peer == m_selectedPeer)
        {
            m_chatStatusLabel->setText(peerStatusText(m_onlineUsers.contains(peer)));
        }

        const QStringList pending = m_pendingMessages.take(peer);
        for (const QString &text : pending)
        {
            sendEncryptedTextMessage(peer, text);
        }
        break;
    }

    case Protocol::MSG_USER_LIST:
        updateUserList(msg.content);
        break;

    default:
        qDebug() << "Неизвестный тип сообщения:" << msg.type;
    }
}

void MainWindow::updateUserList(const QString &userList)
{
    m_onlineUsers.clear();
    m_knownUsers.clear();
    const QStringList users = userList.split(',', Qt::SkipEmptyParts);
    for (const QString &user : users)
    {
        const QString entry = user.trimmed();
        const QStringList parts = entry.split('|');
        const QString name = parts.value(0).trimmed();
        if (name.isEmpty() || name == m_currentUsername)
        {
            continue;
        }

        m_knownUsers.insert(name);
        if (parts.size() == 1 || parts.value(1) == "1")
        {
            m_onlineUsers.insert(name);
        }
    }

    if (!m_selectedPeer.isEmpty() && !m_contacts.contains(m_selectedPeer))
    {
        m_selectedPeer.clear();
        renderConversation(QString());
    }

    refreshChatList();
    ui->statusbar->showMessage(QString("Диалогов: %1").arg(m_contacts.size()), 3000);
}

void MainWindow::refreshChatList()
{
    ui->listWidget_users->clear();

    const QString searchText = m_contactSearchEdit ? m_contactSearchEdit->text().trimmed() : QString();
    QSet<QString> visibleIds = m_contacts;
    for (auto it = m_conversations.begin(); it != m_conversations.end(); ++it)
        visibleIds.insert(it.key());

    auto conversationMatches = [this, &searchText](const QString &contactId) {
        if (searchText.isEmpty())
            return true;

        if (contactId.contains(searchText, Qt::CaseInsensitive) ||
            contactDisplayName(contactId).contains(searchText, Qt::CaseInsensitive))
            return true;

        const QList<ChatLine> lines = m_conversations.value(contactId);
        for (const ChatLine &line : lines)
        {
            if (line.message.contains(searchText, Qt::CaseInsensitive))
                return true;
        }
        return false;
    };

    if (!searchText.isEmpty())
    {
        for (const QString &username : m_knownUsers)
        {
            if (username.contains(searchText, Qt::CaseInsensitive))
                visibleIds.insert(username);
        }
    }

    QStringList contactIds;
    for (const QString &contactId : visibleIds)
    {
        if (contactId == m_currentUsername)
            continue;
        if (conversationMatches(contactId))
            contactIds.append(contactId);
    }

    std::sort(contactIds.begin(), contactIds.end(), [this](const QString &left, const QString &right) {
        return QString::compare(contactDisplayName(left), contactDisplayName(right), Qt::CaseInsensitive) < 0;
    });

    if (m_removeContactButton)
    {
        m_removeContactButton->setEnabled(!m_selectedPeer.isEmpty() && m_contacts.contains(m_selectedPeer));
    }

    if (contactIds.isEmpty())
    {
        m_chatTitleLabel->setText(searchText.isEmpty() ? "Нет диалогов" : "Ничего не найдено");
        m_chatStatusLabel->setText(searchText.isEmpty()
                                       ? "Введите username в поиск, чтобы начать переписку"
                                       : "Проверьте username или текст поиска");
        ui->lineEdit_message->setEnabled(false);
        ui->buttonSend->setEnabled(false);
        renderConversation(QString());
        return;
    }

    bool selectedPeerOnline = false;
    bool selectedPeerExists = false;

    for (const QString &contactId : contactIds)
    {
        const QString displayName = contactDisplayName(contactId);
        const bool online = m_onlineUsers.contains(contactId);
        const QList<ChatLine> lines = m_conversations.value(contactId);
        const bool knownOnly = !m_contacts.contains(contactId) && lines.isEmpty();
        const QString preview = lines.isEmpty()
                                    ? (knownOnly ? QString("Найден пользователь") : QString("Нет сообщений"))
                                    : lines.last().message.left(42).replace('\n', ' ');
        QListWidgetItem *item = new QListWidgetItem(avatarIcon(displayName), displayName);
        item->setData(ChatListRoles::NameRole, displayName);
        item->setData(ChatListRoles::PreviewRole, preview);
        item->setData(ChatListRoles::TimeRole, lines.isEmpty() ? QString() : lines.last().time);
        item->setData(ChatListRoles::OnlineRole, online);
        item->setData(ChatListRoles::UnreadRole, 0);
        item->setData(ChatListRoles::StatusRole, lines.isEmpty() ? QString() : lines.last().status);
        item->setData(Qt::UserRole, contactId);
        item->setData(Qt::UserRole + 1, online);
        item->setToolTip(QString("%1\nИмя: %2").arg(online ? "В сети" : "Не в сети", contactId));
        item->setSizeHint(QSize(0, 66));
        ui->listWidget_users->addItem(item);

        if (contactId == m_selectedPeer)
        {
            ui->listWidget_users->setCurrentItem(item);
            selectedPeerOnline = online;
            selectedPeerExists = true;
        }
    }

    if (m_selectedPeer.isEmpty() && ui->listWidget_users->count() > 0)
    {
        renderConversation(QString());
    }
    else if (!m_selectedPeer.isEmpty() && selectedPeerExists)
    {
        m_chatTitleLabel->setText(contactDisplayName(m_selectedPeer));
        m_chatStatusLabel->setText(peerStatusText(selectedPeerOnline));
        ui->lineEdit_message->setEnabled(m_authenticated);
        ui->buttonSend->setEnabled(m_authenticated);
        renderConversation(m_selectedPeer);
    }
    else if (!m_selectedPeer.isEmpty())
    {
        m_selectedPeer.clear();
        renderConversation(QString());
        m_chatTitleLabel->setText("Выберите собеседника");
        m_chatStatusLabel->setText("Найдите пользователя, чтобы начать переписку");
        ui->lineEdit_message->setEnabled(false);
        ui->buttonSend->setEnabled(false);
    }
}

void MainWindow::addChatMessage(const QString &peer, const QString &sender, const QString &message, const QString &id, const QString &status)
{
    if (!id.isEmpty())
    {
        for (ChatLine &existing : m_conversations[peer])
        {
            if (existing.id == id)
            {
                if (!status.isEmpty())
                {
                    existing.status = status;
                    saveConversations();
                }
                if (peer == m_selectedPeer)
                {
                    renderConversation(peer);
                }
                return;
            }
        }
    }

    ChatLine line;
    line.sender = sender;
    line.message = message;
    line.time = QDateTime::currentDateTime().toString("hh:mm");
    line.id = id;
    line.status = status;
    line.mine = sender == m_currentUsername;

    m_conversations[peer].append(line);
    saveConversations();
    if (peer == m_selectedPeer)
    {
        renderConversation(peer);
    }
}

void MainWindow::updateMessageStatus(const QString &id, const QString &status)
{
    if (id.isEmpty())
    {
        return;
    }

    for (auto it = m_conversations.begin(); it != m_conversations.end(); ++it)
    {
        for (ChatLine &line : it.value())
        {
            if (line.id == id && line.mine)
            {
                line.status = status;
                saveConversations();
                if (it.key() == m_selectedPeer)
                {
                    renderConversation(it.key());
                }
                return;
            }
        }
    }
}

void MainWindow::sendReadStatuses(const QString &peer)
{
    if (peer.isEmpty() || !isConnected() || !m_authenticated)
    {
        return;
    }

    bool changed = false;
    for (ChatLine &line : m_conversations[peer])
    {
        if (!line.mine && !line.id.isEmpty() && line.status != "read")
        {
            line.status = "read";
            sendStatusMessage(peer, line.id, "read");
            changed = true;
        }
    }

    if (changed)
    {
        saveConversations();
    }
}

void MainWindow::sendStatusMessage(const QString &peer, const QString &messageId, const QString &status)
{
    if (!isConnected() || !m_authenticated || messageId.isEmpty())
    {
        return;
    }

    Message msg;
    msg.type = Protocol::MSG_STATUS;
    msg.sender = m_currentUsername;
    msg.receiver = peer;
    msg.id = messageId;
    msg.content = status;

    QByteArray buffer;
    QDataStream out(&buffer, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_0);
    out << msg;

    m_socket->write(buffer);
    m_socket->flush();
}

void MainWindow::publishPreKeyBundle()
{
    if (!isConnected() || !m_authenticated)
    {
        return;
    }

    Message msg;
    msg.type = Protocol::MSG_PREKEY_PUBLISH;
    msg.sender = m_currentUsername;
    msg.content = m_signalManager.localPreKeyBundleJson();

    QByteArray buffer;
    QDataStream out(&buffer, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_0);
    out << msg;
    m_socket->write(buffer);
    m_socket->flush();
}

void MainWindow::requestPreKeyBundle(const QString &peer)
{
    for (auto it = m_preKeyRequests.begin(); it != m_preKeyRequests.end(); ++it)
    {
        if (it.value() == peer)
        {
            return;
        }
    }

    Message msg;
    msg.type = Protocol::MSG_PREKEY_REQUEST;
    msg.sender = m_currentUsername;
    msg.receiver = peer;
    msg.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_preKeyRequests.insert(msg.id, peer);

    QByteArray buffer;
    QDataStream out(&buffer, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_0);
    out << msg;
    m_socket->write(buffer);
    m_socket->flush();
}

void MainWindow::renderConversation(const QString &peer)
{
    if (!m_messageList)
    {
        return;
    }

    m_messageList->clear();

    if (peer.isEmpty())
    {
        QListWidgetItem *item = new QListWidgetItem(m_messageList);
        QLabel *hint = new QLabel("Выберите собеседника слева", m_messageList);
        hint->setAlignment(Qt::AlignCenter);
        hint->setStyleSheet(DesignTokens::emptyStateStyle(QApplication::palette()));
        item->setSizeHint(QSize(0, 120));
        m_messageList->setItemWidget(item, hint);
        return;
    }

    const QList<ChatLine> messages = m_conversations.value(peer);
    if (messages.isEmpty())
    {
        QListWidgetItem *item = new QListWidgetItem(m_messageList);
        QLabel *hint = new QLabel("Канал готов. Сообщений пока нет", m_messageList);
        hint->setAlignment(Qt::AlignCenter);
        hint->setStyleSheet(DesignTokens::emptyStateStyle(QApplication::palette()));
        item->setSizeHint(QSize(0, 120));
        m_messageList->setItemWidget(item, hint);
        return;
    }

    const int maxBubbleWidth = qBound(300, static_cast<int>(m_messageList->viewport()->width() * 0.68), 560);
    for (const ChatLine &line : messages)
    {
        QWidget *row = new QWidget(m_messageList);
        QHBoxLayout *rowLayout = new QHBoxLayout(row);
        rowLayout->setContentsMargins(22, 5, 22, 5);
        rowLayout->setSpacing(8);

        QLabel *bubble = new QLabel(row);
        bubble->setTextFormat(Qt::RichText);
        bubble->setWordWrap(true);
        bubble->setMaximumWidth(maxBubbleWidth);
        const QString status = line.mine ? statusLabel(line.status) : QString();
        const QString meta = status.isEmpty() ? line.time : line.time + "  •  " + status;
        const auto colors = DesignTokens::colors(QApplication::palette());
        const QString metaColor = (line.mine
                                       ? QApplication::palette().color(QPalette::HighlightedText)
                                       : colors.labelSecondary).name(QColor::HexRgb);
        bubble->setText(QString("<span style='font-size:14px;'>%1</span>"
                                "  <span style='font-size:11px; color:%2;'>%3</span>")
                            .arg(line.message.toHtmlEscaped().replace("\n", "<br>"),
                                 metaColor,
                                 meta.toHtmlEscaped()));
        bubble->setStyleSheet(DesignTokens::messageBubbleStyle(QApplication::palette(), line.mine));

        if (line.mine)
        {
            rowLayout->addStretch(1);
            rowLayout->addWidget(bubble, 0, Qt::AlignRight);
        }
        else
        {
            rowLayout->addWidget(bubble, 0, Qt::AlignLeft);
            rowLayout->addStretch(1);
        }

        QListWidgetItem *item = new QListWidgetItem(m_messageList);
        item->setSizeHint(QSize(0, bubble->sizeHint().height() + 16));
        m_messageList->setItemWidget(item, row);
    }

    m_messageList->scrollToBottom();
}

void MainWindow::loadConversations()
{
    m_conversations.clear();
    m_selectedPeer.clear();
    m_contacts.clear();
    m_contactDisplayNames.clear();

    QFile file(historyFilePath());
    if (!file.exists())
    {
        renderConversation(QString());
        return;
    }

    if (!file.open(QIODevice::ReadOnly))
    {
        ui->statusbar->showMessage("Не удалось открыть историю сообщений", 4000);
        return;
    }

    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    file.close();

    if (!document.isObject())
    {
        ui->statusbar->showMessage("История сообщений повреждена", 4000);
        return;
    }

    const QJsonObject root = document.object();
    const QJsonObject chats = root.value("chats").toObject();
    for (auto it = chats.begin(); it != chats.end(); ++it)
    {
        QList<ChatLine> lines;
        const QJsonArray messages = it.value().toArray();
        for (const QJsonValue &value : messages)
        {
            const QJsonObject object = value.toObject();
            ChatLine line;
            line.sender = object.value("sender").toString();
            line.message = object.value("message").toString();
            line.time = object.value("time").toString();
            line.id = object.value("id").toString();
            line.status = object.value("status").toString();
            line.mine = object.value("mine").toBool(line.sender == m_currentUsername);

            if (!line.sender.isEmpty() && !line.message.isEmpty())
            {
                lines.append(line);
            }
        }

        if (!lines.isEmpty())
        {
            m_conversations.insert(it.key(), lines);
        }
    }

    const QJsonArray contacts = root.value("contacts").toArray();
    for (const QJsonValue &value : contacts)
    {
        QString contact;
        QString displayName;
        if (value.isObject())
        {
            const QJsonObject object = value.toObject();
            contact = object.value("id").toString().trimmed();
            displayName = object.value("name").toString().trimmed().left(48);
        }
        else
        {
            contact = value.toString().trimmed();
        }
        if (!contact.isEmpty() && contact != m_currentUsername)
        {
            m_contacts.insert(contact);
            if (!displayName.isEmpty())
                m_contactDisplayNames.insert(contact, displayName);
        }
    }

    if (contacts.isEmpty())
    {
        for (auto it = m_conversations.begin(); it != m_conversations.end(); ++it)
        {
            m_contacts.insert(it.key());
        }
    }

    renderConversation(QString());
}

void MainWindow::saveConversations() const
{
    if (m_currentUsername.isEmpty())
    {
        return;
    }

    const QString path = historyFilePath();
    QDir().mkpath(QFileInfo(path).absolutePath());

    QJsonObject chats;
    for (auto it = m_conversations.begin(); it != m_conversations.end(); ++it)
    {
        QJsonArray messages;
        for (const ChatLine &line : it.value())
        {
            QJsonObject object;
            object.insert("sender", line.sender);
            object.insert("message", line.message);
            object.insert("time", line.time);
            object.insert("id", line.id);
            object.insert("status", line.status);
            object.insert("mine", line.mine);
            messages.append(object);
        }
        chats.insert(it.key(), messages);
    }

    QJsonObject root;
    root.insert("user", m_currentUsername);
    root.insert("chats", chats);
    QJsonArray contacts;
    QStringList contactIds = m_contacts.values();
    std::sort(contactIds.begin(), contactIds.end(), [this](const QString &left, const QString &right) {
        return QString::compare(contactDisplayName(left), contactDisplayName(right), Qt::CaseInsensitive) < 0;
    });
    for (const QString &contact : contactIds)
    {
        QJsonObject object;
        object.insert("id", contact);
        const QString displayName = m_contactDisplayNames.value(contact).trimmed();
        if (!displayName.isEmpty() && displayName != contact)
            object.insert("name", displayName);
        contacts.append(object);
    }
    root.insert("contacts", contacts);

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        return;
    }

    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    file.close();
    QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
}

QString MainWindow::contactDisplayName(const QString &contactId) const
{
    const QString displayName = m_contactDisplayNames.value(contactId).trimmed();
    return displayName.isEmpty() ? contactId : displayName;
}

QString MainWindow::historyFilePath() const
{
    QString basePath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (basePath.isEmpty())
    {
        basePath = QDir::homePath() + "/.tcp_messenger";
    }

    const QString safeUser = QString::fromLatin1(QUrl::toPercentEncoding(m_currentUsername));
    return QDir(basePath).filePath("history_" + safeUser + ".json");
}

QString MainWindow::selectedPeer() const
{
    return m_selectedPeer;
}

void MainWindow::log(const QString &message, const QString &sender)
{
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    QString logEntry;

    if (sender.isEmpty() || sender == "SERVER")
    {
        logEntry = QString("[%1] %2").arg(timestamp, message);
    }
    else
    {
        logEntry = QString("[%1] %2: %3").arg(timestamp, sender, message);
    }

    ui->textEdit->append(logEntry);
}

void MainWindow::logSystem(const QString &message)
{
    log(">>> " + message);
}

void MainWindow::logError(const QString &message)
{
    log("❌ " + message);
}

bool MainWindow::isConnected() const
{
    return m_socket && m_socket->state() == QAbstractSocket::ConnectedState && m_socket->isEncrypted();
}
