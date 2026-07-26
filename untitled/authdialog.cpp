#include "authdialog.h"
#include "designtokens.h"
#include "../protocol.h"

#include <QApplication>
#include <QEvent>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QTabWidget>
#include <QUuid>
#include <QVBoxLayout>

AuthDialog::AuthDialog(QWidget *parent)
    : QDialog(parent),
      m_tabs(new QTabWidget(this)),
      m_statusLabel(new QLabel(this)),
      m_loginNameEdit(nullptr),
      m_loginPasswordEdit(nullptr),
      m_registerNameEdit(nullptr),
      m_registerPasswordEdit(nullptr),
      m_registerPasswordConfirmEdit(nullptr),
      m_serverHostEdit(new QLineEdit(this)),
      m_serverPortSpin(new QSpinBox(this)),
      m_loginButton(nullptr),
      m_registerButton(nullptr)
{
    setWindowTitle("Мессенджер");
    setModal(true);
    setMinimumSize(460, 440);
    resize(460, 460);

    QLabel *title = new QLabel("Вход", this);
    title->setObjectName("authTitle");
    QLabel *subtitle = new QLabel("Вход в защищенные личные диалоги", this);
    subtitle->setObjectName("authSubtitle");
    subtitle->setAlignment(Qt::AlignCenter);
    subtitle->setWordWrap(true);
    title->setAlignment(Qt::AlignCenter);

    QSettings settings;
    m_serverHostEdit->setPlaceholderText("127.0.0.1");
    m_serverHostEdit->setText(settings.value("server/host", "127.0.0.1").toString());
    m_serverHostEdit->setAccessibleName("Адрес сервера");
    m_serverPortSpin->setRange(1, 65535);
    m_serverPortSpin->setValue(settings.value("server/port", Protocol::DEFAULT_PORT).toInt());
    m_serverPortSpin->setAccessibleName("Порт сервера");

    QFormLayout *serverForm = new QFormLayout;
    serverForm->setContentsMargins(0, 0, 0, 0);
    serverForm->setVerticalSpacing(10);
    serverForm->setHorizontalSpacing(14);
    serverForm->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    serverForm->addRow("Сервер", m_serverHostEdit);
    serverForm->addRow("Порт", m_serverPortSpin);

    m_tabs->addTab(createLoginPage(), "Вход");
    m_tabs->addTab(createRegisterPage(), "Регистрация");

    m_statusLabel->setObjectName("authStatus");
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setMinimumHeight(38);

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(34, 28, 34, 24);
    layout->setSpacing(14);
    layout->addWidget(title);
    layout->addWidget(subtitle);
    layout->addLayout(serverForm);
    layout->addWidget(m_tabs);
    layout->addWidget(m_statusLabel);

    const QString savedName = settings.value("lastLoginName",
                                             settings.value("publicId", settings.value("username"))).toString().trimmed();
    m_loginNameEdit->setText(savedName);

    setStyleSheet(DesignTokens::authStyleSheet(QApplication::palette()));
}

void AuthDialog::changeEvent(QEvent *event)
{
    QDialog::changeEvent(event);
    if (event->type() == QEvent::PaletteChange || event->type() == QEvent::ApplicationPaletteChange)
    {
        if (m_applyingTheme)
            return;
        m_applyingTheme = true;
        setStyleSheet(DesignTokens::authStyleSheet(QApplication::palette()));
        m_applyingTheme = false;
    }
}

QWidget *AuthDialog::createLoginPage()
{
    QWidget *page = new QWidget(this);
    m_loginNameEdit = new QLineEdit(page);
    m_loginPasswordEdit = new QLineEdit(page);
    m_loginButton = new QPushButton("Войти", page);
    m_loginButton->setDefault(true);

    m_loginNameEdit->setPlaceholderText("Например, @имя или nlk_...");
    m_loginPasswordEdit->setPlaceholderText("Пароль");
    m_loginPasswordEdit->setEchoMode(QLineEdit::Password);

    QLabel *hint = new QLabel("Введите @имя с этого устройства или публичный ID, созданный при регистрации.", page);
    hint->setObjectName("authSubtitle");
    hint->setWordWrap(true);

    QFormLayout *form = new QFormLayout;
    form->setContentsMargins(0, 14, 0, 8);
    form->setVerticalSpacing(12);
    form->setHorizontalSpacing(14);
    form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    form->addRow("ID или @имя", m_loginNameEdit);
    form->addRow("Пароль", m_loginPasswordEdit);

    QVBoxLayout *layout = new QVBoxLayout(page);
    layout->setContentsMargins(22, 20, 22, 18);
    layout->setSpacing(12);
    layout->addWidget(hint);
    layout->addLayout(form);
    layout->addSpacing(6);
    layout->addWidget(m_loginButton);
    layout->addStretch(1);

    connect(m_loginButton, &QPushButton::clicked, this, &AuthDialog::requestLogin);
    connect(m_loginPasswordEdit, &QLineEdit::returnPressed, this, &AuthDialog::requestLogin);
    connect(m_loginNameEdit, &QLineEdit::returnPressed, m_loginPasswordEdit, qOverload<>(&QWidget::setFocus));

    return page;
}

QWidget *AuthDialog::createRegisterPage()
{
    QWidget *page = new QWidget(this);
    m_registerNameEdit = new QLineEdit(page);
    m_registerPasswordEdit = new QLineEdit(page);
    m_registerPasswordConfirmEdit = new QLineEdit(page);
    m_registerButton = new QPushButton("Создать аккаунт", page);
    m_registerButton->setDefault(true);

    m_registerNameEdit->setText(generatePublicId());
    m_registerNameEdit->setReadOnly(true);
    m_registerNameEdit->setMinimumWidth(340);
    m_registerNameEdit->setCursorPosition(0);
    m_registerNameEdit->setToolTip("Это ваш случайный публичный ID. Его можно передать контакту для добавления.");
    m_registerPasswordEdit->setPlaceholderText("Пароль");
    m_registerPasswordConfirmEdit->setPlaceholderText("Повторите пароль");
    m_registerPasswordEdit->setEchoMode(QLineEdit::Password);
    m_registerPasswordConfirmEdit->setEchoMode(QLineEdit::Password);

    QLabel *hint = new QLabel("Мы создадим случайный публичный ID. Его можно будет передать человеку, чтобы он добавил вас в контакты.", page);
    hint->setObjectName("authSubtitle");
    hint->setWordWrap(true);

    QFormLayout *form = new QFormLayout;
    form->setContentsMargins(0, 14, 0, 8);
    form->setVerticalSpacing(12);
    form->setHorizontalSpacing(14);
    form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    form->addRow("Публичный ID", m_registerNameEdit);
    form->addRow("Пароль", m_registerPasswordEdit);
    form->addRow("Еще раз", m_registerPasswordConfirmEdit);

    QVBoxLayout *layout = new QVBoxLayout(page);
    layout->setContentsMargins(22, 20, 22, 18);
    layout->setSpacing(12);
    layout->addWidget(hint);
    layout->addLayout(form);
    layout->addSpacing(6);
    layout->addWidget(m_registerButton);
    layout->addStretch(1);

    connect(m_registerButton, &QPushButton::clicked, this, &AuthDialog::requestRegistration);
    connect(m_registerPasswordConfirmEdit, &QLineEdit::returnPressed, this, &AuthDialog::requestRegistration);

    return page;
}

void AuthDialog::requestLogin()
{
    const QString loginName = m_loginNameEdit->text().trimmed();
    const QString username = resolveLoginName(loginName);
    const QString password = m_loginPasswordEdit->text();

    if (!validateCredentials(username, password))
    {
        return;
    }

    QSettings settings;
    settings.setValue("server/host", m_serverHostEdit->text().trimmed().isEmpty() ? "127.0.0.1" : m_serverHostEdit->text().trimmed());
    settings.setValue("server/port", m_serverPortSpin->value());
    settings.setValue("lastLoginName", loginName);

    showInfo("Подключение к серверу...");
    emit loginRequested(username, password);
}

void AuthDialog::requestRegistration()
{
    const QString username = m_registerNameEdit->text().trimmed();
    const QString password = m_registerPasswordEdit->text();
    const QString passwordConfirm = m_registerPasswordConfirmEdit->text();

    if (!validateCredentials(username, password, passwordConfirm))
    {
        return;
    }

    QSettings settings;
    settings.setValue("server/host", m_serverHostEdit->text().trimmed().isEmpty() ? "127.0.0.1" : m_serverHostEdit->text().trimmed());
    settings.setValue("server/port", m_serverPortSpin->value());

    showInfo("Создаем анонимный ID...");
    emit registerRequested(username, password);
}

QString AuthDialog::generatePublicId() const
{
    QString random = QUuid::createUuid().toString(QUuid::WithoutBraces).remove('-').left(20).toUpper();
    return "nlk_" + random;
}

QString AuthDialog::resolveLoginName(const QString &input) const
{
    QString loginName = input.trimmed();
    if (!loginName.startsWith('@'))
        return loginName;

    loginName = loginName.left(48);
    const QString mappedId = QSettings().value("handleAliases/" + loginName.toLower()).toString().trimmed();
    return mappedId.isEmpty() ? loginName : mappedId;
}

bool AuthDialog::validateCredentials(const QString &username, const QString &password, const QString &passwordConfirm)
{
    if (username.isEmpty())
    {
        showError("Введите публичный ID или сохраненное @имя.");
        return false;
    }

    if (passwordConfirm.isNull() && username.startsWith('@'))
    {
        showError("Этот @ник еще не привязан к профилю на этом устройстве. Войдите по публичному ID.");
        return false;
    }

    if (username.length() > 64)
    {
        showError("Публичный ID слишком длинный.");
        return false;
    }

    for (const QChar ch : username)
    {
        const bool allowed = ch.isLetterOrNumber() || ch == '_' || ch == '-' || ch == '.';
        if (!allowed)
        {
            showError("Публичный ID содержит недопустимые символы.");
            return false;
        }
    }

    if (!passwordConfirm.isNull() && (!username.startsWith("nlk_") || username.length() != 24))
    {
        showError("Регистрация использует только автоматически созданный публичный ID.");
        return false;
    }

    if (password.isEmpty())
    {
        showError("Введите пароль.");
        return false;
    }

    if (!passwordConfirm.isNull() && password.length() < 8)
    {
        showError("Пароль должен быть не короче 8 символов.");
        return false;
    }

    if (!passwordConfirm.isNull() && password != passwordConfirm)
    {
        showError("Пароли не совпадают.");
        return false;
    }

    return true;
}

void AuthDialog::setBusy(bool busy)
{
    m_tabs->setEnabled(!busy);
    m_loginButton->setEnabled(!busy);
    m_registerButton->setEnabled(!busy);
    setCursor(busy ? Qt::WaitCursor : Qt::ArrowCursor);
}

void AuthDialog::showError(const QString &message)
{
    const auto colors = DesignTokens::colors(QApplication::palette());
    m_statusLabel->setStyleSheet(QString("color: %1; font-size: 13px; font-weight: 600;")
                                     .arg(colors.destructiveColor.name(QColor::HexRgb)));
    m_statusLabel->setText(message);
    setBusy(false);
}

void AuthDialog::showInfo(const QString &message)
{
    const auto colors = DesignTokens::colors(QApplication::palette());
    m_statusLabel->setStyleSheet(QString("color: %1; font-size: 13px; font-weight: 600;")
                                     .arg(colors.accentColor.name(QColor::HexRgb)));
    m_statusLabel->setText(message);
    setBusy(true);
}
