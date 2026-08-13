#ifndef AUTHDIALOG_H
#define AUTHDIALOG_H

#include <QDialog>

class QLabel;
class QLineEdit;
class QPushButton;
class QTabWidget;

class AuthDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AuthDialog(QWidget *parent = nullptr);

    void setBusy(bool busy);
    void showError(const QString &message);
    void showInfo(const QString &message);

signals:
    void loginRequested(const QString &username, const QString &password);
    void registerRequested(const QString &username, const QString &password);

private slots:
    void requestLogin();
    void requestRegistration();

protected:
    void changeEvent(QEvent *event) override;

private:
    bool validateCredentials(const QString &username, const QString &password, const QString &passwordConfirm = QString());
    QWidget *createLoginPage();
    QWidget *createRegisterPage();

    QTabWidget *m_tabs;
    QLabel *m_statusLabel;
    QLineEdit *m_loginNameEdit;
    QLineEdit *m_loginPasswordEdit;
    QLineEdit *m_registerNameEdit;
    QLineEdit *m_registerPasswordEdit;
    QLineEdit *m_registerPasswordConfirmEdit;
    QPushButton *m_loginButton;
    QPushButton *m_registerButton;
    bool m_applyingTheme = false;
};

#endif // AUTHDIALOG_H
