#include "mainwindow.h"
#include <QApplication>
#include <QDebug>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("LocalMessenger");
    QCoreApplication::setApplicationName("Messenger");

    MainWindow w;
    if (!w.showAuthDialog())
    {
        return 0;
    }

    w.show();

    qInfo() << "Мессенджер клиент запущен";

    return app.exec();
}
