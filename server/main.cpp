#include <QCoreApplication>
#include <QCommandLineParser>
#include <QDebug>
#include "server.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("Мессенджер сервер");
    QCoreApplication::setApplicationVersion("1.0");

    QCommandLineParser parser;
    parser.setApplicationDescription("Сервер мессенджера");
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption({{"p", "port"}, "Порт сервера.", "port", QString::number(Protocol::DEFAULT_PORT)});
    parser.addOption({{"d", "data-dir"}, "Папка для users.json, prekey_bundles.json, offline_messages.json и TLS-сертификатов.", "path"});
    parser.process(app);

    bool portOk = false;
    const int requestedPort = parser.value("port").toInt(&portOk);
    const quint16 port = portOk && requestedPort > 0 && requestedPort <= 65535
                             ? static_cast<quint16>(requestedPort)
                             : Protocol::DEFAULT_PORT;

    Server server(parser.value("data-dir"));
    if (!server.startServer(port))
    {
        qCritical() << "Не удалось запустить сервер!";
        return 1;
    }

    qInfo() << "================================";
    qInfo() << "Мессенджер TCP сервер";
    qInfo() << "Порт:" << port;
    qInfo() << "Статус: ЗАПУЩЕН";
    qInfo() << "================================";

    return app.exec();
}
