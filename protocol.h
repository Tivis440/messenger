#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <QString>
#include <QDataStream>

// Константы протокола
namespace Protocol
{
    // Версия протокола
    const int VERSION = 1;

    // Стандартные порты
    const quint16 DEFAULT_PORT = 5555;

    // Типы сообщений
    enum MessageType
    {
        MSG_AUTH = 0x01,          // Аутентификация (login)
        MSG_AUTH_RESPONSE = 0x02, // Ответ на аутентификацию
        MSG_TEXT = 0x03,          // Текстовое сообщение
        MSG_USER_LIST = 0x04,     // Список пользователей онлайн
        MSG_DISCONNECT = 0x05,    // Отключение
        MSG_HEARTBEAT = 0x06,     // Проверка соединения
        MSG_PRIVATE = 0x07        // Приватное сообщение
        ,
        MSG_REGISTER = 0x08 // Регистрация нового пользователя
        ,
        MSG_REGISTER_RESPONSE = 0x09, // Ответ на регистрацию
        MSG_STATUS = 0x0A,            // Статус приватного сообщения
        MSG_PREKEY_PUBLISH = 0x0B,    // Публикация Signal prekey bundle
        MSG_PREKEY_REQUEST = 0x0C,    // Запрос Signal prekey bundle
        MSG_PREKEY_RESPONSE = 0x0D    // Ответ с Signal prekey bundle
    };

    // Коды ответа
    enum ResponseCode
    {
        OK = 0x00,
        AUTH_FAILED = 0x01,
        USER_EXISTS = 0x02,
        INVALID_FORMAT = 0x03,
        SERVER_ERROR = 0x04,
        UNKNOWN_USER = 0x05
    };
}

// Структура сообщения
struct Message
{
    quint32 type;         // Тип сообщения
    QString sender;       // Отправитель
    QString receiver;     // Получатель (для приватных сообщений)
    QString content;      // Содержание
    QString id;           // Уникальный идентификатор сообщения
    quint64 timestamp;    // Временная метка
    quint32 responseCode; // Код ответа

    Message() : type(0), timestamp(0), responseCode(0) {}

    // Сериализация
    friend QDataStream &operator<<(QDataStream &out, const Message &msg)
    {
        out << msg.type
            << msg.sender
            << msg.receiver
            << msg.content
            << msg.id
            << msg.timestamp
            << msg.responseCode;
        return out;
    }

    // Десериализация
    friend QDataStream &operator>>(QDataStream &in, Message &msg)
    {
        in >> msg.type >> msg.sender >> msg.receiver >> msg.content >> msg.id >> msg.timestamp >> msg.responseCode;
        return in;
    }
};

#endif // PROTOCOL_H
