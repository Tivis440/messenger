#ifndef CHATLISTDELEGATE_H
#define CHATLISTDELEGATE_H

#include <QStyledItemDelegate>

namespace ChatListRoles
{
    enum Role
    {
        NameRole = Qt::UserRole + 10,
        PreviewRole,
        TimeRole,
        OnlineRole,
        UnreadRole
    };
}

class ChatListDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    explicit ChatListDelegate(QObject *parent = nullptr);

    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override;
    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
};

#endif // CHATLISTDELEGATE_H
