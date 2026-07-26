#include "chatlistdelegate.h"
#include "designtokens.h"

#include <QApplication>
#include <QPainter>

ChatListDelegate::ChatListDelegate(QObject *parent)
    : QStyledItemDelegate(parent)
{
}

QSize ChatListDelegate::sizeHint(const QStyleOptionViewItem &, const QModelIndex &) const
{
    return QSize(280, DesignTokens::metrics().chatRowHeight);
}

void ChatListDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    painter->save();
    painter->setRenderHint(QPainter::Antialiasing);

    const auto colors = DesignTokens::colors(option.palette);
    const bool selected = option.state & QStyle::State_Selected;
    const bool hovered = option.state & QStyle::State_MouseOver;
    const bool focused = option.state & QStyle::State_HasFocus;

    QRect rowRect = option.rect.adjusted(8, 3, -8, -3);
    QColor background;
    if (selected)
        background = colors.selectedBackground;
    else if (hovered)
        background = colors.hoverBackground;

    if (background.isValid())
    {
        painter->setPen(Qt::NoPen);
        painter->setBrush(background);
        painter->drawRoundedRect(rowRect, 9, 9);
    }

    if (focused)
    {
        painter->setPen(QPen(colors.accentColor, 1));
        painter->setBrush(Qt::NoBrush);
        painter->drawRoundedRect(rowRect.adjusted(1, 1, -1, -1), 8, 8);
    }

    const QString name = index.data(ChatListRoles::NameRole).toString();
    const QString preview = index.data(ChatListRoles::PreviewRole).toString();
    const QString time = index.data(ChatListRoles::TimeRole).toString();
    const bool online = index.data(ChatListRoles::OnlineRole).toBool();
    const int unread = index.data(ChatListRoles::UnreadRole).toInt();
    const QIcon icon = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));

    const int avatarSize = DesignTokens::metrics().avatarSize;
    const QRect avatarRect(rowRect.left() + 10, rowRect.top() + (rowRect.height() - avatarSize) / 2, avatarSize, avatarSize);
    icon.paint(painter, avatarRect);

    const int textLeft = avatarRect.right() + 12;
    const int rightInset = unread > 0 ? 42 : 8;
    QRect nameRect(textLeft, rowRect.top() + 11, rowRect.width() - textLeft + rowRect.left() - rightInset, 20);
    QRect previewRect(textLeft, rowRect.top() + 35, rowRect.width() - textLeft + rowRect.left() - rightInset, 18);
    QRect timeRect(rowRect.right() - 56, rowRect.top() + 12, 48, 16);

    QColor primary = selected ? option.palette.color(QPalette::HighlightedText) : colors.labelPrimary;
    QColor secondary = selected ? option.palette.color(QPalette::HighlightedText) : colors.labelSecondary;
    if (selected)
        secondary.setAlpha(210);

    QFont nameFont = option.font;
    nameFont.setPointSize(14);
    nameFont.setWeight(unread > 0 ? QFont::DemiBold : QFont::Medium);
    painter->setFont(nameFont);
    painter->setPen(primary);
    painter->drawText(nameRect, Qt::AlignVCenter | Qt::AlignLeft, option.fontMetrics.elidedText(name, Qt::ElideRight, nameRect.width()));

    QFont captionFont = option.font;
    captionFont.setPointSize(12);
    painter->setFont(captionFont);
    painter->setPen(secondary);
    painter->drawText(previewRect, Qt::AlignVCenter | Qt::AlignLeft, option.fontMetrics.elidedText(preview, Qt::ElideRight, previewRect.width()));
    painter->drawText(timeRect, Qt::AlignTop | Qt::AlignRight, time);

    if (online)
    {
        painter->setPen(QPen(colors.sidebarBackground, 2));
        painter->setBrush(colors.onlineStatusColor);
        painter->drawEllipse(QPoint(avatarRect.right() - 3, avatarRect.bottom() - 4), 5, 5);
    }

    if (unread > 0)
    {
        QRect badgeRect(rowRect.right() - 31, rowRect.top() + 34, 22, 18);
        painter->setPen(Qt::NoPen);
        painter->setBrush(selected ? option.palette.color(QPalette::HighlightedText) : colors.accentColor);
        painter->drawRoundedRect(badgeRect, 9, 9);
        painter->setPen(selected ? colors.accentColor : option.palette.color(QPalette::HighlightedText));
        QFont badgeFont = option.font;
        badgeFont.setPointSize(10);
        badgeFont.setBold(true);
        painter->setFont(badgeFont);
        painter->drawText(badgeRect, Qt::AlignCenter, QString::number(qMin(unread, 99)));
    }

    painter->restore();
}
