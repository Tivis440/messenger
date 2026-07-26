#ifndef DESIGNTOKENS_H
#define DESIGNTOKENS_H

#include <QColor>
#include <QPalette>
#include <QString>

class DesignTokens
{
public:
    struct Colors
    {
        QColor backgroundPrimary;
        QColor backgroundSecondary;
        QColor backgroundElevated;
        QColor sidebarBackground;
        QColor contentBackground;
        QColor selectedBackground;
        QColor hoverBackground;
        QColor separatorColor;
        QColor labelPrimary;
        QColor labelSecondary;
        QColor labelTertiary;
        QColor accentColor;
        QColor destructiveColor;
        QColor successColor;
        QColor warningColor;
        QColor messageOutgoingBackground;
        QColor messageIncomingBackground;
        QColor onlineStatusColor;
    };

    struct Metrics
    {
        int spacingSmall = 6;
        int spacingMedium = 10;
        int spacingLarge = 16;
        int componentHeight = 32;
        int chatRowHeight = 68;
        int avatarSize = 40;
        int radiusSmall = 8;
        int radiusMedium = 10;
        int radiusLarge = 14;
        int animationFastMs = 120;
        int animationDefaultMs = 180;
        qreal disabledOpacity = 0.48;
        qreal separatorOpacity = 0.36;
    };

    static Colors colors(const QPalette &palette);
    static Metrics metrics();
    static QColor avatarColor(const QString &seed, const QPalette &palette);
    static QString appStyleSheet(const QPalette &palette);
    static QString authStyleSheet(const QPalette &palette);
    static QString messageBubbleStyle(const QPalette &palette, bool outgoing);
    static QString emptyStateStyle(const QPalette &palette);
};

#endif // DESIGNTOKENS_H
