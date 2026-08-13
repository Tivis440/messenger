#include "designtokens.h"

static QString colorName(const QColor &color)
{
    return color.name(QColor::HexRgb);
}

static bool isDarkPalette(const QPalette &palette)
{
    return palette.color(QPalette::Window).lightness() < 128;
}

DesignTokens::Colors DesignTokens::colors(const QPalette &palette)
{
    const bool dark = isDarkPalette(palette);
    const QColor accent = palette.color(QPalette::Highlight);

    Colors c;
    c.backgroundPrimary = palette.color(QPalette::Window);
    c.backgroundSecondary = dark ? QColor("#17171A") : QColor("#F5F5F7");
    c.backgroundElevated = dark ? QColor("#242428") : QColor("#FFFFFF");
    c.sidebarBackground = dark ? QColor("#1C1C1E") : QColor("#F2F2F7");
    c.contentBackground = dark ? QColor("#111113") : QColor("#FFFFFF");
    c.selectedBackground = accent;
    c.hoverBackground = dark ? QColor("#2C2C2E") : QColor("#E9E9ED");
    c.separatorColor = palette.color(QPalette::Mid);
    c.labelPrimary = palette.color(QPalette::WindowText);
    c.labelSecondary = dark ? QColor("#A1A1A6") : QColor("#6E6E73");
    c.labelTertiary = dark ? QColor("#77777D") : QColor("#8E8E93");
    c.accentColor = accent;
    c.destructiveColor = QColor("#FF453A");
    c.successColor = QColor("#32D74B");
    c.warningColor = QColor("#FFD60A");
    c.messageOutgoingBackground = accent;
    c.messageIncomingBackground = dark ? QColor("#2C2C2E") : QColor("#E9E9EB");
    c.onlineStatusColor = QColor("#30D158");
    return c;
}

DesignTokens::Metrics DesignTokens::metrics()
{
    return Metrics{};
}

QColor DesignTokens::avatarColor(const QString &seed, const QPalette &palette)
{
    const Colors c = colors(palette);
    const QList<QColor> avatarColors = {
        c.accentColor,
        c.successColor,
        c.warningColor,
        c.destructiveColor,
        c.accentColor.lighter(124),
        c.labelSecondary
    };

    const uint hash = qHash(seed);
    return avatarColors.at(static_cast<int>(hash % avatarColors.size()));
}

QString DesignTokens::appStyleSheet(const QPalette &palette)
{
    const Colors c = colors(palette);
    return QString(
               "QMainWindow, QWidget#centralwidget {"
               "  background: %1;"
               "  color: %2;"
               "  font-family: -apple-system, 'SF Pro Text';"
               "  font-size: 13px;"
               "}"
               "QWidget#sidePanel {"
               "  background: %3;"
               "  border-right: 1px solid %4;"
               "}"
               "QWidget#chatPanel, QListWidget#messageList {"
               "  background: %5;"
               "}"
               "QWidget#chatHeader, QWidget#composerPanel {"
               "  background: %6;"
               "}"
               "QWidget#chatHeader { border-bottom: 1px solid %4; }"
               "QWidget#composerPanel { border-top: 1px solid %4; }"
               "QSplitter::handle { background: %4; width: 1px; }"
               "QLabel#brandLabel { color: %2; font-size: 16px; font-weight: 700; }"
               "QLabel#chatTitle { color: %2; font-size: 17px; font-weight: 700; }"
               "QLabel#chatStatus { color: %7; font-size: 12px; font-weight: 500; }"
               "QLabel#securityBadge {"
               "  background: transparent;"
               "  color: %7;"
               "  border: 1px solid %4;"
               "  border-radius: 9px;"
               "  padding: 4px 9px;"
               "  font-size: 11px;"
               "}"
               "QLabel { color: %2; }"
               "QListWidget { background: transparent; border: none; outline: none; }"
               "QListWidget#messageList { border: none; padding: 10px 0; }"
               "QListWidget#messageList::item { border: none; padding: 1px 0; }"
               "QLineEdit {"
               "  background: %8;"
               "  border: 1px solid %4;"
               "  border-radius: 9px;"
               "  color: %2;"
               "  padding: 8px 11px;"
               "  min-height: 25px;"
               "}"
               "QLineEdit#contactSearch { margin: 0 16px 4px 16px; }"
               "QLineEdit:focus { border: 1px solid %9; }"
               "QLineEdit:disabled { color: %10; }"
               "QPushButton {"
               "  background: %9;"
               "  border: 1px solid %9;"
               "  border-radius: 8px;"
               "  color: %11;"
               "  padding: 7px 12px;"
               "  min-height: 28px;"
               "  font-weight: 600;"
               "}"
               "QPushButton:hover { background: %12; }"
               "QPushButton:disabled { background: %8; color: %10; border-color: %4; }"
               "QPushButton#contactToolButton, QPushButton#profileButton {"
               "  background: transparent;"
               "  color: %7;"
               "  border: 1px solid %4;"
               "  min-height: 28px;"
               "}"
               "QPushButton#contactToolButton { min-width: 30px; max-width: 30px; padding: 0; font-size: 16px; }"
               "QPushButton#profileButton { min-width: 42px; padding: 0 10px; }"
               "QPushButton#contactToolButton:hover, QPushButton#profileButton:hover { color: %2; border-color: %9; }"
               "QPushButton#buttonSend { min-width: 76px; }"
               "QStatusBar { background: %1; color: %7; }"
               "QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }"
               "QScrollBar::handle:vertical { background: %4; border-radius: 5px; min-height: 28px; }"
               "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }"
               "QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }")
        .arg(colorName(c.backgroundPrimary),
             colorName(c.labelPrimary),
             colorName(c.sidebarBackground),
             colorName(c.separatorColor),
             colorName(c.contentBackground),
             colorName(c.backgroundElevated),
             colorName(c.labelSecondary),
             colorName(c.backgroundSecondary),
             colorName(c.accentColor),
             colorName(c.labelTertiary),
             colorName(palette.color(QPalette::HighlightedText)),
             colorName(c.accentColor.lighter(112)),
             colorName(c.destructiveColor));
}

QString DesignTokens::authStyleSheet(const QPalette &palette)
{
    const Colors c = colors(palette);
    return appStyleSheet(palette) +
           QString("QDialog { background: %1; color: %2; }"
                   "QLabel#authTitle { color: %2; font-size: 25px; font-weight: 700; }"
                   "QLabel#authSubtitle, QLabel#authStatus { color: %3; font-size: 13px; }"
                   "QDialog QLineEdit { min-height: 28px; }"
                   "QDialog QPushButton { min-height: 32px; }"
                   "QTabWidget::pane { border: 1px solid %4; border-radius: 12px; background: %5; margin-top: 8px; }"
                   "QTabBar::tab { background: %1; border: 1px solid %4; color: %3; padding: 7px 18px; min-width: 128px; }"
                   "QTabBar::tab:first { border-top-left-radius: 8px; border-bottom-left-radius: 8px; }"
                   "QTabBar::tab:last { border-top-right-radius: 8px; border-bottom-right-radius: 8px; }"
                   "QTabBar::tab:selected { background: %5; color: %2; border-color: %6; font-weight: 600; }")
               .arg(colorName(c.backgroundPrimary),
                    colorName(c.labelPrimary),
                    colorName(c.labelSecondary),
                    colorName(c.separatorColor),
                    colorName(c.backgroundElevated),
                    colorName(c.accentColor));
}

QString DesignTokens::messageBubbleStyle(const QPalette &palette, bool outgoing)
{
    const Colors c = colors(palette);
    const QColor text = outgoing ? palette.color(QPalette::HighlightedText) : c.labelPrimary;
    const QColor bg = outgoing ? c.messageOutgoingBackground : c.messageIncomingBackground;
    return QString("QLabel { background: %1; color: %2; border-radius: 14px; padding: 9px 13px; }")
        .arg(colorName(bg), colorName(text));
}

QString DesignTokens::emptyStateStyle(const QPalette &palette)
{
    const Colors c = colors(palette);
    return QString("color: %1; padding: 32px; font-size: 14px; font-weight: 500;")
        .arg(colorName(c.labelSecondary));
}
