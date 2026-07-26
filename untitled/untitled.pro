QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = messenger
CONFIG += c++17

SOURCES += \
    authdialog.cpp \
    chatlistdelegate.cpp \
    designtokens.cpp \
    main.cpp \
    mainwindow.cpp \
    signalmanager.cpp

HEADERS += \
    authdialog.h \
    chatlistdelegate.h \
    designtokens.h \
    mainwindow.h \
    signalmanager.h \
    ../protocol.h

macx {
    INCLUDEPATH += /opt/homebrew/include /usr/local/include
    LIBS += -L/opt/homebrew/lib -L/usr/local/lib -lsignal-protocol-c -lcrypto
    LIBS += -framework Security
}

unix:!macx {
    CONFIG += link_pkgconfig
    packagesExist(openssl) {
        PKGCONFIG += openssl
    } else {
        LIBS += -lcrypto
    }
    LIBS += -lsignal-protocol-c
}

win32 {
    isEmpty(SIGNAL_DIR) {
        SIGNAL_DIR = C:/signal-protocol-c
    }
    isEmpty(OPENSSL_DIR) {
        OPENSSL_DIR = C:/OpenSSL-Win64
    }
    INCLUDEPATH += $$SIGNAL_DIR/include $$OPENSSL_DIR/include
    msvc {
        LIBS += $$SIGNAL_DIR/lib/signal-protocol-c.lib $$OPENSSL_DIR/lib/libcrypto.lib
        LIBS += Crypt32.lib
    } else {
        LIBS += -L$$SIGNAL_DIR/lib -L$$OPENSSL_DIR/lib -lsignal-protocol-c -lcrypto
    }
}

FORMS += \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
