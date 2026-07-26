QT = core network

CONFIG += c++17 cmdline

macx {
    INCLUDEPATH += /opt/homebrew/include /usr/local/include
    LIBS += -L/opt/homebrew/lib -L/usr/local/lib -largon2
}

unix:!macx {
    CONFIG += link_pkgconfig
    packagesExist(libargon2) {
        PKGCONFIG += libargon2
    } else {
        LIBS += -largon2
    }
}

win32 {
    isEmpty(ARGON2_DIR) {
        ARGON2_DIR = C:/argon2
    }
    INCLUDEPATH += $$ARGON2_DIR/include
    msvc {
        LIBS += $$ARGON2_DIR/lib/argon2.lib
    } else {
        LIBS += -L$$ARGON2_DIR/lib -largon2
    }
}

SOURCES += \
        main.cpp \
        server.cpp

HEADERS += \
    server.h \
    ../protocol.h

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
