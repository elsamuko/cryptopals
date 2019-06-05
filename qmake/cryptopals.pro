MAIN_DIR =..
DESTDIR=$${MAIN_DIR}/bin
SRC_DIR  =../src
INCLUDEPATH += $${SRC_DIR}

SOURCES += $${SRC_DIR}/cryptopals.cpp

HEADERS += $${SRC_DIR}/utils.hpp
SOURCES += $${SRC_DIR}/utils.cpp
HEADERS += $${SRC_DIR}/log.hpp
SOURCES += $${SRC_DIR}/log.cpp

include( setup.pri )
include( openssl.pri )
linux: include( linux.pri )
win32: include( win.pri )
macx:  include( mac.pri )
