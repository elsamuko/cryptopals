MAIN_DIR =..
DESTDIR=$${MAIN_DIR}/bin
SRC_DIR  =../src
INCLUDEPATH += $${SRC_DIR}

SOURCES += $${SRC_DIR}/cryptopals.cpp

HEADERS += $${SRC_DIR}/utils.hpp
SOURCES += $${SRC_DIR}/utils.cpp
HEADERS += $${SRC_DIR}/crypto.hpp
SOURCES += $${SRC_DIR}/crypto.cpp
HEADERS += $${SRC_DIR}/aesni.hpp
HEADERS += $${SRC_DIR}/openssl.hpp
HEADERS += $${SRC_DIR}/random.hpp
HEADERS += $${SRC_DIR}/cracker.hpp
SOURCES += $${SRC_DIR}/cracker.cpp
HEADERS += $${SRC_DIR}/converter.hpp
SOURCES += $${SRC_DIR}/converter.cpp
HEADERS += $${SRC_DIR}/types.hpp
HEADERS += $${SRC_DIR}/log.hpp
SOURCES += $${SRC_DIR}/log.cpp

HEADERS += $${SRC_DIR}/set1.hpp
SOURCES += $${SRC_DIR}/set1.cpp
HEADERS += $${SRC_DIR}/set2.hpp
SOURCES += $${SRC_DIR}/set2.cpp

include( setup.pri )
# include( openssl.pri )
linux: include( linux.pri )
win32: include( win.pri )
macx:  include( mac.pri )
