OPENSSL_DIR = $${MAIN_DIR}/libs/openssl
OPENSSL_BIN_DIR = $${OPENSSL_DIR}/bin/$${PLATFORM}/$${COMPILE_MODE}

INCLUDEPATH += $${OPENSSL_DIR}/include

win32 {
    LIBS += $${OPENSSL_BIN_DIR}/libssl.lib
    LIBS += $${OPENSSL_BIN_DIR}/libcrypto.lib
} else {
    LIBS += $${OPENSSL_BIN_DIR}/libssl.a
    LIBS += $${OPENSSL_BIN_DIR}/libcrypto.a
}
