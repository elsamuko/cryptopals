#!/usr/bin/env bash

case $(uname) in
    Linux)
        OS=linux
        ;;
    Darwin)
        OS=mac
        ;;
    CYGWIN*)
        OS=win
        ;;
    *)
        echo "Unknown OS" && exit 1
        ;;
esac

PROJECT=openssl
VERSION="1.1.1c"
DL_URL="https://www.openssl.org/source/openssl-$VERSION.tar.gz"

SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
MAIN_DIR="$SCRIPT_DIR/.."
TARGET_DIR="$MAIN_DIR/libs/$PROJECT"
PROJECT_DIR="$MAIN_DIR/tmp/$PROJECT"
DOWNLOAD="$PROJECT_DIR/$PROJECT-$VERSION.tar.gz"
SRC_DIR="$PROJECT_DIR/src"
BUILD_DIR="$SRC_DIR/$PROJECT-$VERSION"

function indent {
    sed  's/^/     /'
}

function doPrepare {
    if [ -d "$SRC_DIR" ]; then
        rm -rf "$SRC_DIR"
    fi
    if [ -d "$TARGET_DIR" ]; then
        rm -rf "$TARGET_DIR"
    fi
    mkdir -p "$PROJECT_DIR"
    mkdir -p "$TARGET_DIR"
    mkdir -p "$SRC_DIR"
}

function doDownload {
    if [ ! -f "$DOWNLOAD" ]; then
        curl -s -L "$DL_URL" -o "$DOWNLOAD" 2>&1
    fi
}

function doUnzip {
    tar xzf "$DOWNLOAD" -C "$SRC_DIR"
}

function doConfigure {
    ./Configure > "$PROJECT_DIR/options.txt"
    case "$1" in
        'd'*)
            ./Configure no-shared threads debug-linux-x86_64 --prefix="$BUILD_DIR/$1"
            ;;
        'r'*)
            ./Configure no-shared threads linux-x86_64 --prefix="$BUILD_DIR/$1"
            ;;
        *)
            echo "Error in $LINENO : \$1 is $1"
            ;;
    esac
}

function doBuild {
    cd "$SRC_DIR/$PROJECT-$VERSION"

    # debug
    (export CXXFLAGS="-g -O0"; \
    export CFLAGS="-g -O0"; \
    doConfigure release)
    make depend
    make -j8
    make install_sw

    # release
    (export CXXFLAGS="-msse2 -Ofast -finline -ffast-math -funsafe-math-optimizations"; \
    export CFLAGS="-msse2 -Ofast -finline -ffast-math -funsafe-math-optimizations"; \
    doConfigure debug)
    make depend
    make -j8
    make install_sw
}

function doCopy {
    mkdir -p "$TARGET_DIR/bin/$OS/debug"
    mkdir -p "$TARGET_DIR/bin/$OS/release"
    mkdir -p "$TARGET_DIR/include"
    cp -r "$BUILD_DIR/debug/lib/libcrypto.a" "$TARGET_DIR/bin/$OS/debug/libcrypto.a"
    cp -r "$BUILD_DIR/debug/lib/libssl.a" "$TARGET_DIR/bin/$OS/debug/libssl.a"
    cp -r "$BUILD_DIR/release/lib/libcrypto.a" "$TARGET_DIR/bin/$OS/release/libcrypto.a"
    cp -r "$BUILD_DIR/release/lib/libssl.a" "$TARGET_DIR/bin/$OS/release/libssl.a"
    cp -r "$BUILD_DIR/release/include"/* "$TARGET_DIR/include"
}


echo "Prepare"
doPrepare | indent

echo "Download"
doDownload | indent

echo "Unzip"
doUnzip | indent

echo "Build"
doBuild 2>&1 | indent

echo "Copy"
doCopy | indent
