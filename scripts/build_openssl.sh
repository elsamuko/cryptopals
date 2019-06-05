#!/usr/bin/env bash

if [[ "$BASH_VERSION" == 3.* ]]; then
    echo "Use bash 4 or later, try"
    echo "/usr/local/bin/bash ${BASH_SOURCE[0]}"
    exit 1
fi

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
BUILD_HELPER="$BUILD_DIR/build.bat"

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

function doConfigureLinux {
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

function doConfigureWin {
    local WBUILD_DIR="$(cygpath -w "$BUILD_DIR")"
    perl Configure > "$PROJECT_DIR/options.txt"
    case "$1" in 
        'd'*)
			echo "perl Configure no-asm no-shared threads debug-VC-WIN64A --openssldir=\"$WBUILD_DIR\\$1\" --prefix=\"$WBUILD_DIR\\$1\""
            perl Configure no-asm no-shared threads debug-VC-WIN64A --openssldir="$WBUILD_DIR\\$1" --prefix="$WBUILD_DIR\\$1"
            ;;
        'r'*)
			echo "perl Configure no-shared threads VC-WIN64A --openssldir=\"$WBUILD_DIR\\$1\" --prefix=\"$WBUILD_DIR\\$1\""
            perl Configure no-asm no-shared threads VC-WIN64A --openssldir="$WBUILD_DIR\\$1" --prefix="$WBUILD_DIR\\$1"
            ;;
        *)
            echo "Error in $LINENO : \$1 is $1"
            ;;
    esac
}

function doConfigureMac {
    ./Configure > "$PROJECT_DIR/options.txt"
    case "$1" in
        'd'*)
            ./Configure no-shared zlib threads debug-darwin64-x86_64-cc --prefix="$BUILD_DIR/$1"
            ;;
        'r'*)
            ./Configure no-shared zlib threads darwin64-x86_64-cc --prefix="$BUILD_DIR/$1"
            ;;
        *)
            echo "Error in $LINENO : \$1 is $1"
            ;;
    esac
}

function doBuildLinux {
    cd "$SRC_DIR/$PROJECT-$VERSION"

    # debug
    (export CXXFLAGS="-g -O0"; \
    export CFLAGS="-g -O0"; \
    doConfigureLinux release)
    make depend
    make -j8
    make install_sw

    # release
    (export CXXFLAGS="-msse2 -Ofast -finline -ffast-math -funsafe-math-optimizations"; \
    export CFLAGS="-msse2 -Ofast -finline -ffast-math -funsafe-math-optimizations"; \
    doConfigureLinux debug)
    make depend
    make -j8
    make install_sw
}

function createHelperWin {
    local VERSIONS=("2019" "2017")
    local EDITIONS=("BuildTools" "Community" "Professional" "Enterprise")

    for VERSION in "${VERSIONS[@]}"; do
        for EDITION in "${EDITIONS[@]}"; do
            local VCVARS_DIR="C:/Program Files (x86)/Microsoft Visual Studio/$VERSION/$EDITION/VC/Auxiliary/Build"
            if [ -d "$VCVARS_DIR" ]; then
                export VSNEWCOMNTOOLS="${VCVARS_DIR////\\}"
                break 2
            fi
        done
    done

    echo -ne '@echo off\r\n' > "$HELPER"
    echo -ne "call \"$VSNEWCOMNTOOLS\\\\vcvars64.bat\"\r\n" >> "$BUILD_HELPER"
	echo -ne 'nmake vclean\r\n' >> "$BUILD_HELPER"
	echo -ne 'nmake \r\n' >> "$BUILD_HELPER"
	echo -ne 'nmake install\r\n' >> "$BUILD_HELPER"

    chmod +x "$BUILD_HELPER"
}

function doBuildWin {
    cd "$SRC_DIR/$PROJECT-$VERSION"
	
    # debug
    doConfigureWin debug
	createHelperWin
	"$BUILD_HELPER"

    # release
    doConfigureWin release
	createHelperWin
	"$BUILD_HELPER"
}

function doBuildMac {
    cd "$SRC_DIR/$PROJECT-$VERSION"

    export CC="clang"
    export CXX="clang++"
    export LDFLAGS="-L/opt/local/lib -lc++"
    export CPPFLAGS="-I/opt/local/include"
    export CXXFLAGS="-std=c++11 -stdlib=libc++ -mmacosx-version-min=10.10"
    export CFLAGS="-I/opt/local/include -mmacosx-version-min=10.10"

    # debug
    (export CXXFLAGS="$CXXFLAGS -g -O0"; \
    export CFLAGS="$CFLAGS -g -O0"; \
    doConfigureMac release)
    make depend
    make -j8
    make install_sw

    # release
    (export CXXFLAGS="$CXXFLAGS -msse2 -Ofast -finline -ffast-math -funsafe-math-optimizations"; \
    export CFLAGS="$CFLAGS -msse2 -Ofast -finline -ffast-math -funsafe-math-optimizations"; \
    doConfigureMac debug)
    make depend
    make -j8
    make install_sw
}

function doCopy {
    mkdir -p "$TARGET_DIR/bin/$OS/debug"
    mkdir -p "$TARGET_DIR/bin/$OS/release"
    mkdir -p "$TARGET_DIR/include"
    cp -r "$BUILD_DIR/debug/lib/libcrypto."* "$TARGET_DIR/bin/$OS/debug/"
    cp -r "$BUILD_DIR/debug/lib/libssl."* "$TARGET_DIR/bin/$OS/debug/"
    cp -r "$BUILD_DIR/release/lib/libcrypto."* "$TARGET_DIR/bin/$OS/release/"
    cp -r "$BUILD_DIR/release/lib/libssl."* "$TARGET_DIR/bin/$OS/release/"
    cp -r "$BUILD_DIR/release/include"/* "$TARGET_DIR/include"
}

echo "Prepare"
doPrepare | indent

echo "Download"
doDownload | indent

echo "Unzip"
doUnzip | indent

echo "Build"
"doBuild${OS^}" 2>&1 | indent

echo "Copy"
doCopy | indent
