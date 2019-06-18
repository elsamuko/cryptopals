#!/usr/bin/env bash
# xz compress ECB/CBC encrypted 4k zero strings
# and print their compressed file sizes

SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
MAIN_DIR="$SCRIPT_DIR/.."
BIN_DIR="$MAIN_DIR/bin"

cd "$BIN_DIR" || exit

# clean
rm ./*.enc
rm ./*.enc.xz

# regenerate
./cryptopals > /dev/null

# stats
for ENC in *.enc; do
    xz -k -z -e "$ENC"
    SIZE=$(stat -c "%s" "$ENC.xz")
    echo "$SIZE $ENC.xz"
done | sort -n
