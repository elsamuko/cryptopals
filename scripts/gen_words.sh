#!/usr/bin/env bash
# from http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/

TYPE="words"
FILE="english_$TYPE.txt"

SUM=$(awk '{sum += $2} END {print sum}' "$FILE")

echo "// auto-generated with"
echo "// $(basename $0) > ../src/english_$TYPE.hpp"
echo
echo "#pragma once"
echo
echo "#include <map>"
echo "#include <string>"
echo
echo "namespace english {"
echo "const static std::map<std::string, float> $TYPE = {"
awk "{print \"    {\\\"\"tolower(\$1)\"\\\", \"\$2/$SUM\"f},\"}" "$FILE" | head -2000
echo "};"
echo "}"
echo





