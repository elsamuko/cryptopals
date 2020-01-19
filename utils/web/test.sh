#!/usr/bin/env bash

BASE="http://localhost:9000"
URL_BAD="$BASE/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51"
URL_GOOD="$BASE/test?file=foo&signature=fa9908c7e2e1dfe6917b19ccfc04998ead09aef9"

function status {
    grep "< HTTP/1.1" | grep -Po '\d{3}'
}

echo -n "ok        : "
curl -vs4 "$BASE/ok"     2>&1 >/dev/null | status
echo -n "error     : "
curl -vs4 "$BASE/error"  2>&1 >/dev/null | status
echo -n "test bad  : "
curl -vs4 "$URL_BAD"     2>&1 >/dev/null | status
echo -n "test good : "
curl -vs4 "$URL_GOOD"    2>&1 >/dev/null | status
