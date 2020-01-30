#!/usr/bin/env bash

BASE="http://localhost:9000"
URL_BAD="$BASE/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51"
URL_GOOD="$BASE/test?file=foo&signature=fa9908c7e2e1dfe6917b19ccfc04998ead09aef9"
URL_SHORT="$BASE/short?file=foo&signature=fa9908c7e2e1dfe6917b19ccfc04998ead09aef9"

function http_GET {
    curl -vs4 "$1" 2>&1 >/dev/null | grep "< HTTP/1.1" | grep -Po '\d{3}'
}

echo -n "ok         : "
http_GET "$BASE/ok"

echo -n "error      : "
http_GET "$BASE/error"

echo -n "test bad   : "
http_GET "$URL_BAD"

echo -n "test good  : "
http_GET "$URL_GOOD"

echo -n "test short : "
http_GET "$URL_SHORT"
