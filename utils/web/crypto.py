#!/usr/bin/env python3.8

import binascii
import hashlib
import hmac
import time


def insecure_compare(a, b):
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
        time.sleep(0.05)
    return True


def check(data, given):
    # hexdump -n 16 -e '4/4 "%08x" 1 "\n"' /dev/urandom
    key = binascii.unhexlify("d9f730866ebbf250461587f5a9df37ca")
    expected = hmac.new(key, data.encode(), hashlib.sha1).digest()
    givenb = binascii.unhexlify(given)
    return insecure_compare(givenb, expected)

