#!/usr/bin/env python3

# https://webpy.org/
# python3 -m pip install web.py
# or
# sudo apt install python3-webpy python3-six

import web
import binascii
import hashlib
import hmac
import time
import crypto

urls = (
    '/ok', 'Ok',
    '/error', 'Error',
    '/test', 'Test',
    '/short', 'Short',
)

# allow functions above
from web.template import ALLOWED_AST_NODES
ALLOWED_AST_NODES.append('Constant')

app = web.application(urls, globals())


class Ok:
    '''returns 200'''

    def GET(self):
        return ''


class Error:
    '''returns 500'''

    def GET(self):
        raise web.internalerror(' ')


class Test:
    '''checks hash with 50 ms compare'''

    def GET(self):
        data = web.input()
        if crypto.check(data.file, data.signature,50):
            return 'OK'
        else:
            raise web.internalerror(' ')

class Short:
    '''checks hash with 5ms compare'''

    def GET(self):
        data = web.input()
        if crypto.check(data.file, data.signature,5):
            return 'OK'
        else:
            raise web.internalerror(' ')

if __name__ == "__main__":
    app.run()
