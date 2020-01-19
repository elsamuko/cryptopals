#!/usr/bin/env python3.8

# https://webpy.org/
# python3.8 -m pip install web.py

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
    '''checks hash'''

    def GET(self):
        data = web.input()
        if crypto.check(data.file, data.signature):
            return 'OK'
        else:
            raise web.internalerror(' ')


if __name__ == "__main__":
    app.run()
