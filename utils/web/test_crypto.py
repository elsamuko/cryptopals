#!/usr/bin/env python3

import crypto

if(not crypto.check("foo", "46b4ec586117154dacd49d664e5d63fdc88efb51")):
    print("BAD")

if(not crypto.check("foo", "46b4")):
    print("TOO SHORT")

if(crypto.check("foo",     "fa9908c7e2e1dfe6917b19ccfc04998ead09aef9")):
    print("OK")
