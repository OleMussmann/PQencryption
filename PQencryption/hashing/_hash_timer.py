#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on Fri Jul  7 16:44:29 CEST 2017
@author: BMMN
"""

from __future__ import print_function  # make print python3 compatible

import timeit

salt = "a" * 128
message = "This is a message. Hash me!"
iterations = 1000000

print("Time in [s] for " + str(iterations) + " iterations.")

print("PyNaCl: "
        + str(timeit.timeit("sha512_hash(salt, message)",
            setup="from sha_512_PyNaCl import sha512_hash;"
            "from __main__ import salt, message",
            number=iterations)))

print("hashlib: "
        + str(timeit.timeit("sha512_hash(salt, message)",
            setup="from sha_512_hashlib import sha512_hash;"
            "from __main__ import salt, message",
            number=iterations)))
