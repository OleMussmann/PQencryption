#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on 4 jul 2017 16:24:30 CEST

@author: BMMN
"""

from __future__ import print_function  # make print python3 compatible

import hashlib
import gc  # garbage collector


def sha512_hash(salt, string):
    if len(salt) != 128:
        raise ValueError('Salt must be 128 bytes long.')

    return hashlib.sha512(salt + string).hexdigest()


if __name__ == "__main__":
    # In production the salt should come from a hardware random number
    # generator and will be shared between parties.

    # Salt must be 128 bytes in hex.
    salt = "a" * 128

    message = "This is a message. Hash me!"
    print(message)

    hashed = sha512_hash(salt, message)
    print(hashed)

    # make sure all memory is flushed after operations
    del salt
    del message
    gc.collect()
