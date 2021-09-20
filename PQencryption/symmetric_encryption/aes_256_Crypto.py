#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on 4 jul 2017 12:31:39 CEST

@author: BMMN
"""

from __future__ import print_function  # make print python3 compatible

import base64
import gc  # garbage collector
from Crypto import Random
from Crypto.Cipher import AES


class AES256Cipher(object):

    def __init__(self, key):
        if len(key) != 32:  # allow only the most secure key length
            raise ValueError('AES Key must be 32 bytes long.')
        self.block_size = AES.block_size
        self.key = key

    def encrypt(self, raw, iv):
        raw = self.pad(raw, self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(enc[self.block_size:])).decode('utf-8')

    @staticmethod
    def pad(s, block_size):  # using PKCS#7 style padding
        return s + (block_size - len(s) % block_size) \
                * chr(block_size - len(s) % block_size)

    @staticmethod
    def unpad(s):  # using PKCS#7 style padding
        return s[:-ord(s[len(s)-1:])]

def key_gen(size=32):
    return Random.new().read(size)

def encrypt(message, key):
    # In production, you would want to have a hardware random number generator
    # for initialization_vector-generation.
    initialization_vector = Random.new().read(AES.block_size)
    my_cipher = AES256Cipher(key)
    return my_cipher.encrypt(message, initialization_vector)

def decrypt(encrypted_message, key):
    my_cipher = AES256Cipher(key)
    return my_cipher.decrypt(encrypted_message)

if __name__ == "__main__":
# This in an example. In production, you would want to read the key from an
# external file or the command line. The key must be 32 bytes long.

# DON'T DO THIS IN PRODUCTION!
    key = key_gen()

    message = 'This is my message.'
    print("message  : " + message)

# encryption
    my_encrypted_message = encrypt(message, key)
    print("encrypted: " + my_encrypted_message)

# decryption
    mydec = decrypt(my_encrypted_message, key)
    print("decrypted: " + mydec)

# make sure all memory is flushed after operations
    del key
    del message
    del mydec
    gc.collect()
