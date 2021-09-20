#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on 4 jul 2017 12:31:39 CEST

@author: BMMN
"""

from __future__ import print_function  # make print python3 compatible

import gc  # garbage collector
import nacl.secret
import nacl.utils
import nacl.encoding

class Salsa20Cipher(object):

    def __init__(self, key):
        if len(key) != 32:  # allow only the most secure key length
            raise ValueError('Salsa20 key must be 32 bytes long.')
        self.key = key
        self.box = nacl.secret.SecretBox(key)

    def encrypt(self, message):
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        return self.box.encrypt(message, nonce,
                encoder=nacl.encoding.HexEncoder)

    def decrypt(self, encrypted):
        return self.box.decrypt(encrypted,
                encoder=nacl.encoding.HexEncoder)

def key_gen(size=32):
    return nacl.utils.random(size)

def encrypt(message, key):
    my_cipher = Salsa20Cipher(key)
    return my_cipher.encrypt(message)

def decrypt(message, key):
    my_cipher = Salsa20Cipher(key)
    return my_cipher.decrypt(message)

if __name__ == "__main__":
# This in an example. In production, you would want to read the key from an
# external file or the command line. The key must be 32 bytes long.

# DON'T DO THIS IN PRODUCTION!
    key = key_gen()

    message = 'This is my message.'
    print("message  : " + message)
    my_cipher = Salsa20Cipher(key)

# encryption
    my_encrypted_message = my_cipher.encrypt(message)
    print("encrypted: " + my_encrypted_message)

# decryption
    my_decrypted_message = my_cipher.decrypt(my_encrypted_message)
    print("decrypted: " + my_decrypted_message)

# make sure all memory is flushed after operations
    del key
    del message
    del my_decrypted_message
    gc.collect()
