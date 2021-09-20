#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on Mon Jul 10 16:26:41 CEST 2017

@author: BMMN
"""

from __future__ import print_function  # make print python3 compatible

import gc  # garbage collector
import nacl.utils
import nacl.public
import nacl.encoding

def encrypt(message, secret_key, public_key):
    encryption_box = nacl.public.Box(secret_key, public_key)
    nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
    return encryption_box.encrypt(message, nonce)

def decrypt(encrypted_message, secret_key, public_key):
    decryption_box = nacl.public.Box(secret_key, public_key)
    return decryption_box.decrypt(encrypted_message)

def key_gen():
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key
    return public_key, private_key

if __name__ == "__main__":
# This in an example. In production, you would want to read the key from an
# external file or the command line. The key must be 32 bytes long.

# DON'T DO THIS IN PRODUCTION!
    secret_key_Bob = nacl.public.PrivateKey.generate()
    public_key_Bob = secret_key_Bob.public_key

    secret_key_Alice = nacl.public.PrivateKey.generate()
    public_key_Alice = secret_key_Alice.public_key

    message = 'This is my message.'
    print("message  : " + message)

# encrypting
    encrypted = encrypt(secret_key_Alice, public_key_Bob, message)
    print("encrypted: "
            + nacl.encoding.HexEncoder.encode(encrypted))

# decrypting
    decrypted_BA = decrypt(secret_key_Bob, public_key_Alice, encrypted)
    print("decrypted_BA: " + decrypted_BA)

    decrypted_AB = decrypt(secret_key_Alice, public_key_Bob, encrypted)
    print("decrypted_AB: " + decrypted_BA)
    exit()


# make sure all memory is flushed after operations
    del secret_key_Alice
    del secret_key_Bob
    del message
    del encrypted
    del decrypted_BA
    del decrypted_AB
    gc.collect()
