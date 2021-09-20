#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on vr 25 aug 2017 17:44:50 CEST

@author: BMMN
"""

from __future__ import print_function  # make print python3 compatible
import ctypes

mcbits = ctypes.CDLL("./libmcbits.so")

# general vars
synd_bytes = 208
len_pk = 1357824
len_sk = 13008

def generate_keys():
    secret_key = (ctypes.c_ubyte * len_sk)()
    public_key = (ctypes.c_ubyte * len_pk)()
    mcbits.crypto_encrypt_keypair(public_key, secret_key)
    return bytearray(secret_key), bytearray(public_key)

def encrypt(message, public_key_byte_array):
    key_length = len(public_key_byte_array)
    public_key = (ctypes.c_ubyte * key_length)(*public_key_byte_array)
    message_length = len(message)
    cypher_length = synd_bytes + message_length + 16
    cypher = (ctypes.c_ubyte * cypher_length)()
    clen = ctypes.c_longlong()

    mcbits.crypto_encrypt(cypher, ctypes.byref(clen), message, message_length,
            public_key)

    return cypher

def decrypt(encrypted_message, secret_key_byte_array):
    key_length = len(secret_key_byte_array)
    secret_key = (ctypes.c_ubyte * key_length)(*secret_key_byte_array)
    cypher_length = len(encrypted_message)
    message_length = len(encrypted_message) - synd_bytes - 16
    decrypted = (ctypes.c_ubyte * message_length)()
    mlen = ctypes.c_longlong()

    status = mcbits.crypto_encrypt_open(decrypted, ctypes.byref(mlen),
            encrypted_message, cypher_length, secret_key)

    if status == 0:
        return decrypted
    else:
        raise ValueError("Decryption failed, 'mcbits.crypto_encrypt_open "
        "return value' is not zero")

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
