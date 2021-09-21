#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on vr 25 aug 2017 17:44:50 CEST

@author: BMMN
"""

import os
import ctypes

dll_folder_location = os.path.dirname(__file__)
dll_full_path = os.path.join(dll_folder_location, 'libmcbits.so')
mcbits = ctypes.CDLL(dll_full_path)

# general vars
synd_bytes = 208
len_pk = 1357824
len_sk = 13008


def generate_keys():
    public_key = (ctypes.c_ubyte * len_pk)()
    secret_key = (ctypes.c_ubyte * len_sk)()
    mcbits.crypto_encrypt_keypair(public_key, secret_key)
    return bytearray(public_key), bytearray(secret_key)


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
                                        encrypted_message, cypher_length,
                                        secret_key)

    if status == 0:
        return str(bytearray(decrypted))
    else:
        raise ValueError("Decryption failed, 'mcbits.crypto_encrypt_open "
                         "return value' is not zero")


if __name__ == "__main__":
    import gc
    # This in an example. In production, you would want to read the key from an
    # external file or the command line.

    # DON'T DO THIS IN PRODUCTION!
    public_key, secret_key = generate_keys()

    message = 'This is my message.'
    print("message  : " + message)

    # encrypting
    encrypted = encrypt(message, public_key)
    print("encrypted: " + str(bytearray(encrypted)))

    # decrypting
    decrypted = decrypt(encrypted, secret_key)

    print("decrypted: " + decrypted)

    # make sure all memory is flushed after operations
    del secret_key
    del message
    del encrypted
    del decrypted
    gc.collect()
