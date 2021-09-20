#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on di 29 aug 2017 11:33:41 CEST

@author: BMMN
"""

from __future__ import print_function  # make print python3 compatible
import encryption_mcbits
import nacl.encoding

secret_key, public_key = encryption_mcbits.generate_keys()

my_message = "Hi! I'm a message."

encrypted = encryption_mcbits.encrypt(my_message, public_key)
decrypted = encryption_mcbits.decrypt(encrypted, secret_key)


print("message:\n" + my_message)
print()
print("encrypted:\n" + nacl.encoding.HexEncoder.encode(bytearray(encrypted)))
print()
print("decrypted:\n" + bytearray(decrypted))
