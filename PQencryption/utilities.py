#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on Thu Jul 13 07:12:15 CEST 2017

@author: BMMN
"""

from __future__ import print_function  # make print python3 compatible
import getpass
import gc  # garbage collector
import re
import nacl.hash
import nacl.utils
import nacl.signing
import nacl.encoding
import nacl.public
from PQencryption.symmetric_encryption import salsa20_256_PyNaCl
from PQencryption.pub_key.pk_signature.quantum_vulnerable \
    import signing_Curve25519_PyNaCl
from PQencryption.pub_key.pk_encryption.quantum_vulnerable \
    import encryption_Curve25519_PyNaCl


def check_password(password):
    length = 20
    length_error = len(password) < length
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    # \W matches any non-word character [^a-zA-Z_0-9] . By including
    # "|_" (or _) we get effectively all special charsacters [^a-zA-Z0-9] .
    symbol_error = re.search(r"\W|_", password) is None
    password_ok = not (length_error or digit_error or uppercase_error
                       or lowercase_error or symbol_error)

    errors = ""
    if length_error:
        errors += "Password too short.\n"
        if digit_error:
            errors += "Password does not contain digits.\n"
        if lowercase_error:
            errors += "Password does not have lowercase characters.\n"
        if uppercase_error:
            errors += "Password does not have uppercase characters.\n"
        if symbol_error:
            errors += "Password does not contain any special characters.\n"
        if not password_ok:
            raise ValueError(errors)


def get_password(validate):
    requirements = ("Password must have at least 20 characters, including:\n"
                    "upper-case    ABC...\n"
                    "lower-case    abc...\n"
                    "digits        012...\n"
                    "special chars !${...")
    print(requirements)
    password = getpass.getpass()
    check_password(password)
    if validate:
        password_2 = getpass.getpass("Repeat password:")
        if password != password_2:
            raise ValueError("Passwords differ.")

    return password


def export_key(key, path, name, header, key_type):
    if ((key_type == "PrivateKey")
            or (key_type == "SigningKey")
            or (key_type == "SymmetricKey")):
        user_password = get_password(validate=True)

        # turn user_password into 32 char storag_password for Salsa20:
        storage_password = \
            nacl.hash.sha512(user_password,
                             encoder=nacl.encoding.HexEncoder)[:32]
        my_cipher = salsa20_256_PyNaCl.Salsa20Cipher(storage_password)
        key_for_file = my_cipher.encrypt(key)
        del user_password
        del storage_password
        del my_cipher
    else:
        key_for_file = key
    with open(path + "/" + name, 'w') as file:
        file.write(header)
        file.write(key_for_file)
    del key_for_file
    gc.collect()


def import_key(path, name, key_type):
    with open(path + "/" + name) as file:
        for line in file:
            if not line.strip().startswith('#'):
                raw_key = line
    if ((key_type == "SigningKey")
            or (key_type == "PrivateKey")
            or (key_type == "SymmetricKey")):
        user_password = get_password(validate=False)

        # turn user_password into 32 char storage_password for Salsa20:
        storage_password = \
            nacl.hash.sha512(user_password,
                             encoder=nacl.encoding.HexEncoder)[:32]
        my_cipher = salsa20_256_PyNaCl.Salsa20Cipher(storage_password)
        decrypted_key = my_cipher.decrypt(raw_key)
        if key_type == "SymmetricKey":
            key = decrypted_key.decode("hex")
        elif key_type == "PrivateKey":
            key = nacl.public.PrivateKey(decrypted_key,
                                         encoder=nacl.encoding.HexEncoder)
        else:
            key = nacl.signing.SigningKey(decrypted_key,
                                          encoder=nacl.encoding.HexEncoder)
    elif key_type == "PublicKey":
        key = nacl.public.PublicKey(raw_key,
                                    encoder=nacl.encoding.HexEncoder)
    elif key_type == "VerifyKey":
        key = nacl.signing.VerifyKey(raw_key,
                                     encoder=nacl.encoding.HexEncoder)
    else:
        raise KeyError("Invalid key type: " + key_type)
    return key


def to_hex(string):
    return nacl.encoding.HexEncoder.encode(string)


def from_hex(string):
    return nacl.encoding.HexEncoder.decode(string)


def generate_public_private_keys():
    signing_key_raw, verify_key_raw = encryption_Curve25519_PyNaCl.key_gen()
    return signing_key_raw, verify_key_raw


def generate_signing_verify_keys():
    signing_key_hex, verify_key_hex = signing_Curve25519_PyNaCl.key_gen()
    return signing_key_hex, verify_key_hex


def generate_symmetric_key():
    symmetric_key = salsa20_256_PyNaCl.key_gen()
    return symmetric_key


def sign_encrypt_sign(message, signing_key, encryption_key):
    signed_message = signing_Curve25519_PyNaCl.sign(signing_key, message)
    encrypted_signed_message = salsa20_256_PyNaCl.encrypt(signed_message,
                                                          encryption_key)
    signed_encrypted_signed_message = signing_Curve25519_PyNaCl.sign(
        signing_key, encrypted_signed_message)
    return signed_encrypted_signed_message


def verify_decrypt_verify(message, verify_key, encryption_key):
    verified_encrypted_signed = verify_key.verify(message)
    signed = salsa20_256_PyNaCl.decrypt(verified_encrypted_signed,
                                        encryption_key)
    verified = verify_key.verify(signed)
    return verified


def sign_models(models, signing_key):
    signed_models = signing_Curve25519_PyNaCl.sign(signing_key, models)
    return signed_models


def verify_models(signed_models, verify_key):
    verified_models = verify_key.verify(signed_models)
    return verified_models
