#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Example usage of the PQencryption package.

This example file demonstrates the usage of the PQencryption package. In the
`if __name__ == "__main__":` section: comment and uncomment the functions
that you want to have demonstrated or omitted. Then run this module as
indicated under 'Example' below.

Example:
    $ python crypto_examples.py

Created on Thu Jul 13 08:46:20 CEST 2017

Modified on Fri Sep 24 14:04:00 CEST 2021:
    - For the purpose of code reviews, an example docstring is added
      to the function 'example_hashing_hashlib'

@author: BMMN
"""

import gc  # garbage collection


def example_hashing_hashlib():
    """Example function to demonstrate hashing with 'hashlib'.

    For the PQencryption package, hashing is always used with a prepended
    'salt'. This is a 128 bytes long cryptographic key pre-pended to the
    message-to-be-hashed to prevent rainbow table attacks
    (see: https://www.geeksforgeeks.org/understanding-rainbow-table-attack/)
    or brute-forcing.

    Key parameters:
        salt (str): a 128 bytes long key in hex
        message (str): an arbitrarily long string

    After all necessary computations, delete sensitive variables and
    manually call the garbage collector for clean-up.
    """
    from PQencryption.hashing import sha_512_hashlib
    # In production the salt should come from a hardware random number
    # generator and will be shared between parties.

    # Salt must be 128 bytes in hex.
    salt = "a" * 128

    message = "This is a message. Hash me!"
    print(message)

    hashed = sha_512_hashlib.sha512_hash(salt, message)
    print(hashed)

    # make sure all memory is flushed after operations
    del salt
    del message
    gc.collect()


def example_hashing_PyNaCl():
    from PQencryption.hashing import sha_512_PyNaCl
    # In production the salt should come from a hardware random number
    # generator and will be shared between parties.

    # Salt must be 128 bytes in hex.
    salt = "a" * 128

    message = "This is a message. Hash me!"
    print(message)

    hashed = sha_512_PyNaCl.sha512_hash(salt, message)
    print(hashed)

    # make sure all memory is flushed after operations
    del salt
    del message
    gc.collect()


def example_AES256():
    from PQencryption.symmetric_encryption import aes_256_Crypto
    from Crypto import Random
    from Crypto.Cipher import AES
    # This in an example. In production, you would want to read the key from an
    # external file or the command line. The key must be 32 bytes long.

    # DON'T DO THIS IN PRODUCTION!
    key = b'Thirtytwo byte key, this is long'

    # In production, you would want to have a hardware random number generator
    # for this.
    initialization_vector = Random.new().read(AES.block_size)

    message = 'This is my message.'
    print("message  : " + message)
    my_cipher = aes_256_Crypto.AES256Cipher(key)

    # encryption
    my_encrypted_message = my_cipher.encrypt(message, initialization_vector)
    print("encrypted: " + my_encrypted_message)

    # decryption
    mydec = my_cipher.decrypt(my_encrypted_message)
    print("decrypted: " + mydec)

    # make sure all memory is flushed after operations
    del key
    del message
    del mydec
    gc.collect()


def example_salsa20_256_PyNaCl():
    from PQencryption.symmetric_encryption import salsa20_256_PyNaCl

    # This in an example. In production, you would want to read the key from an
    # external file or the command line. The key must be 32 bytes long.

    # DON'T DO THIS IN PRODUCTION!
    key = b'Thirtytwo byte key, this is long'

    message = 'This is my message.'
    print("message  : " + message)
    my_cipher = salsa20_256_PyNaCl.Salsa20Cipher(key)

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


def example_quantum_vulnerable_encryption():
    from PQencryption.pub_key.pk_encryption.quantum_vulnerable \
        import encryption_Curve25519_PyNaCl
    from PQencryption import utilities

    # This in an example. In production, you would want to read the key from an
    # external file or the command line. The key must be 32 bytes long.

    # DON'T DO THIS IN PRODUCTION!
    public_key_Alice, secret_key_Alice = \
        utilities.generate_public_private_keys()
    public_key_Bob, secret_key_Bob = \
        utilities.generate_public_private_keys()

    message = 'This is my message.'
    print("message  : " + message)

    # encrypting
    encrypted = encryption_Curve25519_PyNaCl.encrypt(message,
                                                     secret_key_Alice,
                                                     public_key_Bob)
    print("encrypted: " + utilities.to_hex(encrypted))

    # decrypting
    decrypted_BA = encryption_Curve25519_PyNaCl.decrypt(encrypted,
                                                        secret_key_Bob,
                                                        public_key_Alice)
    print("decrypted_BA: " + decrypted_BA)

    decrypted_AB = encryption_Curve25519_PyNaCl.decrypt(encrypted,
                                                        secret_key_Alice,
                                                        public_key_Bob)
    print("decrypted_AB: " + decrypted_BA)

    # make sure all memory is flushed after operations
    del secret_key_Alice
    del secret_key_Bob
    del message
    del encrypted
    del decrypted_BA
    del decrypted_AB
    gc.collect()


def example_quantum_vulnerable_signing():
    from PQencryption.pub_key.pk_signature.quantum_vulnerable \
        import signing_Curve25519_PyNaCl
    from PQencryption import utilities
    # This in an example. In production, you would want to read the key from an
    # external file or the command line. The key must be 32 bytes long.

    # DON'T DO THIS IN PRODUCTION!
    signing_key, verify_key = utilities.generate_signing_verify_keys()

    message = 'This is my message.'
    print()
    print("message  : " + message)
    print()

    # signing
    signed = signing_Curve25519_PyNaCl.sign(signing_key, message)
    verify_key_hex = utilities.to_hex(str(verify_key))
    print()
    print("signed (will look garbled): " + signed)
    print()
    print("verify_key_hex: " + verify_key_hex)
    print()

    # verification
    try:
        print()
        print("verification positive: " + verify_key.verify(signed))
        print()
        print("verification negative:")
        print("="*79)
        print("THIS WILL FAIL WITH A \"nacl.exceptions.BadSignatureError\" "
              "ERROR, AS EXPECTED.")
        print("="*79)
        print(verify_key.verify("0"*len(signed)))
    except Exception as e:
        raise e

    finally:
        print("="*79)
        print("Yes, clean-up is still executed, even after raising errors:")
        print("begin cleanup ...")
        # make sure all memory is flushed after operations
        del signing_key
        del signed
        del message
        del verify_key
        del verify_key_hex
        gc.collect()
        print("... end cleanup.")
        print("="*79)


def example_export_symmetric_key():
    from PQencryption import utilities
    import os

    if not os.path.exists("./.tmp"):
        os.mkdir("./.tmp")

    s_raw = utilities.generate_symmetric_key()
    s = utilities.to_hex(s_raw)
    path = ".tmp"
    s_header = ("# This is an encrypted symmetric key."
                "KEEP IT PRIVATE!\n")
    s_name = "_PRIVATE_symmetric_key_CBS"
    utilities.export_key(s, path, s_name, s_header, key_type="SymmetricKey")
    return path, s, s_name


def example_export_public_key():
    from PQencryption import utilities
    import os

    if not os.path.exists("./.tmp"):
        os.mkdir("./.tmp")

    s_raw, v_raw = utilities.generate_signing_verify_keys()
    s = utilities.to_hex(str(s_raw))
    v = utilities.to_hex(str(v_raw))
    path = ".tmp"
    s_header = ("# This is an encrypted private signing key."
                "KEEP IT PRIVATE!\n")
    v_header = ("# This is a public verification key."
                "Distribute it to your respondents.\n")
    s_name = "_PRIVATE_signing_key_CBS"
    v_name = "verify_key_CBS"
    utilities.export_key(s, path, s_name, s_header, key_type="SigningKey")
    utilities.export_key(v, path, v_name, v_header, key_type="VerifyKey")
    return path, s, s_name, v, v_name


def example_import_public_key(path, signing_key, s_name, verify_key, v_name):
    import nacl.encoding
    from PQencryption import utilities

    print("="*79)
    print("signing_key", signing_key)
    print("verify_key", verify_key)
    print("="*79)
    print()
    print("Importing signing key.")
    imported_signing_key = utilities.import_key(path, s_name, "SigningKey")
    print("Importing verify key.")
    imported_verify_key = utilities.import_key(path, v_name, "VerifyKey")
    print("="*79)
    print("imported_signing_key", imported_signing_key.encode(
        encoder=nacl.encoding.HexEncoder))
    print("imported_verify_key", imported_verify_key.encode(
        encoder=nacl.encoding.HexEncoder))
    print("="*79)


def example_import_symmetric_key(path, symmetric_key, s_name):
    import nacl.encoding
    from PQencryption import utilities

    print("="*79)
    print("symmetric_key", symmetric_key)
    print("="*79)
    print()
    print("Importing symmetric key.")
    imported_symmetric_key = utilities.import_key(path, s_name, "SymmetricKey")
    print("="*79)
    print("imported_symmetric_key", nacl.encoding.HexEncoder.encode(
        imported_symmetric_key))
    print("="*79)


def example_generate_public_private_keys():
    from PQencryption import utilities
    public_key, private_key = utilities.generate_public_private_keys()
    print(public_key)
    print(private_key)


def example_generate_signing_verify_keys():
    from PQencryption import utilities
    signing_key, verify_key = utilities.generate_signing_verify_keys()
    print(signing_key)
    print(verify_key)


def example_generate_symmetric_key():
    from PQencryption import utilities
    symmetric_key_raw = utilities.generate_symmetric_key()
    symmetric_key = utilities.to_hex(symmetric_key_raw)
    print(symmetric_key)


def example_quantum_safe_encryption():
    from PQencryption import utilities

    # This in an example. In production, you would want to read the key from an
    # external file or the command line.

    # DON'T DO THIS IN PRODUCTION!
    public_key, secret_key = \
        utilities.generate_quantum_safe_keys()

    message = 'This is my message.'
    print("message  : " + message)

    # encrypting
    encrypted = utilities.encrypt_quantum_safe(message, public_key)
    print("encrypted: " + utilities.to_hex(encrypted))

    # decrypting
    decrypted = utilities.decrypt_quantum_safe(encrypted, secret_key)

    print("decrypted: " + decrypted)

    # make sure all memory is flushed after operations
    del secret_key
    del message
    del encrypted
    del decrypted
    gc.collect()


if __name__ == "__main__":
    example_hashing_PyNaCl()

    example_hashing_hashlib()

    example_AES256()

    example_salsa20_256_PyNaCl()

    example_generate_public_private_keys()

    example_generate_signing_verify_keys()

    example_generate_symmetric_key()

    example_import_public_key(*example_export_public_key())

    example_import_symmetric_key(*example_export_symmetric_key())

    example_quantum_vulnerable_encryption()

    example_quantum_safe_encryption()

    example_quantum_vulnerable_signing()
