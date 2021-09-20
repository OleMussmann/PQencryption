#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on Thu Jul 13 08:46:20 CEST 2017

@author: BMMN
"""

from __future__ import print_function  # make print python3 compatible
import gc  # garbage collection
import unittest
import mock
import os

try:
    os.mkdir("./.tmp")
except:
    pass

with open("./.tmp/README.md", 'w') as f:
    f.write("This directory stores temporary keys for testing.\n")

class TestFunctions(unittest.TestCase):
    def test_generate_signing_verify_key(self):
        import nacl.signing
        from PQencryption import utilities
        from PQencryption.pub_key.pk_signature.quantum_vulnerable import signing_Curve25519_PyNaCl
        s_raw, v_raw = signing_Curve25519_PyNaCl.key_gen()
        signing_key_hex = utilities.to_hex(str(s_raw))
        verify_key_hex = utilities.to_hex(str(v_raw))

        # Are they of the correct type?
        self.assertIsInstance(s_raw, nacl.signing.SigningKey)
        self.assertIsInstance(v_raw, nacl.signing.VerifyKey)

        # Do they have the length correct?
        self.assertEqual(len(signing_key_hex), 64)
        self.assertEqual(len(verify_key_hex), 64)

        # Are they properly converted to Hex?
        try:
            # if converting to "long, base16" works, it is Hex
            s_to_long = long(signing_key_hex, 16)
            v_to_long = long(verify_key_hex, 16)
        except:
            raise ValueError("Keys not converted to Hex format.")

    def test_generate_public_private_key(self):
        import nacl.public
        from PQencryption import utilities
        from PQencryption.pub_key.pk_encryption.quantum_vulnerable import encryption_Curve25519_PyNaCl
        pub_raw, priv_raw = encryption_Curve25519_PyNaCl.key_gen()
        public_key_hex = utilities.to_hex(str(pub_raw))
        private_key_hex = utilities.to_hex(str(priv_raw))

        # Are they of the correct type?
        self.assertIsInstance(pub_raw, nacl.public.PublicKey)
        self.assertIsInstance(priv_raw, nacl.public.PrivateKey)

        # Do they have the length correct?
        self.assertEqual(len(public_key_hex), 64)
        self.assertEqual(len(private_key_hex), 64)

        # Are they properly converted to Hex?
        try:
            # if converting to "long, base16" works, it is Hex
            s_to_long = long(public_key_hex, 16)
            v_to_long = long(private_key_hex, 16)
        except:
            raise ValueError("Keys not converted to Hex format.")

    def test_generate_symmetric_key(self):
        from PQencryption import utilities
        from PQencryption.symmetric_encryption import salsa20_256_PyNaCl

        sym_raw = salsa20_256_PyNaCl.key_gen()
        symmetric_key_hex = utilities.to_hex(sym_raw)

        # Is it of the correct type?
        self.assertIsInstance(sym_raw, str)

        # Does it have the length correct?
        self.assertEqual(len(sym_raw), 32)

        # Is it properly converted to Hex?
        try:
            # if converting to "long, base16" works, it is Hex
            s_to_long = long(symmetric_key_hex, 16)
        except:
            raise ValueError("Key not converted to Hex format.")

    @mock.patch('PQencryption.utilities.get_password',
            return_value="Aa0!asdfasdfasdfasdf")
    def test_public_key_import_export(self, input):
        import os
        from PQencryption import utilities
        from PQencryption.pub_key.pk_signature.quantum_vulnerable import signing_Curve25519_PyNaCl
        s_raw, v_raw = signing_Curve25519_PyNaCl.key_gen()
        signing_key_for_export_hex = utilities.to_hex(str(s_raw))
        verify_key_for_export_hex = utilities.to_hex(str(v_raw))
        path = ".tmp"
        s_header = ("# This is an encrypted private signing key."
                "KEEP IT PRIVATE!\n")
        v_header = ("# This is a public verification key."
                "Distribute it to your respondents.\n")
        s_name = "_PRIVATE_signing_key_CBS"
        v_name = "verify_key_CBS"

        utilities.export_key(signing_key_for_export_hex, path, s_name,
            s_header, key_type="SigningKey")
        utilities.export_key(verify_key_for_export_hex, path, v_name,
            v_header, key_type="VerifyKey")

        signing_key_imported = utilities.import_key(path, s_name,
                "SigningKey")
        verify_key_imported = utilities.import_key(path, v_name, "VerifyKey")

        os.remove(path + "/" + s_name)
        os.remove(path + "/" + v_name)

        signing_key_imported_hex = utilities.to_hex(str(signing_key_imported))
        verify_key_imported_hex = utilities.to_hex(str(verify_key_imported))

        self.assertEqual(signing_key_for_export_hex, signing_key_imported_hex)
        self.assertEqual(verify_key_for_export_hex, verify_key_imported_hex)

    @mock.patch('PQencryption.utilities.get_password',
            return_value="Aa0!asdfasdfasdfasdf")
    def test_symmetric_key_import_export(self, input):
        import os
        from PQencryption import utilities
        from PQencryption.symmetric_encryption import salsa20_256_PyNaCl
        s_raw = salsa20_256_PyNaCl.key_gen()
        symmetric_key_for_export_hex = utilities.to_hex(s_raw)
        path = ".tmp"
        s_header = ("# This is an encrypted symmetric key."
                "KEEP IT PRIVATE!\n")
        s_name = "_PRIVATE_symmetric_key_CBS"

        utilities.export_key(symmetric_key_for_export_hex, path, s_name,
            s_header, key_type="SymmetricKey")

        symmetric_key_imported = utilities.import_key(path, s_name,
                "SymmetricKey")

        os.remove(path + "/" + s_name)

        symmetric_key_imported_hex = utilities.to_hex(symmetric_key_imported)

        self.assertEqual(symmetric_key_for_export_hex,
                symmetric_key_imported_hex)

    def test_hashing_hashlib(self):
        from PQencryption.hashing import sha_512_hashlib
        from PQencryption.hashing import sha_512_PyNaCl
        salt = "a" * 128
        message = "This is a message. Hash me!"
        hashed_hashlib = sha_512_hashlib.sha512_hash(salt, message)
        self.assertEqual(hashed_hashlib, "ab90b1da9cd3a8625a75a0e0aaaa5c7a14ab9dde9006d23cacac665cc0edbc9309d8cc715aaf715cbcad61e9ddb32eac785881e880bff32c22108cb58cf6a8bf")

    def test_hashing_PyNaCl(self):
        from PQencryption.hashing import sha_512_hashlib
        from PQencryption.hashing import sha_512_PyNaCl
        salt = "a" * 128
        message = "This is a message. Hash me!"
        hashed_PyNaCl = sha_512_PyNaCl.sha512_hash(salt, message)
        self.assertEqual(hashed_PyNaCl, "ab90b1da9cd3a8625a75a0e0aaaa5c7a14ab9dde9006d23cacac665cc0edbc9309d8cc715aaf715cbcad61e9ddb32eac785881e880bff32c22108cb58cf6a8bf")

    def test_symmetric_encryption_AES256(self):
        from PQencryption.symmetric_encryption import aes_256_Crypto
        from PQencryption import utilities

        key = aes_256_Crypto.key_gen()
        message = 'This is my message.'

        # encryption
        my_encrypted_message = aes_256_Crypto.encrypt(message, key)

        # decryption
        my_decrypted_message = aes_256_Crypto.decrypt(my_encrypted_message,
                key)

        self.assertNotEqual(message, my_encrypted_message)
        self.assertEqual(message, my_decrypted_message)

    def test_symmetric_encryption_salsa20(self):
        from PQencryption.symmetric_encryption import salsa20_256_PyNaCl
        from PQencryption import utilities

        key = salsa20_256_PyNaCl.key_gen()
        message = 'This is my message.'

        # encryption
        my_encrypted_message = salsa20_256_PyNaCl.encrypt(message, key)

        # decryption
        my_decrypted_message = salsa20_256_PyNaCl.decrypt(my_encrypted_message,
                key)

        self.assertNotEqual(message, my_encrypted_message)
        self.assertEqual(message, my_decrypted_message)

    def test_sign_encrypt_sign_and_verify_decrypt_verify(self):
        from PQencryption.pub_key.pk_signature.quantum_vulnerable import signing_Curve25519_PyNaCl
        from PQencryption.pub_key.pk_encryption.quantum_vulnerable import encryption_Curve25519_PyNaCl
        from PQencryption.symmetric_encryption import salsa20_256_PyNaCl
        from PQencryption import utilities
        import nacl.encoding

        signing_key, verify_key = signing_Curve25519_PyNaCl.key_gen()
        encryption_key = salsa20_256_PyNaCl.key_gen()

        message = 'This is my message.'

        signed_encrypted_signed_message = utilities.sign_encrypt_sign(message,
                signing_key, encryption_key)

        # verify positive
        verified_decrypted_verified_message = utilities.verify_decrypt_verify(
                signed_encrypted_signed_message, verify_key, encryption_key)
        self.assertEqual(message, verified_decrypted_verified_message)

        # verify negative
        # we should test all layers of the onion, not only the outer one. TODO
        with self.assertRaises(Exception) as bad_signature:
            spoof = "0"*len(nacl.encoding.HexEncoder.encode(
                verified_decrypted_verified_message))
            verified_decrypted_verified_message = \
                    utilities.verify_decrypt_verify(spoof, verify_key,
                            encryption_key)
        self.assertTrue("Signature was forged or corrupt"
                in bad_signature.exception)

    def test_quantum_vulnerable_signing(self):
        from PQencryption.pub_key.pk_signature.quantum_vulnerable import signing_Curve25519_PyNaCl
        from PQencryption import utilities

        signing_key, verify_key = signing_Curve25519_PyNaCl.key_gen()

        message = 'This is my message.'

        # signing
        signed = signing_Curve25519_PyNaCl.sign(signing_key, message)

        # verify positive
        out = verify_key.verify(signed)
        self.assertEqual(message, out)

        # verify negative
        with self.assertRaises(Exception) as bad_signature:
            spoof = "0"*len(signed)
            out = verify_key.verify(spoof)
        self.assertTrue("Signature was forged or corrupt"
                in bad_signature.exception)

        # test derived key
        derived_verify_key = signing_key.verify_key
        self.assertEqual(verify_key, derived_verify_key)

    def test_quantum_vulnerable_encryption(self):
        from PQencryption.pub_key.pk_encryption.quantum_vulnerable import encryption_Curve25519_PyNaCl
        from PQencryption import utilities

        public_key_Alice, secret_key_Alice = \
                encryption_Curve25519_PyNaCl.key_gen()

        public_key_Bob, secret_key_Bob = \
                encryption_Curve25519_PyNaCl.key_gen()

        message = 'This is my message.'

        # encrypting
        encrypted = encryption_Curve25519_PyNaCl.encrypt(message,
                secret_key_Alice, public_key_Bob)

        # decrypting
        decrypted_BA = encryption_Curve25519_PyNaCl.decrypt(encrypted,
                secret_key_Bob, public_key_Alice)

        decrypted_AB = encryption_Curve25519_PyNaCl.decrypt(encrypted,
                secret_key_Alice, public_key_Bob)

        self.assertNotEqual(message, encrypted)
        self.assertEqual(message, decrypted_BA)
        self.assertEqual(message, decrypted_AB)

    def test_to_hex(self):
        from PQencryption import utilities
        string = "Hex me."
        hexed = utilities.to_hex(string)
        self.assertEqual(hexed, "486578206d652e")

    def test_from_hex(self):
        from PQencryption import utilities
        string = "486578206d652e"
        de_hexed = utilities.from_hex(string)
        self.assertEqual(de_hexed, "Hex me.")

if __name__ == "__main__":
    unittest.main(verbosity=2)
