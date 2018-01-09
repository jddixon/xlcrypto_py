#!/usr/bin/env python3
# xlcrypto_py/test_rsa.py

"""
Test RSA crypto routines.

This module specifically exercise github.com/pyca/cryptography.
"""

import base64
import os
import time
import unittest
import warnings

from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from rnglib import SimpleRNG
from xlattice import HashTypes


class TestRSA(unittest.TestCase):
    """ Test RSA crypto routines.  """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def test_rsa_serialization(self):
        """
        Exercise basic RSA functions.

        These include key generation, public key extraction,
        serialization/deserialization for pem and der formats, and
        digital signing and verification.
        """

        # ignore warning about renaming internal to cryptography
        warnings.filterwarnings("ignore", category=PendingDeprecationWarning)

        tmp_dir = 'tmp'
        os.makedirs(tmp_dir, exist_ok=True, mode=0o755)
        while True:
            sub_dir = self.rng.next_file_name(12)
            node_dir = os.path.join(tmp_dir, sub_dir)
            if not os.path.exists(node_dir):
                break
        # DEBUG
        print("node_dir is %s" % node_dir)
        # END
        os.mkdir(node_dir, mode=0o755)

        # RSA PRIVATE KEY GENERATION -----------------------------

        sk_priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,  # cheap key for testing
            backend=default_backend())
        sk_ = sk_priv.public_key()

        self.assertEqual(sk_priv.key_size, 1024)

        # PEM FORMAT RSA PRIVATE KEY ROUND-TRIPPED ------------------

        pem = sk_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())

        key_file = os.path.join(node_dir, 'skPriv.pem')
        with open(key_file, 'wb') as file:
            # written as bytes
            file.write(pem)

        self.assertTrue(os.path.exists(key_file))
        with open(key_file, 'rb') as file:
            sk2_priv = serialization.load_pem_private_key(
                file.read(),
                password=None,
                backend=default_backend())

        # NUMBERS AND KEY EQUALITY ----------------------------------

        # get the public part of the key
        sk2_ = sk2_priv.public_key()

        # __eq__() for public part of RSA keys -------------

        # FAILS because __eq__()  has not been defined
        # self.assertEqual(sk2_, sk_)

        def check_equal_rsa_pub_key(sk2_, sk_):
            """  __eq__ functionalitiy for RSA public keys. """
            pub_n = sk_.public_numbers()
            pub_n2 = sk2_.public_numbers()

            self.assertEqual(pub_n2.e, pub_n.e)
            self.assertEqual(pub_n2.n, pub_n.n)

        check_equal_rsa_pub_key(sk2_, sk_)

        def check_equal_rsa_priv_key(sk2_priv, sk_priv):
            """  __eq__ functionalitiy for RSA private keys. """
            pri_n = sk_priv.private_numbers()
            pri_n2 = sk2_priv.private_numbers()

            # the library guarantees this: p is the larger factor
            self.assertTrue(pri_n.p > pri_n.q)

            self.assertTrue(
                pri_n2.p == pri_n.p and
                pri_n2.q == pri_n.q and
                pri_n2.d == pri_n.d and
                pri_n2.dmp1 == pri_n.dmp1 and
                pri_n2.dmq1 == pri_n.dmq1 and
                pri_n2.iqmp == pri_n.iqmp)

        check_equal_rsa_priv_key(sk2_priv, sk_priv)

        # DER DE/SERIALIZATION ROUND-TRIPPED ------------------------

        der = sk_priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())

        der_key_file = os.path.join(node_dir, 'skPriv.der')
        with open(der_key_file, 'wb') as file:
            # written as bytes
            file.write(der)

        self.assertTrue(os.path.exists(der_key_file))
        with open(der_key_file, 'rb') as file:
            sk3_priv = serialization.load_der_private_key(
                file.read(),
                password=None,
                backend=default_backend())

        check_equal_rsa_priv_key(sk3_priv, sk_priv)

        # OpenSSH PUBLIC KEY DE/SERIALIZATION ROUND-TRIPPED ---------

        ssh_bytes = sk_.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH)

        ssh_key_file = os.path.join(node_dir, 'sk.ssh')
        with open(ssh_key_file, 'wb') as file:
            # written as bytes
            file.write(ssh_bytes)

        self.assertTrue(os.path.exists(ssh_key_file))
        with open(ssh_key_file, 'rb') as file:
            sk4_ = serialization.load_ssh_public_key(
                file.read(),
                backend=default_backend())

        check_equal_rsa_pub_key(sk4_, sk_)  # GEEP 175

        # PEM FORMAT RSA PUBLIC KEY ROUND-TRIPPED -------------------

        pem = sk_.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1)

        key_file = os.path.join(node_dir, 'sk.pem')
        with open(key_file, 'wb') as file:
            # written as bytes
            file.write(pem)

        self.assertTrue(os.path.exists(key_file))
        with open(key_file, 'rb') as file:
            sk5_ = serialization.load_pem_public_key(
                file.read(),
                backend=default_backend())                  # GEEP 193

        check_equal_rsa_pub_key(sk5_, sk_)

    def test_dig_sig(self):
        """ Test digital signatures using a range of hash types. """

        for using in [HashTypes.SHA1, HashTypes.SHA2, ]:
            self.do_test_dig_sig(using)

    def do_test_dig_sig(self, hashtype):
        """"
        Verify calculation of digital signature using speciic hash type.
        """

        if hashtype == HashTypes.SHA1:
            sha = hashes.SHA1
        elif hashtype == HashTypes.SHA2:
            sha = hashes.SHA256
        sk_priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,  # cheap key for testing
            backend=default_backend())
        sk_ = sk_priv.public_key()

        print("WARNING: cannot use hashlib's sha code with pyca cryptography")
        print("WARNING: pyca cryptography does not support sha3/keccak")

        signer = sk_priv.signer(
            padding.PSS(
                mgf=padding.MGF1(sha()),
                salt_length=padding.PSS.MAX_LENGTH),
            sha())

        count = 64 + self.rng.next_int16(192)       # [64..256)
        data = bytes(self.rng.some_bytes(count))

        signer.update(data)
        signature = signer.finalize()               # a binary value; bytes

        # BEGIN interlude: conversion to/from base64, w/ 76-byte lines
        b64sig = base64.encodebytes(signature).decode('utf-8')
        sig2 = base64.decodebytes(b64sig.encode('utf-8'))
        self.assertEqual(sig2, signature)
        # END interlude ---------------------------------------------

        verifier = sk_.verifier(
            signature,
            padding.PSS(
                mgf=padding.MGF1(sha()),
                salt_length=padding.PSS.MAX_LENGTH),
            sha())
        verifier.update(data)

        try:
            verifier.verify()
            # digital signature verification succeeded
        except InvalidSignature:
            self.fail("dig sig verification unexpectedly failed")

        # twiddle a random byte in data array to make verification fail
        data2 = bytearray(data)
        which = self.rng.next_int16(count)
        data2[which] = 0xff & ~data2[which]
        data3 = bytes(data2)

        verifier = sk_.verifier(
            signature,                          # same digital signature
            padding.PSS(
                mgf=padding.MGF1(sha()),
                salt_length=padding.PSS.MAX_LENGTH),
            sha())
        verifier.update(data3)

        try:
            verifier.verify()
            self.fail("expected verification of modified message to fail")

        except InvalidSignature:
            pass    # digital signature verification failed


if __name__ == '__main__':
    unittest.main()
