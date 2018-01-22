#!/usr/bin/env python3

""" Test functionality of 256-bit SHA3 hash. """

import sys
import unittest
import hashlib

from rnglib import SimpleRNG
from xlattice import SHA3_HEX_NONE, SHA3_BIN_NONE
from xlcrypto.hash import XLSHA3

if sys.version_info < (3, 6):
    # pylint:disable=unused-import
    import sha3                     # pysha3
    assert sha3                     # suppress warnings


class TestSHA3_256(unittest.TestCase):
    """ Test functionality of 256-bit SHA3 hash. """

    SHA3_NAME = "sha3"      # 256-bit version
    DIGEST_SIZE = 32        # bytes
    U2H_VECTORS = [
        ('',
         'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'),
        ('abc',
         '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'),
        # GET MORE FROM NIST DOCS

    ]

    def test_constructor(self):
        """ Verify that behavior of pysha3 is as expected """

        sha = XLSHA3()

        # Verify it has the right properties ...
        self.assertEqual(sha.hash_name, self.SHA3_NAME)
        self.assertEqual(sha.digest_size, self.DIGEST_SIZE)
        self.assertEqual(len(sha.digest), self.DIGEST_SIZE)
        self.assertEqual(len(sha.hexdigest), self.DIGEST_SIZE * 2)

        # we shouldn't be able to assign to properties
        self.assertRaises(AttributeError, setattr, sha, "digest", 42)
        self.assertRaises(AttributeError, setattr, sha, "hash_name", "foo")

        # byte strings are acceptable parameters
        XLSHA3(b"foo")
        XLSHA3(data=b"foo")

        # None is not an acceptable parameter to the constructor
        self.assertRaises(TypeError, XLSHA3, None)
        # neitheris unicode
        self.assertRaises(TypeError, XLSHA3, "abcdef")

        # same constraints on parameters to update()
        self.assertRaises(TypeError, sha.update, None)
        self.assertRaises(TypeError, sha.update, "abcdef")

    def test_constants(self):
        """ Verify that the value of SHA3_{BIN,HEX}_NONE is as expected. """
        sha = XLSHA3()
        sha.update(b'')
        self.assertEqual(sha.hexdigest, SHA3_HEX_NONE)
        self.assertEqual(sha.digest, SHA3_BIN_NONE)

    def test_unicode_to_hex_vectors(self):
        """ Verify that the test vectors in U2H_VECTORS compute correctly."""
        for uni_in, expected_hex_out in self.U2H_VECTORS:
            bin_in = uni_in.encode('utf-8')     # .hex()
            self.do_test_bin_in_out(bin_in, expected_hex_out)

    def test_random_value(self):
        """
        Verify that hashlib.sha2 returns the same digest for a few
        quasi-random values.
        """
        rng = SimpleRNG()
        for _ in range(4):
            count = 16 + rng.next_int16(48)
            data = rng.some_bytes(count)
            my_hex = XLSHA3(data).hexdigest
            expected = hashlib.sha3_256(data).hexdigest()
            self.assertEqual(my_hex, expected)

    def do_test_bin_in_out(self, bin_in, expected_hex_out):
        """
        Verify that the binary input value hashes to the expected
        hex output value.
        """

        expected_hex_out = expected_hex_out.lower()
        expected_bin_out = bytes.fromhex(expected_hex_out)
        self.assertEqual(len(expected_bin_out), self.DIGEST_SIZE)

        # shortcut passes bytes to constructor
        sha = XLSHA3(bin_in)
        self.assertEqual(sha.hexdigest, expected_hex_out)
        self.assertEqual(sha.digest, expected_bin_out)

        # longer version has an explicit update call
        sha = XLSHA3()
        sha.update(bin_in)
        self.assertEqual(sha.hexdigest, expected_hex_out)
        self.assertEqual(sha.digest, expected_bin_out)

        # we can also hash the binary value byte by byte
        sha = XLSHA3()
        for b_val in bin_in:
            xxx = bytearray(1)
            xxx[0] = b_val
            sha.update(xxx)
        self.assertEqual(sha.hexdigest, expected_hex_out)
        self.assertEqual(sha.digest, expected_bin_out)


if __name__ == "__main__":
    unittest.main()
