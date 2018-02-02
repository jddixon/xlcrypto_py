#!/usr/bin/env python3

""" Test functionality of 160-bit SHA1 hash. """

import sys
import unittest
import hashlib

from rnglib import SimpleRNG
from xlattice import SHA1_HEX_NONE, SHA1_BIN_NONE
from xlcrypto.hash import XLSHA1


class TestSHA1(unittest.TestCase):
    """ Test functionality of 256-bit SHA1 hash. """

    SHA1_NAME = "sha1"
    DIGEST_SIZE = 20    # bytes
    U2H_VECTORS = [
        ('',
         'da39a3ee5e6b4b0d3255bfef95601890afd80709'),
        ('abc',
         'a9993e364706816aba3e25717850c26c9cd0d89d'),
        # GET MORE FROM NIST DOCS

    ]

    def test_constructor(self):
        """ Verify that behavior of pysha3 is as expected """

        sha = XLSHA1()

        # Verify it has the right attributes ...
        # DEBUG
        print("TYPE hash_name: ", type(sha.hash_name()))
        print("    value:      ", sha.hash_name())
        # END

        self.assertEqual(sha.hash_name(), self.SHA1_NAME)
        self.assertEqual(sha.digest_size(), self.DIGEST_SIZE)
        self.assertEqual(len(sha.digest()), self.DIGEST_SIZE)
        self.assertEqual(len(sha.hexdigest()), self.DIGEST_SIZE * 2)

        # byte strings are acceptable parameters
        XLSHA1(b"foo")
        XLSHA1(data=b"foo")

        # None is not an acceptable parameter to the constructor
        self.assertRaises(TypeError, sha, None)
        # neitheris unicode
        self.assertRaises(TypeError, sha, "abcdef")

        # same constraints on parameters to update()
        self.assertRaises(TypeError, sha.update, None)
        self.assertRaises(TypeError, sha.update, "abcdef")

    def test_constants(self):
        """ Verify that the value of SHA1_{BIN,HEX}_NONE is as expected. """
        sha = XLSHA1()
        sha.update(b'')
        self.assertEqual(sha.hexdigest(), SHA1_HEX_NONE)
        self.assertEqual(sha.digest(), SHA1_BIN_NONE)

    def test_unicode_to_hex_vectors(self):
        """ Verify that the test vectors in U2H_VECTORS compute correctly."""
        for uni_in, expected_hex_out in self.U2H_VECTORS:
            bin_in = uni_in.encode('utf-8')
            self.do_test_bin_in_out(bin_in, expected_hex_out)

    def test_random_value(self):
        """
        Verify that hashlib.sha1 returns the same digest for a few
        quasi-random values.
        """
        rng = SimpleRNG()
        for _ in range(4):
            count = 16 + rng.next_int16(48)
            data = rng.some_bytes(count)
            my_hex = XLSHA1(data).hexdigest()
            expected = hashlib.sha1(data).hexdigest()
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
        sha = XLSHA1(bin_in)
        self.assertEqual(sha.hexdigest(), expected_hex_out)
        self.assertEqual(sha.digest(), expected_bin_out)

        # longer version has an explicit update() call
        sha = XLSHA1()
        sha.update(bin_in)
        self.assertEqual(sha.hexdigest(), expected_hex_out)
        self.assertEqual(sha.digest(), expected_bin_out)

        # we can also hash the binary value byte by byte
        sha = XLSHA1()
        for b_val in bin_in:
            xxx = bytearray(1)
            xxx[0] = b_val
            sha.update(xxx)
        self.assertEqual(sha.hexdigest(), expected_hex_out)
        self.assertEqual(sha.digest(), expected_bin_out)


if __name__ == "__main__":
    unittest.main()
