#!/usr/bin/env python3

""" Test functionality of 160-bit SHA2 hash. """

import sys
import unittest
import hashlib

from rnglib import SimpleRNG
from xlattice import SHA2_HEX_NONE, SHA2_BIN_NONE
from xlcrypto.hash import XLSHA2


class TestSHA2(unittest.TestCase):
    """ Test functionality of 256-bit SHA2 hash. """

    SHA2_NAME = "sha2"
    DIGEST_SIZE = 32    # bytes
    U2H_VECTORS = [
        ('',
         'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
        ('abc',
         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
        # GET MORE FROM NIST DOCS

    ]

    def test_constructor(self):
        """ Verify that behavior of pysha3 is as expected """

        sha = XLSHA2()

        # Verify it has the right properties ...
        self.assertEqual(sha.hash_name, self.SHA2_NAME)
        self.assertEqual(sha.digest_size, self.DIGEST_SIZE)
        self.assertEqual(len(sha.digest), self.DIGEST_SIZE)
        self.assertEqual(len(sha.hexdigest), self.DIGEST_SIZE * 2)

        # we shouldn't be able to assign to properties
        self.assertRaises(AttributeError, setattr, sha, "digest", 42)
        self.assertRaises(AttributeError, setattr, sha, "hash_name", "foo")

        # byte strings are acceptable parameters
        XLSHA2(b"foo")
        XLSHA2(data=b"foo")

        # None is not an acceptable parameter to the constructor
        self.assertRaises(TypeError, sha, None)
        # neitheris unicode
        self.assertRaises(TypeError, sha, "abcdef")

        # same constraints on parameters to update()
        self.assertRaises(TypeError, sha.update, None)
        self.assertRaises(TypeError, sha.update, "abcdef")

    def test_constants(self):
        """ Verify that the value of SHA2_{BIN,HEX}_NONE is as expected. """
        sha = XLSHA2()
        sha.update(b'')
        self.assertEqual(sha.hexdigest, SHA2_HEX_NONE)
        self.assertEqual(sha.digest, SHA2_BIN_NONE)

    def test_unicode_to_hex_vectors(self):
        """ Verify that the test vectors in U2H_VECTORS compute correctly."""
        for uni_in, expected_hex_out in self.U2H_VECTORS:
            bin_in = uni_in.encode('utf-8')
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
            my_hex = XLSHA2(data).hexdigest
            expected = hashlib.sha256(data).hexdigest()
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
        sha = XLSHA2(bin_in)
        self.assertEqual(sha.hexdigest, expected_hex_out)
        self.assertEqual(sha.digest, expected_bin_out)

        # longer version has an explicit update() call
        sha = XLSHA2()
        sha.update(bin_in)
        self.assertEqual(sha.hexdigest, expected_hex_out)
        self.assertEqual(sha.digest, expected_bin_out)

        # we can also hash the binary value byte by byte
        sha = XLSHA2()
        for b_val in bin_in:
            xxx = bytearray(1)
            xxx[0] = b_val
            sha.update(xxx)
        self.assertEqual(sha.hexdigest, expected_hex_out)
        self.assertEqual(sha.digest, expected_bin_out)


if __name__ == "__main__":
    unittest.main()
