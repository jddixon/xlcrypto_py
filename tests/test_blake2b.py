#!/usr/bin/env python3

""" Test functionality of 256-bit BLAKE2B hash. """

import sys
import unittest
import hashlib

from rnglib import SimpleRNG
from xlattice import BLAKE2B_HEX_NONE, BLAKE2B_BIN_NONE
from xlcrypto.hash import XLBLAKE2B

if sys.version_info < (3, 6):
    # pylint:disable=unused-import
    from pyblake2 import blake2b
    assert blake2b                     # suppress warnings
else:
    import pyblake2


class TestBLAKE2B_256(unittest.TestCase):
    """ Test functionality of 256-bit BLAKE2B hash. """

    BLAKE2B_NAME = "blake2b"      # 256-bit version
    DIGEST_SIZE = 32        # bytes
    U2H_VECTORS = [
        (b'',
         '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8'),
        (b'abc',
         'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319'),
        # GET MORE FROM NIST DOCS

    ]

    def test_constructor(self):
        """ Verify that behavior of blake2b is as expected """

        sha = XLBLAKE2B()

        # Verify it has the right properties ...
        self.assertEqual(sha.hash_name(), self.BLAKE2B_NAME)
        self.assertEqual(sha.digest_size(), self.DIGEST_SIZE)
        self.assertEqual(len(sha.digest()), self.DIGEST_SIZE)
        self.assertEqual(len(sha.hexdigest()), self.DIGEST_SIZE * 2)

        # byte strings are acceptable parameters
        XLBLAKE2B(b"foo")
        XLBLAKE2B(data=b"foo")

        # None is not an acceptable parameter to the constructor
        self.assertRaises(TypeError, XLBLAKE2B, None)
        # neitheris unicode
        self.assertRaises(TypeError, XLBLAKE2B, "abcdef")

        # same constraints on parameters to update()
        self.assertRaises(TypeError, sha.update, None)
        self.assertRaises(TypeError, sha.update, "abcdef")

    def test_constants(self):
        """ Verify that the value of BLAKE2B_{BIN,HEX}_NONE is as expected. """
        sha = XLBLAKE2B()
        sha.update(b'')
        self.assertEqual(sha.hexdigest(), BLAKE2B_HEX_NONE)
        self.assertEqual(sha.digest(), BLAKE2B_BIN_NONE)

    def test_unicode_to_hex_vectors(self):
        """ Verify that the test vectors in U2H_VECTORS compute correctly."""
        for bytes_in, expected_hex_out in self.U2H_VECTORS:
            self.do_test_bytes_in_out(bytes_in, expected_hex_out)

    def test_random_value(self):
        """
        Verify that pyblake2.blake2b and hashlib.blake2b return the same
        digest for a few quasi-random values.  This test only makes sense
        for more recent versions of hashlib which support blake2.
        """
        if sys.version_info >= (3, 6):
            rng = SimpleRNG()
            for _ in range(4):
                count = 16 + rng.next_int16(48)
                data = rng.some_bytes(count)
                my_hex = XLBLAKE2B(data).hexdigest()
                expected = pyblake2.blake2b(data, digest_size=32).hexdigest()
                self.assertEqual(my_hex, expected)

    def do_test_bytes_in_out(self, bytes_in, expected_hex_out):
        """
        Verify that the binary input value hashes to the expected
        hex output value.
        """

        expected_hex_out = expected_hex_out.lower()
        expected_bin_out = bytes.fromhex(expected_hex_out)
        self.assertEqual(len(expected_bin_out), self.DIGEST_SIZE)

        # shortcut passes bytes to constructor
        sha = XLBLAKE2B(bytes_in)
        self.assertEqual(sha.hexdigest(), expected_hex_out)
        self.assertEqual(sha.digest(), expected_bin_out)

        # longer version has an explicit update call
        sha = XLBLAKE2B()
        sha.update(bytes_in)
        self.assertEqual(sha.hexdigest(), expected_hex_out)
        self.assertEqual(sha.digest(), expected_bin_out)

        # we can also hash the binary value byte by byte
        sha = XLBLAKE2B()
        for b_val in bytes_in:
            xxx = bytearray(1)
            xxx[0] = b_val
            sha.update(xxx)
        self.assertEqual(sha.hexdigest(), expected_hex_out)
        self.assertEqual(sha.digest(), expected_bin_out)


if __name__ == "__main__":
    unittest.main()
