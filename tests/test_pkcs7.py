#!/usr/bin/env python3
# xlattice_py/testPKCS7.py

""" test PKCS7 padding """

import time
import unittest

from rnglib import SimpleRNG
from xlcrypto import AES_BLOCK_BYTES
from xlcrypto.padding import(
    pkcs7_padding, add_pkcs7_padding, strip_pkcs7_padding)


class TestPKCS7Padding(unittest.TestCase):
    """ test PKCS7 padding """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def do_test_padding(self, block_bytes, data_bytes):
        """ Both block size and data length are in bytes. """

        data = self.rng.some_bytes(data_bytes)
        extra = pkcs7_padding(data, block_bytes)
        padded = data + extra
        extra_bytes = len(extra)

        # verify that value of padding bytes is in each case the length
        for ndx, extra_byte in enumerate(extra):
            self.assertEqual(extra_byte, extra_bytes)   # byte contains length

        # verify that padded data structure is a whole number of blocks
        self.assertEqual(len(padded) % block_bytes, 0)

        # stripping ofd the padding should return the original value
        unpadded = strip_pkcs7_padding(padded, AES_BLOCK_BYTES)
        self.assertEqual(unpadded, data)

    def test_padding(self):
        """ test PKCS7 padding """

        self.do_test_padding(AES_BLOCK_BYTES, 7)
        self.do_test_padding(AES_BLOCK_BYTES, 8)
        self.do_test_padding(AES_BLOCK_BYTES, 9)

        self.do_test_padding(AES_BLOCK_BYTES, 15)
        self.do_test_padding(AES_BLOCK_BYTES, 16)
        self.do_test_padding(AES_BLOCK_BYTES, 17)

        self.do_test_padding(AES_BLOCK_BYTES, 63)
        self.do_test_padding(AES_BLOCK_BYTES, 64)
        self.do_test_padding(AES_BLOCK_BYTES, 65)


if __name__ == '__main__':
    unittest.main()
