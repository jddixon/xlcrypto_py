#!/usr/bin/env python3
# xlattice_py/testPKCS7.py

""" test PKCS7 padding """

import time
import unittest

from rnglib import SimpleRNG
from xlcrypto import(
    AES_BLOCK_BYTES,
    pkcs7_padding, add_pkcs7_padding, strip_pkcs7_padding)


class TestPKCS7Padding(unittest.TestCase):
    """ test PKCS7 padding """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    # actual unit tests #############################################

    def test_padding(self):
        """ test PKCS7 padding """

        seven = bytearray(7)
        self.rng.next_bytes(seven)

        fifteen = bytearray(15)
        self.rng.next_bytes(fifteen)

        sixteen = bytearray(16)
        self.rng.next_bytes(sixteen)

        seventeen = bytearray(17)
        self.rng.next_bytes(seventeen)

        padding = pkcs7_padding(seven, AES_BLOCK_BYTES)
        self.assertEqual(len(padding), AES_BLOCK_BYTES - 7)
        self.assertEqual(padding[0], AES_BLOCK_BYTES - 7)

        padding = pkcs7_padding(fifteen, AES_BLOCK_BYTES)
        self.assertEqual(len(padding), AES_BLOCK_BYTES - 15)
        self.assertEqual(padding[0], AES_BLOCK_BYTES - 15)

        padding = pkcs7_padding(sixteen, AES_BLOCK_BYTES)
        self.assertEqual(len(padding), AES_BLOCK_BYTES)
        self.assertEqual(padding[0], 16)

        padding = pkcs7_padding(seventeen, AES_BLOCK_BYTES)
        expected_len = 2 * AES_BLOCK_BYTES - 17
        self.assertEqual(len(padding), expected_len)
        self.assertEqual(padding[0], expected_len)

        padded_seven = add_pkcs7_padding(seven, AES_BLOCK_BYTES)
        unpadded_seven = strip_pkcs7_padding(padded_seven, AES_BLOCK_BYTES)
        self.assertEqual(seven, unpadded_seven)

        paddd_fifteen = add_pkcs7_padding(fifteen, AES_BLOCK_BYTES)
        unpaddd_fifteen = strip_pkcs7_padding(paddd_fifteen, AES_BLOCK_BYTES)
        self.assertEqual(fifteen, unpaddd_fifteen)

        padded_sixteen = add_pkcs7_padding(sixteen, AES_BLOCK_BYTES)
        unpadded_sixteen = strip_pkcs7_padding(padded_sixteen, AES_BLOCK_BYTES)
        self.assertEqual(sixteen, unpadded_sixteen)

        padded_seventeen = add_pkcs7_padding(seventeen, AES_BLOCK_BYTES)
        unpadded_seventeen = strip_pkcs7_padding(
            padded_seventeen, AES_BLOCK_BYTES)
        self.assertEqual(seventeen, unpadded_seventeen)


if __name__ == '__main__':
    unittest.main()
