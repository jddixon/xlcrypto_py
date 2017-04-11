#!/usr/bin/env python3

# xlcrypto_py/test_key_selector.py

""" Exercise KeySelector functionality. """

#import hashlib
#import os
import time
import unittest

from rnglib import SimpleRNG
from xlcrypto import XLFilterError
from xlcrypto.filters import BloomSHA, KeySelector


class TestKeySelector(unittest.TestCase):
    """ Exercise KeySelector functionality. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def test_param_exceptions(self):
        """
        Verify that out of range or otherwise unacceptable constructor
        parameters are caught.
        """

        fltr = BloomSHA(m=20, k=8, key_bytes=20)

        bad_key = self.rng.some_bytes(15)               # wrong key length
        try:
            _ = KeySelector(bad_key, fltr)
            self.fail("KeySelector accepted key with wrong length")
        except XLFilterError:
            pass

        good_key = self.rng.some_bytes(20)               # correct key length
        try:
            _ = KeySelector(good_key, None)
            self.fail("KeySelector accepted key with wrong length")
        except XLFilterError:
            pass

    def test_key_selectors(self):

        m = 20                  # m: size of filter as power of two: 2**20 bits
        k = 8                   # k: number of filters
        b = []                  # will be 32 keys
        for _ in range(32):
            # keys are 20 bytes=160 bits long
            b.append(self.rng.some_bytes(20))

        # DEBUG
        print("len(b) is %d" % len(b))
        print("len(b[0]) is %d" % len(b[0]))
        # END

        fltr = BloomSHA(m, k, key_bytes=20)    # so BloomSHA1
        self.assertIsNotNone(fltr)

        # the most elementary of tests
        for i in range(32):
            # self.assertFalse(fltr.is_member(b[i]))

            keysel = KeySelector(b[i], fltr)
            self.assertIsNotNone(keysel)

            bitsel, bytesel = keysel.bitsel, keysel.bytesel
            self.assertIsNotNone(bitsel)
            self.assertEqual(len(bitsel), k)

            self.assertIsNotNone(bytesel)
            self.assertEqual(len(bytesel), k)

            # fltr.insert(b[i])
            # self.assertTrue(fltr.is_member(b[i]))

if __name__ == '__main__':
    unittest.main()
