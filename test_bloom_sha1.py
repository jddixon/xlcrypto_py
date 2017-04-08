#!/usr/bin/env python3
# xlcrypto_py/test_bloom_sha1.py

""" Bloom filters for sets whose members are SHA1 digests. """

import time
import unittest
from hashlib import sha1

from rnglib import SimpleRNG
from xlcrypto import XLFilterError
from xlcrypto.filters import BloomSHA1

rng = SimpleRNG(time.time())


class TestBloomSHA1(unittest.TestCase):
    """ Bloom filters for sets whose members are SHA1 digests. """

    def setUp(self):
        self.filter = None      # BloomSHA1
        self.m = 20             # M = 2**m is number of bits in filter
        self.k = 8              # numberof hash funcions
        self.keys = []          # new byte[100][20]

    def test_empty_filter(self):
        filter = BloomSHA1(self.m, self.k)
        self.assertEqual(0, len(filter),
                         "brand new filter isn't empty")
        self.assertEqual(2 << (self.m - 1), filter.capacity,
                         "filter capacity is wrong")

    def test_param_exceptions(self):
        """
        Verify that out of range or otherwise unacceptable constructor
        parameters are caught.
        """

        # m (m_exp) checks
        try:
            filter = BloomSHA1(-5)
            self.fail("didn't catch negative filter size exponent")
        except XLFilterError:
            pass
        try:
            filter = BloomSHA1(0)
            self.fail("didn't catch zero filter size exponent")
        except XLFilterError:
            pass
        try:
            filter = BloomSHA1(21)
            self.fail("didn't catch too-large filter size exponent")
        except XLFilterError:
            pass

        # checks on k (hash_count)
        try:
            filter = BloomSHA1(20, -1)
            self.fail("didn't catch zero hash function count")
        except XLFilterError:
            pass
        try:
            filter = BloomSHA1(20, 0)
            self.fail("didn't catch zero hash function count")
        except XLFilterError:
            pass
        try:
            filter = BloomSHA1(3, 0)
            self.fail("didn't catch invalid hash function count")
        except XLFilterError:
            pass
        try:
            filter = BloomSHA1(247, 0)
            self.fail("didn't catch invalid hash function count")
        except XLFilterError:
            pass

    def do_test_inserts(self, m, k, num_key):
        keys = []
        # set up distinct keys, each the hash of a unique value
        for i in range(num_key):
            sha = sha1()
            stuff = rng.some_bytes(20)      # 20 quasi-random bytes
            stuff[0] = i                    # guarantee uniqueness
            sha.update(stuff)
            stuff2 = sha.digest()           # SHA1 of stuff
            keys.append(stuff)

        filter = BloomSHA1(m, k)
        for i in range(num_key):
            self.assertEqual(i, len(filter))
            self.assertFalse(filter.member(keys[i]),
                             "key %d not yet in set, but found!" % i)
            filter.insert(keys[i])              # add key to filter

        for i in range(num_key):
            self.assertTrue(filter.member(keys[i]),
                            "key " + i + " has been added but not found in set")

    def test_inserts(self):
        self.do_test_inserts(self.m, self.k, 16)  # default values
        self.do_test_inserts(14, 8, 16)   # stride = 9
        self.do_test_inserts(13, 8, 16)   # stride = 8
        self.do_test_inserts(12, 8, 16)   # stride = 7

        self.do_test_inserts(14, 7, 16)   # stride = 9
        self.do_test_inserts(13, 7, 16)   # stride = 8
        self.do_test_inserts(12, 7, 16)   # stride = 7

        self.do_test_inserts(14, 6, 16)   # stride = 9
        self.do_test_inserts(13, 6, 16)   # stride = 8
        self.do_test_inserts(12, 6, 16)   # stride = 7

        self.do_test_inserts(14, 5, 16)   # stride = 9
        self.do_test_inserts(13, 5, 16)   # stride = 8
        self.do_test_inserts(12, 5, 16)   # stride = 7

if __name__ == '__main__':
    unittest.main()
