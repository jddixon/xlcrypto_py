#!/usr/bin/env python3
# xlcrypto_py/test_bloom_sha1.py

""" Bloom filters for sets whose members are SHA1 digests. """

import time
import unittest
from hashlib import sha1, sha256 as sha2

from rnglib import SimpleRNG
from xlcrypto import XLFilterError
from xlcrypto.filters import BloomSHA

RNG = SimpleRNG(time.time())


class TestBloomSHA(unittest.TestCase):
    """ Bloom filters for sets whose members are SHA1 digests. """

    def setUp(self):
        self.m = 20             # M = 2**m is number of bits in filter
        self.k = 8              # numberof hash funcions
        self.key_bytes = 20     # so these are BloomSHA1s
        self.keys = []          # new byte[100][20]

    def test_empty_filter(self):
        """ Verify that empty BloomSHA has expected properties. """
        fltr = BloomSHA(self.m, self.k, self.key_bytes)
        self.assertEqual(0, len(fltr),
                         "brand new fltr isn't empty")
        self.assertEqual(2 << (self.m - 1), fltr.capacity,
                         "fltr capacity is wrong")

    def test_param_exceptions(self):
        """
        Verify that out of range or otherwise unacceptable constructor
        parameters are caught.
        """

        # m (m_exp) checks
        try:
            _ = BloomSHA(-5)
            self.fail("didn't catch negative filter size exponent")
        except XLFilterError:
            pass
        try:
            _ = BloomSHA(0)
            self.fail("didn't catch zero filter size exponent")
        except XLFilterError:
            pass

        # checks on k (hash_count)
        try:
            _ = BloomSHA(20, -1)
            self.fail("didn't catch zero hash function count")
        except XLFilterError:
            pass
        try:
            _ = BloomSHA(20, 0)
            self.fail("didn't catch zero hash function count")
        except XLFilterError:
            pass
        try:
            _ = BloomSHA(3, 0)
            self.fail("didn't catch invalid hash function count")
        except XLFilterError:
            pass
        try:
            _ = BloomSHA(247, 0)
            self.fail("didn't catch invalid hash function count")
        except XLFilterError:
            pass

        try:
            _ = BloomSHA(20, 8, -47)
            self.fail("didn't catch invalid key_bytes")
        except XLFilterError:
            pass

        try:
            _ = BloomSHA(20, 8, 0)
            self.fail("didn't catch key_bytes==0")
        except XLFilterError:
            pass

    def do_test_sha1_inserts(self, m, k, num_key):
        """ Test BloomSHA1 for specific parameters. """
        keys = []
        # set up distinct keys, each the hash of a unique value
        for i in range(num_key):
            sha = sha1()
            stuff = RNG.some_bytes(20)      # 20 quasi-random bytes
            stuff[0] = i                    # guarantee uniqueness
            sha.update(stuff)
            keys.append(stuff)

        fltr = BloomSHA(m, k, key_bytes=20)
        for i in range(num_key):
            self.assertEqual(i, len(fltr))
            self.assertFalse(fltr.is_member(keys[i]),
                             "key %d not yet in set, but found!" % i)
            fltr.insert(keys[i])              # add key to fltr

        for i in range(num_key):
            self.assertTrue(fltr.is_member(keys[i]),
                            "key " + str(i) + " has been added but not found in set")

    def test_sha1_inserts(self):
        """ Test BloomSHA1 for various parameter settings. """
        self.do_test_sha1_inserts(self.m, self.k, 16)  # default values
        self.do_test_sha1_inserts(14, 8, 16)   # stride = 9
        self.do_test_sha1_inserts(13, 8, 16)   # stride = 8
        self.do_test_sha1_inserts(12, 8, 16)   # stride = 7

        self.do_test_sha1_inserts(14, 7, 16)   # stride = 9
        self.do_test_sha1_inserts(13, 7, 16)   # stride = 8
        self.do_test_sha1_inserts(12, 7, 16)   # stride = 7

        self.do_test_sha1_inserts(14, 6, 16)   # stride = 9
        self.do_test_sha1_inserts(13, 6, 16)   # stride = 8
        self.do_test_sha1_inserts(12, 6, 16)   # stride = 7

        self.do_test_sha1_inserts(14, 5, 16)   # stride = 9
        self.do_test_sha1_inserts(13, 5, 16)   # stride = 8
        self.do_test_sha1_inserts(12, 5, 16)   # stride = 7

    def do_test_sha2_inserts(self, m, k, num_key):
        """ Test BloomSHA2 for specific parameters. """
        keys = []
        # set up distinct keys, each the hash of a unique value
        for i in range(num_key):
            sha = sha2()
            stuff = RNG.some_bytes(32)      # 32 quasi-random bytes
            stuff[0] = i                    # guarantee uniqueness
            sha.update(stuff)
            keys.append(stuff)

        fltr = BloomSHA(m, k, key_bytes=32)
        for i in range(num_key):
            self.assertEqual(i, len(fltr))
            self.assertFalse(fltr.is_member(keys[i]),
                             "key %d not yet in set, but found!" % i)
            fltr.insert(keys[i])              # add key to fltr

        for i in range(num_key):
            self.assertTrue(fltr.is_member(keys[i]),
                            "key %d has been added but not found in set" % i)

    def test_sha2_inserts(self):
        """ Test SHA2 version of BloomSHA filter. """
        self.do_test_sha2_inserts(32, 8, 16)
        self.do_test_sha2_inserts(16, 16, 16)

if __name__ == '__main__':
    unittest.main()
