#!/usr/bin/env python3
# xlcrypto_py/test_bloom_sha1.py

""" Bloom filters for sets whose members are SHA1 digests. """

import time
import unittest

from rnglib import SimpleRNG
from xlcrypto import XLFilterError
from xlcrypto.filters import BloomSHA1


class TestBloomSHA1(unittest.TestCase):
    """ Bloom filters for sets whose members are SHA1 digests. """

    def setUp(self):
        self.filter = None      # BloomSHA1
        self.m_exp = 20             # number of strings in set
        self.hash_count = 8
        self.keys = []          # new byte[100][20]

    def test_empty_filter(self):
        filter = BloomSHA1(self.m_exp, self.hash_count)
        self.assertEqual("brand new filter isn't empty", 0, len(filter))
        self.assertEqual("filter capacity is wrong",
                         2 << (m_exp - 1), filter.capacity)

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

    def do_test_inserts(self, m_exp, hash_count, num_key):
        keys = []
        # set up distinct keys
        for ndx in range(num_key):
            keys.append([])
            for j in range(20):
                keys[ndx].append(0xff & (ndx + j + 100))

        filter = BloomSHA1(m_exp, hash_count)
        for ndx in range(num_key):
            self.assertEqual(ndx, len(filter))
            self.assertFalse("key " + ndx + " not yet in set, but found!",
                             filter.member(keys[ndx]))
            filter.insert(keys[ndx])

        for ndx in range(num_key):
            # if the message isn't there, we get an NPE - weird
            self.assertTrue("key " + ndx + " has been added but not found in set",
                            filter.member(keys[ndx]))

    def test_inserts(self):
        self.do_test_inserts(self.m_exp, self.hash_count, 16)  # default values
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
