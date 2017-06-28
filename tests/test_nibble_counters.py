#!/usr/bin/env python3
# xlcrypto_py/test_nibble_counters.py

""" Test nibble counters used in CountingBlooms. """

import time
import unittest
from hashlib import sha1, sha256 as sha2

from rnglib import SimpleRNG
from xlcrypto import XLFilterError
from xlcrypto.filters import BloomSHA, NibbleCounters

RNG = SimpleRNG(time.time())


class TestNibbleCounters(unittest.TestCase):
    """
    Tests the counters associated with Bloom filters for sets whose members
    are 20- or 32-byte SHA digests.
    """

    def do_nibble_test_bit(self, counters, filter_bit):
        value = 0

        # DEBUG
        # print("do_nibble_test_bit: filter_bit %6d" % filter_bit)
        # END

        # count up through all possible values and beyond
        for i in range(18):
            # DEBUG
            #print("  up %2d" % i)
            # END
            value = counters.inc(filter_bit)
            if i < 15:
                self.assertEqual(value, i + 1,
                                 "bit %d:  error adding 1 to %d" % (filter_bit, i))
            else:
                self.assertEqual(value, 15,
                                 "bit %d:  overflow error" % filter_bit)

        # count back down
        for i in range(18):
            # DEBUG
            #print("  down %2d" % i)
            # END
            value = counters.dec(filter_bit)
            if i < 15:
                self.assertEqual(value, 14 - i,
                                 "bit %d filter_bit: error subtracting 1 from %d" % (
                                     filter_bit, 15 - i))
            else:
                self.assertEqual(value, 0,
                                 "bit %d: underflow error" % filter_bit)

    def do_nibble_test(self, m):
        """ Run tests for specific value of m. """

        fltr = BloomSHA(m)                  # used only to calculate capacity
        fltr_size = fltr.capacity
        self.assertEqual(fltr_size, 1 << m)

        counters = NibbleCounters(m)

        # verify we get exceptions for bits out of range
        try:
            _ = counters.inc(-1)
        except XLFilterError:
            pass
        try:
            _ = counters.inc(fltr_size)
        except XLFilterError:
            pass
        try:
            _ = counters.dec(-1)
        except XLFilterError:
            pass
        try:
            _ = counters.dec(fltr_size)
        except XLFilterError:
            pass

        # test top bits, bottom bits, and some in the middle
        self.do_nibble_test_bit(counters, 0)
        self.do_nibble_test_bit(counters, 1)
        self.do_nibble_test_bit(counters, fltr_size - 2)
        self.do_nibble_test_bit(counters, fltr_size - 1)
        for _ in range(4):
            bit = 2 + RNG.next_int16(fltr_size - 4)
            self.do_nibble_test_bit(counters, bit)

    def test_nibs(self):
        """ Run tests for various values of m. """
        self.do_nibble_test(16)
        self.do_nibble_test(17)
        self.do_nibble_test(20)
        self.do_nibble_test(24)


if __name__ == '__main__':
    unittest.main()
