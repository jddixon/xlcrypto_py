#!/usr/bin/env python3
# dev/py/xlattice_py/test_crypto.py

""" Test "crypto" functionality (line of spaces cache) for xlattic_py. """

import unittest
from rnglib import SimpleRNG
from xlattice.crypto import SP


class TestCrypto(unittest.TestCase):
    """ Test "crypto" functionality (line of spaces cache) for xlattic_py. """

    def setUp(self):
        self.rng = SimpleRNG()

    def test_spaces(self):
        """ Do a simple test of line-of-spaces caching. """

        for _ in range(4):
            count = self.rng.next_int16(32)
            spaces = SP.get_spaces(count)
            self.assertEqual(len(spaces), count)
            for ch_ in spaces:
                self.assertEqual(ch_, ' ')


if __name__ == '__main__':
    unittest.main()
