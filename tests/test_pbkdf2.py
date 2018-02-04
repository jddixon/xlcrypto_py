#!/usr/bin/env python3
# dev/py/xlcrypto_py/src/xlcrypto/test_pbkdf2.py

""" Test key derivation function pbkdf2 """

import unittest

from rnglib import SimpleRNG
from xlcrypto.keyderiv import pbkdf2
from xlattice import HashTypes


class TestPBKDF2(unittest.TestCase):
    """ Test key derivation function pbkdf2 """

    def setUp(self):
        self.rng = SimpleRNG()

    def test_pbkdf2(self):
        """ Do a simple test of line-of-spaces caching. """

        for hashtype in [HashTypes.SHA1, HashTypes.SHA2]:
            salt = self.rng.some_bytes(8)
            key = pbkdf2('foo', salt, hashtype)
            # for now, that's good enough
            _ = key


if __name__ == '__main__':
    unittest.main()
