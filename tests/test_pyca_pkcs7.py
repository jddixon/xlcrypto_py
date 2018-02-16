#!/usr/bin/env python3
# xlattice_py/test_pyca_pkcs7.py

""" Test pyca's PKCS7 padding. """

import time
import unittest

from rnglib import SimpleRNG
from xlcrypto import AES_BLOCK_BYTES, AES_BLOCK_BITS
from cryptography.hazmat.primitives import padding


class TestPKCS7Padding(unittest.TestCase):
    """ test PKCS7 padding """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def do_test_padding(self, length):
        """ length is in bytes. """

#       # DEBUG
#       def dump(title, data):
#           print(title, end='')
#           for ndx, datum in enumerate(data):
#               print('%02x ' % datum, end='' )
#           print()
#       # END

        data_ = bytearray(length)
        self.rng.next_bytes(data_)
        data = bytes(data_)

#       # DEBUG
#       dump("DATA:   ", data)
#       # END
        padder = padding.PKCS7(AES_BLOCK_BITS).padder()
        padded_data = padder.update(data) + padder.finalize()
#       # DEBUG
#       dump("PADDED: ", padded_data)
#       # END

        # round up to the next higher number of whole blocks
        if length % AES_BLOCK_BYTES == 0:
            expected_len = length + AES_BLOCK_BYTES
        else:
            expected_len = ((length + AES_BLOCK_BYTES - 1) // AES_BLOCK_BYTES)\
                * AES_BLOCK_BYTES
        delta = expected_len - length       # number of bytes of padding
        self.assertEqual(padded_data[-1], delta)

        self.assertEqual(len(padded_data), expected_len)

        unpadder = padding.PKCS7(AES_BLOCK_BITS).unpadder()
        data_out = unpadder.update(padded_data) + unpadder.finalize()
        self.assertEqual(data_out, data)

    def test_padding(self):
        """ test PKCS7 padding """

        self.do_test_padding(7)
        self.do_test_padding(15)
        self.do_test_padding(16)
        self.do_test_padding(17)
        self.do_test_padding(31)
        self.do_test_padding(32)
        self.do_test_padding(33)


if __name__ == '__main__':
    unittest.main()
