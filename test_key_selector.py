#!/usr/bin/env python3

# xlcrypto_py/test_key_selector.py

""" Exercise KeySelector functionality. """

#import hashlib
#import os
import time
import unittest
from copy import deepcopy

from rnglib import SimpleRNG
from xlcrypto import XLFilterError
from xlcrypto.filters import _KeySelector


class TestKeySelector(unittest.TestCase):
    """ Exercise KeySelector functionality. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())
        self.keysel = None                  # KeySelector
        self.m = 20                     # m: size of set as power of two
        self.k = 8                 # k: number of filters

        # 32 keys by default
        # self.b = new byte[32][20]
        self.b = []
        for _ in range(32):
            self.b.append(self.rng.some_bytes(20))

        self.b_off = [0] * self.k
        self.w_off = [0] * self.k

        # DEBUG
        print("len(b) is %d" % len(self.b))
        print("len(b[0]) is %d" % len(self.b[0]))
        print("len(b_off) is %d" % len(self.b_off))
        print("len(w_off) is %d" % len(self.w_off))
        # END

    def tearDown(self):
        pass

    # WE NOW ASSUME PARAMS HAVE BEEN CHECKED
#   def test_param_exceptions(self):
#       """
#       Verify that out of range or otherwise unacceptable constructor
#       parameters are caught.
#       """
#       # DEBUG
#       print("\nTEST_PARAM_EXCEPTIONS")
#       # END

#       # m check keysel
#       try:
#           self.keysel = _KeySelector(-5, self.k, self.b[0])
#           self.fail("didn't catch negative filter size exponent")
#       except XLFilterError:
#           pass
#       try:
#           self.keysel = _KeySelector(0, self.k, self.b[0])
#           self.fail("didn't catch zero filter size exponent")
#       except XLFilterError:
#           pass

#       # check s on k
#       try:
#           self.keysel = _KeySelector(20, -1, self.b[0])
#           self.fail("didn't catch negative hash function count")
#       except XLFilterError:
#           pass
#       try:
#           self.keysel = _KeySelector(20, 0, self.b[0])
#           self.fail("didn't catch zero hash function count")
#       except XLFilterError:
#           pass
#       try:
#           self.keysel = _KeySelector(3, 0, self.b[0])
#           self.fail("didn't catch invalid hash function count")
#       except XLFilterError:
#           pass
#       try:
#           self.keysel = _KeySelector(247, 0, self.b[0])
#           self.fail("didn't catch invalid hash function count")
#       except XLFilterError:
#           pass

#       # checks on arrays
#       try:
#           self.keysel = _KeySelector(20, 8, None)
#           self.fail("didn't catch None bit offset array")
#       except XLFilterError:
#           pass

    def _set_bit_sels(self, b, val):   # bytes-like, int[]
        """
        Set the bit selectors, which are _KeySelector.KEY_SEL_BITS-bit values
        packed at the beginning of a key.

        @param b key, expected to be at least 20 bytes long
        @param val       array of key values, exp. to be self.k long
        """

        # XXX
        b_len = len(b)
        v_len = len(val)

        # DEBUG
        print("_set_bit_sels: b_len = %d, v_len = %d" % (b_len, v_len))
        # END
        cur_bit = 0
        cur_byte = 0

        for i in range(v_len):
            cur_byte = cur_bit // 8
            offset_in_byte = cur_bit - (cur_byte * 8)
            # mask value to _KeySelector.KEY_SEL_BITS bits
            b_val = val[i] & _KeySelector.UNMASK[_KeySelector.KEY_SEL_BITS]
            # DEBUG
#           print(
#               "hash " + ndx + ": bit " + cur_bit + ", byte " + cur_byte
#               + "; inserting " + itoh(b_val)
#               + " into " + btoh(b[cur_byte]))
            # END
            if offset_in_byte == 0:
                # write val to left end of byte
                #b[cur_byte] &= 0xf1

                # XXX THE 0xff IS A HACK
                b[cur_byte] |= 0xff & (b_val << 3)
#              # DEBUG
#              print(
#                  "    current byte becomes " + btoh(b[cur_byte]))
#              # END
            elif offset_in_byte < 4:
                # it will fit in this byte
                #b[cur_byte] &= (_KeySelector.MASK[_KeySelector.KEY_SEL_BITS] << (3 - offset_in_byte) )
                b[cur_byte] |= (b_val << (3 - offset_in_byte))
#              # DEBUG
#              print(
#                  "    offset_in_byte " + offsetInByte
#              + "\n    current byte becomes " + btoh(b[cur_byte]))
#              # END
            else:
                # some goes in this byte, some in the next
                bits_this_byte = 8 - offset_in_byte
#              # DEBUG
#              print(
#                  "SPLIT VALUE: "
#                  + "bit " + cur_bit + ", byte " + cur_byte
#                  + ", offset_in_byte " + offsetInByte
#                  + ", bitsThisByte = " + bitsThisByte)
#              # END
                val_this_byte = (b_val & _KeySelector.UNMASK[bits_this_byte])
                #b[cur_byte] &= _KeySelector.MASK[bitsThisByte]
                b[cur_byte] |= val_this_byte

                # XXX THE 0xff IS A HACK
                val_next_byte = 0xff & (
                    (b_val & _KeySelector.MASK[bits_this_byte]) << 3)
                # b[cur_byte+1] &= (KeySelector.MASK[KeySelector.KEY_SEL_BITS - bitsThisByte]
                #                    << (3 + bitsThisByte))
                b[cur_byte + 1] |= val_next_byte

            cur_bit += _KeySelector.KEY_SEL_BITS

    def test_bit_selection(self):
        """ Exhaustive test. """

        # DEBUG
        print("\nTEST_BIT_SELECTION")
        # END

        # set up 32 test keys
        for i in range(32):
            # reinitialize our test keys
            self.b.append(self.rng.some_bytes(20))

            # DEBUG
            print("test_bit_selection: key %d" % i)
            for n, bval in enumerate(self.b[i]):
                print("%2d 0x%02x" % (n, bval))
            # END

            bit_sels = [
                (i % 32), (i + 1) % 32, (i + 2) % 32, (i + 3) % 32,
                (i + 4) % 32, (i + 5) % 32, (i + 6) % 32, (i + 7) % 32]
            self._set_bit_sels(self.b[i], bit_sels)

        self.keysel = _KeySelector(self.m, self.k, self.b[i])
        for i in range(32):
            self.keysel.get_offsets(self.b[i])
            for j in range(self.k):
                self.assertEqual(
                    (i + j) % 32, self.b_off[j],
                    "key %d, hash %d returns wrong value 0x%02x" % (
                        i, j, self.b_off[j]))

    def set_byte_sels(self, b, val, m, k):
        """
        Set the word selectors, which are (m - KEY_SEL_BITS)-bit values.

        @param b  key, expected to be at least 20 bytes long
        @param val        array of key values, expected to be k long
        @param m      memory size in bytes is 2**m
        @param k number of hash functions
        """

        b_len = len(b)  # number of bytes in key
        v_len = len(val)
        # set number of bits in word selector
        stride = m - _KeySelector.KEY_SEL_BITS

        # DEBUG
        print("set_byte_sels: b_len %d, v_len %d, stride %d; m %d h %d" % (
            b_len, v_len, stride, m, k))
        # END

        # position beyond the bit selectors
        cur_bit = k * _KeySelector.KEY_SEL_BITS
        cur_byte = 0
        for i in range(v_len):
            # force value within range
            # DEBUG
            val[i]
            _KeySelector.UNMASK[stride]
            # END
            w_val = val[i] & _KeySelector.UNMASK[stride]
            bits_to_go = stride
            cur_byte = cur_bit // 8
            offset_in_byte = cur_bit - (cur_byte * 8)

#          # DEBUG
#          print(
#              "hash " + i + ": bit " + cur_bit + ", byte " + cur_byte
#              + "; inserting " + itoh(wVal) + " at offset " + offset_in_byte
#              + "\n    next three bytes     are "
#              + btoh(b[cur_byte])
#              + ( cur_byte < 19 ?
#                  " " + btoh(b[cur_byte+1]) : "" )
#              + ( cur_byte < 18 ?
#                  " " + btoh(b[cur_byte+2]) : "" )
#          )
#          # END

            if offset_in_byte == 0:
                # aligned
                if bits_to_go >= 8:
                    # first of two bytes
                    b[cur_byte] = w_val & _KeySelector.UNMASK[8]
                    w_val >>= 8
                    bits_to_go -= 8
                    # second byte
                    b[cur_byte + 1] |= (
                        w_val & _KeySelector.UNMASK[bits_to_go]) << (8 - bits_to_go)
                else:
                    # only one byte affected
                    b[cur_byte] |= w_val << (8 - bits_to_go)

            else:
                # not starting at byte boundary
                if bits_to_go < (8 - offset_in_byte):
                    # CASE 1: it all fits in the first byte
                    b[cur_byte] |= w_val << (
                        offset_in_byte - bits_to_go)
                else:
                    bits_first_byte = 8 - offset_in_byte
                    # first byte
                    b[cur_byte] |= w_val & _KeySelector.UNMASK[
                        bits_first_byte]
                    bits_to_go -= bits_first_byte
                    w_val >>= bits_first_byte

                    # second byte
                    if bits_to_go < 8:
                        # CASE 2: it doesn't fill the second byte
                        b[cur_byte + 1] |= w_val << (8 - bits_to_go)
                    else:
                        # CASE 3: it fills the second byte
                        bits_to_go -= 8
                        b[cur_byte + 1] = 0xff & w_val
                        if bits_to_go > 0:
                            # CASE 4: it puts some bits in a third byte
                            w_val >>= 8
                            b[cur_byte + 2] |= (
                                w_val << (8 - bits_to_go))


#          # DEBUG
#          print("    next three bytes are now "
#              + btoh(b[cur_byte])
#              + ( cur_byte < 19 ?
#                  " " + btoh(b[cur_byte+1]) : "" )
#              + ( cur_byte < 18 ?
#                  " " + btoh(b[cur_byte+2]) : "" )
#          )
#          # END
            cur_bit += stride

    def do_test_byte_selection(self, m, k, num_keys):
        # DEBUG
        print("\nDO_TEST_WORD_SELECTION: m = %d, k = %d for %d keys" % (
            m, k, num_keys))
        # END

        num_byte_sel = 1 << (m - _KeySelector.KEY_SEL_BITS)
        # int[][] byte_sels = new int [num_keys][8]
        byte_sels = []
        for i in range(num_keys):
            byte_sels.append([0] * 8)

        # set up the test keys
        keys = []
        zeroes = [0] * 20
        for i in range(num_keys):
            keys.append(deepcopy(zeroes))

        for i in range(num_keys):
            for j in range(k):
                # up to 2^14 64-bit words in a 2^20 bit array
                byte_sels[i][j] = self.rng.next_int16(num_byte_sel)

            self.set_byte_sels(
                keys[i], byte_sels[i], m, k)

        keysel = _KeySelector(
            m, k, self.b_off, self.w_off)   # default m=20, k=8
        for i in range(num_keys):
            keysel.get_offsets(keys[i])
            for j in range(k):
                # DEBUG
                if byte_sels[i][j] != self.w_off[j]:
                    print("byte_sels[ndx][j] = %d (0x%04x)" % (
                        byte_sels[i][j], byte_sels[i][j]))
                    print("self.w_off[j]        = %d" % self.w_off[j])
                # END
                self.assertEqual(
                    byte_sels[i][j], self.w_off[j],
                    "key %d, hash %d returns wrong value 0x%x" % (
                        i, j, self.w_off[j]))

    def test_byte_selection(self):
        # DEBUG
        print("\nTEST_WORD_SELECTION")
        # END

        self.do_test_byte_selection(20, 8, 32)    # default values
        self.do_test_byte_selection(14, 8, 32)    # stride = 9
        self.do_test_byte_selection(13, 8, 32)    # stride = 8
        self.do_test_byte_selection(12, 8, 32)    # stride = 7

    def test_hacking_about(self):
        x = bytes([n for n in range(256)])
        i = int.from_bytes(x, 'big')
        for k in range(256):
            m = i & 0xff
            i >>= 8
            print(m)        # prints 255 .. 0 inclusive

    # DEBUG METHODS #//////////////////////////////////////////////
#   String itoh (int ndx):
#       return BloomSHA1.itoh(ndx)
#
#   String btoh (byte b):
#       return BloomSHA1.btoh(b)


if __name__ == '__main__':
    unittest.main()
