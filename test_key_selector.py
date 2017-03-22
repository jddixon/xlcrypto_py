#!/usr/bin/env python3
# xlcrypto_py/test_key_selector.py

""" Currently just exercises test framework. """

#import hashlib
#import os
import time
import unittest

from rnglib import SimpleRNG
from xlcrypto import XLFilterError
from xlcrypto.filters import KeySelector


class TestKeySelector(unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())
        self.keysel = None                  # KeySelector
        self.m_exp = 20                     # m: size of set as power of two
        self.hash_count = 8                 # k: number of filters

        # 32 keys by default
        # self.keys = new byte[32][20]
        self.keys = []
        for _ in range(32):
            self.keys.append(bytes(0) * 20)

        self.b_off = [0] * self.hash_count
        self.w_off = [0] * self.hash_count

    def tearDown(self):
        pass

    def test_param_exceptions(self):
        """
        Verify that out of range or otherwise unacceptable constructor
        parameters are caught.
        """

        # m check keysel
        try:
            self.keysel = KeySelector(-5, self.hash_count, b'ab')
            self.fail("didn't catch negative filter size exponent")
        except XLFilterError:
            pass
        try:
            self.keysel = KeySelector(0, self.hash_count, b'ab')
            self.fail("didn't catch zero filter size exponent")
        except XLFilterError:
            pass

        # check s on k
        try:
            self.keysel = KeySelector(20, -1, b'ab')
            self.fail("didn't catch negative hash function count")
        except XLFilterError:
            pass
        try:
            self.keysel = KeySelector(20, 0, b'ab')
            self.fail("didn't catch zero hash function count")
        except XLFilterError:
            pass
        try:
            self.keysel = KeySelector(3, 0, b'ab')
            self.fail("didn't catch invalid hash function count")
        except XLFilterError:
            pass
        try:
            self.keysel = KeySelector(247, 0, b'ab')
            self.fail("didn't catch invalid hash function count")
        except XLFilterError:
            pass

#       # check s on arrays
#       try:
#           self.keysel = KeySelector(20, 8, None)
#           self.fail("didn't catch None bit offset array")
#       except XLFilterError:
#           pass
#       try:
#           self.keysel = KeySelector(20, 8, self.b_off, None)
#           self.fail("didn't catch None word offset array")
#       except XLFilterError:
#           pass

    def _set_bit_offsets(self, key_bytes, val):   # bytes-like, int[]
        """
        Set the bit selectors, which are 5-bit values packed at
        the beginning of a key.
        @param key_bytes   key, expected to be at least 20 bytes long
        @param val array of key values, expected to be self.hash_count long
        """

        b_len = len(key_bytes)
        v_len = len(val)
        cur_bit = 0
        cur_byte = 0

        for ndx in range(v_len):
            cur_byte = cur_bit // 8
            offset_in_byte = cur_bit - (cur_byte * 8)
            b_val = val[ndx] & KeySelector.UNMASK[5]   # mask value to 5 bits
            # DEBUG
#           print(
#               "hash " + ndx + ": bit " + cur_bit + ", byte " + cur_byte
#               + "; inserting " + itoh(b_val)
#               + " into " + btoh(b[cur_byte]))
            # END
            if offset_in_byte == 0:
                # write val to left end of byte
                #b[cur_byte] &= 0xf1
                key_bytes[cur_byte] |= (b_val << 3)
#              # DEBUG
#              print(
#                  "    current byte becomes " + btoh(b[cur_byte]))
#              # END
            elif offset_in_byte < 4:
                # it will fit in this byte
                #b[cur_byte] &= ( KeySelector.MASK[5] << (3 - offset_in_byte) )
                key_bytes[cur_byte] |= (b_val << (3 - offset_in_byte))
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
                val_this_byte = (b_val & KeySelector.UNMASK[bits_this_byte])
                #b[cur_byte] &= KeySelector.MASK[bitsThisByte]
                key_bytes[cur_byte] |= val_this_byte

                val_next_byte = (b_val & KeySelector.MASK[bits_this_byte]) << 3
                # b[cur_byte+1] &= (KeySelector.MASK[5 - bitsThisByte]
                #                    << (3 + bitsThisByte))
                key_bytes[cur_byte + 1] |= val_next_byte

            cur_bit += 5

    def test_bit_selection(self):
        """ Exhaustive test. """

        # set up 32 test keys
        for ndx in range(32):
            bit_offsets = [
                (ndx % 32), (ndx + 1 % 32), (ndx + 2 % 32), (ndx + 3 % 32),
                (ndx + 4 % 32), (ndx + 5 % 32), (ndx + 6 % 32), (ndx + 7 % 32)]
            self._set_bit_offsets(self.keys[ndx], bit_offsets)

        self.keysel = KeySelector(self.m_exp, self.hash_count,
                                  self.b_off, self.w_off)  # default m=20, k=8
        for ndx in range(32):
            self.keysel.get_offsets(keys[ndx])
            for j in range(hash_count):
                self.assertEqual(
                    "key " + ndx + ", func " + j + " returns wrong value",
                    (ndx + j) % 32, self.b_off[j])

    def set_word_offsets(self, key_bytes, val, m_exp, hash_count):
        """
        Set the word selectors, which are (m_exp-5)-bit values.
        @param key_bytes   key, expected to be at least 20 bytes long
        @param val array of key values, expected to be hash_count long
        """

        b_len = len(key_bytes)
        v_len = len(val)
        stride = m_exp - 5     # number of bits in word selector

        cur_bit = hash_count * 5     # position beyond the bit selectors
        cur_byte = 0
        for ndx in range(v_len):
            # force value within range
            w_val = val[ndx] & KeySelector.UNMASK[stride]
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
                    key_bytes[cur_byte] = (byte)(w_val & KeySelector.UNMASK[8])
                    w_val >>= 8
                    bits_to_go -= 8
                    # second byte
                    key_bytes[cur_byte + 1] |= (
                        w_val & KeySelector.UNMASK[bits_to_go]) << (8 - bits_to_go)
                else:
                    # only one byte affected
                    key_bytes[cur_byte] |= w_val << (8 - bits_to_go)

            else:
                # not starting at byte boundary
                if bits_to_go < (8 - offset_in_byte):
                    # CASE 1: it all fits in the first byte
                    key_bytes[cur_byte] |= w_val << (
                        offset_in_byte - bits_to_go)
                else:
                    bitsFirstByte = 8 - offset_in_byte
                    # first byte
                    key_bytes[cur_byte] |= w_val & KeySelector.UNMASK[
                        bitsFirstByte]
                    bits_to_go -= bitsFirstByte
                    w_val >>= bitsFirstByte

                    # second byte
                    if bits_to_go < 8:
                        # CASE 2: it doesn't fill the second byte
                        key_bytes[cur_byte + 1] |= w_val << (8 - bits_to_go)
                    else:
                        # CASE 3: it fills the second byte
                        bits_to_go -= 8
                        key_bytes[cur_byte + 1] = (byte)(0xff & w_val)
                        if bits_to_go > 0:
                            # CASE 4: it puts some bits in a third byte
                            w_val >>= 8
                            key_bytes[
                                cur_byte +
                                2] |= (
                                w_val << (
                                    8 -
                                    bits_to_go))


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

    def do_test_word_selection(self, m_exp, hash_count, num_keys):
        num_word_sel = 1 << (m_exp - 5)
        # int[][] word_offsets = new int [num_keys][8]
        word_offsets = []
        for ndx in range(num_keys):
            word_offsets.append([0] * 8)

        # set up the test self.keys
        # self.keys = new byte[num_keys][20]
#       for (int ndx = 0; ndx < num_keys; ndx++):
#           for (int j = 0; j < 20; j++):
#               self.keys[ndx][j] = 0
        self.keys = []
        for ndx in range(num_keys):
            self.keys.append(bytes(20))

        for ndx in range(num_keys):
            for j in range(hash_count):
                # up to 2^15 32-bit words in a 2^20 bit array
                word_offsets[ndx][j] = self.rng.next_int32(num_word_sel)

            self.set_word_offsets(
                self.keys[ndx], word_offsets[ndx], m_exp, hash_count)

        self.keysel = KeySelector(
            m_exp, hash_count, self.b_off, self.w_off)   # default m=20, k=8
        for ndx in range(num_keys):
            self.keysel.get_offsets(keys[ndx])
            for j in range(hash_count):
                self.assertEqual(
                    "key " + ndx + ", func " + j + " returns wrong value",
                    word_offsets[ndx][j], self.w_off[j])

    def test_word_selection(self):
        self.do_test_word_selection(20, 8, 32)    # default values, succeeds
        self.do_test_word_selection(14, 8, 32)    # stride = 9
        self.do_test_word_selection(13, 8, 32)    # stride = 8
        self.do_test_word_selection(12, 8, 32)    # stride = 7

    # DEBUG METHODS #//////////////////////////////////////////////
#   String itoh (int ndx):
#       return BloomSHA1.itoh(ndx)
#
#   String btoh (byte key_bytes):
#       return BloomSHA1.btoh(key_bytes)


if __name__ == '__main__':
    unittest.main()
