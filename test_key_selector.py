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
from xlcrypto.filters import KeySelector


class TestKeySelector(unittest.TestCase):
    """ Exercise KeySelector functionality. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())
        self.keysel = None                  # KeySelector
        self.m_exp = 20                     # m: size of set as power of two
        self.hash_count = 8                 # k: number of filters

        # 32 keys by default
        # self.key_bytes = new byte[32][20]
        self.key_bytes = []
        for _ in range(32):
            self.key_bytes.append(self.rng.some_bytes(20))

        self.b_off = [0] * self.hash_count
        self.w_off = [0] * self.hash_count

        # DEBUG
        print("len(key_bytes) is %d" % len(self.key_bytes))
        print("len(key_bytes[0]) is %d" % len(self.key_bytes[0]))
        print("len(b_off) is %d" % len(self.b_off))
        print("len(w_off) is %d" % len(self.w_off))
        # END

    def tearDown(self):
        pass

    def test_param_exceptions(self):
        """
        Verify that out of range or otherwise unacceptable constructor
        parameters are caught.
        """
        # DEBUG
        print("\nTEST_PARAM_EXCEPTIONS")
        # END

        # m check keysel
        try:
            self.keysel = KeySelector(-5, self.hash_count,
                                      self.b_off, self.w_off)
            self.fail("didn't catch negative filter size exponent")
        except XLFilterError:
            pass
        try:
            self.keysel = KeySelector(
                0, self.hash_count, self.b_off, self.w_off)
            self.fail("didn't catch zero filter size exponent")
        except XLFilterError:
            pass

        # check s on k
        try:
            self.keysel = KeySelector(20, -1, self.b_off, self.w_off)
            self.fail("didn't catch negative hash function count")
        except XLFilterError:
            pass
        try:
            self.keysel = KeySelector(20, 0, self.b_off, self.w_off)
            self.fail("didn't catch zero hash function count")
        except XLFilterError:
            pass
        try:
            self.keysel = KeySelector(3, 0, self.b_off, self.w_off)
            self.fail("didn't catch invalid hash function count")
        except XLFilterError:
            pass
        try:
            self.keysel = KeySelector(247, 0, self.b_off, self.w_off)
            self.fail("didn't catch invalid hash function count")
        except XLFilterError:
            pass

        # checks on arrays
        try:
            self.keysel = KeySelector(20, 8, None, self.w_off)
            self.fail("didn't catch None bit offset array")
        except XLFilterError:
            pass
        try:
            self.keysel = KeySelector(20, 8, self.b_off, None)
            self.fail("didn't catch None word offset array")
        except XLFilterError:
            pass

    def _set_bit_offsets(self, key_bytes, val):   # bytes-like, int[]
        """
        Set the bit selectors, which are KeySelector.KEY_SEL_BITS-bit values
        packed at the beginning of a key.

        @param key_bytes key, expected to be at least 20 bytes long
        @param val       array of key values, exp. to be self.hash_count long
        """

        # XXX
        b_len = len(key_bytes)
        v_len = len(val)

        # DEBUG
        print("_set_bit_offsets: b_len = %d, v_len = %d" % (b_len, v_len))
        # END
        cur_bit = 0
        cur_byte = 0

        for ndx in range(v_len):
            cur_byte = cur_bit // 8
            offset_in_byte = cur_bit - (cur_byte * 8)
            # mask value to KeySelector.KEY_SEL_BITS bits
            b_val = val[ndx] & KeySelector.UNMASK[KeySelector.KEY_SEL_BITS]
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
                key_bytes[cur_byte] |= 0xff & (b_val << 3)
#              # DEBUG
#              print(
#                  "    current byte becomes " + btoh(b[cur_byte]))
#              # END
            elif offset_in_byte < 4:
                # it will fit in this byte
                #b[cur_byte] &= ( KeySelector.MASK[KeySelector.KEY_SEL_BITS] << (3 - offset_in_byte) )
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

                # XXX THE 0xff IS A HACK
                val_next_byte = 0xff & (
                    (b_val & KeySelector.MASK[bits_this_byte]) << 3)
                # b[cur_byte+1] &= (KeySelector.MASK[KeySelector.KEY_SEL_BITS - bitsThisByte]
                #                    << (3 + bitsThisByte))
                key_bytes[cur_byte + 1] |= val_next_byte

            cur_bit += KeySelector.KEY_SEL_BITS

    def test_bit_selection(self):
        """ Exhaustive test. """

        # DEBUG
        print("\nTEST_BIT_SELECTION")
        # END

        # set up 32 test keys
        for ndx in range(32):
            # reinitialize our test keys
            self.key_bytes.append(self.rng.some_bytes(20))

            # DEBUG
            print("test_bit_selection: key %d" % ndx)
            for n, bval in enumerate(self.key_bytes[ndx]):
                print("%2d 0x%02x" % (n, bval))
            # END

            bit_offsets = [
                (ndx % 32), (ndx + 1) % 32, (ndx + 2) % 32, (ndx + 3) % 32,
                (ndx + 4) % 32, (ndx + 5) % 32, (ndx + 6) % 32, (ndx + 7) % 32]
            self._set_bit_offsets(self.key_bytes[ndx], bit_offsets)

        self.keysel = KeySelector(self.m_exp, self.hash_count,
                                  self.b_off, self.w_off)  # default m=20, k=8
        for ndx in range(32):
            self.keysel.get_offsets(self.key_bytes[ndx])
            for j in range(self.hash_count):
                self.assertEqual(
                    (ndx + j) % 32, self.b_off[j],
                    "key %d, hash %d returns wrong value 0x%02x" % (
                        ndx, j, self.b_off[j]))

    def set_word_offsets(self, key_bytes, val, m_exp, hash_count):
        """
        Set the word selectors, which are (m_exp-KeySelector.KEY_SEL_BITS)-bit values.

        @param key_bytes  key, expected to be at least 20 bytes long
        @param val        array of key values, expected to be hash_count long
        @param m_exp      memory size in bytes is 2^m_exp
        @param hash_count number of hash functions
        """

        b_len = len(key_bytes)  # number of bytes in key
        v_len = len(val)
        # set number of bits in word selector
        stride = m_exp - KeySelector.KEY_SEL_BITS

        # reinitialize our test keys
        for _ in range(32):
            self.key_bytes.append(self.rng.some_bytes(20))

        # DEBUG
        print("set_word_offsets: b_len %d, v_len %d, stride %d; m %d h %d" % (
            b_len, v_len, stride, m_exp, hash_count))
        # END

        # position beyond the bit selectors
        cur_bit = hash_count * KeySelector.KEY_SEL_BITS
        cur_byte = 0
        for ndx in range(v_len):
            # force value within range
            # DEBUG
            val[ndx]
            KeySelector.UNMASK[stride]
            # END
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
                    key_bytes[cur_byte] = w_val & KeySelector.UNMASK[8]
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
                    bits_first_byte = 8 - offset_in_byte
                    # first byte
                    key_bytes[cur_byte] |= w_val & KeySelector.UNMASK[
                        bits_first_byte]
                    bits_to_go -= bits_first_byte
                    w_val >>= bits_first_byte

                    # second byte
                    if bits_to_go < 8:
                        # CASE 2: it doesn't fill the second byte
                        key_bytes[cur_byte + 1] |= w_val << (8 - bits_to_go)
                    else:
                        # CASE 3: it fills the second byte
                        bits_to_go -= 8
                        key_bytes[cur_byte + 1] = 0xff & w_val
                        if bits_to_go > 0:
                            # CASE 4: it puts some bits in a third byte
                            w_val >>= 8
                            key_bytes[cur_byte + 2] |= (
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

    def do_test_word_selection(self, m_exp, hash_count, num_keys):
        num_word_sel = 1 << (m_exp - KeySelector.KEY_SEL_BITS)
        # int[][] word_offsets = new int [num_keys][8]
        word_offsets = []
        for ndx in range(num_keys):
            word_offsets.append([0] * 8)

        # set up the test self.key_bytes
        self.key_bytes = []
        for ndx in range(num_keys):
            self.key_bytes.append(self.rng.some_bytes(20))

        for ndx in range(num_keys):
            for j in range(hash_count):
                # up to 2^15 32-bit words in a 2^20 bit array
                word_offsets[ndx][j] = self.rng.next_int32(num_word_sel)

            self.set_word_offsets(
                self.key_bytes[ndx], word_offsets[ndx], m_exp, hash_count)

        self.keysel = KeySelector(
            m_exp, hash_count, self.b_off, self.w_off)   # default m=20, k=8
        for ndx in range(num_keys):
            self.keysel.get_offsets(self.key_bytes[ndx])
            for j in range(hash_count):
                # DEBUG
                if word_offsets[ndx][j] != self.w_off[j]:
                    print("word_offsets[ndx][j] = %d (0x%04x)" % (
                        word_offsets[ndx][j], word_offsets[ndx][j]))
                    print("self.w_off[j]        = %d" % self.w_off[j])
                # END
                self.assertEqual(
                    word_offsets[ndx][j], self.w_off[j],
                    "key %d, hash %d returns wrong value 0x%x" % (
                        ndx, j, self.w_off[j]))

    def test_word_selection(self):
        # DEBUG
        print("\nTEST_WORD_SELECTION")
        # END

        self.do_test_word_selection(20, 8, 32)    # default values
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
