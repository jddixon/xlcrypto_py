# this can be xlcrypto/filters.pyor xlcrypto/filters/__init__.py
# The file formerly known as const.go

# All of these should be constants.

# xlcrypto_py/xlcrypto/filters/key_selector.java

from copy import deepcopy

from xlattice.u import SHA1_BIN_LEN
from xlcrypto import XLCryptoError, XLFilterError

__all__ = ['MIN_M', 'MAX_M', 'MIN_K', 'MAX_MK_PRODUCT',
           'KeySelector', ]

# EXPORTED CONSTANTS ------------------------------------------------

MIN_M = 2
MAX_M = 24      # XXX arguments for limit?
MIN_K = 1

# ostensibly "too many hash functions for filter size"
MAX_MK_PRODUCT = 256

# PRIVATE CONSTANTS -------------------------------------------------

SIZEOF_UINT64 = 8  # bytes


class KeySelector(object):
    BITS_PER_WORD = 64
    KEY_SEL_BITS = 6

    # AND with byte to expose index-many bits */
    UNMASK = [
        # 0 1  2  3   4   5   6    7    8
        0, 1, 3, 7, 15, 31, 63, 127, 255]
    # AND with byte to zero out index-many bits */
    MASK = [255, 254, 252, 248, 240, 224, 192, 128, 0]

# Given a key, populates arrays determining word and bit offsets into
# a Bloom filter.
# type KeySelector struct:
#    m, k       uint
#    b          []byte # key that we are inserting into the filter
#    bit_offset  []byte
#    word_offset []uint

    def __init__(self, m_exp, hash_count, key_bytes):
        """
        Creates a key selector for a Bloom filter.  When a key is presented
        to the get_offsets(, the k 'hash function' values are
        extracted and used to populate bit_offset and word_offset arrays which
        specify the k flags to be set or examined in the filter.

        @param m    size of the filter as a power of 2
        @param k    number of 'hash functions'
        """

        if m_exp < MIN_M or m_exp > MAX_M:
            raise XLFilterError("m = %d is out of range" % m_exp)

        self._m = m_exp     # must be power of two
        self._k = hash_count     # count of hash functions
        self._b = b''
        self._bit_offset = bytearray(hash_count)     # that many bytes
        self._word_offset = [0] * hash_count           # that many uint

        self.get_offsets(key_bytes)                 # will raise if invalid

    def get_offsets(self, key):  # []byte) (err error):
        """
        Given a key, populate the word and bit offset arrays, each
        of which has k elements.

        @param key cryptographic key used in populating the arrays
        """
        if key is None:
            raise XLFilterError("key may not be None")
        if len(key) < SHA1_BIN_LEN:
            raise XLCryptoError("key is too short: %d" % len(key))

        self._b = deepcopy(key)
        self.get_bit_selectors()
        self.get_word_selectors()

    def get_bit_selectors(self):
        """
        Extracts the k bit offsets from a key, suitable for general values
        of m and k.
        """

        cur_bit, cur_byte, key_sel = 0, 0, 0
        for j in range(self._k):
            cur_byte = cur_bit / 8
            t_bit = cur_bit - 8 * cur_byte  # bit offset this byte
            u_bits = 8 - t_bit          # unused, left in byte

            if cur_bit % 8 == 0:
                key_sel = self._b[cur_byte] & KeySelector.UNMASK[
                    KeySelector.KEY_SEL_BITS]
            elif u_bits >= KeySelector.KEY_SEL_BITS:
                # it's all in this byte
                key_sel = (self._b[cur_byte] >>
                           t_bit) & KeySelector.UNMASK[KeySelector.KEY_SEL_BITS]
            else:
                # the selector spans two bytes
                r_bits = KeySelector.KEY_SEL_BITS - u_bits
                l_side = (
                    self._b[cur_byte] >> t_bit) & KeySelector.UNMASK[u_bits]
                r_side = (
                    self._b[
                        cur_byte +
                        1] & KeySelector.UNMASK[r_bits]) << u_bits
                key_sel = l_side | r_side

            self._bit_offset[j] = key_sel       # may need masking
            cur_bit += KeySelector.KEY_SEL_BITS

    def get_word_selectors(self):
        """
        Extracts the k word offsets from a key.  Suitable for general
        values of m and k.

        Extract the k offsets into the word offset array
        """
        # the word selectors being created
        sel_bits = self._m - uint(6)
        sel_bytes = (sel_bits + 7) / 8
        bits_last_byte = sel_bits - 8 * (sel_bytes - 1)

        # bit offset into self._b, the key being inserted into the filter
        cur_bit = self._k * KeySelector.KEY_SEL_BITS

        for ndx in range(self._k):
            cur_byte = cur_bit / 8

            word_sel = 0  # uint: accumulate selector bits here

            if cur_bit % 8 == 0:
                # byte-aligned, life is easy
                for j in range(sel_bytes):
                    word_sel |= self._b[cur_byte] << (j * 8)
                    cur_byte += 1

                word_sel |= (self._b[cur_byte] & KeySelector.UNMASK[bits_last_byte]) <<\
                    ((sel_bytes - 1) * 8)
                cur_bit += sel_bits

            else:
                end_bit = cur_bit + sel_bits
                used_bits = cur_bit - (8 * cur_byte)
                word_sel = self._b[cur_byte] >> used_bits
                cur_bit += (8 - used_bits)
                word_sel_bit = 8 - used_bits

                while cur_bit < end_bit:
                    cur_byte = cur_bit // 8
                    if end_bit - cur_bit >= 8:
                        bits_this_byte = 8
                    else:
                        bits_this_byte = end_bit - cur_bit

                    val = self._b[cur_byte] & KeySelector.UNMASK[
                        bits_this_byte]
                    word_sel |= val << word_sel_bit
                    word_sel_bit += bits_this_byte
                    cur_bit += bits_this_byte

            self._word_offset[ndx] = word_sel
