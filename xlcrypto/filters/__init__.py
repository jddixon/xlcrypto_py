# this can be xlcrypto/filters.pyor xlcrypto/filters/__init__.py
# The file formerly known as const.go

# All of these should be constants.

# xlcrypto_py/xlcrypto/filters/key_selector.java

from asyncio import Lock
from binascii import b2a_hex
from copy import deepcopy

from xlattice.u import SHA1_BIN_LEN
from xlcrypto import XLCryptoError, XLFilterError

__all__ = ['MIN_M', 'MAX_M', 'MIN_K', 'MAX_MK_PRODUCT',
           'BloomSHA1', 'KeySelector', ]

# EXPORTED CONSTANTS ------------------------------------------------

MIN_M = 2
MAX_M = 24      # XXX arguments for limit?
MIN_K = 1

# ostensibly "too many hash functions for filter size"
MAX_MK_PRODUCT = 256

# PRIVATE CONSTANTS -------------------------------------------------

SIZEOF_UINT64 = 8  # bytes


# ===================================================================

class BloomSHA1(object):
    """
    A Bloom filter for sets of SHA1 digests.  A Bloom filter uses a set
    of k hash functions to determine set membership.  Each hash function
    produces a value in the range 0..M-1.  The filter is of size M.  To
    add a member to the set, apply each function to the new member and
    set the corresponding bit in the filter.  For M very large relative
    to k, this will normally set k bits in the filter.  To check whether
    x is a member of the set, apply each of the k hash functions to x
    and check whether the corresponding bits are set in the filter.  If
    any are not set, x is definitely not a member.  If all are set, x
    may be a member.  The probability of error (the False positive rate)
    is f = (1 - e^(-kN/M))^k, where N is the number of set members.

    This class takes advantage of the fact that SHA1 digests are good-
    quality pseudo-random numbers.  The k hash functions are the values
    of distinct sets of bits taken from the 20-byte SHA1 hash.  The
    number of bits in the filter, M, is constrained to be a power of
    2; M == 2^m.  The number of bits in each hash function may not
    exceed floor(m/k).

    This class is designed to be thread-safe, but this has not been
    exhaustively tested.
    """

    def __init__(self, m=20, k=8):                              # SHA1
        """
         Creates a filter with 2^m bits and k 'hash functions',
         where each hash function is a portion of the 160-bit   # SHA1
         SHA1 hash.                                             # SHA1

         @param m determines number of bits in filter,
            defaults to 20                                      # SHA1
          @param k number of hash functions, defaults to 8      # SHA1
        """

        # XXX need to devise more reasonable set of checks
        if m < 2 or m > 20:                                  # SHA1
            raise XLFilterError("m = %d out of range" % m)

        if k < 1 or (k * m > 160):                           # SHA1
            raise XLFilterError(
                "too many hash functions (%d) for filter size" % k)

        self._m = m
        self._k = k
        self._count = 0
        # convenience variables
        self._filter_bits = 1 << m
        self._filter_words = (self._filter_bits + 31) // 32
        # round up
        self._filter = [0] * self._filter_words
        self._doClear()
        # offsets into the filter
        self._word_offset = [0] * k
        self._bit_offset = [0] * k
        self._keysel = KeySelector(m, k, self._bit_offset, self._word_offset)
        self._lock = Lock()

        # DEBUG
        print("Bloom constructor: m = " + self._m + ", k = " + self._k
              + "\n    self._filter_bits = " + self._filter_bits
              + ", self._filter_words = " + self._filter_words)
        # END

    def _doClear(self):
        """ Clear the filter, unsynchronized. """

        for i in range(self._filter_words):
            self._filter[i] = 0

    def clear(self):
        """ Clear the filter, synchronized version. """
        with (yield from self._lock):
            self._doClear(self)
            self._count = 0
            # jdd added 2005 - 02 - 19

    def __len__(self):
        """
        Returns the number of keys which have been inserted.  This
        class (BloomSHA1) does not guarantee uniqueness in any sense
        if the same key is added N times, the number of set members reported
        will increase by N.
        """
        with (yield from self._lock):
            return count

    def capacity(self):
        """ Return number of bits in filter. """
        return self._filter_bits

    def insert(self, bytesval):
        """
        Add a key to the set represented by the filter.

        XXX This version does not maintain 4 - bit counters, it is not
        a counting Bloom filter.

        @param bytesval byte array representing a key(SHA1 digest)
        """
        with (yield from self._lock):
            self._keysel.get_offsets(bytesval)
            for i in range(self._k):
                self._filter[self._word_offset[i]] |= 1 << self._bit_offset[i]

            self._count += 1

    def _is_member(self, bytesval):
        """
        Whether a key is in the filter.  Sets up the bit and word offset
        arrays.

        @param bytesval byte array representing a key(SHA1 digest)
        @return True if b is in the filter
        """
        self._keysel.get_offsets(bytesval)
        for i in range(self._k):
            if not ((self._filter[self._word_offset[i]] &
                     (1 << self._bit_offset[i])) != 0):
                return False

        return True

    def member(self, bytesval):
        """
        Whether a key is in the filter.  External interface, internally
        synchronized.

        @param b byte array representing a key(SHA1 digest)
        @return True if b is in the filter
        """
        with (yield from self._lock):
            return self._is_member(bytesval)

    def false_positives(self, n=0):
        """
        @param n number of set members
        @return approximate False positive rate
        """
        if n == 0:
            n = self._count
        # (1 - e(-kN / M)) ^ k  # XXX we want k to be interpreted as a double
        return (1 - exp(-self._k * n / self._filter_bits)) ** self._k

    # DEBUG METHODS =================================================

    def key_to_string(self, keybytes):
        return b2a_hex(keybytes)

    # convert 64 - bit integer to hex String #
    @staticmethod
    def ltoh(longval):
        return "0x%16x" % intval

    # convert 32 - bit integer to String #
    @staticmethod
    def itoh(intval):
        return "0x%08x" % intval

    # convert single byte to String #
    @staticmethod
    def btoh(byteval):
        intval = 0xff & byteval
        return self.BloomSHA1(intval)

# ===================================================================


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

    #                  m      k           int[]       int[]
    def __init__(self, m_exp, hash_count, bit_offset, word_offset):
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
        if hash_count < 1:
            raise XLFilterError("hash_count must be positive but is %d" %
                                hash_count)
        if not bit_offset:
            raise XLFilterError("bit_offset may not be None or empty")
        if not word_offset:
            raise XLFilterError("word_offset may not be None or empty")

        self._m = m_exp                             # must be power of two
        self._k = hash_count                        # count of hash functions
        self._b = deepcopy(key_bytes)
        self._bit_offset = deepcopy(bit_offset)
        self._word_offset = deepcopy(word_offset)

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
