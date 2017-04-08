# this can be xlcrypto/filters.pyor xlcrypto/filters/__init__.py
# xlcrypto_py/xlcrypto/filters/key_selector.java

""" Bloom filter for fixed length keys which are usually SHA hashes. """

from threading import Lock
from binascii import b2a_hex
from copy import deepcopy
from math import exp

from xlattice.u import SHA1_BIN_LEN
from xlcrypto import XLCryptoError, XLFilterError

__all__ = ['MIN_M', 'MAX_M', 'MIN_K', 'BloomSHA', ]

# EXPORTED CONSTANTS ------------------------------------------------

MIN_M = 2   # minimum hashlen in bits as exponent of 2
MAX_M = 20  # maximum hashlen in bits, also an exponent of 2
MIN_K = 1   # minimum number of 'hash functions'

# PRIVATE CONSTANTS -------------------------------------------------

SIZEOF_UINT64 = 8  # bytes


# ===================================================================

class BloomSHA(object):
    """
    A Bloom filter for sets of Secure Hash Algorithm (SHA) digests.

    A Bloom filter uses a set of k hash functions to determine set
    membership.  Each hash function produces a value in the range 0..M-1.
    The filter is of size M bits, where M is a power of two.  To add a
    member to the set, apply each hash function to the new member and set
    the corresponding bit in the filter.  For M very large relative to k,
    this will normally set k bits in the filter.  To check whether x is a
    member of the set, apply each of the k hash functions to x and check
    whether the corresponding bits are set in the filter.  If any are not
    set, x is definitely not a member.  If all are set, x may be a member.
    The probability of error (the false positive rate) is
        f = (1 - e^(-kN/M))^k
    where N is the number of filter (set) members.

    This class takes advantage of the fact that SHA digests are good-
    quality pseudo-random numbers.  The k hash functions are the values
    of distinct sets of bits taken from the SHA hash.  The number of bytes
    in the filter, M, is constrained to be a power of 2; M == 2**m.  The
    number of bits in each hash function may not exceed floor(m/k), or as
    we say in Python, m//k.

    This class is designed to be thread-safe, but this has not been
    exhaustively tested.
    """

    def __init__(self, m=20, k=8, key_len=160):
        """
        Creates a filter with 2**m bits and k 'hash functions',
        where each hash function is a portion of the 160-bit
        SHA1 hash.

        @param m determines number of bits in filter, defaults to 20
        @param k number of hash functions, defaults to 8
        """

        m = int(m)                  # must be an int
        if m < MIN_M or m > MAX_M:
            raise XLFilterError("m = %d out of range" % m)

        key_len = int(key_len)      # must be an int
        if key_len <= 0:
            raise XLFilterError("must specify a positive key length")

        k = int(k)                  # must be an int
        if k < MIN_K:
            raise XLFilterError(
                "too many hash functions (%d) for filter size" % k)
        if k * m > key_len:
            k = key_len // m        # rounds down to number that will fit

        self._mm = m
        self._kk = k
        self._key_len = key_len

        self._count = 0
        # convenience variables
        self._filter_bits = 1 << m
        self._filter_bytes = (self._filter_bits + 7) // 8   # round up
        self._filter = bytearray(self._filter_bytes)
        self._lock = Lock()

        # DEBUG
        print("Bloom ctor: m = %d, k = %d, filter_bits = %d, filter_bytes = %d" % (
            self._mm, self._kk, self._filter_bits, self._filter_bytes))
        # END

    def _do_clear(self):
        """ Clear the filter, unsynchronized. """

        for i in range(self._filter_bytes):
            self._filter[i] = 0

    def clear(self):
        """ Clear the filter, synchronized version. """
        try:
            self._lock.acquire()
            self._do_clear()
            self._count = 0
            # jdd added 2005-02-19
        finally:
            self._lock.release()

    def __len__(self):
        """
        Returns the number of keys which have been inserted.  This
        class (BloomSHA) does not guarantee uniqueness in any sense
        if the same key is added N times, the number of set members
        reported will increase by N.
        """
        try:
            self._lock.acquire()
            return self._count
        finally:
            self._lock.release()

    @property
    def capacity(self):
        """ Return number of bits in filter. """
        return self._filter_bits

    def false_positives(self, n=0):
        """
        @param n number of set members
        @return approximate False positive rate
        """
        if n == 0:
            n = self._count
        return (1 - exp(-self._kk * n / self._filter_bits)) ** self._kk

    def insert(self, b):
        """
        Add a key to the set represented by the filter.

        XXX This version does not maintain 4 - bit counters, it is not
        a counting Bloom filter.

        @param b    byte array representing a key(SHA1 digest)
        """
        bitsel, bytesel = self.get_selectors(b)
        try:
            self._lock.acquire()
            for i in range(self._kk):
                self._filter[bytesel[i]] |= (1 << bitsel[i])
            self._count += 1
        finally:
            self._lock.release()

    def _is_member(self, b):
        """
        Whether a key is in the filter.  Sets up the bit and byte offset
        arrays.

        @param b    byte array representing a key(SHA1 digest)
        @return True if b is in the filter
        """
        bitsel, bytesel = self.get_selectors(b)
        for i in range(self._kk):
            check_byte = self._filter[bytesel[i]]
            if (check_byte & (1 << bitsel[i])) == 0:
                return False
        return True

    def member(self, b):
        """
        Whether a key is in the filter.  External interface, internally
        synchronized.

        @param b    byte array representing a key(SHA1 digest)
        @return True if b is in the filter
        """
        try:
            self._lock.acquire()
            return self._is_member(b)
        finally:
            self._lock.release()

    def get_selectors(self, b):
        """
        Create bit and byte selectors for a key being added to the
        Bloom filter.

        When the key is presented to get_selectos(), the k 'hash function'
        values are extracted and used to populate bitsel and bytesel arrays
        which specify the k flags to be set or examined in the filter.

        XXX NEED TO CHECK THAT KEY HAS THE CORRECT LENGTH.

        @param b    key being added to the Bloom Filter
        """

        if b is None or len(b) == 0:
            raise XLFilterError(
                "key being added to filter may not be None or empty")
        if len(b) != self._key_len:
            raise XLFilterError(
                "key of length %d but filter expects length of %d bytes" % (
                    len(b), self._key_len))

        # DEBUG
        print("get_selectors: m = %d, k = %d" % (self._mm, self._kk))
        # END
        bitsel = [0] * self._kk        # ints used to select flag bits
        bytesel = [0] * self._kk       # ints used to select flag bytes

        # Given a key, populate the byte and bit offset arrays, each
        # of which has k elements.  The low order 3 bits are used to
        # select a bit within a byte.  The higher order bits are used
        # select the byte.

        # convert the bytes of the key to a single long int
        i = int.from_bytes(b, 'little')     # signed=False

        # extract the k bit and byte selectors
        for j in range(self._kk):
            bitsel[j] = i & 0x7       # get 3 bits selecting bit in byte
            i >>= 3
            byte_mask = (1 << (self._mm - 3)) - 1
            bytesel[j] = i & byte_mask
            i >>= self._mm - 3

        return bitsel, bytesel
