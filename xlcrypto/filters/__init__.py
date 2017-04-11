# this can be xlcrypto/filters.pyor xlcrypto/filters/__init__.py
# xlcrypto_py/xlcrypto/filters/key_selector.java

""" Bloom filter for fixed length keys which are usually SHA hashes. """

from threading import Lock
from binascii import b2a_hex
from copy import deepcopy
from math import exp

from xlattice.u import SHA1_BIN_LEN
from xlcrypto import XLCryptoError, XLFilterError

__all__ = ['MIN_M', 'MIN_K', 'BloomSHA', 'NibbleCounters']

# EXPORTED CONSTANTS ------------------------------------------------

MIN_M = 2   # minimum hashlen in bits as exponent of 2
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

    def __init__(self, m=20, k=8, key_bytes=20):
        """
        Creates a filter with 2**m bits and k 'hash functions',
        where each hash function is a portion of the SHA digest.

        @param m         determines number of bits in filter, defaults to 20
        @param k         number of hash functions, defaults to 8
        @param key_bytes length in bytes of keys acceptable to the filter
        """

        m = int(m)                  # must be an int
        if m < MIN_M:
            raise XLFilterError("m = %d but must be > %d" % (m, MIN_M))

        key_bytes = int(key_bytes)  # must be an int
        if key_bytes <= 0:
            raise XLFilterError("must specify a positive key length")
        key_bits = key_bytes * 8  # length of keys in bits

        k = int(k)                  # must be an int
        if k < MIN_K:
            raise XLFilterError(
                "too many hash functions (%d) for filter size" % k)
        if k * m > key_bits:
            k = key_bits // m       # rounds down to number that will fit

        self._mm = m
        self._kk = k
        self._key_bytes = key_bytes

        self._key_count = 0
        # convenience variables
        self._filter_bits = 1 << m
        self._filter_bytes = (self._filter_bits + 7) // 8   # round up
        self._filter = bytearray(self._filter_bytes)
        self._lock = Lock()

        # DEBUG
        # print("Bloom ctor: m = %d, k = %d, filter_bits = %d, filter_bytes = %d" % (
        #    self._mm, self._kk, self._filter_bits, self._filter_bytes))
        # END

    @property
    def m(self):
        return self._mm

    @property
    def k(self):
        return self._kk

    @property
    def key_bytes(self):
        return self._key_bytes

    def _do_clear(self):
        """ Clear the filter, unsynchronized. """

        for i in range(self._filter_bytes):
            self._filter[i] = 0

    def clear(self):
        """ Clear the filter, synchronized version. """
        try:
            self._lock.acquire()
            self._do_clear()
            self._key_count = 0
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
            return self._key_count
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
            n = self._key_count
        return (1 - exp(-self._kk * n / self._filter_bits)) ** self._kk

    def insert(self, b):
        """
        Add a key to the set represented by the filter.

        XXX This version does not maintain 4 - bit counters, it is not
        a counting Bloom filter.

        @param b    byte array representing a key(SHA1 digest)
        """
        keysel = KeySelector(b, self)
        bitsel, bytesel = keysel.bitsel, keysel.bytesel
        try:
            self._lock.acquire()
            for i in range(self._kk):
                self._filter[bytesel[i]] |= (1 << bitsel[i])
            self._key_count += 1
        finally:
            self._lock.release()

    def _is_member(self, b):
        """
        Whether a key is in the filter.  Sets up the bit and byte offset
        arrays.

        @param b    byte array representing a key(SHA1 digest)
        @return True if b is in the filter
        """
        keysel = KeySelector(b, self)
        bitsel, bytesel = keysel.bitsel, keysel.bytesel
        for i in range(self._kk):
            check_byte = self._filter[bytesel[i]]
            if (check_byte & (1 << bitsel[i])) == 0:
                return False
        return True

    def is_member(self, b):
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

# ===================================================================


class KeySelector(object):

    def __init__(self, b, bloom):
        if b is None or len(b) == 0:
            raise XLFilterError(
                "key being added to KeySelector may not be None or empty")
        self._key = bytes(deepcopy(b))      # so immutable

        if bloom is None:
            raise XLFilterError("bloom may not be None")

        key_bytes = bloom.key_bytes
        if len(b) != key_bytes:
            raise XLFilterError(
                "key of length %d but fltr expects length of %d bytes" % (
                    len(b), key_bytes))
        m, k = bloom.m, bloom.k

        # DEBUG
        # print("KeySelector: m = %d, k = %d" % (m, k))
        # END
        bitsel = [0] * k        # ints used to select flag bits
        bytesel = [0] * k       # ints used to select flag bytes

        # Given a key, populate the byte and bit offset arrays, each
        # of which has k elements.  The low order 3 bits are used to
        # select a bit within a byte.  The higher order bits are used
        # select the byte.

        # convert the bytes of the key to a single long int
        i = int.from_bytes(b, 'little')     # signed=False

        # extract the k bit and byte selectors
        for j in range(k):
            bitsel[j] = i & 0x7       # get 3 bits selecting bit in byte
            i >>= 3
            byte_mask = (1 << (m - 3)) - 1
            bytesel[j] = i & byte_mask
            i >>= m - 3

        self._bitsel = bitsel
        self._bytesel = bytesel

    @property
    def bitsel(self):
        return self._bitsel

    @property
    def bytesel(self):
        return self._bytesel

    @property
    def key(self):
        return self._key

# ===================================================================


class NibbleCounters(object):
    """
    Maintain a set of 4-bit counters, one for each bit in a BloomSHA.

    Counters are stored in bytes, two counters per byte.

    The presence of the counters allows keys to be removed without
    having to recalculate the entire BloomSHA.

    As it stands, this class is not thread-safe.  Using classes are
    expected to provide synchronization.
    """

    def __init__(self, m=20):           # default is for SHA1
        self._nibble_count = 1 << m     # ie, 2**20; the size of the filter
        self._counters = bytearray(self._nibble_count // 2)

    def clear(self):
        """ Zero out all of the counters.  Unsynchronized. """

        for i in range(self._counters // 2):
            self._counters[i] = 0           # zeroes out two counters

    def inc(self, filter_bit):
        """
        Increment the nibble, ignoring any overflow.

        @param filter_bit offset of bit in the filter
        @return           value of nibble after operation
        """
        if filter_bit < 0:
            raise XLFilterError("filter bit offset cannot be negative.")
        if filter_bit >= self._nibble_count:
            raise XLFilterError("filter bit offset %d out of range" %
                                filter_bit)

        byte_offset = filter_bit // 2
        upper_nibble = filter_bit & 1       # interpreted as boolean
        cur_byte = self._counters[byte_offset]

        if upper_nibble:
            value = cur_byte >> 4
        else:
            value = cur_byte & 0xf
        # DEBUG
        #print("bit %6d: value 0x%x => " % (filter_bit, value), end='')
        # END
        if value < 0xf:
            value += 1          # increment counter, ignoring any overflow
        # DEBUG
        #print("0x%x  " % value, end='')
        # END

        if upper_nibble:
            self._counters[byte_offset] &= 0x0f  # mask off existing value
            self._counters[byte_offset] |= (value << 4)
        else:
            self._counters[byte_offset] &= 0xf0  # mask off low-order nibble
            self._counters[byte_offset] |= value

        # DEBUG
        # print(" counters: 0x%02x => 0x%02x" % (
        #    cur_byte, self._counters[byte_offset]))
        # END
        return value

    def dec(self, filter_bit):
        """
        Decrement the nibble, ignoring any underflow

        @param filterWord offset of 32-bit word
        @param filter_bit  offset of bit in that word (so in range 0..31)
        @return value of nibble after operation
        """

        if filter_bit < 0:
            raise XLFilterError("filter bit offset cannot be negative.")
        if filter_bit >= self._nibble_count:
            raise XLFilterError("filter bit offset %d out of range" %
                                filter_bit)

        byte_offset = filter_bit // 2
        upper_nibble = filter_bit & 1       # interpreted as boolean
        cur_byte = self._counters[byte_offset]

        if upper_nibble:
            value = cur_byte >> 4
        else:
            value = cur_byte & 0xf
        # DEBUG
        #print("bit %6d: value 0x%x => " % (filter_bit, value), end='')
        # END
        if value > 0:
            value -= 1          # decrement counter, ignoring underflow
        # DEBUG
        #print("0x%x  " % value, end='')
        # END

        if upper_nibble:
            self._counters[byte_offset] &= 0x0f  # mask off existing value
            self._counters[byte_offset] |= value << 4
        else:
            self._counters[byte_offset] &= 0xf0   # mask off low-order nibble
            self._counters[byte_offset] |= value

        # DEBUG
        # print(" counters: 0x%02x => 0x%02x" % (
        #    cur_byte, self._counters[byte_offset]))
        # END
        return value
