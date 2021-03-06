# xlcrypto_py/src/xlcrypto/hash

import hashlib
import sys

from xlattice import SHA1_BIN_LEN, SHA2_BIN_LEN, SHA3_BIN_LEN, BLAKE2B_BIN_LEN
from xlcrypto import XLHash

if sys.version_info < (3, 6):
    from pyblake2 import blake2b

    # pylint:disable=unused-import
    import sha3                     # pysha3    - monkey-patches hashhlib
    # assert sha3                   # suppress warnings


class XLSHA1(XLHash):
    """ Implementation of the 20-byte/160-bit SHA1 hash algorithm. """

    def __init__(self, data=b''):
        self._hash = hashlib.sha1(data)

    def update(self, data):
        """ Add data to the internal hash. """
        self._hash.update(data)

    def digest(self):
        """ Return a fixed-length binary digest, a bytes-like value. """
        return self._hash.digest()

    def hexdigest(self):
        """ Return a fixed-length hex digest, a string. """
        return self._hash.hexdigest()

    # these are actually class attributes

    def digest_size(self):
        """ Return digest size in bytes, an integer value. """
        return SHA1_BIN_LEN

    @classmethod
    def hash_name(cls):
        """ Return a standard name for the hash. """
        return "sha1"

    @classmethod
    def lib_func(cls):
        """ The implementing library function. """
        return hashlib.sha1


class XLSHA2(XLHash):
    """ Implementation of the 32-byte/256-bit SHA256 hash algorithm. """

    def __init__(self, data=b''):
        self._hash = hashlib.sha256(data)

    def update(self, data):
        """ Add data to the internal hash. """
        self._hash.update(data)

    def digest(self):
        """ Return a fixed-length binary digest, a bytes-like value. """
        return self._hash.digest()

    def hexdigest(self):
        """ Return a fixed-length hex digest, a string. """
        return self._hash.hexdigest()

    # these are actually class attributes

    def digest_size(self):
        """ Return digest size in bytes, an integer value. """
        return SHA2_BIN_LEN

    @classmethod
    def hash_name(cls):
        """ Return a standard name for the hash. """
        return "sha2"

    @classmethod
    def lib_func(cls):
        """ The implementing library function. """
        return hashlib.sha256


class XLSHA3(XLHash):
    """ Implementation of the 32-byte/256-bit SHA356 hash algorithm. """

    def __init__(self, data=b''):
        self._hash = hashlib.sha3_256(data)

    def update(self, data):
        """ Add data to the internal hash. """
        self._hash.update(data)

    def digest(self):
        """ Return a fixed-length binary digest, a bytes-like value. """
        return self._hash.digest()

    def hexdigest(self):
        """ Return a fixed-length hex digest, a string. """
        return self._hash.hexdigest()

    # these are actually class attributes

    def digest_size(self):
        """ Return digest size in bytes, an integer value. """
        return SHA3_BIN_LEN

    @classmethod
    def hash_name(cls):
        """ Return a standard name for the hash. """
        return "sha3"

    @classmethod
    def lib_func(cls):
        """ The implementing library function. """
        return hashlib.sha3_256


class XLBLAKE2B_256(XLHash):
    """
    Implementation of the blake2b hash algorithm with a 32-byte/256-bit digest.
    """

    def __init__(self, data=b''):
        if sys.version_info >= (3, 6):
            self._hash = hashlib.blake2b(data, digest_size=BLAKE2B_BIN_LEN)
        else:
            self._hash = blake2b(data, digest_size=BLAKE2B_BIN_LEN)

    def update(self, data):
        """ Add data to the internal hash. """
        self._hash.update(data)

    def digest(self):
        """ Return a fixed-length binary digest, a bytes-like value. """
        return self._hash.digest()

    def hexdigest(self):
        """ Return a fixed-length hex digest, a string. """
        return self._hash.hexdigest()

    # these are actually class attributes

    def digest_size(self):
        """ Return digest size in bytes, an integer value. """
        return BLAKE2B_BIN_LEN

    @classmethod
    def hash_name(cls):
        """ Return a standard name for the hash. """
        return "blake2b_256"

    @classmethod
    def lib_func(cls):
        """ The implementing library function. """
        return hashlib.blake2b
