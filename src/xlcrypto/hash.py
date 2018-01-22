# xlcrypto_py/src/xlcrypto/hash

import hashlib
import sys

from xlcrypto import XLHash

if sys.version_info < (3, 6):
    # pylint:disable=unused-import
    import sha3                     # pysha3    - monkey-patches hashhlib
    # assert sha3                     # suppress warnings


class XLSHA1(XLHash):
    """ Implementation of the 20-byte/160-bit SHA1 hash algorithm. """

    def __init__(self, data=b''):
        self._hash = hashlib.sha1(data)

    def update(self, data):
        self._hash.update(data)

    @property
    def digest(self):
        return self._hash.digest()

    @property
    def hexdigest(self):
        return self._hash.hexdigest()

    # these are actually class attributes

    @property
    def hash_name(self):
        return "sha1"

    @property
    def digest_size(self):
        """ Return digest size in bytes. """
        return 20


class XLSHA2(XLHash):
    """ Implementation of the 32-byte/256-bit SHA256 hash algorithm. """

    def __init__(self, data=b''):
        self._hash = hashlib.sha256(data)

    def update(self, data):
        self._hash.update(data)

    @property
    def digest(self):
        return self._hash.digest()

    @property
    def hexdigest(self):
        return self._hash.hexdigest()

    # these are actually class attributes

    @property
    def hash_name(self):
        return "sha2"

    @property
    def digest_size(self):
        """ Return digest size in bytes. """
        return 32


class XLSHA3(XLHash):
    """ Implementation of the 32-byte/256-bit SHA356 hash algorithm. """

    def __init__(self, data=b''):
        self._hash = hashlib.sha3_256(data)

    def update(self, data):
        self._hash.update(data)

    @property
    def digest(self):
        return self._hash.digest()

    @property
    def hexdigest(self):
        return self._hash.hexdigest()

    # these are actually class attributes

    @property
    def hash_name(self):
        return "sha3"

    @property
    def digest_size(self):
        """ Return digest size in bytes. """
        return 32
