# xlcrypto_py/src/xlcrypto/hash

import hashlib
from xlcrypto import XLHash


class XLSHA1(XLHash):

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
