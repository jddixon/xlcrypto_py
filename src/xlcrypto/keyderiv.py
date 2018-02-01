# xlcrypto_py/src/xlcrypto/keyderiv

"""
Key derivation functions are used to reduce the vulnerability of
encrypted passwords to brute force attacks.  See for example RFC 8018.

Argon2 is an alternative to PBKDF2 built on BLAKE2 and the winner of
the 2015 Password Hashing Competition.
"""

import hashlib
import sys

if sys.version_info >= (3, 6):
    from hashlib import pbkdf2_hmac as _pbkdf2   # a function
else:
    from pbkdf2 import PBKDF2               # a class

    # pylint:disable=unused-import
    import sha3                     # pysha3    - monkey-patches hashhlib
    # assert sha3                   # suppress warnings


def pbkdf2(hash_name, passwd, salt, iterations=10000, dklen=None):
    # blake2b gets "unsupported hash type"
    if sys.version_info >= (3, 6):
        # hash_name is str like 'sha1' or 'sha256'
        #     LIMITATION: 'sha3', variations, and 'blake2b' are NOT SUPPORTED
        # passwd must be bytes-like
        return _pbkdf2(hash_name, passwd, salt, iterations, dklen)

    else:
        if not dklen:
            dklen = 32              # just playing around
        return PBKDF2(passwd, salt, iterations=iterations).read(dklen)
