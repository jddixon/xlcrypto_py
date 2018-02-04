# xlcrypto_py/src/xlcrypto/keyderiv

"""
Key derivation functions are used to reduce the vulnerability of
encrypted passwords to brute force attacks.  See for example RFC 8018.

Argon2 is an alternative to PBKDF2 built on BLAKE2 and the winner of
the 2015 Password Hashing Competition.
"""

import hashlib
import sys
from xlattice import HashTypes, check_hashtype

if sys.version_info >= (3, 6):
    from hashlib import pbkdf2_hmac as _pbkdf2   # a function
else:
    from pbkdf2 import PBKDF2               # a class

    # pylint:disable=unused-import
    import sha3                     # pysha3    - monkey-patches hashhlib
    # assert sha3                   # suppress warnings


def pbkdf2(passwd, salt, hashtype=HashTypes.SHA2,
           iterations=10000, dklen=None):
    """
    Derive a bytes-like key from a string password using the specified
    hash.  salt is bytes-like.  Greater iterations provide greater security.
    If dklen is specified, it must be an int.
    """
    if isinstance(passwd, str):
        passwd = passwd.encode()
    check_hashtype(hashtype)
    if hashtype == HashTypes.SHA1:
        hash_name = 'sha1'
    elif hashtype == HashTypes.SHA2:
        hash_name = 'sha256'
    elif hashtype == HashTypes.SHA3:
        hash_name = 'sha3_256'
    elif hashtype == HashTypes.BLAKE2B:
        hash_name = 'blake2b'

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
