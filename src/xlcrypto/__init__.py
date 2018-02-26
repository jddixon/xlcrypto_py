# xlcrypto/__init__.py

""" Crypto library for python XLattice packages. """

import hashlib
import sys

if sys.version_info < (3, 6):
    # pylint: disable=unused-import
    import sha3                     # pysha3 monkey-patches hashlib
    from pyblake2 import blake2b

__version__ = '0.2.9'
__version_date__ = '2018-02-26'


__all__ = ['AES_BLOCK_BITS', 'AES_BLOCK_BYTES',
           'next_nb_line', 'collect_pem_rsa_public_key',
           # Classes
           'XLCryptoError', 'xLFilterError', 'SP',
           # THIS BELONGS IN xlattice_py
           'XLHash', ]

# EXPORTED CONSTANTS

AES_BLOCK_BITS = 128
AES_BLOCK_BYTES = 16


class XLCryptoError(RuntimeError):
    """ General purpose exception for the package. """
    pass


class XLFilterError(XLCryptoError):
    """ Exception related to XLcrypto/filters. """
    pass


class XLHash(object):
    """ The plan if for this to be in xlattice_py. """

    def update(self, data):
        raise NotImplementedError

    def digest(self, data):
        raise NotImplementedError

    def hexdigest(self, data):
        raise NotImplementedError

    def digest_size(self):
        raise NotImplementedError

    @classmethod
    def hash_name(self):
        raise NotImplementedError

    @classmethod
    def lib_func(self):
        """ The implementing library. """
        raise NotImplementedError

#####################################################################
# LESS WELL-ORGANIZED CODE
#####################################################################

# STRING ARRAYS / PEM SERIALIZSTION =================================


class SP(object):

    __SPACES__ = ['']

    @staticmethod
    def get_spaces(nnn):
        """ cache strings of N spaces """
        kkk = len(SP.__SPACES__) - 1
        while kkk < nnn:
            kkk = kkk + 1
            SP.__SPACES__.append(' ' * kkk)
        return SP.__SPACES__[nnn]


def next_nb_line(lines):
    """
    Enter with a reference to a list of lines.  Return the next line
    which is not empty after trimming, AND a reference to the edited
    array of strings.
    """
    if lines is not None:
        while len(lines) > 0:
            line = lines[0]
            lines = lines[1:]
            line = line.strip()
            if line != '':
                return line, lines
        raise XLCryptoError("exhausted list of strings")
    raise XLCryptoError("arg to nextNBLine cannot be None")


def collect_pem_rsa_public_key(first_line, lines):
    """
    Given the opening line of the PEM serializaton of an RSA Public Key,
    and a pointer to an array of strings which should begin with the rest
    of the PEM serialization, return the entire PEM serialization as a
    single string.
    """

    # XXX PROBLEM: PyCrypto omits "RSA ", pycryptodome doesn't.
    #   Including 'RSA ' appears to be correct.
    first_line = first_line.strip()
    if first_line != '-----BEGIN RSA PUBLIC KEY-----' and \
            first_line != '-----BEGIN PUBLIC KEY-----':
        raise XLCryptoError('PEM public key cannot begin with %s' % first_line)
    found_last = False

    # DEBUG
    # ndx = 0
    # print("%2d %s" % (ndx, first_line))
    # END

    ret = [first_line]      # of string
    while len(lines) > 0:
        line, lines = next_nb_line(lines)
        # DEBUG
        # ndx += 1
        # print("%2d %s" % (ndx, line))
        # END
        ret = ret + [line]
        if line == '-----END RSA PUBLIC KEY-----' or  \
                line == '-----END PUBLIC KEY-----':
            found_last = True
            break

    if not found_last:
        raise XLCryptoError("didn't find closing line of PEM serialization")
    return '\n'.join(ret), lines
