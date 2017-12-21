# xlcrypto/__init__.py

""" Crypto library for python XLattice packages. """

__version__ = '0.0.23'
__version_date__ = '2017-12-21'


# class XLFilterError(XLCryptoError):
class XLFilterError(RuntimeError):
    """ Exception related to XLcrypto/filters. """
    pass


class XLCryptoError(RuntimeError):
    """ General purpose exception for the package. """
    pass
