# xlcrypto/__init__.py

""" Crypto library for python XLattice packages. """

__version__ = '0.0.3'
__version_date__ = '2017-02-21'

__all__ = ['__version__', '__version_date__', 'XLCryptoError', ]


class XLCryptoError(RuntimeError):
    """ General purpose exception for the package. """
