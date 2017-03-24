# xlcrypto/__init__.py

""" Crypto library for python XLattice packages. """

__version__ = '0.0.7'
__version_date__ = '2017-03-24'

__all__ = ['__version__', '__version_date__',
           'XLCryptoError', 'XLFilterError', ]


# class XLFilterError(XLCryptoError):
class XLFilterError(RuntimeError):
    """ Exception related to XLcrypto/filters. """
    pass


class XLCryptoError(RuntimeError):
    """ General purpose exception for the package. """
    pass
