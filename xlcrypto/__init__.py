# xlcrypto/__init__.py

__version__ = '0.0.2'
__version_date__ = '2017-02-20'

__all__ = ['__version__', '__version_date__', 'XLCryptoError', ]


class XLCryptoError(RuntimeError):
    """ General purpose exception for the package. """
