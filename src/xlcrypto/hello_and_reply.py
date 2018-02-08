# xlcrypto_py/src/xlcrypto/hello_and_reply.py

"""
Implementation of the hello-and-reply protocol.

This allows a client to establish a secure conntection to a server
whose RSA public key the client knows.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA1

from rnglib import SystemRNG
from xlattice.crypto import AES_BLOCK_BYTES, AES_BLOCK_BITS

__all__ = ['client_encrypt_hello', 'server_decrypt_hello',
           'server_encrypt_hello_reply', 'client_decrypt_hello_reply', ]


def client_encrypt_hello(version, ck_):
    """
    Generate a client Hello message for public key ck  and
    DecimalVersion version.

    version is a 4-byte unsigned int seen as a.b.c.d, in little-endian
    byte order.

    ck is the server's RSA public key.

    The ciphertext, the message passed to the server, is 80 bytes long.  It
    is encrypted using the server's RSA public key.  The message encrypted
    consists of
    * iv1,      16 bytes, a random value
    * key1,     32 bytes, a random value
    * salt1,     8 bytes, a random value
    * oaepSalt, 20 bytes, a random value
    * version1,  4 bytes, the protocol version proposed by the client
    This first four of these are arrays of bytes which are filled with
    random values.

    Returns
    * ciphertext, the data above in encrypted form
    * iv1,      the 16-byte AES initialization vector
    * key1,     the 32-byte AES key
    * salt1,    an 8-byte random value
    """

    rng = SystemRNG()

    iv1_ = bytearray(AES_BLOCK_BYTES)
    rng.next_bytes(iv1_)
    iv1 = bytes(iv1_)

    key1_ = bytearray(2 * AES_BLOCK_BYTES)
    rng.next_bytes(key1_)
    key1 = bytes(key1_)

    salt1_ = bytearray(8)
    rng.next_bytes(salt1_)
    salt1 = bytes(salt1_)

    # little-endiant version1
    version1_ = bytearray(4)
    version1_[0] = version & 0xff
    version1_[1] = (version >> 8) & 0xff
    version1_[2] = (version >> 16) & 0xff
    version1_[3] = (version >> 24) & 0xff
    version1 = bytes(version1_)

    msg = iv1 + key1 + salt1 + version1

    # hash defaults to SHA1
    ciphertext = ck_.encrypt(
        msg,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA1()),
            algorithm=SHA1(),
            label=None))

    # The IV, key, and salt are returned to allow the caller to confirm
    # that the server has decrypted them correctly -- that is, to confirm
    # that whoever is on the other end of the connection knows the RSA
    # private key.

    return ciphertext, iv1, key1, salt1


def server_decrypt_hello(ciphertext, ck_priv):
    """
    The server uses its private RSA key to decryptthe message from
    the client, discarding the OAEP padding.
    """

    msg = ck_priv.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA1()),
            algorithm=SHA1(),
            label=None))

    # split the msg into its constituent bits
    iv1s = msg[0: AES_BLOCK_BYTES]
    key1s = msg[AES_BLOCK_BYTES: 3 * AES_BLOCK_BYTES]
    salt1s = msg[3 * AES_BLOCK_BYTES: 3 * AES_BLOCK_BYTES + 8]
    v_offset = 3 * AES_BLOCK_BYTES + 8
    v_bytes = msg[v_offset: v_offset + 4]
    version = v_bytes[0] +\
        (v_bytes[1] << 8) +\
        (v_bytes[2] << 16) +\
        (v_bytes[3] << 24)
    return iv1s, key1s, salt1s, version


def server_encrypt_hello_reply(iv1, key1, salt1, version2s):
    """
    We use iv1, key1 to AES-encrypt our reply.  The server returns salt1
    to show it has decrypted the hello correctly.  It also sends version2
    and salt2.  The server may have overridden the client's requested
    protocol version.

    The method returns the server-selected AES iv2 and key2, salt2, and
    the AES-encrypted ciphertext.
    """

    # The cast to bytes avoids an "argument 1 must be read-only pinned buffer"
    # error
    iv1 = bytes(iv1)
    key1 = bytes(key1)

    rng = SystemRNG()

    iv2 = bytearray(AES_BLOCK_BYTES)
    rng.next_bytes(iv2)
    iv2 = bytes(iv2)

    key2 = bytearray(2 * AES_BLOCK_BYTES)
    rng.next_bytes(key2)
    key2 = bytes(key2)

    salt2 = bytearray(8)
    rng.next_bytes(salt2)

    # little-endiant version1
    version2 = bytearray(4)
    version2[0] = version2s & 0xff
    version2[1] = (version2s >> 8) & 0xff
    version2[2] = (version2s >> 16) & 0xff
    version2[3] = (version2s >> 24) & 0xff

    reply = iv2 + key2 + salt2 + salt1 + version2

    # add PKCS7 padding
    # padded_reply = add_pkcs7_padding(reply, AES_BLOCK_BYTES)
    padder = padding.PKCS7(AES_BLOCK_BITS).padder()
    padded_reply = padder.update(reply) + padder.finalize()

    # encrypt the reply using iv1, key1, CBC.
    # cipher = AES.new(key1, AES.MODE_CBC, iv1)
    cipher = Cipher(
        algorithms.AES(key1),
        modes.CBC(iv1),
        backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_reply) + encryptor.finalize()

    return iv2, key2, salt2, ciphertext


def client_decrypt_hello_reply(ciphertext, iv1, key1):
    """
    Decrypt the server's reply using the IV and key we sent to it.
    Returns iv2, key2, salt2 (8 bytes), and the original salt1.
    The pair iv2/key2 are to be used in future communications.
    Salt1 is returned to help confirm the integrity of the operation.
    """

    iv1 = bytes(iv1)
    key1 = bytes(key1)

    # iv_ = ciphertext[0:AES_BLOCK_BYTES]   # of no interest
    cipher = Cipher(
        algorithms.AES(key1),
        modes.CBC(iv1),
        backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # unpadded = strip_pkcs7_padding(plaintext, AES_BLOCK_BYTES)
    unpadder = padding.PKCS7(AES_BLOCK_BITS).unpadder()
    unpadded = unpadder.update(plaintext) + unpadder.finalize()

    iv2 = unpadded[:AES_BLOCK_BYTES]
    key2 = unpadded[AES_BLOCK_BYTES: 3 * AES_BLOCK_BYTES]
    salt2 = unpadded[3 * AES_BLOCK_BYTES: 3 * AES_BLOCK_BYTES + 8]
    salt1 = unpadded[3 * AES_BLOCK_BYTES + 8: 3 * AES_BLOCK_BYTES + 16]
    v_bytes = unpadded[3 * AES_BLOCK_BYTES + 16: 3 * AES_BLOCK_BYTES + 20]
    version2 = v_bytes[0] |\
        (v_bytes[1] << 8) |\
        (v_bytes[2] << 16) |\
        (v_bytes[3] << 24)

    return iv2, key2, salt2, salt1, version2
