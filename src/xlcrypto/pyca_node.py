# ~/dev/py/xlattice_py/xlattice/pyca_node.py

""" Functions implementing the XLattice Node. """

import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

from xlattice import HashTypes, check_hashtype  # , UnrecognizedSHAError


class AbstractNode(object):
    """ The XLattice Peer / BaseNode. """

    #   # DEBUG
    #   @staticmethod
    #   def dump_hex(title, byte_vals):
    #       print("%s: " % title, end='')
    #       for val in byte_vals:
    #           print("%02x " % val, end='')
    #       print()
    #   # END

    def __init__(self, hash_types=HashTypes.SHA2,
                 sk_=None, ck_=None, node_id=None):

        check_hashtype(hash_types)
        self._hash_types = hash_types
        if node_id is None:
            # we arbitrarily use sk_ to calculate a unique node ID
            if sk_:
                if hash_types == HashTypes.SHA1:
                    sha_ = hashes.SHA1
                elif hash_types == HashTypes.SHA2:
                    sha_ = hashes.SHA256
                sha = hashes.Hash(sha_(), backend=default_backend())
                pem = sk_.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.PKCS1)
                sha.update(pem)
                node_id = sha.finalize()    # a binary value
                # DEBUG
                # AbstractNode.dump_hex(
                #     "SHA%d Abs Calc ID" % hash_types, node_id)
                # END
            else:
                raise ValueError(
                    'cannot calculate nodeID without public key sk_')

            self._node_id = node_id
        self._sk = sk_
        self._ck = ck_

    @property
    def node_id(self):
        """ Return the NodeID, a 20- or 32-byte value unique to this node."""
        return self._node_id

    @property
    def sk_(self):
        """ Return the RSA ate key used for signing. """
        return self._sk

    @property
    def ck_(self):
        """ Return the RSA ate key used for encrytiion. """
        return self._ck


class Node(AbstractNode):
    """
    An object with two RSA keys, one for signing and one for
    encryption/decryption.
    """

    def __init__(self, hash_types=HashTypes.SHA2,
                 key_bits=2048, sk_priv=None, ck_priv=None):
        """
        Create a node with two RSA keys with the indicated number
        of bits.

        The first RSA key is used for creating digital signatures.
        The second is for RSA encryption and decryption.

        If a key is supplied but has the wrong key size the
        candidate key is ignored.  If a key is not supplied or
        is to be ignored, an appropriately sized RSA key is created.
        """
        if sk_priv and sk_priv.key_size != key_bits:
            # If sk_priv has the wrong key_size, we will regenerate
            # both RSA keys.
            sk_priv = None
            ck_priv = None
        if ck_priv and ck_priv.key_size != key_bits:
            # if ck_priv has the wrong key size, we will regenerate it.
            ck_priv = None

        if sk_priv is None:
            # We will generate values for both keys.
            ck_priv = None
            sk_priv = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_bits,
                backend=default_backend())
        if ck_priv is None:
            # We will generate a value.
            ck_priv = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_bits,
                backend=default_backend())

        node_id, sk_, ck_ = Node.calc_id_and_pub_keys_for_node(
            hash_types, sk_priv, ck_priv)
        AbstractNode.__init__(self, hash_types, sk_, ck_, node_id)

        self._sk_priv = sk_priv
        self._ck_priv = ck_priv
        self._node_id = node_id

        # each of these needs some sort of map or maps, or we will have to do
        # a linear search
        self._peers = []
        self._overlays = []    #
        self._connections = []    # with peers? with clients?

    @property
    def sk_priv(self):
        """ Return the RSA private key used for signing. """
        return self._sk_priv

    @property
    def ck_priv(self):
        """ Return the RSA private key used for encrytiion. """
        return self._ck_priv

    def create_from_key(self, string):
        # XXX STUB: given the serialization of a node, create one
        # despite the name, this should also handle peer lists, etc
        # XXX WE ALSO NEED a serialization function
        pass

    @staticmethod
    def calc_id_and_pub_keys_for_node(hash_types, sk_priv, ck_priv):
        """ Calculate the nodeID from the ck_ public key. """
        check_hashtype(hash_types)
        (node_id, ck_) = (None, None)
        sk_ = sk_priv.public_key()
        ck_ = ck_priv.public_key()
        pem_ck = sk_.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1)

        if hash_types == HashTypes.SHA1:
            sha_ = hashes.SHA1
        elif hash_types == HashTypes.SHA2:
            sha_ = hashes.SHA256
        sha = hashes.Hash(sha_(), backend=default_backend())
        sha.update(pem_ck)
        node_id = sha.finalize()
        # DEBUG
        # Node.dump_hex("Get SHA%d Node" % hash_types, node_id)
        # END
        return (node_id,         # nodeID = 160/256 bit BINARY value
                sk_, ck_)        # public keys, from private keys

    def sign(self, msg):
        """ Sign a message using the secret RSA key used for signing. """
        if self._hash_types == HashTypes.SHA1:
            sha_ = hashes.SHA1
        elif self._hash_types == HashTypes.SHA2:
            sha_ = hashes.SHA256

        signer = self._sk_priv.signer(
            padding.PSS(
                mgf=padding.MGF1(sha_()),
                salt_length=padding.PSS.MAX_LENGTH),
            sha_())

        signer.update(bytes(msg))
        signature = signer.finalize()
        return signature                # XXX
        return base64.b64encode(signature)      # bytes, and must be

    def verify(self, msg, signature):
        """
        Check the digital signature against the message, possibly
        raising InvalidSigature.
        """
        if self._hash_types == HashTypes.SHA1:
            sha_ = hashes.SHA1
        elif self._hash_types == HashTypes.SHA2:
            sha_ = hashes.SHA256
        verifier = self._sk.verifier(
            signature,
            padding.PSS(
                mgf=padding.MGF1(sha_()),
                salt_length=padding.PSS.MAX_LENGTH),
            sha_())
        verifier.update(msg)
        verifier.verify()               # may raise InvalidSignature


class Peer(AbstractNode):
    """ a Peer is a Node seen from the outside """

    def __init__(self, hash_types=False, node_id=None, pub_key=None):
        AbstractNode.__init__(self, hash_types, node_id, pub_key)
