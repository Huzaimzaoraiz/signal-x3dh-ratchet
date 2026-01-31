class X3DHKeyBundle:
    def __init__(self, identity_key, signed_prekey, one_time_prekey=None):
        self.identity_key = identity_key
        self.signed_prekey = signed_prekey
        self.one_time_prekey = one_time_prekey

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization
from crypto.hkdf import derive_key

class X3DH:
    def __init__(self, key_bundle: X3DHKeyBundle):
        self.user_id=user_id

        self.identity_private=X25519PrivateKey.generate()
        self.identity_public=self.identity_private.public_key()

        self.signed_prekey_private=X25519PrivateKey.generate()
        self.signed_prekey_public=self.signed_prekey_private.public_key()

        self.one_time_prekey_private=X25519PrivateKey.generate()
        self.one_time_prekey_public=self.one_time_prekey_private.public_key()



    def get_public_bundle(self):
        return X3DHKeyBundle(
       identity_key=self._serialize_public_key(self.identity_public),
            signed_prekey=self._serialize_public_key(self.signed_prekey_public),
            one_time_prekey=self._serialize_public_key(self.one_time_prekey_public)
        )
    
    def initiate_session(self,recipient_bundle):

        #temp keys for this session
        ephemeral_private=X25519PrivateKey.generate()
        ephemeral_public=ephemeral_private.public_key()

        # Deserialize recipient's public keys
        
    
    def _serialize_public_key(self,public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    def _deserialize_public_key(self,key_bytes):
        return X25519PublicKey.from_public_bytes(key_bytes)
    