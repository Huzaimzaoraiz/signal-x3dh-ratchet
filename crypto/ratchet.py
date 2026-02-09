import os
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives import serialization

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import INFO_MESSAGE_KEYS, INFO_CHAIN_KEY, INFO_ROOT_KEY, MAX_SKIPPED_MESSAGES

from crypto.hkdf import derive_key,derive_two_keys
from crypto.aes import encrypt_message,decrypt_message

class DoubleRatchet:
    def __init__(self,shared_secret,is_initiator=True):
        self.root_key=shared_secret
        self.sending_chain_key=None
        self.receiving_chain_key=None
        self.sending_counter=0
        self.receiving_counter=0
        self.dh_private=None
        self.dh_public=None
        self.remote_dh_public=None
        self.skipped_message_keys={}

        if is_initiator:
            self._init_as_initiator()
        else:
            self._init_as_responder()
    def _init_as_initiator(self):
        self.dh_private=X25519PrivateKey.generate()
        self.dh_public=self.dh_private.public_key()

        # Initiator sends on this chain; responder must receive on the same one
        self.sending_chain_key=derive_key(self.root_key,b"InitiatorToResponder")

    def _init_as_responder(self):
        self.dh_private=X25519PrivateKey.generate()
        self.dh_public=self.dh_private.public_key()

        # Responder receives on the same chain the initiator sends on
        self.receiving_chain_key=derive_key(self.root_key,b"InitiatorToResponder")

    def encrypt_message(self,plaintext):

        message_key = derive_key(self.sending_chain_key,INFO_MESSAGE_KEYS)
        self.sending_chain_key = derive_key(self.sending_chain_key,INFO_CHAIN_KEY)

        nonce, ciphertext = encrypt_message(message_key, plaintext)

        current_counter = self.sending_counter
        self.sending_counter += 1

        return {
            'dh_public': self._serialize_public_key(self.dh_public),
            'counter': current_counter,
            'nonce': nonce,
            'ciphertext': ciphertext
        }
    
    def _dh_ratchet(self,remote_public_bytes):

        remote_public = X25519PublicKey.from_public_bytes(remote_public_bytes)

        dh_output = self.dh_private.exchange(remote_public)

        self.root_key, self.receiving_chain_key = derive_two_keys(
            dh_output,
            INFO_ROOT_KEY,
            b"ReceivingChain"
        )

        self.receiving_counter = 0

        self.dh_private = X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()

        dh_output = self.dh_private.exchange(remote_public)

        self.root_key, self.sending_chain_key = derive_two_keys(
            dh_output,
            INFO_ROOT_KEY,
            b"SendingChain"
        )

        self.sending_counter = 0

        self.remote_dh_public = remote_public


    def decrypt_message(self,message):

        remote_dh_public=message['dh_public']
        counter=message['counter']
        nonce=message['nonce']
        ciphertext=message['ciphertext']

        if self.remote_dh_public is None:
            # First message received — just record sender's DH key,
            # use the pre-initialised receiving chain (no ratchet yet)
            self.remote_dh_public = X25519PublicKey.from_public_bytes(remote_dh_public)
        elif remote_dh_public != self._serialize_public_key(self.remote_dh_public):
            # Sender's DH key changed — perform a DH ratchet step
            self._dh_ratchet(remote_dh_public)

        message_key=self._try_skipped_message_keys(remote_dh_public,counter)

        if message_key is None:
            message_key=self._derive_reciving_key(counter)

        plaintext=decrypt_message(message_key,nonce,ciphertext)

        return plaintext

    def _derive_reciving_key(self,target_counter):
        while self.receiving_counter<target_counter:

            skipped_key=derive_key(self.receiving_chain_key,INFO_MESSAGE_KEYS)

            remote_dh_bytes=self._serialize_public_key(self.remote_dh_public) if self.remote_dh_public else b""
            self.skipped_message_keys[(remote_dh_bytes,self.receiving_counter)]=skipped_key

            self.receiving_chain_key=derive_key(self.receiving_chain_key,INFO_CHAIN_KEY)
            self.receiving_counter+=1

            if(len(self.skipped_message_keys)>MAX_SKIPPED_MESSAGES):
                raise Exception("Too many skipped message - possible attack detected")
        
        message_key = derive_key(self.receiving_chain_key,INFO_MESSAGE_KEYS)

        self.receiving_chain_key = derive_key(self.receiving_chain_key,INFO_CHAIN_KEY)
        self.receiving_counter += 1

        return message_key


    def _try_skipped_message_keys(self,remote_dh_public,counter):
        key = (remote_dh_public, counter)
        return self.skipped_message_keys.pop(key, None)
    
    def _serialize_public_key(self, public_key):
        if public_key is None:
            return b""
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    # ── Pickle support (needed for SQLite session storage) ────
    def __getstate__(self):
        state = self.__dict__.copy()
        # Serialize X25519 keys to raw bytes for pickling
        if state.get('dh_private'):
            state['dh_private'] = state['dh_private'].private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
        if state.get('dh_public'):
            state['dh_public'] = self._serialize_public_key(state['dh_public'])
        if state.get('remote_dh_public'):
            state['remote_dh_public'] = self._serialize_public_key(state['remote_dh_public'])
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        # Deserialize raw bytes back to X25519 key objects
        if self.dh_private:
            self.dh_private = X25519PrivateKey.from_private_bytes(self.dh_private)
        if self.dh_public:
            self.dh_public = X25519PublicKey.from_public_bytes(self.dh_public)
        if self.remote_dh_public:
            self.remote_dh_public = X25519PublicKey.from_public_bytes(self.remote_dh_public)