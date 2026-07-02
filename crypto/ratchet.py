import os
import sys
import base64

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
        self.is_initiator = is_initiator

        if is_initiator:
            self._init_as_initiator()
        else:
            self._init_as_responder()

    def _init_as_initiator(self):
        self.dh_private=X25519PrivateKey.generate()
        self.dh_public=self.dh_private.public_key()
        self.sending_chain_key=derive_key(self.root_key,b"InitialSendingChain")
        self.receiving_chain_key=derive_key(self.root_key,b"InitialReceivingChain")

    def _init_as_responder(self):
        self.dh_private=X25519PrivateKey.generate()
        self.dh_public=self.dh_private.public_key()
        self.receiving_chain_key=derive_key(self.root_key,b"InitialSendingChain")
        self.sending_chain_key=derive_key(self.root_key,b"InitialReceivingChain")

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
            b"ChainKey"
        )
        self.receiving_counter = 0

        self.dh_private = X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()

        dh_output_send = self.dh_private.exchange(remote_public)
        self.root_key, self.sending_chain_key = derive_two_keys(
            dh_output_send,
            INFO_ROOT_KEY,
            b"ChainKey"
        )
        self.sending_counter = 0
        self.remote_dh_public = remote_public

    def decrypt_message(self,message):
        remote_dh_public=message['dh_public']
        counter=message['counter']
        nonce=message['nonce']
        ciphertext=message['ciphertext']

        is_new_dh = False
        if self.remote_dh_public is None:
            is_new_dh = True
        elif remote_dh_public != self._serialize_public_key(self.remote_dh_public):
            is_new_dh = True

        if is_new_dh:
            if not getattr(self, 'is_initiator', True) and self.remote_dh_public is None:
                # Responder receiving first message: HALF RATCHET
                self.remote_dh_public = X25519PublicKey.from_public_bytes(remote_dh_public)
                
                # Half ratchet to setup sending_chain_key
                self.dh_private = X25519PrivateKey.generate()
                self.dh_public = self.dh_private.public_key()
                dh_output_send = self.dh_private.exchange(self.remote_dh_public)
                self.root_key, self.sending_chain_key = derive_two_keys(
                    dh_output_send, INFO_ROOT_KEY, b"ChainKey"
                )
                self.sending_counter = 0
            else:
                # Full ratchet
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

    def to_dict(self):
        def enc(b):
            return base64.b64encode(b).decode('utf-8') if b else None

        state = {
            'root_key': enc(self.root_key),
            'sending_chain_key': enc(self.sending_chain_key),
            'receiving_chain_key': enc(self.receiving_chain_key),
            'sending_counter': self.sending_counter,
            'receiving_counter': self.receiving_counter,
            'is_initiator': self.is_initiator,
            'skipped_message_keys': {}
        }

        if self.dh_private:
            state['dh_private'] = enc(self.dh_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ))
        else:
            state['dh_private'] = None

        state['dh_public'] = enc(self._serialize_public_key(self.dh_public)) if self.dh_public else None
        state['remote_dh_public'] = enc(self._serialize_public_key(self.remote_dh_public)) if self.remote_dh_public else None

        for (dh_bytes, count), key_bytes in self.skipped_message_keys.items():
            k_str = f"{enc(dh_bytes) if dh_bytes else ''}:{count}"
            state['skipped_message_keys'][k_str] = enc(key_bytes)

        return state

    @classmethod
    def from_dict(cls, data):
        def dec(s):
            return base64.b64decode(s) if s else None

        # Pass a dummy shared_secret, we will overwrite it
        obj = cls(b"dummy", is_initiator=data.get('is_initiator', True))
        
        obj.root_key = dec(data['root_key'])
        obj.sending_chain_key = dec(data['sending_chain_key'])
        obj.receiving_chain_key = dec(data['receiving_chain_key'])
        obj.sending_counter = data['sending_counter']
        obj.receiving_counter = data['receiving_counter']
        obj.is_initiator = data.get('is_initiator', True)
        
        if data.get('dh_private'):
            obj.dh_private = X25519PrivateKey.from_private_bytes(dec(data['dh_private']))
        else:
            obj.dh_private = None
            
        if data.get('dh_public'):
            obj.dh_public = X25519PublicKey.from_public_bytes(dec(data['dh_public']))
        else:
            obj.dh_public = None
            
        if data.get('remote_dh_public'):
            obj.remote_dh_public = X25519PublicKey.from_public_bytes(dec(data['remote_dh_public']))
        else:
            obj.remote_dh_public = None
            
        obj.skipped_message_keys = {}
        for k_str, v_str in data['skipped_message_keys'].items():
            dh_str, count_str = k_str.split(':')
            dh_b = dec(dh_str) if dh_str else b""
            obj.skipped_message_keys[(dh_b, int(count_str))] = dec(v_str)

        return obj