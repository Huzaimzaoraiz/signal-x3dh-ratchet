import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import NONCE_SIZE

def encrypt_message(key,plaintext):
    cipher = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ciphertext  # Prepend nonce for decryption

def decrypt_message(key,nonce,ciphertext):
    cipher =AESGCM(key)
    try:
        plaintext=cipher.decrypt(nonce,ciphertext,associated_data=None)
        return plaintext
    except Exception as e:
        raise Exception(f"Decryption failed: {e}")
    