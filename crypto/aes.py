import os
import importlib.util
from pathlib import Path

config_path = Path(__file__).resolve().parent.parent / "config.py"
spec = importlib.util.spec_from_file_location("config", str(config_path))
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = config.NONCE_SIZE

def encrypt_message(key,plaintext):
    cipher = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)
    return nonce , ciphertext  # Prepend nonce for decryption

def decrypt_message(key,nonce,ciphertext):
    cipher =AESGCM(key)
    try:
        plaintext=cipher.decrypt(nonce,ciphertext,associated_data=None)
        return plaintext
    except Exception as e:
        raise Exception(f"Decryption failed: {e}")