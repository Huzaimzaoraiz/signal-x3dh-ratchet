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
    if __name__ == "__main__":
    # Generate a random key
    key = os.urandom(32)
    
    # Encrypt
    message = b"Hello, World!"
    nonce, encrypted = encrypt_message(key, message)
    print(f"Encrypted: {encrypted.hex()}")
    
    # Decrypt
    decrypted = decrypt_message(key, nonce, encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Try tampering
    tampered = encrypted[:-1] + b"X"
    try:
        decrypt_message(key, nonce, tampered)
        print("ERROR: Should have failed!")
    except:
        print("✓ Tampering detected correctly")