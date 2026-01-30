import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

print("encrtp")
