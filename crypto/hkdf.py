from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as CryptoHKDF
from config import KEY_LENGTH

def derive_key(input_key_material, info, length=KEY_LENGTH):
    hkdf = CryptoHKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(input_key_material)

def derive_two_keys(input_key_material, info1, info2, length=KEY_LENGTH):
    key1 = derive_key(input_key_material, info1)
    key2 = derive_key(input_key_material, info2)
    return key1, key2