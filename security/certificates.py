import hashlib


def compute_fingerprint(public_key_bytes):

    # Hash the public key with SHA-256
    hash_obj = hashlib.sha256(public_key_bytes)
    
    # Return as hexadecimal string (easier to read/compare)
    return hash_obj.hexdigest()


def format_fingerprint(fingerprint_hex):
    # Split into groups of 4 characters
    groups = [fingerprint_hex[i:i+4] for i in range(0, len(fingerprint_hex), 4)]
    return " ".join(groups)


class CertificatePinner:
    
    def __init__(self):
        self.trusted_fingerprints = {}
    
    def pin_key(self, user_id, public_key_bytes):

        fingerprint = compute_fingerprint(public_key_bytes)
        self.trusted_fingerprints[user_id] = fingerprint
        return fingerprint
    
    def verify_key(self, user_id, public_key_bytes):

        if user_id not in self.trusted_fingerprints:
            raise Exception(f"No pinned fingerprint for user: {user_id}")
        
        # Compute fingerprint of the provided key
        current_fingerprint = compute_fingerprint(public_key_bytes)
        
        # Compare with stored fingerprint
        expected_fingerprint = self.trusted_fingerprints[user_id]
        
        return current_fingerprint == expected_fingerprint
    
    def get_fingerprint(self, user_id):

        return self.trusted_fingerprints.get(user_id)
    
    def pin_if_new(self, user_id, public_key_bytes):

        current_fingerprint = compute_fingerprint(public_key_bytes)
        
        if user_id not in self.trusted_fingerprints:
            # First time seeing this user - pin their key
            self.trusted_fingerprints[user_id] = current_fingerprint
            return True, current_fingerprint
        else:
            # Verify against pinned fingerprint
            expected = self.trusted_fingerprints[user_id]
            is_trusted = (current_fingerprint == expected)
            return is_trusted, current_fingerprint
