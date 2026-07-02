import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import MESSAGE_PADDING_SIZE


def pad_message(message, target_size=MESSAGE_PADDING_SIZE):
    """Pad message to fixed size using a 4-byte length prefix."""
    current_len = len(message)

    # Reserve 4 bytes for the length prefix
    if current_len > target_size - 4:
        raise Exception(
            f"Message is too long to pad (current length: {current_len}, "
            f"max payload: {target_size - 4})"
        )

    # 4-byte big-endian length + original message + zero padding
    length_prefix = current_len.to_bytes(4, byteorder='big')
    padding_needed = target_size - 4 - current_len
    padded = length_prefix + message + (b'\x00' * padding_needed)

    return padded


def unpad_message(padded_message):
    """Remove padding by reading the 4-byte length prefix."""
    if len(padded_message) < 4:
        return padded_message

    # Read original message length from the first 4 bytes
    msg_len = int.from_bytes(padded_message[:4], byteorder='big')

    # Sanity check
    if msg_len > len(padded_message) - 4:
        raise Exception("Invalid padding: declared length exceeds available data")

    return padded_message[4 : 4 + msg_len]

class ProtocolMessage:
    def __init__(self, sender_id, recipient_id, encrypted_payload, message_id=None):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.encrypted_payload = encrypted_payload
        self.message_id = message_id or os.urandom(16)
        self.timestamp = None

    def to_dict(self):
        return {
            'message_id': self.message_id,
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'encrypted_payload': self.encrypted_payload
        }
    
    @classmethod
    def from_dict(cls, data):
        return cls(
            sender_id=data['sender_id'],
            recipient_id=data['recipient_id'],
            encrypted_payload=data['encrypted_payload'],
            message_id=data.get('message_id')
        )


def create_message_envelope(sender_id, recipient_id, plaintext, ratchet):
    """Create an encrypted message envelope with padding and metadata."""
    # Step 1: Pad the plaintext to hide length
    padded_plaintext = pad_message(plaintext)
    
    # Step 2: Encrypt using the Double Ratchet
    encrypted_payload = ratchet.encrypt_message(padded_plaintext)
    
    # Step 3: Create the protocol message with metadata
    message = ProtocolMessage(
        sender_id=sender_id,
        recipient_id=recipient_id,
        encrypted_payload=encrypted_payload
    )
    
    return message

def unwrap_message_envelope(message, ratchet):
    """Decrypt and unpad a message from its envelope."""
    # Step 1: Decrypt the payload
    padded_plaintext = ratchet.decrypt_message(message.encrypted_payload)
    
    # Step 2: Remove padding
    plaintext = unpad_message(padded_plaintext)
    
    return plaintext