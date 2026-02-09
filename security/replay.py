
import os


class ReplayProtector:

    
    def __init__(self, max_size=100000):
        # Set of message IDs we've seen
        self.seen_message_ids = set()
        
        # Maximum size to prevent memory attacks
        # In production, you'd use a time-based expiration instead
        self.max_size = max_size
    
    def check_and_add(self, message_id):
        
        # Convert bytes to a hashable type if needed
        msg_id_key = message_id if isinstance(message_id, bytes) else message_id
        
        # Check if we've seen this ID before
        if msg_id_key in self.seen_message_ids:
            # Replay attack detected!
            return False
        
        # New message - remember this ID
        self.seen_message_ids.add(msg_id_key)
        
        # Prevent memory exhaustion by limiting size
        # In production, use time-based expiration or a database
        if len(self.seen_message_ids) > self.max_size:
            # Remove oldest entries (simplified - in production use LRU or time-based)
            # For a simple implementation, we'll clear half when full
            self.seen_message_ids = set(list(self.seen_message_ids)[self.max_size // 2:])
        
        return True
    
    def is_duplicate(self, message_id):
        
        msg_id_key = message_id if isinstance(message_id, bytes) else message_id
        return msg_id_key in self.seen_message_ids
    
    def clear(self):
        self.seen_message_ids.clear()


def generate_message_id():
    return os.urandom(16)
