import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.x3dh import X3DHKeyBundle


class SecureMessengerServer:    
    def __init__(self):
        # Store public key bundles for all users
        # Format: {user_id: X3DHKeyBundle}
        self.user_bundles = {}
        
        # Store messages waiting to be delivered
        # Format: {recipient_id: [message1, message2, ...]}
        self.pending_messages = {}
        
        print("Server Started")
    
    def register_user(self, user_id, key_bundle):
        if user_id in self.user_bundles:
            print(f"User {user_id} already registered, updating keys...")
        else:
            print(f"Registered new user: {user_id}")
        
        # Store the user's public key bundle
        self.user_bundles[user_id] = key_bundle
        
        # Initialize message queue for this user
        if user_id not in self.pending_messages:
            self.pending_messages[user_id] = []
    
    def get_user_bundle(self, user_id):
        if user_id not in self.user_bundles:
            raise Exception(f"User {user_id} is not registered")
        
        return self.user_bundles[user_id]
    
    def send_message(self, message):
        recipient_id = message.recipient_id
        sender_id = message.sender_id
        
        # Verify recipient exists
        if recipient_id not in self.user_bundles:
            raise Exception(f"Recipient {recipient_id} not found")
        
        # Add message to recipient's queue
        if recipient_id not in self.pending_messages:
            self.pending_messages[recipient_id] = []
        
        self.pending_messages[recipient_id].append(message)
        
        print(f"Message queued: {sender_id} -> {recipient_id}")
    
    def receive_messages(self, user_id):
        if user_id not in self.user_bundles:
            raise Exception(f"User {user_id} is not registered")
        
        # Get all pending messages
        messages = self.pending_messages.get(user_id, [])
        
        # Clear the queue
        self.pending_messages[user_id] = []
        
        if messages:
            print(f"Delivering {len(messages)} messages to {user_id}")
        
        return messages
    
    def list_users(self):
        return list(self.user_bundles.keys())
    
    def get_stats(self):
        total_pending = sum(len(msgs) for msgs in self.pending_messages.values())
        
        return {
            'total_users': len(self.user_bundles),
            'pending_messages': total_pending,
            'users': self.list_users()
        }
