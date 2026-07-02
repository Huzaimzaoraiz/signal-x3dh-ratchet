import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.x3dh import X3DH, X3DHKeyBundle
from crypto.ratchet import DoubleRatchet
from storage.keystore import Keystore
from storage.session_store import SessionStore
from security.replay import ReplayProtector
from security.certificates import CertificatePinner
from network.protocal import create_message_envelope,unwrap_message_envelope, ProtocolMessage

class SecureMessengerClient:
    
    def __init__(self, user_id, db_path=None):
        self.user_id = user_id
        
        # Use user-specific database path if not provided
        if db_path is None:
            db_path = f"secure_messenger_{user_id}.db"
        
        # Initialize X3DH for key exchange
        self.x3dh = X3DH(user_id)
        
        # Initialize storage
        self.keystore = Keystore(db_path)
        self.session_store = SessionStore(db_path)
        
        # Initialize security features
        self.replay_protector = ReplayProtector()
        self.cert_pinner = CertificatePinner()
        
        # Active sessions (in memory for performance)
        # Maps: remote_user_id → DoubleRatchet
        self.active_sessions = {}
        
        # Load existing sessions from storage
        self._load_sessions()
    
    def _load_sessions(self):
    
        session_list = self.session_store.list_sessions(self.user_id)
        
        for remote_user in session_list:
            ratchet = self.session_store.load_session(self.user_id, remote_user)
            if ratchet:
                self.active_sessions[remote_user] = ratchet
    
    def get_public_bundle(self):
        return self.x3dh.get_public_bundle()
    
    def start_conversation(self, remote_user_id, remote_bundle):
        # Pin the identity key for MITM protection
        is_trusted, fingerprint = self.cert_pinner.pin_if_new(
            remote_user_id, 
            remote_bundle.identity_key
        )
        
        if not is_trusted:
            raise Exception(f"Key mismatch for {remote_user_id}! Possible MITM attack!")
        
        # Perform X3DH to get shared secret
        shared_secret, ephemeral_public = self.x3dh.initiate_session(remote_bundle)
        
        # Create Double Ratchet with the shared secret
        ratchet = DoubleRatchet(shared_secret, is_initiator=True)
        
        # Store the session
        self.active_sessions[remote_user_id] = ratchet
        self.session_store.save_session(self.user_id, remote_user_id, ratchet)
        
        print(f"✓ Started conversation with {remote_user_id}")
        print(f"  Identity fingerprint: {fingerprint[:16]}...")
        return self.x3dh._serialize_public_key(self.x3dh.identity_public), ephemeral_public

    def accept_conversation(self, initiator_id, initiator_id_pub, initiator_eph_pub):
        shared_secret = self.x3dh.respond_to_session(initiator_id_pub, initiator_eph_pub)
        ratchet = DoubleRatchet(shared_secret, is_initiator=False)
        self.active_sessions[initiator_id] = ratchet
        self.session_store.save_session(self.user_id, initiator_id, ratchet)
        print(f"✓ Accepted conversation from {initiator_id}")
    
    def send_message(self, remote_user_id, message_text):
        # Check if we have a session with this user
        if remote_user_id not in self.active_sessions:
            raise Exception(f"No session with {remote_user_id}. Call start_conversation() first.")
        
        # Get the ratchet for this conversation
        ratchet = self.active_sessions[remote_user_id]
        
        # Convert message to bytes
        plaintext = message_text.encode('utf-8')
        
        # Create encrypted message envelope
        message = create_message_envelope(
            sender_id=self.user_id,
            recipient_id=remote_user_id,
            plaintext=plaintext,
            ratchet=ratchet
        )
        
        # Save updated session (keys have changed due to ratchet)
        self.session_store.save_session(self.user_id, remote_user_id, ratchet)
        
        return message
    
    def receive_message(self, message):
        # Check for replay attack
        if not self.replay_protector.check_and_add(message.message_id):
            raise Exception("Replay attack detected! Message already seen.")
        
        sender_id = message.sender_id
        
        # Get or create session
        if sender_id not in self.active_sessions:
            raise Exception(f"No session with {sender_id}. They need to start conversation first.")
        
        # Get the ratchet for this conversation
        ratchet = self.active_sessions[sender_id]
        
        # Decrypt the message
        plaintext = unwrap_message_envelope(message, ratchet)
        
        # Save updated session
        self.session_store.save_session(self.user_id, sender_id, ratchet)
        
        # Convert bytes back to text
        message_text = plaintext.decode('utf-8')
        
        return message_text
    
    def list_conversations(self):
        return list(self.active_sessions.keys())
    
    def close(self):
        # Close storage connections
        self.keystore.close()
        self.session_store.close()

