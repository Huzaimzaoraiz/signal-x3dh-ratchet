<div align="center">
  <h1> Double Ratchet Algorithm</h1>
  <p><strong>A Modern Implementation in Python</strong></p>

  <p>
    <img src="https://img.shields.io/badge/Python-3.8+-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
    <img src="https://img.shields.io/badge/Cryptography-Hazmat-red.svg?style=for-the-badge&logo=python&logoColor=white" alt="Crypto" />
  </p>
</div>

---

##  Overview

This repository provides a complete implementation of the Double Ratchet Algorithm (along with X3DH) built from the ground up. It implements industry-standard cryptographic paradigms, providing perfect forward secrecy, post-compromise security, and robust resilience against common network-layer attacks.

##  Core Capabilities

| Feature | Description |
| --- | --- |
|  **End-to-End Encryption** | `AES-GCM` encryption for all message payloads with authenticated data. |
|  **X3DH Key Exchange** | Extended Triple Diffie-Hellman for secure, asynchronous initial key agreement. |
|  **Double Ratchet** | KDF chains and public-key operations for perfect forward secrecy. |
|  **Certificate Pinning** | Identity key fingerprinting to prevent Man-In-The-Middle (MITM) attacks. |
|  **Replay Protection** | Cryptographically secure UUIDs tracked to detect and block replay attempts. |
|  **Traffic Padding** | Protocol-level message padding to mitigate traffic analysis. |
|  **Persistent Stores** | SQLite-backed `Keystore` and `SessionStore` for persisting states. |

##  System Architecture & Core Methods


### 1. The Client Layer (`network/client.py`)
The primary interface for the application, orchestrating cryptography, network, and storage mechanisms.
- `SecureMessengerClient(user_id, db_path)`: Initializes the client, local X3DH identity, and SQLite storage.
- `.get_public_bundle()`: Generates and returns the user's X3DH identity bundle.
- `.start_conversation(remote_user_id, remote_bundle)`: Initiates an X3DH session and sets up the Double Ratchet.
- `.accept_conversation(initiator_id, initiator_id_pub, initiator_eph_pub)`: Responds to an incoming X3DH initialization.
- `.send_message(remote_user_id, message_text)`: Encrypts, pads, and envelopes a plaintext message.
- `.receive_message(message)`: Validates against replay attacks, unwraps the envelope, and decrypts the payload.
- `.list_conversations()`: Returns a list of active secure sessions.

### 2. The Cryptography Layer (`crypto/`)
Handles all mathematical primitives, key derivation, and cryptographic state machines.
- **`DoubleRatchet` (`ratchet.py`)**: 
  - `.encrypt_message(plaintext)`: Advances the sending chain and encrypts data.
  - `.decrypt_message(message_dict)`: Triggers Diffie-Hellman ratchet steps and decrypts incoming data.
- **`X3DH` (`x3dh.py`)**: 
  - `.initiate_session()` & `.respond_to_session()`: Computes the 4-way Diffie-Hellman shared secret.
- **`HKDF` & `AES` (`hkdf.py`, `aes.py`)**: 
  - `derive_key()`, `derive_two_keys()`: Extracts and expands key material.
  - `encrypt_message()`, `decrypt_message()`: Authenticated symmetric encryption operations.

### 3. The Security Layer (`security/`)
Defends against network tampering, impersonation, and message spoofing.
- **`CertificatePinner` (`certificates.py`)**:
  - `.pin_if_new(user_id, public_key_bytes)`: Stores an identity key fingerprint or verifies it if it already exists.
  - `.verify_key(user_id, public_key_bytes)`: Checks if a key matches the pinned fingerprint.
- **`ReplayProtector` (`replay.py`)**:
  - `.check_and_add(message_id)`: Registers a unique message ID and flags duplicate attempts.
  - `.is_duplicate(message_id)`: Helper to check if a message has already been processed.

### 4. The Storage Layer (`storage/`)
Provides seamless SQLite serialization for local state persistence.
- **`Keystore` (`keystore.py`)**:
  - `.save_key()`, `.load_key()`, `.delete_keys()`: Stores and retrieves static and ephemeral keypairs.
- **`SessionStore` (`session_store.py`)**:
  - `.save_session()`, `.load_session()`, `.list_sessions()`: Serializes and persists active Double Ratchet state trees.

##  Getting Started



### Quick Start: Alice & Bob

```python
from network.client import SecureMessengerClient

# 1. Initialize Clients (automatically creates local SQLite databases)
alice = SecureMessengerClient("Alice", db_path="alice.db")
bob = SecureMessengerClient("Bob", db_path="bob.db")

# 2. Key Exchange (X3DH)
# In a real app, Bob's bundle would be retrieved from a central server
bob_bundle = bob.get_public_bundle()

# Alice initiates the session
alice_id_pub, alice_eph_pub = alice.start_conversation("Bob", bob_bundle)

# Bob accepts the session
bob.accept_conversation("Alice", alice_id_pub, alice_eph_pub)

# 3. Secure Messaging (Double Ratchet)
encrypted_msg = alice.send_message("Bob", "Hello Bob, secure comms established! 📡")

decrypted_text = bob.receive_message(encrypted_msg)
print(decrypted_text)  # Output: Hello Bob, secure comms established! 📡
```

**Coverage Highlights:**
* HKDF Determinism & Key Derivation Validation
* AES-GCM Encryption / Decryption & Tamper Resistance
* X3DH Shared Secret Agreement
* Double Ratchet Message Chaining & Bidirectional Flow
* Message Padding & Protocol Envelopes
* Certificate Pinning & MITM Rejection
* Replay Attack Detection & Blocking
* Keystore & SessionStore SQLite Persistence Integrity
