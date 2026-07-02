# End-to-End Encryption: Key Management & Conversation Flow Guide

This document explains the types of keys used in this application, how sessions are established, how keys are stored, and a complete dry run showing how a conversation progresses step-by-step.

---

## 1. Cryptographic Key Guide

The security of this system is split into two phases: **X3DH** (to establish a shared secret) and the **Double Ratchet** (to secure active messaging).

### The Key Directory

| Key Name | Key Type | Owner | Where Stored | When is it Stored? | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Identity Key (IK)** | X25519 (KeyPair) | Sender & Recipient | Client `keys` table | App Installation | Long-term identity. Alice uses Bob's Public IK to verify she is talking to the real Bob. |
| **Signed Prekey (SPK)** | X25519 (KeyPair) | Recipient | Client `keys` table | Periodically (e.g. weekly) | Medium-term key. Signed by the IK to prevent attackers from substituting Bob's prekeys. |
| **One-Time Prekey (OPK)** | X25519 (KeyPair) | Recipient | Client `keys` table | In bulk at registration | Short-term key. Used once to establish a session, then deleted to ensure perfect forward secrecy. |
| **Ephemeral Key (EK)** | X25519 (KeyPair) | Sender (Initiator) | Temporary / RAM | Created dynamically on start | Used once during the handshake to compute the initial shared secret. |
| **Root Key (RK)** | 32-byte Symmetric | Shared (Session) | Client `sessions` table | Updated on every DH ratchet | The master key of the current ratchet state. Used to derive new chain keys. |
| **Chain Key (CK)** | 32-byte Symmetric | Shared (Session) | Client `sessions` table | Updated on every message | Used to derive the specific Message Keys. We have two: a `sending_chain_key` and a `receiving_chain_key`. |
| **Message Key (MK)** | 32-byte Symmetric | Shared (Message) | Temporary / RAM (unless skipped) | Generated dynamically | Used with AES-GCM to encrypt/decrypt a single message. Deleted immediately after use. |

---

## 2. Session Initialization (X3DH Flow)

When **Alice** wants to send her first message to **Bob**:

1. **Pre-requisite (Bob Registration)**:
   * Bob generates his long-term Identity Key ($IK_B$), Signed Prekey ($SPK_B$), and a pool of One-Time Prekeys ($OPK_B$).
   * Bob uploads their public parts (the "Public Bundle") to the server.
   * Bob saves the private parts in his local database (`keys` table).

2. **Alice Initiates**:
   * Alice downloads Bob's Public Bundle from the server.
   * Alice generates a temporary Ephemeral Key ($EK_A$).
   * Alice performs 4 Diffie-Hellman (DH) computations:
     * $DH_1 = IK_{A, private} \times SPK_{B, public}$ (Authenticates Alice)
     * $DH_2 = EK_{A, private} \times IK_{B, public}$ (Authenticates Bob)
     * $DH_3 = EK_{A, private} \times SPK_{B, public}$ (Provides forward secrecy)
     * $DH_4 = EK_{A, private} \times OPK_{B, public}$ (Provides forward secrecy)
   * Alice hashes the concatenation of these DH values using HKDF to get the **Shared Secret**:
     $$\text{Shared Secret} = \text{HKDF}(DH_1 \mathbin{\Vert} DH_2 \mathbin{\Vert} DH_3 \mathbin{\Vert} DH_4)$$
   * Alice instantiates a `DoubleRatchet(Shared Secret, is_initiator=True)`. She stores this session in her local `sessions` table.
   * Alice sends her public Identity Key ($IK_A$) and her Ephemeral public key ($EK_A$) to Bob, along with the encrypted message.

3. **Bob Responds**:
   * Bob receives Alice's public keys ($IK_A$, $EK_A$).
   * Bob loads his matching private keys ($IK_B, SPK_{B, private}, OPK_{B, private}$) from his database.
   * Bob performs the same 4 DH computations:
     * $DH_1 = SPK_{B, private} \times IK_{A, public}$
     * $DH_2 = IK_{B, private} \times EK_{A, public}$
     * $DH_3 = SPK_{B, private} \times EK_{A, public}$
     * $DH_4 = OPK_{B, private} \times EK_{A, public}$
   * Bob derives the exact same **Shared Secret** and instantiates `DoubleRatchet(Shared Secret, is_initiator=False)`. He deletes the specific $OPK_{B}$ private key he used from his local database (so it can never be used again).

---

## 3. Ultra-Detailed System Flow & Execution Trace

This section maps out every function call, database query, key derivation, JSON state transition, and byte packet structure in chronological order.

### Setup Phase: Database Schema Definitions

All clients run SQLite. The structure of their local databases (`Alice_client.db`, `Bob_client.db`) contains two tables:

#### Schema for `keys` Table
```sql
CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    key_type TEXT NOT NULL,       -- "identity", "signed_prekey", or "one_time_prekey"
    key_data BLOB NOT NULL,       -- Raw 32 bytes private key
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_user_keytype ON keys(user_id, key_type);
```

#### Schema for `sessions` Table
```sql
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    local_user TEXT NOT NULL,
    remote_user TEXT NOT NULL,
    ratchet_state BLOB NOT NULL,   -- UTF-8 encoded JSON string of the DoubleRatchet state
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(local_user, remote_user)
);
```

---

### Step 1: Bob Installs Client & Registers on Server
Bob starts his messenger client for the very first time.

#### 1. Client Execution (`Bob`)
*   **File**: `network/client.py`
*   **Code Called**: `SecureMessengerClient("Bob", db_path="Bob_client.db")`
*   **Details**:
    *   Initializes database connection to `Bob_client.db`.
    *   Creates instances of `Keystore("Bob_client.db")` and `SessionStore("Bob_client.db")`.
    *   Creates an instance of `X3DH("Bob")`.
*   **Key Generation (X3DH Class)**:
    *   **File**: `crypto/x3dh.py`
    *   Executes:
        ```python
        self.identity_private = X25519PrivateKey.generate()
        self.identity_public = self.identity_private.public_key()
        self.signed_prekey_private = X25519PrivateKey.generate()
        self.signed_prekey_public = self.signed_prekey_private.public_key()
        self.one_time_prekey_private = X25519PrivateKey.generate()
        self.one_time_prekey_public = self.one_time_prekey_private.public_key()
        ```
*   **Local Storage Action**:
    *   Calls `Keystore.save_key("Bob", "identity", raw_private_identity_bytes)`.
    *   Calls `Keystore.save_key("Bob", "signed_prekey", raw_private_signed_prekey_bytes)`.
    *   Calls `Keystore.save_key("Bob", "one_time_prekey", raw_private_one_time_prekey_bytes)`.
    *   **Database State**: `Bob_client.db` now contains 3 rows in the `keys` table representing Bob's private keys.

#### 2. Network Transmission (Registration)
*   **File**: `run_client.py`
*   Bob's client calls `get_public_bundle()`. This serializes Bob's public keys using `public_bytes(Encoding.Raw, PublicFormat.Raw)`.
*   Sends HTTP POST to `http://127.0.0.1:8000/register`:
    ```json
    {
      "user_id": "Bob",
      "identity_key": "4c9e7a...ef21",  // Bob's Public IK (32 bytes hex)
      "signed_prekey": "bc820d...f9fc", // Bob's Public SPK (32 bytes hex)
      "one_time_prekey": "05d79a...07f2" // Bob's Public OPK (32 bytes hex)
    }
    ```

#### 3. Server Storage Action
*   **File**: `server.py`
*   FastAPI endpoint `/register` triggers:
    `USER_BUNDLES["Bob"] = { ... }` (saving Bob's public key hex strings in memory/database).

---

### Step 2: Alice Initiates Conversation and Sends "Hello Bob!"
Alice starts her app and wants to message Bob.

#### 1. Client Setup (`Alice`)
*   Alice runs `SecureMessengerClient("Alice", db_path="Alice_client.db")`.
*   Generates her long-term identity keys ($IK_A$), saving them locally in `Alice_client.db`.

#### 2. Handshake Phase
*   **File**: `run_client.py`
*   Alice calls `alice.send_chat("Bob", "Hello Bob!")`.
*   Since `Bob` is not in `alice.messenger.active_sessions`, Alice triggers `start_conversation()`:
    1.  **Network Request**: Calls `GET /bundle/Bob` on Server.
        *   Server returns Bob's public bundle and pops/removes Bob's one-time prekey from the active server inventory.
    2.  **Key Pinning**: Calls `CertificatePinner.pin_if_new("Bob", Bob_IK_bytes)`.
        *   Calculates SHA-256 fingerprint of Bob's Identity Key.
        *   Checks against pinned entries. Since it is new, it records: `trusted=True` and pins Bob's identity.
    3.  **Shared Secret Derivation (X3DH)**:
        *   Alice generates Ephemeral Keypair: `ephemeral_private = X25519PrivateKey.generate()`.
        *   Computes X3DH components:
            *   $DH_1 = IK_{A, private} \times SPK_{B, public}$
            *   $DH_2 = EK_{A, private} \times IK_{B, public}$
            *   $DH_3 = EK_{A, private} \times SPK_{B, public}$
            *   $DH_4 = EK_{A, private} \times OPK_{B, public}$
        *   Concatenates `material = DH1 + DH2 + DH3 + DH4` (128 bytes).
        *   Calls `hkdf.derive_key(material, b"X3DH shared secret")` to output 32-byte `shared_secret`.
    4.  **Double Ratchet Initialization**:
        *   Alice runs `DoubleRatchet(shared_secret, is_initiator=True)`.
        *   **File**: `crypto/ratchet.py`
        *   Sets:
            *   `self.root_key = shared_secret`
            *   `self.dh_private = X25519PrivateKey.generate()` (Alice's active DH keypair)
            *   `self.dh_public = self.dh_private.public_key()`
            *   `self.remote_dh_public = None`
        *   Derives initial chain keys via `derive_two_keys(self.root_key, info=INFO_ROOT_KEY)`:
            *   Outputs `self.root_key` (new root key) and `self.sending_chain_key`.
            *   Sets `self.receiving_chain_key = None`.
        *   `self.sending_counter = 0`, `self.receiving_counter = 0`.
    5.  **Local Database Session Saving**:
        *   Alice calls `SessionStore.save_session("Alice", "Bob", ratchet)`.
        *   **File**: `storage/session_store.py`
        *   Calls `ratchet.to_dict()`. The keys are base64 encoded into a JSON string:
            ```json
            {
              "root_key": "dGVzdF9rZXk...",
              "sending_chain_key": "c2VuZF9rZXk...",
              "receiving_chain_key": null,
              "sending_counter": 0,
              "receiving_counter": 0,
              "is_initiator": true,
              "dh_private": "cHJpdmF0ZV9rZXk...",
              "dh_public": "cHVibGljX2tleQ...",
              "remote_dh_public": null,
              "skipped_message_keys": {}
            }
            ```
        *   This JSON string is encoded to UTF-8 bytes and written into the `sessions` table in `Alice_client.db`.

#### 3. Message Encryption
*   Alice calls `SecureMessengerClient.send_message("Bob", "Hello Bob!")`.
*   Plaintext `"Hello Bob!"` is padded to exactly 1024 bytes in `network/protocal.py` using a 4-byte big-endian length prefix:
    *   Length of message = 10 (`\x00\x00\x00\x0a`)
    *   Padded bytes = `\x00\x00\x00\x0a` + `Hello Bob!` + `\x00 * 1010`
*   **Double Ratchet Encryption Step**:
    *   Uses `self.sending_chain_key` to derive `Message Key (MK)` and advances `sending_chain_key`:
        *   `MK = derive_key(self.sending_chain_key, INFO_MESSAGE_KEYS)`
        *   `self.sending_chain_key = derive_key(self.sending_chain_key, INFO_CHAIN_KEY)`
    *   Encrypts padded payload using AES-GCM:
        *   `ciphertext, nonce = aes.encrypt_message(MK, padded_plaintext)`
        *   (Note: `nonce` is a cryptographically secure random 12-byte block generated in `aes.py`).
    *   Increments `sending_counter` to 1.
*   **Envelope Packaging**:
    *   Wraps keys into a `ProtocolMessage` class containing:
        *   `message_id` = random 16 bytes.
        *   `sender_id` = `"Alice"`
        *   `recipient_id` = `"Bob"`
        *   `payload` = `{"dh_public": Alice_DH_public_bytes, "counter": 0, "nonce": nonce, "ciphertext": ciphertext}`
*   **Local Database Update**:
    *   Alice updates her session state in `Alice_client.db` (saving the advanced `sending_chain_key` and the advanced `sending_counter = 1`).

#### 4. Network Transmission
Alice sends HTTP POST to `http://127.0.0.1:8000/send` with the base64/hex payload.
*   **Server Action**:
    *   FastAPI captures the envelope and stores it in Bob's delivery queue inside `MESSAGE_QUEUES["Bob"]`.

---

### Step 3: Bob Decrypts Alice's First Message
Bob polls the server, receives Alice's message, and decrypts it.

#### 1. Network Fetching
*   Bob's client runs `fetch_incoming()` which hits `GET /pop-messages/Bob`.
*   The server returns the JSON representation of Alice's `ProtocolMessage`.

#### 2. Replay & Pin Verification
*   Bob's client calls `ReplayProtector.check_and_add(message_id)`.
    *   Saves the `message_id` to prevent it from being processed again.
*   Bob verifies Alice's long-term identity key fingerprint.

#### 3. X3DH Response Handshake (Session Creation)
*   Since `Alice` is not in `Bob.active_sessions`, Bob triggers `accept_conversation("Alice", Alice_IK_bytes, Alice_EK_bytes)`:
    1.  Bob queries his local `keys` table in `Bob_client.db` to load his private keys: $IK_{B, private}$, $SPK_{B, private}$, and the specific $OPK_{B, private}$ matching the one Bob posted (obtained from the incoming X3DH data payload).
    2.  Bob performs the X3DH math:
        *   $DH_1 = SPK_{B, private} \times IK_{A, public}$
        *   $DH_2 = IK_{B, private} \times EK_{A, public}$
        *   $DH_3 = SPK_{B, private} \times EK_{A, public}$
        *   $DH_4 = OPK_{B, private} \times EK_{A, public}$
    3.  Bob derives the identical `shared_secret` via `hkdf.derive_key(DH1 + DH2 + DH3 + DH4, b"X3DH shared secret")`.
    4.  Bob deletes the one-time prekey $OPK_{B, private}$ from his local SQLite `keys` table so it can never be retrieved by an attacker in the future.
    5.  Bob instantiates `DoubleRatchet(shared_secret, is_initiator=False)`:
        *   `self.root_key = shared_secret`
        *   `self.dh_private` is not set yet (responder waits for initiator's DH key).
        *   `self.remote_dh_public = None`
        *   Derives initial receiving chain:
            *   `self.root_key, self.receiving_chain_key = derive_two_keys(self.root_key, info=INFO_ROOT_KEY)`
            *   Sets `self.sending_chain_key = None`.
    6.  Saves Bob's new session inside the SQLite `sessions` table in `Bob_client.db`.

#### 4. Decryption Step
*   Bob calls `SecureMessengerClient.receive_message(envelope)`.
*   **Double Ratchet Decryption**:
    *   Bob verifies if the public DH key in the envelope matches his records.
    *   Since this is Bob's first message from Alice, Bob's ratchet accepts Alice's public DH key (`c5ed...f533`) as the active `remote_dh_public` without doing a full DH ratchet step.
    *   Bob derives `Message Key (MK)` from his `receiving_chain_key`:
        *   `MK = derive_key(self.receiving_chain_key, INFO_MESSAGE_KEYS)`
        *   `self.receiving_chain_key = derive_key(self.receiving_chain_key, INFO_CHAIN_KEY)`
    *   Calls `aes.decrypt_message(MK, ciphertext)` using the package `nonce`.
    *   Decrypted output is `padded_plaintext` (1024 bytes).
*   **Unpadding**:
    *   Bob reads the first 4 bytes of `padded_plaintext` as an integer = 10.
    *   Slices the next 10 bytes: `Hello Bob!`.
*   **Save State**:
    *   Bob updates the session state in `Bob_client.db` (saving the updated `receiving_chain_key` and `receiving_counter = 1`).

---

### Step 4: Bob Replies to Alice (Self-Healing DH Ratchet)
Bob sends a reply: `"I'm good Alice, thanks!"`

#### 1. Double Ratchet DH Step on Bob
*   Because Bob was receiving and is now sending, his client detects the change of direction.
*   Bob triggers `_dh_ratchet(Alice_DH_public_bytes)`:
    1.  Bob generates a new DH keypair locally: `self.dh_private = X25519PrivateKey.generate()`.
    2.  Bob computes the shared DH secret: `dh_secret = self.dh_private.exchange(self.remote_dh_public)`.
    3.  Bob updates his Root Key and derives his new Sending Chain Key:
        *   `self.root_key, self.sending_chain_key = derive_two_keys(self.root_key + dh_secret, info=INFO_ROOT_KEY)`
    4.  Bob resets his `sending_counter` to 0.
*   **Symmetric Send Step**:
    *   Derives `MK_0 = derive_key(self.sending_chain_key, INFO_MESSAGE_KEYS)`.
    *   Advances `self.sending_chain_key = derive_key(self.sending_chain_key, INFO_CHAIN_KEY)`.
    *   Increments `sending_counter` to 1.
*   Encrypts `"I'm good Alice, thanks!"` (padded to 1024 bytes) using $MK_0$.
*   Saves the session state to `Bob_client.db`.

#### 2. Network Payload
Bob transmits the packet containing Bob's new public DH key ($DH_{B2, public}$) to the Server:
```json
{
  "message_id": "97e4...fc66",
  "sender_id": "Bob",
  "recipient_id": "Alice",
  "payload": {
    "dh_public": "8d48...0402", // Bob's NEW public DH key (DH_B2_pub)
    "counter": 0,               // Bob's message counter is reset to 0
    "nonce": "df13...da51",
    "ciphertext": "cf2a...5ca2"
  }
}
```

---

### Step 5: Alice Decrypts Bob's Reply
Alice polls the server, fetches Bob's reply, and decrypts it.

#### 1. DH Ratchet Step on Alice
*   Alice loads her session state with Bob from `Alice_client.db`.
*   Alice notices Bob's incoming public DH key (`8d48...0402`) does not match her recorded `remote_dh_public` (which was Alice's own handshake parameters).
*   Alice triggers `_dh_ratchet(Bob_DH_B2_public)`:
    1.  Alice computes the DH shared secret using her own active private DH key and Bob's new public DH key:
        `dh_secret = self.dh_private.exchange(Bob_DH_B2_public)`
    2.  Alice derives the new Root Key and Receiving Chain Key:
        `self.root_key, self.receiving_chain_key = derive_two_keys(self.root_key + dh_secret, info=INFO_ROOT_KEY)`
    3.  Alice saves Bob's public key as `self.remote_dh_public = Bob_DH_B2_public`.
    4.  Alice resets her `receiving_counter` to 0.

#### 2. Decryption
*   Alice derives `MK_0 = derive_key(self.receiving_chain_key, INFO_MESSAGE_KEYS)`.
*   Advances her receiving chain key.
*   Decrypts Bob's payload, unpads the 1024 bytes, and reads `"I'm good Alice, thanks!"`.
*   Saves the updated session state to `Alice_client.db`.

---

### Step 6: Alice sends Message #2 (Symmetric Ratchet Only)
Alice immediately responds to Bob with `"Glad to hear!"` before Bob has typed anything else.

*   **Who**: Alice
*   **Action**: `send_message("Bob", "Glad to hear!")`
*   **What gets called**:
    1.  Alice's client detects she is sending *again* (no direction change).
    2.  **No DH Ratchet occurs**.
    3.  **Symmetric Ratchet occurs**:
        *   Alice advances her sending chain:
            *   `MK_1 = derive_key(self.sending_chain_key, INFO_MESSAGE_KEYS)`
            *   `self.sending_chain_key = derive_key(self.sending_chain_key, INFO_CHAIN_KEY)`
        *   Alice increments `sending_counter` to 2.
    4.  Encrypts `"Glad to hear!"` (padded to 1024 bytes) using $MK_1$.
    5.  Saves state to database.
*   **Payload sent to Server**:
    Notice that the payload contains Alice's **same** DH public key from before, but the `counter` is now `1` (which corresponds to index `1`, i.e., the second message in this DH chain).
    ```json
    {
      "message_id": "0ac8...f95b",
      "sender_id": "Alice",
      "recipient_id": "Bob",
      "payload": {
        "dh_public": "c5ed...f533", // Same DH key as Alice's first message
        "counter": 1,               // Counter incremented to 1
        "nonce": "e436...3940",
        "ciphertext": "cd88...abf6"
      }
    }
    ```

---

### Step 7: Bob Decrypts Alice's Second Message
Bob receives Alice's message.

*   Bob loads his session.
*   Sees the DH public key in the message (`c5ed...f533`) matches his stored `remote_dh_public`.
*   **No DH Ratchet occurs** because the sender's DH key did not change.
*   **Symmetric Ratchet occurs**:
    *   Bob advances his receiving chain:
        *   `MK_1 = derive_key(self.receiving_chain_key, INFO_MESSAGE_KEYS)`
        *   `self.receiving_chain_key = derive_key(self.receiving_chain_key, INFO_CHAIN_KEY)`
    *   Increments `receiving_counter` to 2.
*   Bob decrypts the payload using $MK_1$ and reads `"Glad to hear!"`.
*   Saves the session state.

---

## 4. Edge Case Flow: Out-of-Order Message Handling

To show the robustness of the system, this trace shows what happens when messages arrive out of order.

```
[Timeline]
1. Alice sends Message #3 (Counter 2) -> Delayed in transit
2. Alice sends Message #4 (Counter 3) -> Reaches Bob first
3. Bob decrypts Message #4
4. Alice's Message #3 finally reaches Bob
5. Bob decrypts Message #3
```

Here is exactly how the client handles this:

#### 1. Alice Sends Messages #3 and #4
*   Alice calls `send_message("Bob", "Message 3")`.
    *   Uses sending chain key to derive `MK_2`.
    *   Advances sending chain.
    *   `sending_counter` becomes 3.
    *   Message #3 is sent but delayed by network lag.
*   Alice calls `send_message("Bob", "Message 4")`.
    *   Uses sending chain key to derive `MK_3`.
    *   Advances sending chain.
    *   `sending_counter` becomes 4.
    *   Message #4 is transmitted and reaches Bob successfully.

#### 2. Bob Receives Message #4 First
*   Bob's client receives the envelope for Message #4.
*   Bob inspects the envelope payload:
    *   `counter` = 3
    *   `dh_public` = Alice's same public DH key.
*   Bob's current `receiving_counter` is `2`.
*   Bob detects a gap: Bob was expecting counter `2` (Message #3), but received counter `3` (Message #4).
*   **Skipped Keys Calculation**:
    *   Bob enters a loop to skip and save the missing keys:
        *   For `counter` index 2:
            *   Derives `SKIPPED_MK_2` from the current `receiving_chain_key`.
            *   Advances `self.receiving_chain_key = derive_key(self.receiving_chain_key, INFO_CHAIN_KEY)`.
            *   Saves `SKIPPED_MK_2` into the skipped keys map locally:
                `self.skipped_message_keys[(remote_dh_public_bytes, 2)] = SKIPPED_MK_2`
    *   Bob is now caught up to counter 3.
*   **Decrypting Message #4**:
    *   Derives `MK_3` from the now-advanced `receiving_chain_key`.
    *   Advances `receiving_chain_key` once more.
    *   Decrements the expected counter gap.
    *   Decrypts Message #4 successfully.
    *   Saves state (including the new entries in `skipped_message_keys` dictionary) to `Bob_client.db`.

#### 3. Bob Receives the Delayed Message #3
*   Bob's client receives the envelope for Message #3.
*   Bob inspects the envelope payload:
    *   `counter` = 2
*   Bob checks his `skipped_message_keys` list to see if he has a key saved for `(Alice_DH_public_bytes, 2)`.
*   **Match Found!**
    *   Bob retrieves `SKIPPED_MK_2` from the map.
    *   Decrypts Message #3 successfully.
    *   **Deletes** the key from the dictionary `skipped_message_keys` so it can never be used again.
    *   Updates `Bob_client.db` (removing the entry from `skipped_message_keys` in the serialized JSON block).
*   Bob successfully displays `"Message 3"` to the user.
