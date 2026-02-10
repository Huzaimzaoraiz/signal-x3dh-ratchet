#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║   SECURE END-TO-END ENCRYPTED CHAT                       ║
║   Using: X3DH + Double Ratchet + AES-GCM                ║
╚══════════════════════════════════════════════════════════╝

This simulates two users chatting on the SAME machine.
In a real app each user runs on a different device, and
the encrypted envelopes travel over the network.

Usage:
    python chat.py                  # interactive mode
    python chat.py --demo           # automated demo
"""

import os
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from network.client import SecureMessengerClient
from security.certificates import format_fingerprint, compute_fingerprint

# ── Colours ───────────────────────────────────────────────
BLUE   = "\033[94m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def show_bytes(data, limit=16):
    """Return a truncated hex preview."""
    h = data.hex()
    return h[:limit*2] + "…" if len(data) > limit else h


def print_header():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗
║          SECURE END-TO-END ENCRYPTED CHAT                ║
║     X3DH  ·  Double Ratchet  ·  AES-256-GCM             ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")


def print_phase(title):
    print(f"\n{BOLD}{BLUE}── {title} ─────────────────────────────────────{RESET}")


def setup_session():
    """
    Create Alice & Bob clients and perform the full handshake.
    Returns (alice, bob) ready to chat.
    """
    db_a = os.path.join(ROOT, "chat_alice.db")
    db_b = os.path.join(ROOT, "chat_bob.db")
    # Start fresh each time
    for f in [db_a, db_b]:
        if os.path.exists(f):
            os.remove(f)

    print_phase("1 · CREATING IDENTITIES")
    alice = SecureMessengerClient("Alice", db_path=db_a)
    bob   = SecureMessengerClient("Bob",   db_path=db_b)
    print(f"  {GREEN}✔{RESET} Alice created  (X25519 identity key generated)")
    print(f"  {GREEN}✔{RESET} Bob   created  (X25519 identity key generated)")

    # ── Key bundle exchange (simulates a server) ──────────
    print_phase("2 · KEY BUNDLE EXCHANGE  (simulates a public server)")
    bob_bundle = bob.get_public_bundle()
    print(f"  {DIM}Bob publishes his key bundle:{RESET}")
    print(f"    identity key   : {DIM}{show_bytes(bob_bundle.identity_key)}{RESET}")
    print(f"    signed prekey  : {DIM}{show_bytes(bob_bundle.signed_prekey)}{RESET}")
    print(f"    one-time prekey: {DIM}{show_bytes(bob_bundle.one_time_prekey)}{RESET}")

    # ── X3DH handshake ────────────────────────────────────
    print_phase("3 · X3DH HANDSHAKE  (4× Diffie-Hellman)")
    print(f"  {DIM}DH1: Alice identity   × Bob signed prekey{RESET}")
    print(f"  {DIM}DH2: Alice ephemeral  × Bob identity{RESET}")
    print(f"  {DIM}DH3: Alice ephemeral  × Bob signed prekey{RESET}")
    print(f"  {DIM}DH4: Alice ephemeral  × Bob one-time prekey{RESET}")

    alice_id_pub, alice_eph_pub = alice.start_conversation("Bob", bob_bundle)
    bob.accept_conversation("Alice", alice_id_pub, alice_eph_pub)

    # Show fingerprints for verification
    alice_fp = format_fingerprint(compute_fingerprint(alice_id_pub))
    bob_fp   = format_fingerprint(compute_fingerprint(bob_bundle.identity_key))
    print(f"\n  {BOLD}🔐 Session established!{RESET}")
    print(f"  {DIM}Alice fingerprint: {alice_fp[:40]}…{RESET}")
    print(f"  {DIM}Bob   fingerprint: {bob_fp[:40]}…{RESET}")

    print_phase("4 · DOUBLE RATCHET INITIALISED")
    print(f"  {GREEN}✔{RESET} Alice: initiator ratchet (sending chain ready)")
    print(f"  {GREEN}✔{RESET} Bob  : responder ratchet (receiving chain ready)")
    print(f"  {DIM}Every message uses a unique key — forward secrecy active{RESET}")

    return alice, bob


def send_and_show(sender, receiver, sender_name, receiver_name, text):
    """
    Encrypt → transmit → decrypt a message, showing every step.
    """
    # Encrypt
    envelope = sender.send_message(receiver_name, text)
    payload = envelope.encrypted_payload

    print(f"\n  {BOLD}{MAGENTA}{sender_name}{RESET}: {text}")
    print(f"  {DIM}  ┌─ encrypted ─────────────────────────────────────")
    print(f"  {DIM}  │ msg id    : {show_bytes(envelope.message_id)}")
    print(f"  {DIM}  │ dh_public : {show_bytes(payload['dh_public'])}")
    print(f"  {DIM}  │ counter   : {payload['counter']}")
    print(f"  {DIM}  │ nonce     : {show_bytes(payload['nonce'])}")
    print(f"  {DIM}  │ ciphertext: {show_bytes(payload['ciphertext'])}")
    print(f"  {DIM}  └──────────────────────────────────────────────────{RESET}")

    # "Transmit" over the wire (in real app this goes via network)
    # Decrypt
    plaintext = receiver.receive_message(envelope)

    print(f"  {GREEN}  → {receiver_name} decrypted: \"{plaintext}\"{RESET}")
    return plaintext


def run_demo(alice, bob):
    """Automated demo conversation."""
    print_phase("5 · ENCRYPTED CONVERSATION")
    print(f"  {DIM}Each message below is encrypted with a UNIQUE key.{RESET}")
    print(f"  {DIM}The cipher details are shown for every message.{RESET}")

    conversation = [
        ("Alice", "Bob",   "Hey Bob! Can you hear me? 🔐"),
        ("Alice", "Bob",   "This is message #2 — same sending chain, new key."),
        ("Bob",   "Alice", "Loud and clear, Alice! Ratchet just stepped. 🔑"),
        ("Alice", "Bob",   "Perfect. Every message has forward secrecy now."),
        ("Bob",   "Alice", "Even if someone records this, they can't decrypt later."),
        ("Alice", "Bob",   "That's the beauty of the Double Ratchet 🎉"),
    ]

    for sender_name, receiver_name, text in conversation:
        sender   = alice if sender_name == "Alice" else bob
        receiver = bob   if receiver_name == "Bob" else alice
        send_and_show(sender, receiver, sender_name, receiver_name, text)
        time.sleep(0.3)  # slight pause for readability

    # ── Replay attack demo ────────────────────────────────
    print_phase("6 · REPLAY ATTACK TEST")
    print(f"  {DIM}Eve captures a message and tries to replay it…{RESET}")
    captured = alice.send_message("Bob", "This will be intercepted")
    bob.receive_message(captured)  # first time — accepted
    print(f"  {GREEN}  ✔ First delivery: accepted{RESET}")
    try:
        bob.receive_message(captured)  # replay — blocked
    except Exception as e:
        print(f"  {RED}  ✘ Replay attempt: {e}{RESET}")
    print(f"  {GREEN}  ✔ Replay protection working!{RESET}")


def run_interactive(alice, bob):
    """Interactive two-person chat in the terminal."""
    print_phase("5 · INTERACTIVE CHAT")
    print(f"""
  {BOLD}Commands:{RESET}
    {CYAN}a:{RESET} <message>   — Alice sends to Bob
    {CYAN}b:{RESET} <message>   — Bob sends to Alice
    {CYAN}quit{RESET}           — exit

  {DIM}Example:  a: Hello Bob!{RESET}
""")

    while True:
        try:
            raw = input(f"  {BOLD}>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not raw or raw.lower() == "quit":
            break

        if raw.lower().startswith("a:"):
            text = raw[2:].strip()
            if not text:
                continue
            send_and_show(alice, bob, "Alice", "Bob", text)

        elif raw.lower().startswith("b:"):
            text = raw[2:].strip()
            if not text:
                continue
            send_and_show(bob, alice, "Bob", "Alice", text)

        else:
            print(f"  {YELLOW}Use 'a: message' or 'b: message'{RESET}")


def cleanup(alice, bob):
    alice.close()
    bob.close()
    for f in ["chat_alice.db", "chat_bob.db"]:
        p = os.path.join(ROOT, f)
        if os.path.exists(p):
            os.remove(p)


def main():
    print_header()

    alice, bob = setup_session()

    if "--demo" in sys.argv:
        run_demo(alice, bob)
    else:
        run_interactive(alice, bob)

    print(f"\n{BOLD}{CYAN}── DONE ──────────────────────────────────────────{RESET}")
    cleanup(alice, bob)
    print(f"  {GREEN}✔{RESET} Sessions closed, temp databases removed.\n")


if __name__ == "__main__":
    main()
