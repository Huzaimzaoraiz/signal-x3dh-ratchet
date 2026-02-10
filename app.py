#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║   SECURE MESSENGER — CLIENT APP                           ║
║   End-to-end encrypted chat over TCP.                     ║
║   X3DH · Double Ratchet · AES-256-GCM                    ║
╚═══════════════════════════════════════════════════════════╝

Usage:
    python app.py --user Alice                   # connect to localhost:9000
    python app.py --user Bob --host 192.168.1.5  # remote server
    python app.py --user Alice --port 9001       # custom port
"""

import asyncio
import json
import base64
import argparse
import sys
import os
import threading

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from crypto.x3dh import X3DH, X3DHKeyBundle
from crypto.ratchet import DoubleRatchet
from crypto.hkdf import derive_key
from crypto.aes import encrypt_message, decrypt_message
from network.protocal import pad_message, unpad_message
from security.replay import ReplayProtector
from security.certificates import CertificatePinner, compute_fingerprint, format_fingerprint

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

# Move cursor & clear line for clean prompt redraw
CLEAR_LINE = "\033[2K\r"


def b64e(data: bytes) -> str:
    """Encode bytes to base64 string for JSON transport."""
    return base64.b64encode(data).decode()


def b64d(s: str) -> bytes:
    """Decode base64 string back to bytes."""
    return base64.b64decode(s)


class SecureMessengerApp:
    """
    Production-style E2E encrypted chat client.

    Flow:
      1. Connect to relay server via TCP
      2. Register: publish X3DH key bundle
      3. To chat: fetch remote user's bundle → X3DH handshake → Double Ratchet
      4. Send/receive encrypted messages through the relay server
    """

    def __init__(self, user_id: str, host: str, port: int):
        self.user_id = user_id
        self.host = host
        self.port = port

        # Crypto
        self.x3dh = X3DH(user_id)
        self.replay_protector = ReplayProtector()
        self.cert_pinner = CertificatePinner()

        # Sessions: remote_user → DoubleRatchet
        self.sessions: dict[str, DoubleRatchet] = {}

        # Network
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.loop: asyncio.AbstractEventLoop | None = None

        # State
        self.current_chat: str | None = None  # who we're chatting with
        self.running = True

    # ══════════════════════════════════════════════════════
    #  NETWORK — connect, send, receive
    # ══════════════════════════════════════════════════════

    async def connect(self):
        """Connect to the relay server."""
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

    async def send_json(self, obj: dict):
        """Send a JSON message to the server."""
        data = json.dumps(obj).encode() + b"\n"
        self.writer.write(data)
        await self.writer.drain()

    async def read_json(self) -> dict | None:
        """Read one JSON message from the server."""
        try:
            line = await self.reader.readline()
            if not line:
                return None
            return json.loads(line.decode())
        except (json.JSONDecodeError, ConnectionError):
            return None

    # ══════════════════════════════════════════════════════
    #  REGISTRATION — publish key bundle
    # ══════════════════════════════════════════════════════

    async def register(self):
        """Register with the server and upload our key bundle."""
        bundle = self.x3dh.get_public_bundle()
        await self.send_json({
            "action": "register",
            "user_id": self.user_id,
            "bundle": {
                "identity_key": b64e(bundle.identity_key),
                "signed_prekey": b64e(bundle.signed_prekey),
                "one_time_prekey": b64e(bundle.one_time_prekey),
            }
        })
        resp = await self.read_json()
        if resp and resp.get("status") == "ok":
            return True
        return False

    # ══════════════════════════════════════════════════════
    #  HANDSHAKE — X3DH key exchange via the server
    # ══════════════════════════════════════════════════════

    async def start_session(self, remote_user: str):
        """Initiate X3DH with a remote user through the server."""
        # 1. Fetch their key bundle from the server
        await self.send_json({"action": "get_bundle", "user_id": remote_user})
        resp = await self.read_json()

        if not resp or resp.get("action") == "error":
            err = resp.get("message", "Unknown error") if resp else "No response"
            print(f"\n  {RED}Error: {err}{RESET}")
            return False

        # Reconstruct the bundle
        b = resp["bundle"]
        remote_bundle = X3DHKeyBundle(
            identity_key=b64d(b["identity_key"]),
            signed_prekey=b64d(b["signed_prekey"]),
            one_time_prekey=b64d(b["one_time_prekey"]),
        )

        # 2. Pin / verify identity key
        is_trusted, fp = self.cert_pinner.pin_if_new(remote_user, remote_bundle.identity_key)
        if not is_trusted:
            print(f"\n  {RED}⚠ KEY CHANGED for {remote_user}! Possible MITM attack!{RESET}")
            return False

        # 3. Perform X3DH
        shared_secret, ephemeral_public = self.x3dh.initiate_session(remote_bundle)
        identity_public = self.x3dh._serialize_public_key(self.x3dh.identity_public)

        # 4. Create ratchet
        ratchet = DoubleRatchet(shared_secret, is_initiator=True)
        self.sessions[remote_user] = ratchet

        # 5. Send handshake data to remote user via server
        await self.send_json({
            "action": "handshake",
            "from": self.user_id,
            "target": remote_user,
            "identity_key": b64e(identity_public),
            "ephemeral_key": b64e(ephemeral_public),
        })

        resp2 = await self.read_json()
        formatted_fp = format_fingerprint(fp)
        print(f"\n  {GREEN}🔐 Session established with {BOLD}{remote_user}{RESET}")
        print(f"  {DIM}Fingerprint: {formatted_fp[:48]}…{RESET}")
        return True

    def accept_handshake(self, from_user: str, identity_key_b64: str, ephemeral_key_b64: str):
        """Accept an incoming X3DH handshake (called when server delivers it)."""
        identity_key = b64d(identity_key_b64)
        ephemeral_key = b64d(ephemeral_key_b64)

        # Pin / verify
        is_trusted, fp = self.cert_pinner.pin_if_new(from_user, identity_key)
        if not is_trusted:
            print(f"\n  {RED}⚠ KEY CHANGED for {from_user}! Ignoring handshake.{RESET}")
            return

        # Complete X3DH
        shared_secret = self.x3dh.respond_to_session(identity_key, ephemeral_key)
        ratchet = DoubleRatchet(shared_secret, is_initiator=False)
        self.sessions[from_user] = ratchet

        formatted_fp = format_fingerprint(fp)
        print(f"\n  {GREEN}🔐 {BOLD}{from_user}{RESET}{GREEN} established a session with you{RESET}")
        print(f"  {DIM}Fingerprint: {formatted_fp[:48]}…{RESET}")

    # ══════════════════════════════════════════════════════
    #  MESSAGING — encrypt, send, receive, decrypt
    # ══════════════════════════════════════════════════════

    async def send_message(self, remote_user: str, text: str):
        """Encrypt and send a message to a remote user."""
        if remote_user not in self.sessions:
            print(f"  {RED}No session with {remote_user}. Use /chat {remote_user} first.{RESET}")
            return

        ratchet = self.sessions[remote_user]
        plaintext = text.encode("utf-8")

        # Pad → encrypt via ratchet
        padded = pad_message(plaintext)
        encrypted = ratchet.encrypt_message(padded)

        # Serialize for JSON transport
        envelope = {
            "message_id": b64e(os.urandom(16)),
            "dh_public": b64e(encrypted["dh_public"]),
            "counter": encrypted["counter"],
            "nonce": b64e(encrypted["nonce"]),
            "ciphertext": b64e(encrypted["ciphertext"]),
        }

        await self.send_json({
            "action": "send_message",
            "from": self.user_id,
            "target": remote_user,
            "envelope": envelope,
        })

    def decrypt_incoming(self, from_user: str, envelope: dict) -> str | None:
        """Decrypt an incoming message envelope."""
        # Replay check
        msg_id = b64d(envelope["message_id"])
        if not self.replay_protector.check_and_add(msg_id):
            print(f"  {RED}⚠ Replay attack blocked!{RESET}")
            return None

        if from_user not in self.sessions:
            print(f"  {RED}No session with {from_user} — cannot decrypt.{RESET}")
            return None

        ratchet = self.sessions[from_user]

        # Reconstruct the encrypted payload
        encrypted = {
            "dh_public": b64d(envelope["dh_public"]),
            "counter": envelope["counter"],
            "nonce": b64d(envelope["nonce"]),
            "ciphertext": b64d(envelope["ciphertext"]),
        }

        # Decrypt → unpad
        padded_plaintext = ratchet.decrypt_message(encrypted)
        plaintext = unpad_message(padded_plaintext)
        return plaintext.decode("utf-8")

    # ══════════════════════════════════════════════════════
    #  INCOMING MESSAGE LISTENER (background)
    # ══════════════════════════════════════════════════════

    async def listen_for_messages(self):
        """Background loop that processes incoming server messages."""
        while self.running:
            msg = await self.read_json()
            if msg is None:
                if self.running:
                    print(f"\n  {RED}Disconnected from server.{RESET}")
                break

            action = msg.get("action")

            if action == "incoming_handshake":
                self.accept_handshake(
                    msg["from"],
                    msg["identity_key"],
                    msg["ephemeral_key"],
                )
                self._reprint_prompt()

            elif action == "incoming_message":
                from_user = msg["from"]
                text = self.decrypt_incoming(from_user, msg["envelope"])
                if text:
                    print(f"{CLEAR_LINE}  {MAGENTA}{BOLD}{from_user}{RESET}: {text}")
                self._reprint_prompt()

            elif action == "user_list":
                users = msg["users"]
                print(f"\n  {BOLD}Online users:{RESET}")
                for u in users:
                    status = f"{GREEN}online{RESET}" if u["online"] else f"{DIM}offline{RESET}"
                    me = " (you)" if u["user_id"] == self.user_id else ""
                    print(f"    {u['user_id']}{me}  [{status}]")
                self._reprint_prompt()

            elif action == "handshake_sent":
                pass  # handled inline

            elif action == "message_sent":
                pass  # handled inline

            elif action == "error":
                print(f"\n  {RED}Server error: {msg['message']}{RESET}")
                self._reprint_prompt()

    def _reprint_prompt(self):
        """Reprint the input prompt after an incoming message."""
        target = self.current_chat or "?"
        print(f"  {BOLD}[{self.user_id} → {target}]{RESET} > ", end="", flush=True)

    # ══════════════════════════════════════════════════════
    #  USER INTERFACE — interactive terminal
    # ══════════════════════════════════════════════════════

    def print_help(self):
        print(f"""
  {BOLD}Commands:{RESET}
    {CYAN}/chat <user>{RESET}     — Start encrypted session and chat with a user
    {CYAN}/users{RESET}           — List registered users
    {CYAN}/switch <user>{RESET}   — Switch to an existing conversation
    {CYAN}/sessions{RESET}        — List your active sessions
    {CYAN}/fingerprint{RESET}     — Show current chat partner's fingerprint
    {CYAN}/help{RESET}            — Show this help
    {CYAN}/quit{RESET}            — Exit

  {DIM}Type any other text to send a message to your current chat partner.{RESET}
""")

    async def input_loop(self):
        """Main user input loop (runs in the event loop via executor)."""
        loop = asyncio.get_event_loop()

        self.print_help()

        while self.running:
            try:
                target = self.current_chat or "?"
                prompt = f"  {BOLD}[{self.user_id} → {target}]{RESET} > "
                raw = await loop.run_in_executor(None, lambda: input(prompt))
                raw = raw.strip()
            except (EOFError, KeyboardInterrupt):
                self.running = False
                break

            if not raw:
                continue

            # ── Commands ──────────────────────────────────
            if raw.lower() == "/quit":
                self.running = False
                break

            elif raw.lower() == "/help":
                self.print_help()

            elif raw.lower() == "/users":
                await self.send_json({"action": "list_users"})
                # Response handled in listen_for_messages
                await asyncio.sleep(0.3)

            elif raw.lower() == "/sessions":
                if not self.sessions:
                    print(f"  {DIM}No active sessions yet.{RESET}")
                else:
                    print(f"  {BOLD}Active sessions:{RESET}")
                    for u in self.sessions:
                        marker = " ← current" if u == self.current_chat else ""
                        print(f"    {GREEN}●{RESET} {u}{marker}")

            elif raw.lower().startswith("/chat "):
                remote = raw[6:].strip()
                if not remote:
                    print(f"  {YELLOW}Usage: /chat <username>{RESET}")
                    continue

                if remote == self.user_id:
                    print(f"  {YELLOW}You can't chat with yourself!{RESET}")
                    continue

                if remote in self.sessions:
                    self.current_chat = remote
                    print(f"  {GREEN}Switched to {BOLD}{remote}{RESET}{GREEN} (session exists){RESET}")
                    continue

                print(f"  {DIM}Establishing secure session with {remote}…{RESET}")
                ok = await self.start_session(remote)
                if ok:
                    self.current_chat = remote

            elif raw.lower().startswith("/switch "):
                remote = raw[8:].strip()
                if remote in self.sessions:
                    self.current_chat = remote
                    print(f"  {GREEN}Switched to {BOLD}{remote}{RESET}")
                else:
                    print(f"  {YELLOW}No session with {remote}. Use /chat {remote} first.{RESET}")

            elif raw.lower() == "/fingerprint":
                if not self.current_chat:
                    print(f"  {YELLOW}Not chatting with anyone yet.{RESET}")
                else:
                    fp = self.cert_pinner.get_fingerprint(self.current_chat)
                    if fp:
                        formatted = format_fingerprint(fp)
                        print(f"  {BOLD}{self.current_chat}{RESET}'s fingerprint:")
                        print(f"  {DIM}{formatted}{RESET}")
                    else:
                        print(f"  {YELLOW}No fingerprint stored for {self.current_chat}.{RESET}")

            elif raw.startswith("/"):
                print(f"  {YELLOW}Unknown command. Type /help{RESET}")

            # ── Regular message ───────────────────────────
            else:
                if not self.current_chat:
                    print(f"  {YELLOW}No active chat. Use /chat <username> first.{RESET}")
                    continue

                await self.send_message(self.current_chat, raw)
                # Show our own message locally
                print(f"{CLEAR_LINE}  {CYAN}{BOLD}{self.user_id}{RESET}: {raw}")

    # ══════════════════════════════════════════════════════
    #  MAIN ENTRY
    # ══════════════════════════════════════════════════════

    async def run(self):
        """Connect, register, then run input + listener concurrently."""
        print(f"""
{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════╗
║          SECURE MESSENGER — CLIENT                        ║
║     X3DH  ·  Double Ratchet  ·  AES-256-GCM              ║
╚═══════════════════════════════════════════════════════════╝{RESET}
""")

        # Connect
        print(f"  {DIM}Connecting to {self.host}:{self.port}…{RESET}")
        try:
            await self.connect()
        except ConnectionRefusedError:
            print(f"  {RED}Cannot connect to server at {self.host}:{self.port}{RESET}")
            print(f"  {DIM}Make sure server.py is running first.{RESET}")
            return

        # Register
        print(f"  {DIM}Registering as {BOLD}{self.user_id}{RESET}{DIM}…{RESET}")
        ok = await self.register()
        if not ok:
            print(f"  {RED}Registration failed.{RESET}")
            return

        fp = format_fingerprint(compute_fingerprint(
            self.x3dh._serialize_public_key(self.x3dh.identity_public)
        ))
        print(f"  {GREEN}✔ Connected and registered as {BOLD}{self.user_id}{RESET}")
        print(f"  {DIM}Your fingerprint: {fp[:48]}…{RESET}")

        # Run listener + input loop concurrently
        listener = asyncio.create_task(self.listen_for_messages())
        try:
            await self.input_loop()
        finally:
            self.running = False
            listener.cancel()
            if self.writer:
                self.writer.close()
            print(f"\n  {GREEN}✔ Disconnected. Goodbye!{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Secure Messenger Client")
    parser.add_argument("--user", required=True, help="Your username")
    parser.add_argument("--host", default="127.0.0.1", help="Server address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9000, help="Server port (default: 9000)")
    args = parser.parse_args()

    app = SecureMessengerApp(user_id=args.user, host=args.host, port=args.port)

    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        print(f"\n  {YELLOW}Interrupted.{RESET}\n")


if __name__ == "__main__":
    main()
