#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║   SECURE MESSENGER — RELAY SERVER                         ║
║   Stores key bundles and relays encrypted messages.       ║
║   The server NEVER sees plaintext — only ciphertext.      ║
╚═══════════════════════════════════════════════════════════╝

Usage:
    python server.py                    # default: 0.0.0.0:9000
    python server.py --host 0.0.0.0 --port 9000
"""

import asyncio
import json
import base64
import argparse
import signal
import sys
from datetime import datetime

# ── Colours ───────────────────────────────────────────────
BLUE   = "\033[94m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def log(level, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    colours = {"INFO": GREEN, "WARN": YELLOW, "ERR": RED, "CONN": CYAN}
    c = colours.get(level, RESET)
    print(f"  {DIM}{ts}{RESET}  {c}{level:4s}{RESET}  {msg}")


class SecureRelayServer:
    """
    Central relay server. It stores:
      - key bundles   (identity + signed prekey + one-time prekey)
      - offline messages  (queued until recipient connects)
      - handshake data (X3DH ephemeral keys for session setup)

    It never decrypts anything — it just routes opaque blobs.
    """

    def __init__(self, host="0.0.0.0", port=9000):
        self.host = host
        self.port = port

        # user_id → key bundle dict  (base64 encoded)
        self.key_bundles: dict[str, dict] = {}

        # user_id → asyncio.StreamWriter  (online clients)
        self.online_clients: dict[str, asyncio.StreamWriter] = {}

        # user_id → list of pending messages/handshakes
        self.offline_queue: dict[str, list] = {}

        # user_id → list of pending handshake packets
        self.pending_handshakes: dict[str, list] = {}

    # ── Send a JSON message to a client ───────────────────
    async def send_to(self, writer: asyncio.StreamWriter, obj: dict):
        data = json.dumps(obj).encode() + b"\n"
        writer.write(data)
        await writer.drain()

    # ── Read one JSON line from a client ──────────────────
    async def read_from(self, reader: asyncio.StreamReader) -> dict | None:
        try:
            line = await reader.readline()
            if not line:
                return None
            return json.loads(line.decode())
        except (json.JSONDecodeError, ConnectionError):
            return None

    # ── Handle a single client connection ─────────────────
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        user_id = None

        try:
            while True:
                msg = await self.read_from(reader)
                if msg is None:
                    break

                action = msg.get("action")

                if action == "register":
                    user_id = msg["user_id"]
                    bundle = msg["bundle"]
                    self.key_bundles[user_id] = bundle
                    self.online_clients[user_id] = writer
                    log("CONN", f"{BOLD}{user_id}{RESET} registered from {addr}")
                    await self.send_to(writer, {
                        "action": "registered",
                        "status": "ok",
                        "user_id": user_id
                    })

                    # Deliver any queued handshakes
                    if user_id in self.pending_handshakes:
                        for hs in self.pending_handshakes.pop(user_id):
                            await self.send_to(writer, hs)
                            log("INFO", f"Delivered queued handshake to {user_id}")

                    # Deliver any queued messages
                    if user_id in self.offline_queue:
                        for queued in self.offline_queue.pop(user_id):
                            await self.send_to(writer, queued)
                            log("INFO", f"Delivered queued message to {user_id}")

                elif action == "list_users":
                    users = [
                        {"user_id": uid, "online": uid in self.online_clients}
                        for uid in self.key_bundles
                    ]
                    await self.send_to(writer, {
                        "action": "user_list",
                        "users": users
                    })

                elif action == "get_bundle":
                    target = msg["user_id"]
                    if target in self.key_bundles:
                        await self.send_to(writer, {
                            "action": "bundle",
                            "user_id": target,
                            "bundle": self.key_bundles[target]
                        })
                    else:
                        await self.send_to(writer, {
                            "action": "error",
                            "message": f"User '{target}' not found"
                        })

                elif action == "handshake":
                    # Initiator sends X3DH handshake data TO the responder
                    target = msg["target"]
                    packet = {
                        "action": "incoming_handshake",
                        "from": msg["from"],
                        "identity_key": msg["identity_key"],
                        "ephemeral_key": msg["ephemeral_key"],
                    }

                    if target in self.online_clients:
                        await self.send_to(self.online_clients[target], packet)
                        log("INFO", f"Handshake {msg['from']} → {target} (live)")
                    else:
                        self.pending_handshakes.setdefault(target, []).append(packet)
                        log("INFO", f"Handshake {msg['from']} → {target} (queued)")

                    await self.send_to(writer, {"action": "handshake_sent", "target": target})

                elif action == "send_message":
                    target = msg["target"]
                    packet = {
                        "action": "incoming_message",
                        "from": msg["from"],
                        "envelope": msg["envelope"],
                    }

                    if target in self.online_clients:
                        await self.send_to(self.online_clients[target], packet)
                        log("INFO", f"Message {msg['from']} → {target} ({len(json.dumps(msg['envelope']))} bytes, live)")
                    else:
                        self.offline_queue.setdefault(target, []).append(packet)
                        log("INFO", f"Message {msg['from']} → {target} (queued)")

                    await self.send_to(writer, {"action": "message_sent", "target": target})

                else:
                    await self.send_to(writer, {
                        "action": "error",
                        "message": f"Unknown action: {action}"
                    })

        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            if user_id:
                self.online_clients.pop(user_id, None)
                log("CONN", f"{BOLD}{user_id}{RESET} disconnected")
            writer.close()

    # ── Start the server ──────────────────────────────────
    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )

        print(f"""
{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════╗
║          SECURE MESSENGER — RELAY SERVER                  ║
╚═══════════════════════════════════════════════════════════╝{RESET}

  Listening on {BOLD}{self.host}:{self.port}{RESET}
  {DIM}The server never sees plaintext — only encrypted blobs.{RESET}
  {DIM}Press Ctrl+C to stop.{RESET}
""")

        async with server:
            await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="Secure Messenger Relay Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9000, help="Port (default: 9000)")
    args = parser.parse_args()

    relay = SecureRelayServer(host=args.host, port=args.port)

    try:
        asyncio.run(relay.start())
    except KeyboardInterrupt:
        print(f"\n  {YELLOW}Server stopped.{RESET}\n")


if __name__ == "__main__":
    main()
