#!/usr/bin/env python3
"""
main_chat.py — CLI Orchestration Entry Point
=============================================
TAD Reference: Section 3.4, Section 6

Responsibility
--------------
Top-level CLI entry point.  Wires together the full session lifecycle:

  1. Interactive REPL with commands: start, send, status, end, help, quit.
  2. TCP socket transport (listener or connector).
  3. X25519 public-key exchange during handshake (TAD Section 6.1).
  4. Shared secret → HKDF → K0 → DKESessionState seeding.
  5. Steady-state bidirectional encrypted message loop (TAD Section 6.2).

Usage
-----
Run two terminals side-by-side:

  Terminal A (listener / Alice):
      python main_chat.py
      >> start --listen 9000

  Terminal B (connector / Bob):
      python main_chat.py
      >> start --connect 127.0.0.1:9000

Once connected, both sides can type:
      >> send Hello!
      >> status
      >> end

Session Establishment Sequence (TAD Section 6.1)
-------------------------------------------------
  Alice (listener)                        Bob (connector)
    generate_keypair()                      generate_keypair()
    send(a_pub)   ─────────────────────►  recv → peer_pub = a_pub
    recv → peer_pub = b_pub  ◄─────────  send(b_pub)
    shared = ECDH(a_priv, b_pub)           shared = ECDH(b_priv, a_pub)
    K0 = HKDF(shared, info=SESSION_INFO)   K0 = HKDF(shared, info=SESSION_INFO)
    [Both sides hold identical K0]

Transport Framing (envelope receive)
-------------------------------------
Envelopes are self-describing:
  1. Read exactly HEADER_SIZE (30) bytes.
  2. Parse ct_len from header bytes [26:30] (uint32 big-endian).
  3. Read exactly ct_len + TAG_SIZE (16) more bytes.
  4. Concatenate and pass to protocol.decode_envelope().

No extra length-prefix framing is required because the header already
encodes the ciphertext length.

Error Handling Philosophy (TAD Section 7.1)
--------------------------------------------
* Decryption / tag failures → message dropped, metadata logged, session
  continues.
* Sequence mismatch → message dropped, session continues.
* Peer disconnect → session state discarded; new 'start' required.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import textwrap
import threading
from typing import Optional

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

from cryptography.exceptions import InvalidTag

# ---------------------------------------------------------------------------
# Project modules
# ---------------------------------------------------------------------------
import crypto_core
import dke_engine
import protocol
from crypto_core import SESSION_INFO, PUBLIC_KEY_SIZE
from dke_engine import (
    DKESessionState,
    SequenceError,
    inbound_key,
    outbound_params,
    rotate_receive,
    rotate_send,
)
from protocol import (
    HEADER_SIZE,
    TAG_SIZE,
    ParseError,
    decode_envelope,
    encode_envelope,
    encrypt,
    decrypt,
)

# ---------------------------------------------------------------------------
# Version / Banner
# ---------------------------------------------------------------------------

_VERSION = "1.0"
_BANNER = (
    "DKE Messaging Engine v" + _VERSION + "\n"
    "End-to-end encrypted chat with Dynamic Key Evolution.\n"
    "Type 'help' for available commands."
)

_PROMPT = ">> "

# ---------------------------------------------------------------------------
# Global session state  (protected by _lock)
# ---------------------------------------------------------------------------

_lock: threading.Lock = threading.Lock()
_session_state: Optional[DKESessionState] = None
_session_sock: Optional[socket.socket] = None
_session_role: Optional[str] = None          # "alice" or "bob" — display only
_session_peer: str = ""                      # "host:port" for display
_session_active: threading.Event = threading.Event()
_recv_thread: Optional[threading.Thread] = None


# ===========================================================================
# Low-level transport helpers
# ===========================================================================


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes from ``sock``, blocking until available.

    Parameters
    ----------
    sock : socket.socket
        An open, connected TCP socket.
    n : int
        Number of bytes to read.

    Returns
    -------
    bytes
        Exactly ``n`` bytes.

    Raises
    ------
    ConnectionError
        If the connection closes before ``n`` bytes are received.

    TAD Reference: Section 2.2 — Transport (dumb pipe)
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Peer closed the connection.")
        buf.extend(chunk)
    return bytes(buf)


MAX_CIPHERTEXT_SIZE: int = 64 * 1024 * 1024  # 64 MB maximum ciphertext payload safety cap


def _recv_envelope(sock: socket.socket) -> bytes:
    """Read exactly one complete DKE envelope from the socket.

    Uses the envelope's own header to determine the total byte count —
    no external length-prefix framing needed.

    Steps:
      1. Read HEADER_SIZE (30) bytes.
      2. Parse ``ct_len`` from bytes [26:30] (uint32 big-endian).
      3. Read ``ct_len + TAG_SIZE`` more bytes.

    Returns
    -------
    bytes
        Complete raw envelope ready for ``protocol.decode_envelope()``.

    Raises
    ------
    ConnectionError
        If the connection closes mid-read.
    ParseError
        If ``ct_len`` exceeds the maximum safe payload limit.

    TAD Reference: Section 4.1 — Envelope Structure
    """
    header_bytes = _recv_exactly(sock, HEADER_SIZE)
    (ct_len,) = struct.unpack_from("!I", header_bytes, offset=26)
    if ct_len > MAX_CIPHERTEXT_SIZE:
        raise ParseError(
            f"Declared ciphertext length {ct_len} exceeds maximum safety limit "
            f"({MAX_CIPHERTEXT_SIZE} bytes)."
        )
    rest = _recv_exactly(sock, ct_len + TAG_SIZE)
    return header_bytes + rest


def _send_envelope(sock: socket.socket, envelope: bytes) -> None:
    """Send a complete envelope over the socket.

    Uses ``sendall()`` to guarantee the full byte sequence is written.

    Raises
    ------
    OSError
        If the send fails (connection broken).

    TAD Reference: Section 2.2 — Transport (dumb pipe)
    """
    sock.sendall(envelope)


# ===========================================================================
# Handshake
# ===========================================================================


def _handshake_listener(port: int) -> tuple[socket.socket, DKESessionState, str]:
    """Listen for one incoming connection and perform the DKE handshake.

    Role: **Alice** (listener).

    Handshake order:
      1. Bind and listen on ``port``.
      2. Accept the first incoming connection (one-shot server).
      3. Generate X25519 keypair.
      4. Send local public key (32 bytes) to peer.
      5. Receive peer's public key (32 bytes).
      6. ECDH → HKDF → K0 → DKESessionState.

    Parameters
    ----------
    port : int
        TCP port to listen on (0–65535).

    Returns
    -------
    tuple[socket.socket, DKESessionState, str]
        ``(conn, session_state, peer_addr_string)``

    Raises
    ------
    OSError
        If the socket cannot be bound.

    TAD Reference: Section 6.1 — Session Establishment
               Section 4.3 — Public Key Exchange Format
    """
    try:
        server_sock = socket.create_server(("", port), family=socket.AF_INET6, dualstack_ipv6=True)
    except Exception:
        server_sock = socket.create_server(("", port))

    print(f"[*] Listening on port {port} — waiting for peer...", flush=True)
    conn, addr = server_sock.accept()
    server_sock.close()          # one-shot: reject further connections

    peer_str = f"{addr[0]}:{addr[1]}"
    print(f"[*] Peer connected from {peer_str}", flush=True)

    try:
        # ── Key exchange ───────────────────────────────────────────────────
        priv, pub = crypto_core.generate_keypair()
        conn.sendall(pub)                            # Alice sends first
        peer_pub = _recv_exactly(conn, PUBLIC_KEY_SIZE)

        # ── Key derivation ─────────────────────────────────────────────────
        shared = crypto_core.derive_shared_secret(priv, peer_pub)
        k0 = crypto_core.hkdf_derive(shared, info=SESSION_INFO)
        state = DKESessionState.from_k0(k0)
    except Exception as exc:
        conn.close()
        raise ConnectionError(f"Key exchange failed with peer {peer_str}: {exc}") from exc

    return conn, state, peer_str


def _handshake_connector(host: str, port: int) -> tuple[socket.socket, DKESessionState, str]:
    """Connect to a listening peer and perform the DKE handshake.

    Role: **Bob** (connector).

    Handshake order:
      1. Connect to ``host:port``.
      2. Generate X25519 keypair.
      3. Receive peer's public key (32 bytes).   ← Alice sends first
      4. Send local public key (32 bytes) to peer.
      5. ECDH → HKDF → K0 → DKESessionState.

    Parameters
    ----------
    host : str
        Hostname or IP address to connect to.
    port : int
        TCP port to connect to.

    Returns
    -------
    tuple[socket.socket, DKESessionState, str]
        ``(conn, session_state, peer_addr_string)``

    Raises
    ------
    OSError
        If the connection is refused.

    TAD Reference: Section 6.1 — Session Establishment
               Section 4.3 — Public Key Exchange Format
    """
    target_host = "127.0.0.1" if host.lower() in ("localhost", "127.0.0.1") else host
    peer_str = f"{host}:{port}"
    print(f"[*] Connecting to {peer_str}...", flush=True)
    conn = socket.create_connection((target_host, port), timeout=10)
    conn.settimeout(None)
    print(f"[*] Connected.", flush=True)

    try:
        # ── Key exchange ───────────────────────────────────────────────────
        priv, pub = crypto_core.generate_keypair()
        peer_pub = _recv_exactly(conn, PUBLIC_KEY_SIZE)  # Bob reads first
        conn.sendall(pub)

        # ── Key derivation ─────────────────────────────────────────────────
        shared = crypto_core.derive_shared_secret(priv, peer_pub)
        k0 = crypto_core.hkdf_derive(shared, info=SESSION_INFO)
        state = DKESessionState.from_k0(k0)
    except Exception as exc:
        conn.close()
        raise ConnectionError(f"Key exchange failed with peer {peer_str}: {exc}") from exc

    return conn, state, peer_str


# ===========================================================================
# Receive thread
# ===========================================================================


def _receive_loop() -> None:
    """Background daemon thread: read and display inbound encrypted messages.

    Runs until the peer disconnects or the session is ended locally.
    On each iteration:

    1. Read one complete envelope from the socket.
    2. Decode (parse + validate wire format).
    3. Validate sequence number (reject replays / reorders).
    4. Decrypt and authenticate (AES-256-GCM).
    5. Display plaintext.
    6. Rotate key + increment inbound seq counter.

    All errors are logged with metadata only — no plaintext is ever
    written to the log on failure (TAD Section 7.1).

    TAD Reference: Section 6.2 — Steady-State Receive
               Section 6.3 — Decryption Failure Path
               Section 7   — Failure Modes & Error Handling
    """
    global _session_state, _session_sock, _session_role

    while _session_active.is_set():
        try:
            raw = _recv_envelope(_session_sock)
        except ConnectionError:
            if _session_active.is_set():
                print(
                    f"\n[!] Peer disconnected. Session ended.\n{_PROMPT}",
                    end="",
                    flush=True,
                )
                _session_active.clear()
            return
        except OSError:
            return
        except ParseError as exc:
            print(
                f"\n[!] Malformed envelope dropped: {exc}\n{_PROMPT}",
                end="",
                flush=True,
            )
            continue

        try:
            seq, nonce, ct, tag = decode_envelope(raw)
        except ParseError as exc:
            # Structural error — drop message, log metadata only, continue
            print(
                f"\n[!] Malformed envelope dropped (seq unknown): {exc}\n{_PROMPT}",
                end="",
                flush=True,
            )
            continue

        try:
            with _lock:
                if _session_state is None or not _session_active.is_set():
                    return
                key = inbound_key(_session_state, seq)
                plaintext = decrypt(key, ct, nonce, tag)   # raises on failure
                rotate_receive(_session_state, nonce, seq)
        except SequenceError as exc:
            print(
                f"\n[!] Sequence error — message dropped (seq {seq}): {exc}\n{_PROMPT}",
                end="",
                flush=True,
            )
            continue
        except InvalidTag:
            # Authentication failed — fail closed, never display partial data
            print(
                f"\n[!] Authentication failed — message dropped (seq {seq}). "
                f"Possible tampering.\n{_PROMPT}",
                end="",
                flush=True,
            )
            continue
        except ValueError as exc:
            # Protocol violation (e.g. nonce reuse) — drop message, continue
            print(
                f"\n[!] Protocol violation — message dropped (seq {seq}): {exc}\n{_PROMPT}",
                end="",
                flush=True,
            )
            continue

        text = plaintext.decode("utf-8", errors="replace")
        print(f"\n[peer, seq {seq}] {text}\n{_PROMPT}", end="", flush=True)


# ===========================================================================
# Command handlers
# ===========================================================================


def _cmd_start(args: list[str]) -> None:
    """Handle ``start --listen <port>`` and ``start --connect <host:port>``.

    Establishes a TCP connection, performs the DKE handshake, seeds the
    session state, and starts the background receive thread.

    TAD Reference: Section 3.4 — Startup Sequence
               Section 6.1 — Session Establishment
    """
    global _session_state, _session_sock, _session_role, _session_peer
    global _recv_thread

    if _session_active.is_set():
        print("[!] A session is already active. Use 'end' first.")
        return

    if len(args) < 2:
        print("[!] Usage: start --listen <port>  |  start --connect <host:port>")
        return

    mode = args[0].lower()

    try:
        # ── Listener (Alice) ────────────────────────────────────────────
        if mode == "--listen":
            try:
                port = int(args[1])
            except ValueError:
                print(f"[!] Invalid port: {args[1]!r}")
                return
            conn, state, peer_str = _handshake_listener(port)
            role = "alice"

        # ── Connector (Bob) ─────────────────────────────────────────────
        elif mode == "--connect":
            raw_addr = args[1]
            if ":" not in raw_addr:
                print(f"[!] Expected <host:port>, got: {raw_addr!r}")
                return
            host, port_str = raw_addr.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                print(f"[!] Invalid port: {port_str!r}")
                return
            conn, state, peer_str = _handshake_connector(host, port)
            role = "bob"

        else:
            print(f"[!] Unknown flag {mode!r}. Use --listen or --connect.")
            return

    except ConnectionRefusedError:
        print(f"[!] Connection refused. Is the listener running?")
        return
    except TimeoutError:
        print(f"[!] Connection timed out connecting to peer.")
        return
    except socket.gaierror as exc:
        print(f"[!] Hostname resolution failed: {exc}")
        return
    except ConnectionError as exc:
        print(f"[!] {exc}")
        return
    except OSError as exc:
        print(f"[!] Network error: {exc}")
        return
    except Exception as exc:
        print(f"[!] Failed to establish session: {exc}")
        return

    # ── Store session globals ────────────────────────────────────────────
    with _lock:
        _session_state = state
        _session_sock  = conn
        _session_role  = role
        _session_peer  = peer_str

    _session_active.set()

    # ── Start background receive thread ──────────────────────────────────
    _recv_thread = threading.Thread(target=_receive_loop, daemon=True, name="dke-recv")
    _recv_thread.start()

    role_label = "listener" if role == "alice" else "connector"
    k0_hex = bytes(_session_state.outbound.current_key).hex()[:16]
    print(
        f"[*] Session established — role: {role_label}, peer: {peer_str}\n"
        f"[*] K0: {k0_hex}... (first 8 bytes shown)\n"
        f"[*] Type 'send <message>' to chat, 'status' to inspect, 'end' to close.",
        flush=True,
    )


def _cmd_send(parts: list[str]) -> None:
    """Encrypt and send a plaintext message to the peer.

    Steps (TAD Section 6.2 — Steady-State Send):
      1. Snapshot current key and outbound seq from session state.
      2. Generate fresh 12-byte nonce via os.urandom(12).
      3. Encrypt plaintext with AES-256-GCM.
      4. Encode into a DKE binary envelope.
      5. Send over TCP socket.
      6. Rotate key and increment outbound seq counter.

    TAD Reference: Section 3.4 — Steady-State Loop
               Section 6.2 — Steady-State Send
    """
    if not _session_active.is_set():
        print("[!] No active session. Use 'start' first.")
        return
    if not parts:
        print("[!] Usage: send <message>")
        return

    plaintext_str = " ".join(parts)
    plaintext = plaintext_str.encode("utf-8")
    nonce = os.urandom(12)

    try:
        with _lock:
            key, seq = outbound_params(_session_state)
            ct, tag = encrypt(key, plaintext, nonce)
            envelope = encode_envelope(seq, nonce, ct, tag)
            _send_envelope(_session_sock, envelope)
            rotate_send(_session_state, nonce)
    except OSError as exc:
        print(f"[!] Send failed: {exc}")
        _session_active.clear()
        return

    print(f"[you, seq {seq}] {plaintext_str}")


def _cmd_status() -> None:
    """Display current session state and ratchet counters.

    TAD Reference: Section 3.4 — status command
    """
    if not _session_active.is_set():
        print("[!] No active session.")
        return

    with _lock:
        role   = _session_role
        state  = _session_state
        peer   = _session_peer
        out_key_hex = bytes(state.outbound.current_key).hex()[:16]
        in_key_hex  = bytes(state.inbound.current_key).hex()[:16]
        out_seq = state.outbound.sequence_number
        in_seq  = state.inbound.sequence_number

    role_label = "listener" if role == "alice" else "connector"

    print(
        f"session  : ACTIVE\n"
        f"role     : {role_label}\n"
        f"peer     : {peer}\n"
        f"out-key  : {out_key_hex}... (first 8 bytes)\n"
        f"in-key   : {in_key_hex}... (first 8 bytes)\n"
        f"out-seq  : {out_seq}\n"
        f"in-seq   : {in_seq}"
    )


def _cmd_end() -> None:
    """Gracefully close the session and discard all session state.

    Session state (keys, counters) is discarded entirely.
    A new session requires a fresh key exchange.

    TAD Reference: Section 7 — Failure Modes (Peer disconnects)
    """
    global _session_state, _session_sock, _session_role, _session_peer

    if not _session_active.is_set():
        print("[!] No active session to end.")
        return

    _session_active.clear()

    with _lock:
        if _session_sock:
            try:
                _session_sock.shutdown(socket.SHUT_RDWR)
                _session_sock.close()
            except OSError:
                pass
        if _session_state is not None:
            _session_state.wipe()   # Best-effort zeroization of remaining key material
        _session_state = None
        _session_sock  = None
        _session_role  = None
        _session_peer  = ""

    print("[*] Session ended. Key material discarded.")


def _cmd_help() -> None:
    """Print the list of available commands."""
    print(textwrap.dedent("""
      Commands
      --------
      start --listen <port>        Wait for a peer to connect (you are the listener)
      start --connect <host:port>  Connect to a listening peer
      send <message>               Encrypt and send a message
      status                       Show session state and ratchet counters
      end                          Close session and discard all key material
      help                         Show this help text
      quit                         Exit the program

      Message display
      ---------------
      [you, seq N] <text>          Message you sent, at sequence N
      [peer, seq N] <text>         Message received from peer, at sequence N
      [!] <text>                   Error or warning
      [*] <text>                   Status / info
    """).rstrip())


# ===========================================================================
# Main REPL
# ===========================================================================


def main() -> None:
    """Interactive REPL entry point.

    Prints the banner then loops reading user input.  If command-line
    arguments are provided (e.g. 'start --listen 5050' or
    'start --connect localhost:5050'), executes the command initially
    before continuing into the interactive REPL.

    TAD Reference: Section 3.4 — main_chat.py overview
    """
    print(_BANNER)
    print("")

    # Parse initial command-line arguments if provided
    # e.g.: python main_chat.py start --listen 5050
    #       python main_chat.py start --connect localhost:5050
    #       python main_chat.py --listen 5050
    if len(sys.argv) > 1:
        first = sys.argv[1].lower()
        if first == "start":
            _cmd_start(sys.argv[2:])
        elif first in ("--listen", "-l", "--connect", "-c"):
            _cmd_start(sys.argv[1:])
        elif first in ("help", "--help", "-h"):
            _cmd_help()
            sys.exit(0)
        elif first == "status":
            _cmd_status()
        elif first in ("quit", "exit", "q"):
            sys.exit(0)
        else:
            print(f"[!] Unknown command-line argument: '{first}'. Type 'help' for available commands.")

    while True:
        try:
            line = input(_PROMPT).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            _cmd_end()
            print("[*] Goodbye.")
            sys.exit(0)

        if not line:
            continue

        tokens = line.split()
        cmd    = tokens[0].lower()
        args   = tokens[1:]

        if cmd == "start":
            _cmd_start(args)
        elif cmd == "send":
            _cmd_send(args)
        elif cmd == "status":
            _cmd_status()
        elif cmd == "end":
            _cmd_end()
        elif cmd in ("help", "?"):
            _cmd_help()
        elif cmd in ("quit", "exit", "q"):
            _cmd_end()
            print("  Goodbye.")
            sys.exit(0)
        else:
            print(f"[!] Unknown command: '{cmd}'. Type 'help' for available commands.")


if __name__ == "__main__":
    main()
