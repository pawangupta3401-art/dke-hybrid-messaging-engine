# Frontend Specification Document
## Dynamic Key Evolution (DKE) Hybrid Messaging Engine
### Command-line interface specification (main_chat.py)

---

## 1. Scope
The "frontend" for this project is a command-line interface (CLI), not a graphical application. This document specifies the CLI's commands, screens (terminal states), input/output formats, and error messaging so the interface itself is a documented, original piece of work. A note on a possible future GUI is included in Section 7.

---

## 2. Users
- **Party A and Party B** — two independent local users, each running their own instance of the CLI, with no concept of "accounts" or persistent identity across sessions.

---

## 3. Application States

| State | Description |
|---|---|
| **Idle / Startup** | CLI has launched, waiting for the user to start or join a session |
| **Key Exchange** | Public keys are being generated and exchanged with the peer |
| **Session Active** | Shared key established; user can send and receive messages |
| **Error** | A recoverable problem occurred (e.g. bad input, failed decryption of one message) |
| **Session Ended** | Session was closed by either party; all session key material is discarded |

---

## 4. CLI Commands

| Command | Arguments | Effect |
|---|---|---|
| `start --listen <port>` | port | Starts as the session initiator, waiting for a peer to connect |
| `start --connect <host:port>` | host, port | Starts as the joining party, connecting to a waiting peer |
| `send <message>` | message text | Encrypts and sends a message in an active session |
| `status` | — | Shows current session state and message counters (sent/received), no key material |
| `end` | — | Ends the session and discards all key material |
| `help` | — | Lists available commands |

---

## 5. Screen / Output Specifications

### 5.1 Session Establishment
```text
> start --listen 5050
[*] Waiting for peer to connect on port 5050 ...
[*] Peer connected. Exchanging public keys ...
[+] Secure session established. Type your message and press Enter.
```

### 5.2 Sending a Message
```text
> send Hello Bob, this is a secure test message.
[you, seq 1] Hello Bob, this is a secure test message.
```

### 5.3 Receiving a Message
```text
[peer, seq 1] Hi Alice, got it securely!
```

### 5.4 Status Command
```text
> status
Session: ACTIVE
Messages sent: 3   Messages received: 2
Current sequence (out): 4   Current sequence (in): 3
```

---

## 6. Error & Edge-Case Messages

| Condition | User-Facing Message |
|---|---|
| **Peer's message failed authentication** | `[!] A message failed integrity verification and was discarded.` |
| **Out-of-order sequence number received** | `[!] Unexpected message order detected; message discarded. Session remains active.` |
| **Peer disconnected unexpectedly** | `[!] Peer connection lost. Session ended; start a new session to continue.` |
| **Invalid command** | `[!] Unknown command. Type 'help' to see available commands.` |
| **Attempt to send before session is active** | `[!] No active session. Use 'start --listen' or 'start --connect' first.` |

---

## 7. Non-Functional / UX Notes
- **No plaintext key material** is ever printed to the terminal or included in any on-screen message.
- **Centralized User-Facing Strings:** All user-facing strings are centralized in one module so wording is consistent and easy to audit for accidental key/plaintext leakage into logs.
- **Graceful Terminal Degradation:** Terminal output should degrade gracefully on terminals without color support (no reliance on color alone to convey meaning, e.g. errors are prefixed with `"[!]"` not just shown in red).
- **Future GUI (out of scope for this version):** If a graphical frontend is built later, it should reuse `crypto_core`/`dke_engine`/`protocol` unchanged and only replace `main_chat.py`'s presentation layer, keeping the security-relevant code untouched and already covered by this project's existing tests.
