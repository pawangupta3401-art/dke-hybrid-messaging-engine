# Dynamic Key Evolution (DKE) Hybrid Messaging Engine

[![Tests](https://img.shields.io/badge/tests-64%20passed-brightgreen.svg)](tests/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](requirements.txt)
[![Cryptography](https://img.shields.io/badge/cryptography-AES--256--GCM%20%7C%20X25519-orange.svg)](crypto_core.py)

A secure, two-party peer-to-peer encrypted messaging engine featuring **Dynamic Key Evolution (DKE)** — an autonomous per-message ratcheting protocol that ensures forward secrecy and backward secrecy by evolving symmetric keys after every transmission.

---

## Key Features

- **X25519 Ephemeral Key Exchange:** Elliptic-curve Diffie-Hellman (ECDH) key agreement generates a fresh root secret ($K_0$) on each session connection.
- **Dynamic Key Evolution (DKE Ratchet):** Independent outbound and inbound key chains advance via one-way cryptographic hash operations (`SHA-256(current_key || nonce || sequence)`), destroying prior keys in memory.
- **AES-256-GCM Authenticated Encryption:** Industry-standard AEAD cipher provides confidentiality, integrity, and authenticity for every message payload.
- **Strict Wire Protocol:** Custom binary envelope format with fixed 30-byte header, length-prefixed payload framing, and 16-byte authentication tags to prevent replay and out-of-order injection.
- **Interactive CLI & Automated Demo:** Clean command-line interface adhering to the Frontend Specification with real-time status monitoring and tamper simulation.

---

## System Architecture

The engine is structured in strict modular layers:

```
+-------------------------------------------------------------+
| main_chat.py   - Interactive CLI, socket networking, REPL   |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| protocol.py    - Wire envelope codec, AES-256-GCM AEAD      |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| dke_engine.py  - Directional session states & key ratchets  |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| crypto_core.py - X25519 ECDH, HKDF-SHA256, primitives       |
+-------------------------------------------------------------+
```

---

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/pawangupta3401-art/dke-hybrid-messaging-engine.git
   cd dke-hybrid-messaging-engine
   ```

2. **Set up a virtual environment (optional but recommended):**
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux / macOS:
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

### Interactive CLI (`main_chat.py`)

Open two terminal sessions:

#### Terminal 1 — Listener (Alice):
```bash
python main_chat.py
>> start --listen 5050
```

#### Terminal 2 — Connector (Bob):
```bash
python main_chat.py
>> start --connect localhost:5050
```

#### Commands:
- `send <message>` — Encrypts with current outbound key, sends envelope, and evolves key.
- `status` — Displays active role, sequence counters, and current key fingerprints.
- `end` — Securely terminates session and wipes key material from memory.
- `help` — Shows available commands and syntax.

---

### Automated End-to-End Demo (`demo_e2e.py`)

To run an automated loopback demonstration showing session handshake, message exchange, key ratchet verification, and AEAD tamper rejection:

```bash
python demo_e2e.py
```

---

## Running Unit Tests

The test suite covers key agreement, ratchet non-reversibility, sequence integrity, tamper rejection, and malformed envelope parsing:

```bash
pytest tests/ -v
```

All **64 unit tests** should pass.

---

## License & Notice

See [NOTICE.md](NOTICE.md) for attribution, copyright notices, and security considerations.
