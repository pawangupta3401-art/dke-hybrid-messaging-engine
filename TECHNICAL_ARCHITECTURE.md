# Technical Architecture Document
## Dynamic Key Evolution (DKE) Hybrid Messaging Engine

> **Document Type:** Technical Architecture Document (TAD)  
> **Companion To:** Product Requirements Document (PRD)  
> **Version:** 1.0  
> **Status:** Draft  

---

## Table of Contents

1. [Purpose & Scope](#1-purpose--scope)
2. [System Context](#2-system-context)
3. [Component Architecture](#3-component-architecture)
4. [Data Structures & Wire Format](#4-data-structures--wire-format)
5. [Cryptographic Design](#5-cryptographic-design)
6. [Data Flow & Sequence Diagrams](#6-data-flow--sequence-diagrams)
7. [Failure Modes & Error Handling](#7-failure-modes--error-handling)
8. [Scalability & Extensibility](#8-scalability--extensibility)
9. [Technology Stack](#9-technology-stack)
10. [Dependencies](#10-dependencies)
11. [Security Threat Model](#11-security-threat-model)
12. [Module Responsibility Matrix](#12-module-responsibility-matrix)

---

## 1. Purpose & Scope

This document describes the technical design of the DKE Messaging Engine at the **implementation level**: components, data structures, technology choices, runtime behaviour, and failure handling.

It assumes the reader has read the PRD for product-level goals and the originality / attribution statement.

**What this document covers:**
- Internal module decomposition and API contracts
- Cryptographic state machine and key-evolution logic
- Wire-format encoding and decoding rules
- Session lifecycle from establishment through teardown
- Failure taxonomy and recovery behaviour
- Extensibility boundaries and known limitations

**What this document does NOT cover:**
- UI/UX specification (see Frontend Specification Document)
- MITM / public-key authentication (see Security & Access Document)
- Group messaging (explicitly out of scope for v1)

---

## 2. System Context

The system is a **two-party, session-based encrypted messaging demo**. There is no central server holding key material. The two parties — Alice and Bob — each run their own local client instance, exchange public keys directly or through a simple relay, and independently derive identical key material.

### 2.1 Actors

| Actor / System | Role |
|---|---|
| **Party A (Alice)** | Initiates or joins a session; runs the client locally |
| **Party B (Bob)** | Joins or initiates a session; runs the client locally |
| **Transport (relay / socket)** | Forwards opaque message envelopes only; never sees keys or plaintext |

### 2.2 Trust Boundaries

```
+---------------------------------------------------------------------+
|                        ALICE'S PROCESS                              |
|  +--------------+   +--------------+   +-----------------------+   |
|  | crypto_core  |-->|  dke_engine  |-->|  protocol / main_chat |   |
|  +--------------+   +--------------+   +----------+------------+   |
+-----------------------------------------------------|---------------+
                                                      | encrypted envelope only
                          +---------------------------v--------------+
                          |        TRANSPORT / RELAY (dumb pipe)     |
                          |    Opaque bytes only - zero key access   |
                          +---------------------------+--------------+
                                                      |
+-----------------------------------------------------|---------------+
|                        BOB'S PROCESS                |               |
|  +--------------+   +--------------+   +-----------v-----------+   |
|  | crypto_core  |-->|  dke_engine  |-->|  protocol / main_chat |   |
|  +--------------+   +--------------+   +-----------------------+   |
+---------------------------------------------------------------------+
```

> **Key invariant:** The relay never touches key material, nonces, or plaintext. Its only job is byte forwarding.

---

## 3. Component Architecture

The engine is composed of five Python modules with strict dependency ordering: each layer depends only on layers below it.

```
main_chat.py          <- CLI / orchestration layer (top)
    |
protocol.py           <- Envelope encoding, AEAD wrappers
    |
dke_engine.py         <- Key evolution state machine
    |
crypto_core.py        <- Primitive wrappers (X25519, HKDF, AES-GCM)
    |
cryptography (pyca)   <- Audited library -- never hand-rolled (bottom)
```

---

### 3.1 `crypto_core.py` — Cryptographic Primitive Wrappers

**Responsibility:** Thin, audited-library-backed wrappers around all raw cryptographic primitives. No key material is written to disk by this module.

#### Public API

| Function | Signature | Description |
|---|---|---|
| `generate_keypair` | `() -> (private_key, public_key)` | Generates an X25519 key pair using `cryptography.hazmat.primitives.asymmetric.x25519` |
| `derive_shared_secret` | `(private_key, peer_public_key) -> bytes[32]` | Performs X25519 ECDH; returns raw 32-byte shared secret |
| `hkdf_derive` | `(shared_secret, info, length=32) -> bytes` | HKDF-SHA-256 key derivation; produces initial symmetric key **K0** |

#### Design Constraints

- **No hand-rolled ECC.** `generate_keypair()` and `derive_shared_secret()` delegate entirely to `cryptography.hazmat.primitives.asymmetric.x25519`.
- **No hand-rolled HKDF.** Uses `cryptography.hazmat.primitives.kdf.hkdf.HKDF`.
- **No disk writes.** All key material lives in process memory only.
- `info` parameter in `hkdf_derive()` must be a fixed, context-specific ASCII string (e.g., `"dke-session-init-v1"`) to domain-separate different key usages.

---

### 3.2 `dke_engine.py` — Dynamic Key Evolution State Machine

**Responsibility:** Maintains per-session ratchet state. Advances the symmetric key after every successful send or receive, providing **forward secrecy** within a session.

#### Session State

```python
@dataclass
class DKESessionState:
    current_key: bytes          # 32-byte AES-256 key (current)
    sequence_alice_to_bob: int  # Monotonic; Alice's send counter
    sequence_bob_to_alice: int  # Monotonic; Bob's send counter
    last_nonce: bytes           # Last nonce used (for audit/logging only)
```

#### Public API

| Function | Signature | Description |
|---|---|---|
| `advance_key` | `(current_key, nonce, sequence) -> next_key` | Computes `Hash(current_key || nonce || sequence)` using SHA-256 |

#### Key Evolution Formula

```
K_(i+1) = SHA-256( K_i  ||  nonce_i  ||  seq_i )
```

Where `||` denotes concatenation and `seq_i` is encoded as a fixed-width big-endian integer.

#### Ratchet Lifecycle

```
Session Init
     |
     v
  K0 (from hkdf_derive)
     |
     |-- Message 1 sent/received
     v
  K1 = SHA-256(K0 || nonce0 || 0)    <- K0 memory overwritten
     |
     |-- Message 2 sent/received
     v
  K2 = SHA-256(K1 || nonce1 || 1)    <- K1 memory overwritten
     |
    ...
```

#### Memory Safety Rule

After `advance_key()` produces `K_(i+1)`, the engine **overwrites** the memory location of `K_i` with zeros before releasing the reference. This prevents key material from lingering in the heap.

#### Sequence Number Tracking

- Alice->Bob and Bob->Alice sequence numbers are tracked **independently**.
- Sequence numbers are **strictly monotonic** — no gaps, no reuse.
- This prevents nonce and key reuse, which would be catastrophic for AES-GCM security.

---

### 3.3 `protocol.py` — Envelope Encoding & AEAD Wrappers

**Responsibility:** Serialises and deserialises message envelopes; wraps AES-256-GCM encryption/decryption. Does **not** implement AES or GCM.

#### Public API

| Function | Signature | Description |
|---|---|---|
| `encode_envelope` | `(header, sequence, nonce, ciphertext, tag) -> bytes` | Packs fields into wire format per Section 4 |
| `decode_envelope` | `(bytes) -> (header, sequence, nonce, ciphertext, tag)` | Strict length checks before parsing; raises on malformed input |
| `encrypt` | `(key, plaintext, nonce) -> (ciphertext, tag)` | Wraps `cryptography.hazmat.primitives.ciphers.aead.AESGCM` |
| `decrypt` | `(key, ciphertext, nonce, tag) -> plaintext` | Raises `InvalidTag` on authentication failure; never returns garbage |

#### AEAD Contract

- `encrypt()` uses AES-256-GCM from `cryptography.hazmat.primitives.ciphers.aead`.
- AES-GCM is **not** re-implemented. The `cryptography` library's implementation is used as-is.
- `decrypt()` raises an exception on tag mismatch — it **never** returns plaintext on failure. Callers must handle the exception explicitly.

---

### 3.4 `main_chat.py` — CLI Orchestration Entry Point

**Responsibility:** Top-level CLI entry point. Wires together the session lifecycle and the send/receive loop.

#### Startup Sequence

1. Parse CLI arguments (`--role alice|bob`, `--host`, `--port`).
2. Call `crypto_core.generate_keypair()` for local key pair.
3. Exchange public keys with peer via transport (see Section 6.1).
4. Call `crypto_core.derive_shared_secret()` -> `crypto_core.hkdf_derive()` -> seed `dke_engine`.
5. Enter the **steady-state message loop**.

#### Steady-State Loop

```
while session_active:
    +-- local input available? ------------------------------------------+
    |   nonce = os.urandom(12)                                            |
    |   ct, tag = protocol.encrypt(K_i, plaintext, nonce)                |
    |   envelope = protocol.encode_envelope(header, seq, nonce, ct, tag) |
    |   transport.send(envelope)                                          |
    |   K_(i+1) = dke_engine.advance_key(K_i, nonce, seq); erase K_i    |
    +---------------------------------------------------------------------+
    +-- remote envelope available? ---------------------------------------+
    |   header, seq, nonce, ct, tag = protocol.decode_envelope(raw)      |
    |   plaintext = protocol.decrypt(K_i, ct, nonce, tag)  # raises      |
    |   display(plaintext)                                                |
    |   K_(i+1) = dke_engine.advance_key(K_i, nonce, seq); erase K_i    |
    +---------------------------------------------------------------------+
```

> See the **Frontend Specification Document** for exact CLI command and message formats.

---

### 3.5 `test_dke.py` — Test Suite

**Responsibility:** Automated correctness and security regression tests using `pytest`.

| Test Case | What It Verifies |
|---|---|
| **ECDH symmetry** | Alice's `derive_shared_secret(a_priv, b_pub)` == Bob's `derive_shared_secret(b_priv, a_pub)` |
| **Key rotation non-reversibility** | `K_(i+1) != K_i`; no mechanism to recover `K_i` from `K_(i+1)` |
| **Tampered ciphertext** | Flipping any bit in ciphertext causes `decrypt()` to raise, not return garbage |
| **Tampered tag** | Providing a wrong authentication tag causes `decrypt()` to raise |
| **Sequence monotonicity** | Out-of-order sequence numbers are rejected |
| **Replay rejection** | A previously-seen `(sequence, nonce)` pair is rejected |

---

## 4. Data Structures & Wire Format

### 4.1 Envelope Structure (Binary Wire Format)

All multi-byte integer fields are **big-endian**.

```
 Byte offset  Field                Size
 -----------  -------------------  ----
 0            Magic (DKE1)         4 bytes
 4            Version              1 byte
 5            Flags                1 byte
 6            Sequence Number      8 bytes  (uint64, big-endian)
 14           Nonce                12 bytes (AES-GCM nonce)
 26           Ciphertext Length    4 bytes  (uint32, big-endian)
 30           Ciphertext           variable
 30+N         Authentication Tag   16 bytes (AES-GCM 128-bit tag)
```

| Field | Size | Notes |
|---|---|---|
| Magic | 4 bytes | Fixed: `0x444B4531` (`DKE1`) — protocol identification |
| Version | 1 byte | Currently `0x01` |
| Flags | 1 byte | Reserved; must be `0x00` in v1 |
| Sequence Number | 8 bytes | `uint64`, big-endian; strictly monotonic per direction |
| Nonce | 12 bytes | Random per message; generated via `os.urandom(12)` |
| Ciphertext Length | 4 bytes | `uint32`, big-endian; max `2^32 - 1` bytes |
| Ciphertext | Variable | AES-256-GCM ciphertext |
| Authentication Tag | 16 bytes | AES-256-GCM 128-bit tag |

### 4.2 Minimum Envelope Size

```
4 (magic) + 1 (version) + 1 (flags) + 8 (seq) + 12 (nonce) + 4 (ct_len) + 0 (ct) + 16 (tag)
= 46 bytes minimum
```

`decode_envelope()` rejects any input shorter than 46 bytes immediately.

### 4.3 Public Key Exchange Format (Session Establishment)

During the handshake phase, raw 32-byte X25519 public keys are transmitted directly over the transport. No envelope framing is applied at this stage.

```
[32 bytes: X25519 public key]
```

---

## 5. Cryptographic Design

### 5.1 Key Hierarchy

```
os.urandom() --> X25519 keypair generation
                    |
                    |  ECDH(a_priv, b_pub) = ECDH(b_priv, a_pub)
                    v
              Shared Secret (32 bytes raw)
                    |
                    |  HKDF-SHA256(secret, salt=None, info="dke-session-init-v1")
                    v
                  K0 -- Initial Symmetric Key (32 bytes / AES-256)
                    |
                    |  SHA-256(K0 || nonce0 || seq0)
                    v
                  K1 -- Second Symmetric Key
                    |
                   ...
                    |  SHA-256(Ki || noncei || seqi)
                    v
                 K(i+1) -- Evolved Key
```

### 5.2 Security Properties

| Property | Mechanism | Guarantee |
|---|---|---|
| **Confidentiality** | AES-256-GCM | 256-bit key; computationally infeasible to decrypt without key |
| **Integrity & Authenticity** | AES-GCM 128-bit tag | Any ciphertext modification detected; decryption raises |
| **Forward Secrecy (within session)** | DKE ratchet + memory overwrite | Compromise of `Ki` does not expose messages encrypted under `K0...K(i-1)` |
| **Replay Prevention** | Strict monotonic sequence numbers | Receiver rejects any `seq <= last_seen_seq` |
| **Nonce Uniqueness** | `os.urandom(12)` per message | Probability of nonce collision negligible (birthday bound: ~2^48 messages) |
| **Key Non-reversibility** | SHA-256 one-wayness | `Ki` cannot be recovered from `K(i+1)` |

### 5.3 What This Project Does NOT Implement

> [!IMPORTANT]
> The following primitives are deliberately **not** re-implemented. The `cryptography` (pyca) library provides audited, tested implementations:
> - X25519 elliptic curve arithmetic
> - HKDF-SHA-256
> - AES-256-GCM encryption and decryption
>
> Writing original protocol logic, state machine, message format, and orchestration code — while relying on audited primitives — is both the safer engineering practice and the correct basis for copyright attribution.

### 5.4 Algorithm Choices Rationale

| Algorithm | Why Chosen |
|---|---|
| **X25519** | Constant-time, high-performance ECDH; immune to curve parameter manipulation; widely deployed (TLS 1.3, Signal) |
| **HKDF-SHA-256** | Standardised (RFC 5869); domain-separable via `info` parameter; stretches raw ECDH output safely |
| **AES-256-GCM** | Combined AEAD; 256-bit security margin; hardware acceleration on modern CPUs; single-pass encrypt+authenticate |
| **SHA-256 (ratchet)** | One-way; fast; sufficient collision resistance for key derivation within a chain |

---

## 6. Data Flow & Sequence Diagrams

### 6.1 Session Establishment

```
      Alice                                    Bob
        |                                       |
        |  generate_keypair() -> (a_priv, a_pub)|
        |                                       |  generate_keypair() -> (b_priv, b_pub)
        |                                       |
        |---------- a_pub (32 bytes) ---------->|
        |<--------- b_pub (32 bytes) -----------|
        |                                       |
        |  shared = derive_shared_secret        |  shared = derive_shared_secret
        |            (a_priv, b_pub)            |            (b_priv, a_pub)
        |                                       |
        |  K0 = hkdf_derive(shared,             |  K0 = hkdf_derive(shared,
        |    info="dke-session-init-v1")        |    info="dke-session-init-v1")
        |                                       |
        |  [Both sides now hold identical K0]   |
        |  [Session is ready for messaging]     |
```

> **Note:** The relay forwards raw 32-byte public keys without modification. It cannot derive the shared secret because it never holds a private key.

### 6.2 Steady-State Message Send (Alice -> Bob)

```
      Alice                    Transport                    Bob
        |                          |                         |
        |  nonce = os.urandom(12)  |                         |
        |  ct,tag = encrypt(Ki,    |                         |
        |    plaintext, nonce)     |                         |
        |  envelope =              |                         |
        |   encode_envelope(       |                         |
        |    header, seqi,         |                         |
        |    nonce, ct, tag)       |                         |
        |                          |                         |
        |---- envelope (bytes) --->|---- envelope (bytes) -->|
        |                          |                         |
        |                          |   decode_envelope()     |
        |                          |   decrypt(Ki,ct,        |
        |                          |     nonce,tag)          |
        |                          |   display(plaintext)    |
        |                          |                         |
        |  K_(i+1)=advance_key     |   K_(i+1)=advance_key( |
        |   (Ki,nonce,seqi)        |    Ki,nonce,seqi)       |
        |  erase Ki                |   erase Ki              |
```

### 6.3 Decryption Failure Path

```
      Alice                    Transport                    Bob
        |                          |                         |
        |                          |  [bit-flipped env] ---->|
        |                          |                         |
        |                          |   decode_envelope()     |
        |                          |   decrypt() --> RAISES  |
        |                          |   InvalidTag            |
        |                          |                         |
        |                          |   log "rejected msg"    |
        |                          |   (metadata only,       |
        |                          |    no plaintext)        |
        |                          |                         |
        |                          |   session continues     |
        |                          |   Ki unchanged          |
```

---

## 7. Failure Modes & Error Handling

| Failure | Detection Point | Handling | Session Impact |
|---|---|---|---|
| **Malformed envelope** (wrong magic, bad length, truncated) | `decode_envelope()` | Raises `ParseError`; message dropped; logged | Session continues |
| **Authentication tag mismatch** | `decrypt()` | Raises `InvalidTag`; plaintext never returned; logged (metadata only) | Session continues |
| **Out-of-order sequence number** | `dke_engine` receiver check | Message rejected; expected sequence unchanged | Session continues |
| **Replayed message** (seq <= last_seen) | `dke_engine` receiver check | Message rejected; duplicate logged | Session continues |
| **Nonce reuse** (defensive check) | `dke_engine` last_nonce check | Rejected as protocol violation | Session continues |
| **Peer disconnects mid-session** | Transport EOF / socket exception | Session state discarded; new session requires fresh key exchange | Session terminated |
| **Key exchange failure** (no peer response) | Timeout in `main_chat.py` | Connection abandoned; no session state persisted | No session established |

### 7.1 Failure Handling Philosophy

- **Fail closed:** On any cryptographic error, the engine raises an exception and drops the message. It never degrades to returning unauthenticated plaintext.
- **Metadata-only logging:** When a message is rejected, only metadata (timestamp, sequence number, rejection reason) is logged — never ciphertext fragments or partial plaintext.
- **No implicit key sync:** The engine does not attempt to auto-resync keys after a failure. Key desynchronisation requires a fresh session.

---

## 8. Scalability & Extensibility

### 8.1 Current Scope & Limits

| Dimension | v1 Limit | Reason |
|---|---|---|
| Parties per session | **Exactly 2** | X25519 ECDH is a two-party primitive; group key agreement requires a different structure (e.g., MLS) |
| Message ordering | **Strict monotonic** | Simplicity; out-of-order delivery is treated as an error |
| Session persistence | **In-memory only** | No session resumption across process restarts |
| Transport | **Any byte-forwarding channel** | Relay is fully decoupled from crypto stack |

### 8.2 Extension Points

| Extension | How to Add | Modules Affected |
|---|---|---|
| **Swap transport** (TCP -> WebSocket -> message queue) | Replace socket I/O in `main_chat.py` | `main_chat.py` only |
| **Public-key authentication (MITM prevention)** | Sign public keys with long-term identity keys before exchange | `crypto_core.py` (new `sign`/`verify`), `main_chat.py` handshake |
| **Session resumption** | Serialise `DKESessionState` to encrypted store | `dke_engine.py` + new `session_store.py` |
| **Port to another language** | Re-implement 5 modules; use language-native X25519/HKDF/AES-GCM library | All modules |
| **Post-quantum upgrade** | Replace X25519 with ML-KEM (CRYSTALS-Kyber) in `crypto_core.py` | `crypto_core.py` only (interface unchanged) |

> [!NOTE]
> The relay/transport is intentionally "dumb" (bytes only). Swapping it for TCP sockets, WebSockets, or a message queue does **not** affect `crypto_core`, `dke_engine`, or `protocol`.

> [!IMPORTANT]
> **Recommended next milestone before any real-world use:** Add public-key authentication (see Security & Access Document, MITM section). Currently the design assumes the public key exchange channel is trusted or authenticated out-of-band.

---

## 9. Technology Stack

| Concern | Choice | Notes |
|---|---|---|
| **Language** | Python 3.10+ | Reference implementation; portable to other languages later |
| **ECDH** | X25519 via `cryptography` (pyca) | Do **not** hand-roll elliptic curve math |
| **KDF** | HKDF-SHA-256 via `cryptography.hazmat.primitives.kdf.hkdf` | Standard RFC 5869 |
| **AEAD** | AES-256-GCM via `cryptography.hazmat.primitives.ciphers.aead` | Do **not** hand-roll AES or GCM |
| **Ratchet hash** | SHA-256 via `hashlib.sha256` (stdlib) | One-way key evolution |
| **Nonce generation** | `os.urandom(12)` | Cryptographically secure; platform-delegated |
| **CLI** | `argparse` or `click` | Simple two-process demo |
| **Testing** | `pytest` | Standard Python test runner |

---

## 10. Dependencies

| Package | Purpose | License (verify before distribution) |
|---|---|---|
| `cryptography` (pyca) | X25519, HKDF-SHA-256, AES-256-GCM primitives | Apache-2.0 / BSD (verify current version) |
| `pytest` | Test runner | MIT |
| `click` or `argparse` | CLI argument parsing | BSD / stdlib |

### 10.1 Dependency Acquisition

```bash
pip install cryptography pytest click
```

`requirements.txt`:

```
cryptography>=41.0.0
pytest>=7.0.0
click>=8.0.0
```

> [!CAUTION]
> Always pin dependency versions in production use and verify their licenses before distribution. The `cryptography` package version determines which underlying OpenSSL (or BoringSSL) primitives are used.

---

## 11. Security Threat Model

### 11.1 In-Scope Threats (Mitigated in v1)

| Threat | Mitigation |
|---|---|
| **Passive eavesdropper on relay** | AES-256-GCM encryption; relay only sees opaque bytes |
| **Ciphertext tampering** | 128-bit GCM authentication tag; `decrypt()` raises on any modification |
| **Replay attack** | Strictly monotonic sequence numbers; replayed messages rejected |
| **Key compromise (retrospective)** | DKE ratchet + memory overwrite; old keys are gone after advance |
| **Nonce / key reuse** | Separate per-direction sequence counters; OS-random nonces |

### 11.2 Out-of-Scope Threats (v1)

| Threat | Status | Mitigation Path |
|---|---|---|
| **Man-in-the-Middle on key exchange** | ⚠️ Not mitigated in v1 | Add long-term identity key signatures (see Security & Access Document) |
| **Endpoint compromise** | ⚠️ Out of scope | OS-level security; not a messaging-layer concern |
| **Denial of Service** | ⚠️ Out of scope | Transport-level concern |
| **Group messaging security** | ❌ Not applicable | Group messaging is out of scope for v1 |
| **Post-quantum adversaries** | ⚠️ Not mitigated in v1 | Replace X25519 with ML-KEM in `crypto_core.py` |

---

## 12. Module Responsibility Matrix

| Responsibility | `crypto_core` | `dke_engine` | `protocol` | `main_chat` | `test_dke` |
|---|:---:|:---:|:---:|:---:|:---:|
| Key pair generation | ✅ | | | | |
| Shared secret derivation (ECDH) | ✅ | | | | |
| Key derivation (HKDF) | ✅ | | | | |
| Key evolution (ratchet) | | ✅ | | | |
| Sequence number tracking | | ✅ | | | |
| Memory overwrite of old keys | | ✅ | | | |
| Envelope encode / decode | | | ✅ | | |
| AES-GCM encrypt / decrypt | | | ✅ | | |
| Session lifecycle orchestration | | | | ✅ | |
| CLI I/O | | | | ✅ | |
| Automated tests | | | | | ✅ |

---

## Appendix A — Glossary

| Term | Definition |
|---|---|
| **DKE** | Dynamic Key Evolution — the per-message key ratchet that advances the symmetric key after every send/receive |
| **ECDH** | Elliptic Curve Diffie-Hellman — the key agreement protocol used in session establishment |
| **HKDF** | HMAC-based Key Derivation Function (RFC 5869) — stretches raw shared secret into usable key material |
| **AEAD** | Authenticated Encryption with Associated Data — provides both confidentiality and integrity |
| **AES-GCM** | Advanced Encryption Standard in Galois/Counter Mode — the AEAD scheme used for message encryption |
| **Forward Secrecy** | Property ensuring that compromise of a current key does not expose past messages |
| **Ratchet** | A one-way key evolution mechanism; keys can only advance forward, never backward |
| **Relay** | A byte-forwarding transport component with no access to key material or plaintext |
| **Envelope** | The binary wire-format container for an encrypted message |

---

*End of Technical Architecture Document — DKE Hybrid Messaging Engine v1.0*
