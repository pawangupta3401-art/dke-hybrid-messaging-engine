# Product Requirements Document (PRD)
## Dynamic Key Evolution (DKE) Hybrid Messaging Engine
### ECDH (X25519) + HKDF + Per-Message Key Ratchet + AES-256-GCM

---

## 1. Overview
This document specifies the requirements for a session-based secure messaging engine that combines Elliptic-Curve Diffie-Hellman (ECDH) key agreement with a per-message symmetric key ratchet and authenticated encryption (AES-256-GCM). The goal of the project is to produce a complete, original, well-documented implementation whose source code, data formats, and documentation are eligible for copyright registration.

**Design note on originality:** The overall approach (ECDH + KDF + per-message hash ratchet + authenticated encryption) follows the publicly known "Double Ratchet" pattern popularized by the Signal Protocol (Perrin & Marlinspike, 2013). This project does not claim to invent that concept. The original, copyrightable contribution is this project's own source code, module structure, message format, state-machine logic, and documentation — not the underlying cryptographic technique, which is a matter of public knowledge and cannot itself be copyrighted.

---

## 2. Goals and Non-Goals

### 2.1 Goals
- Provide confidentiality and integrity for messages between two parties over an untrusted channel.
- Avoid ever transmitting a long-term symmetric key over the network (solve AES's key-distribution limitation).
- Encrypt actual message content efficiently (solve the fact that DH/ECDH alone only agrees on a secret, it does not encrypt data).
- Limit the impact of a single key compromise to the smallest practical window (intra-session forward secrecy).
- Produce a fully original codebase, message format, and documentation suitable for copyright registration.

### 2.2 Non-Goals
- This project does not claim to invent a new cryptographic primitive or a solution to an open problem in cryptography (e.g. factoring hardness, P vs NP, or a wholly new key-agreement scheme).
- This project is not seeking patent protection; no claim of novel invention is made over the underlying technique.
- Formal security proofs and third-party security audits are out of scope for the initial version.

---

## 3. Background: Limitations Being Addressed

| Limitation | Source | How This Design Addresses It |
|---|---|---|
| No safe way to share a symmetric key over an open channel | AES alone | ECDH (X25519) performs key agreement without transmitting the secret itself |
| Key agreement alone does not encrypt data | ECDH/DH alone | AES-256-GCM encrypts and authenticates the message payload |
| A single leaked long-term key exposes the entire conversation | Static-key symmetric/hybrid systems | Per-message key rotation (hash ratchet) limits exposure to a single message on key compromise |

**Note on performance claims:** earlier drafts of this concept referenced fixed figures (e.g. "10x–50x faster", "500+ MB/s", "85–90% bandwidth reduction"). These are not asserted as guaranteed facts in this PRD. Key-size reduction (Curve25519 public keys are 32 bytes vs. 256+ bytes for comparable classical DH/RSA keys) is a verifiable, fixed property and may be cited as such. Throughput and end-to-end bandwidth figures are hardware- and implementation-dependent and must be produced from this project's own benchmark results (see Section 8) rather than quoted from external sources.

---

## 4. System Architecture

### 4.1 Core Components
1. **Asymmetric Key Exchange** — ECDH over Curve25519 (X25519) establishes an initial shared secret between two parties.
2. **Master Key Derivation** — HKDF (HMAC-SHA-256) derives a fixed-length initial symmetric key (K0) from the raw ECDH shared secret.
3. **Dynamic Key Rotation Engine (DKE)** — after each message, the symmetric key evolves via a one-way hash chain: $K_{i+1} = \text{Hash}(K_i \parallel \text{nonce}_i \parallel \text{sequence}_i)$.
4. **Authenticated Payload Encryption** — AES-256-GCM encrypts each message payload and produces an integrity/authenticity tag in a single pass.

### 4.2 Data Flow (Pseudocode)

```
Setup (once per session):
  Alice generates ECDH key pair (a_priv, a_pub)
  Bob generates ECDH key pair (b_priv, b_pub)
  Alice and Bob exchange public keys (32 bytes each)
 
Shared Secret:
  shared = ECDH(a_priv, b_pub) == ECDH(b_priv, a_pub)
 
Master Key:
  K0 = HKDF(shared, info="dke-session-init-v1", length=32)
 
Per-Message Send:
  nonce_i, seq_i = generate_nonce(), next_sequence()
  ciphertext, tag = AES_256_GCM_Encrypt(K_i, plaintext, nonce_i)
  send(header, nonce_i, seq_i, ciphertext, tag)
  K_(i+1) = Hash(K_i || nonce_i || seq_i)
  erase K_i from memory
 
Per-Message Receive:
  plaintext = AES_256_GCM_Decrypt(K_i, ciphertext, nonce_i, tag)
  K_(i+1) = Hash(K_i || nonce_i || seq_i)
  erase K_i from memory
```

### 4.3 Custom Message Envelope (Original Data Format)
The wire format for each message is an original design choice of this project and is a candidate copyrightable data format:

| Field | Size | Purpose |
|---|---|---|
| Magic | 4 bytes | Protocol identifier (`DKE1`) |
| Version | 1 byte | Protocol version (`0x01`) |
| Flags | 1 byte | Reserved flags (`0x00`) |
| Sequence Number | 8 bytes | Ordering and ratchet synchronization (uint64, big-endian) |
| Nonce | 12 bytes | AES-GCM nonce (must never repeat under the same key) |
| Ciphertext Length | 4 bytes | Length of encrypted payload (uint32, big-endian) |
| Ciphertext | variable | Encrypted payload |
| Authentication Tag | 16 bytes | GCM integrity/authenticity tag |

---

## 5. Module Breakdown

| Module | Responsibility |
|---|---|
| `crypto_core.py` | Curve25519 (X25519) ECDH key generation and exchange; HKDF master key derivation. |
| `dke_engine.py` | Key-rotation state machine: derives $K_{i+1}$, tracks sequence numbers, securely erases superseded keys. |
| `protocol.py` | AES-256-GCM encryption/decryption; packing and unpacking of the custom message envelope. |
| `main_chat.py` | Interactive CLI demo application exercising the full flow between two simulated parties (Alice and Bob). |
| `test_dke.py` | Automated tests verifying correct key rotation, envelope round-trips, and memory hygiene of old keys. |

---

## 6. Functional Requirements
- **FR1:** The system SHALL derive a shared secret using ECDH (X25519) without transmitting private key material.
- **FR2:** The system SHALL derive the initial symmetric key from the shared secret using HKDF-SHA256.
- **FR3:** The system SHALL rotate the symmetric key after every message using a one-way hash function of the previous key, nonce, and sequence number.
- **FR4:** The system SHALL encrypt and authenticate every message using AES-256-GCM with a unique nonce per message.
- **FR5:** The system SHALL discard (overwrite in memory) superseded keys immediately after rotation.
- **FR6:** The system SHALL reject and discard any message that fails authentication (invalid GCM tag).
- **FR7:** The system SHALL provide a working command-line demonstration of two parties exchanging encrypted messages.

---

## 7. Non-Functional Requirements
- **NFR1 (Security):** Nonces must never repeat under the same key; sequence numbers must be strictly increasing per session.
- **NFR2 (Originality):** All source code, naming, module structure, and the message envelope format must be independently written for this project.
- **NFR3 (Documentation):** Every design decision with a security implication must be documented with its rationale.
- **NFR4 (Testability):** Key rotation and envelope encode/decode logic must have automated unit tests.
- **NFR5 (Honesty of claims):** Any performance or efficiency figures published in documentation must be derived from this project's own benchmarks, not quoted as generic industry figures.

---

## 8. Documentation & Testing Deliverables

### 8.1 Documentation
- `README.md` — project purpose, architecture diagram, and how to run the demo.
- `TECHNICAL_ARCHITECTURE.md` — state diagrams for the key-rotation engine and sequence diagrams for a full message exchange.
- `NOTICE.md` — a clear statement (see Section 9) that the design pattern is inspired by the Signal Protocol's Double Ratchet, with this project's original implementation described explicitly.

### 8.2 Testing
- Unit tests for ECDH key exchange producing matching shared secrets on both sides.
- Unit tests confirming $K_{i+1}$ differs from $K_i$ and cannot be reversed to recover $K_i$.
- Unit tests confirming a tampered ciphertext or tag is rejected.
- A benchmark script recording this project's own measured key-exchange time and encryption throughput on the developer's own hardware, to replace any generic performance claims.

---

## 9. Attribution & Originality Statement
This project's architecture is inspired by the Double Ratchet Algorithm used in the Signal Protocol (Trevor Perrin and Moxie Marlinspike, 2013), and uses well-established, publicly documented primitives: X25519 (ECDH), HKDF, and AES-256-GCM. None of these primitives or the general ratcheting concept are original inventions of this project.

The original, copyrightable contribution of this project consists of: its specific source code and module structure; its specific message envelope format; its specific state-management and key-erasure logic; its documentation, diagrams, and test suite; and any implementation-specific choices not dictated by the underlying algorithms. This document and the resulting codebase should be described accordingly in any copyright filing — as an original software implementation of a known design pattern, not as a novel cryptographic invention.

---

## 10. Copyright Filing Checklist
1. Complete and test all modules listed in Section 5.
2. Finalize README, architecture document, and attribution statement (Section 9).
3. Establish a timestamped record of authorship (e.g. a Git repository with commit history, or a dated email to oneself with the code attached).
4. Compile source code, documentation, diagrams, and test outputs into a single submission package.
5. File with the relevant national copyright office (e.g. copyright.gov.in or copyright.gov) under "Literary Work / Computer Software."

---

## 11. Open Risks / Notes
- This design has not undergone formal, independent security review; it should be treated as a learning/portfolio project, not production-grade security software, unless and until reviewed.
- Secure erasure of key material in memory is best-effort in most high-level languages (e.g. Python); this limitation should be documented rather than overstated as solved.
- Any figures for speed or bandwidth must be labeled with the exact test hardware and conditions used to produce them.
