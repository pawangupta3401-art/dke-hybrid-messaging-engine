# NOTICE

## Dynamic Key Evolution (DKE) Hybrid Messaging Engine

Copyright (c) 2026 Pawan Gupta and Project Contributors.

---

### Attribution & Originality Statement (PRD Section 9)

This project's architecture is inspired by the Double Ratchet Algorithm used in the Signal Protocol (Trevor Perrin and Moxie Marlinspike, 2013), and uses well-established, publicly documented primitives: X25519 (ECDH), HKDF, and AES-256-GCM. None of these primitives or the general ratcheting concept are original inventions of this project.

The original, copyrightable contribution of this project consists of: its specific source code and module structure; its specific message envelope format; its specific state-management and key-erasure logic; its documentation, diagrams, and test suite; and any implementation-specific choices not dictated by the underlying algorithms. This document and the resulting codebase should be described accordingly in any copyright filing — as an original software implementation of a known design pattern, not as a novel cryptographic invention.

---

### Underlying Cryptographic Standards

This project implements cryptographic workflows and ratcheting concepts based on published standards:

- **X25519 Curve Diffie-Hellman Key Agreement:** Specified in RFC 7748.
- **HMAC-based Extract-and-Expand Key Derivation Function (HKDF):** Specified in RFC 5869.
- **Galois/Counter Mode (GCM) for AES (AES-256-GCM):** Specified in NIST Special Publication 800-38D.
- **Underlying Primitives:** Provided by the audited Python Cryptographic Authority (`cryptography`) library.

---

### Security Disclaimer & Usage Notice

1. **Experimental / Educational Design:** The DKE Hybrid Messaging Engine is an implementation designed to demonstrate per-message dynamic key ratcheting, forward secrecy, and AEAD tamper protection.
2. **Identity Verification:** The initial key exchange in v1.0 uses ephemeral X25519 keys without an external Public Key Infrastructure (PKI) or manual key fingerprint verification, meaning protection against active Man-in-the-Middle (MITM) attacks requires an authenticated out-of-band channel or future PKI extensions.
3. **Memory Erasure:** Python runtime memory management (garbage collection and immutable bytes) restricts guaranteed secure key erasure; best-effort memory wiping via `bytearray` zeroization is applied across all active state objects.
