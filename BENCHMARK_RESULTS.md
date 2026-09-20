# Empirical Benchmark Results
## Dynamic Key Evolution (DKE) Hybrid Messaging Engine
> **Reference:** PRD Section 3, Section 8.2, and Non-Functional Requirement NFR5

---

### Test Environment & Hardware Specification

| Attribute | Specification |
|---|---|
| **Operating System** | Windows 11 (Build 10.0.26200) |
| **Architecture** | AMD64 (64-bit) |
| **CPU Model** | AMD64 Family 25 Model 80 Stepping 0 (AuthenticAMD) |
| **Python Runtime** | CPython 3.13.7 |
| **Cryptography Library** | `cryptography` (PyCA) with OpenSSL backend |

---

### Empirical Measurements

Benchmark executed via [`benchmark.py`](benchmark.py) with minimum 1-second sample windows per operation:

| Operation / Benchmark | Throughput (ops/sec) | Latency (µs / ms) | Effective Bandwidth |
|---|---|---|---|
| **X25519 Keypair Generation** | 27,700 ops/sec | 36.14 µs | — |
| **X25519 ECDH Shared Secret** | 29,700 ops/sec | 33.69 µs | — |
| **HKDF-SHA256 (K0 Derivation)** | 102,200 ops/sec | 9.78 µs | — |
| **Full Handshake (Alice + Bob)** | 8,400 handshakes/sec | 119.42 µs | — |
| **DKE Ratchet Advance (`advance_key`)** | 942,200 ratchets/sec | 1.06 µs | — |
| **AES-256-GCM Encrypt (64 B payload)** | 264,400 ops/sec | 3.78 µs | 16.14 MB/s |
| **AES-256-GCM Decrypt (64 B payload)** | 258,600 ops/sec | 3.87 µs | 15.79 MB/s |
| **AES-256-GCM Encrypt (1 KB payload)** | 238,900 ops/sec | 4.19 µs | 233.30 MB/s |
| **AES-256-GCM Decrypt (1 KB payload)** | 248,500 ops/sec | 4.02 µs | 242.71 MB/s |
| **AES-256-GCM Encrypt (64 KB payload)** | 43,800 ops/sec | 22.83 µs | 2,737.47 MB/s (~2.7 GB/s) |
| **AES-256-GCM Decrypt (64 KB payload)** | 49,600 ops/sec | 20.15 µs | 3,102.28 MB/s (~3.1 GB/s) |
| **AES-256-GCM Encrypt (1 MB payload)** | 1,100 ops/sec | 942.14 µs | 1,061.41 MB/s (~1.0 GB/s) |
| **AES-256-GCM Decrypt (1 MB payload)** | 938 ops/sec | 1.07 ms | 938.67 MB/s |
| **E2E Send Pipeline (msg + ratchet)** | 126,600 messages/sec | 7.90 µs | — |

---

### Key Findings & NFR5 Compliance

1. **Sub-Microsecond Ratchet Overhead:** Advancing the DKE symmetric key takes approximately **1.06 µs** (nearly 1,000,000 advances per second), proving that per-message dynamic key ratcheting imposes negligible overhead on high-frequency chat.
2. **Instantaneous Session Establishment:** Complete two-party ECDH key agreement and HKDF master key derivation takes approximately **119.4 µs** (~0.12 ms), enabling instant session startup without perceptible delay.
3. **High-Throughput Streaming:** Authenticated encryption achieves over **2.7 GB/s** on 64 KB blocks and **1.0 GB/s** on 1 MB blocks via AES-NI hardware acceleration.
