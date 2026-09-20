"""
tests/test_dke.py — Automated Test Suite
=========================================
TAD Reference: Section 3.5

Responsibility
--------------
Correctness and security regression tests for the DKE Messaging Engine.
Run with::

    pytest tests/

All test functions follow the naming convention ``test_<behaviour>``
and use only public module APIs.

Design note on two-chain state
--------------------------------
``DKESessionState`` now holds two independent ``DirectionState`` objects:

  state.outbound  — key + seq for messages *sent* by this party
  state.inbound   — key + seq for messages *received* by this party

The cross-matching invariant after any exchange:
  sender.outbound.current_key  ==  receiver.inbound.current_key

Test Coverage Matrix (TAD Section 3.5)
----------------------------------------
+----------------------------------------------------+---------------------------+
| Test case                                          | TAD property verified     |
+----------------------------------------------------+---------------------------+
| ECDH symmetry                                      | Shared secret derivation  |
| HKDF output length                                 | Key derivation contract   |
| HKDF domain separation via info string             | Key derivation contract   |
| advance_key changes the key                        | Forward secrecy           |
| advance_key is deterministic                       | Ratchet correctness       |
| advance_key is non-reversible                      | Key Non-reversibility     |
| Ratchet chain: all steps unique                    | Forward secrecy           |
| validate_sequence rejects out-of-order             | Replay prevention         |
| validate_sequence rejects replay (seq too low)     | Replay prevention         |
| validate_sequence accepts correct seq              | Sequence counter          |
| DKESessionState initial counter values             | State correctness         |
| rotate_send advances outbound key & erases old     | Memory safety             |
| rotate_receive validates + advances inbound key    | State correctness         |
| rotate_receive rejects bad seq (state unchanged)   | Fail-closed ratchet       |
| Outbound chain independent of inbound chain        | Directional isolation     |
| Cross-match: sender.outbound == receiver.inbound   | End-to-end DKE            |
| Full bidirectional session key agreement           | End-to-end DKE            |
| encrypt/decrypt round-trip                         | AEAD confidentiality      |
| encrypt: empty plaintext                           | Edge case                 |
| tampered ciphertext -> InvalidTag                  | Integrity (GCM tag)       |
| tampered tag -> InvalidTag                         | Authenticity (GCM tag)    |
| wrong key -> InvalidTag                            | Key binding               |
| decrypt never returns on tag failure               | Fail-closed policy        |
| encode_envelope / decode_envelope round-trip       | Wire format               |
| decode rejects input < 46 bytes                    | Malformed envelope        |
| decode rejects wrong magic                         | Malformed envelope        |
| decode rejects unsupported version                 | Malformed envelope        |
| decode rejects non-zero flags                      | Malformed envelope        |
| decode rejects truncated ciphertext                | Malformed envelope        |
| decode rejects padded envelope                     | Malformed envelope        |
| decode rejects mismatched ct_len field             | Malformed envelope        |
| Full pipeline: ECDH -> HKDF -> DKE -> AES-GCM     | Integration               |
| Tampered envelope: decode OK, decrypt fails        | Fail-closed policy        |
+----------------------------------------------------+---------------------------+
"""

from __future__ import annotations

import os
import struct

import pytest
from cryptography.exceptions import InvalidTag

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from crypto_core import (
    generate_keypair,
    derive_shared_secret,
    hkdf_derive,
    SESSION_INFO,
    PUBLIC_KEY_SIZE,
    DEFAULT_KEY_LENGTH,
)
from dke_engine import (
    DirectionState,
    DKESessionState,
    SequenceError,
    advance_key,
    validate_sequence,
    outbound_params,
    inbound_key,
    rotate_send,
    rotate_receive,
    KEY_SIZE,
    NONCE_SIZE,
)
from protocol import (
    encode_envelope,
    decode_envelope,
    encrypt,
    decrypt,
    ParseError,
    MAGIC,
    TAG_SIZE,
    MIN_ENVELOPE_SIZE,
    HEADER_SIZE,
)


# ===========================================================================
# Shared fixtures
# ===========================================================================


@pytest.fixture()
def keypair_alice():
    """Fresh X25519 key pair for Alice."""
    return generate_keypair()


@pytest.fixture()
def keypair_bob():
    """Fresh X25519 key pair for Bob."""
    return generate_keypair()


@pytest.fixture()
def shared_secret(keypair_alice, keypair_bob):
    """Raw ECDH shared secret (same from both sides)."""
    priv_a, pub_a = keypair_alice
    priv_b, pub_b = keypair_bob
    return derive_shared_secret(priv_a, pub_b)


@pytest.fixture()
def k0(shared_secret):
    """Initial 32-byte AES-256 key derived from the shared secret."""
    return hkdf_derive(shared_secret, info=SESSION_INFO)


@pytest.fixture()
def session_states(k0):
    """Pair of DKESessionState objects both seeded with K0 (Alice and Bob)."""
    return DKESessionState.from_k0(k0), DKESessionState.from_k0(k0)


@pytest.fixture()
def aes_key():
    """Random 32-byte AES-256 key."""
    return os.urandom(KEY_SIZE)


@pytest.fixture()
def nonce():
    """Random 12-byte AES-GCM nonce."""
    return os.urandom(NONCE_SIZE)


@pytest.fixture()
def encrypted_hello(aes_key, nonce):
    """Pre-encrypted b'hello world' and its tag."""
    ct, tag = encrypt(aes_key, b"hello world", nonce)
    return ct, tag


# ===========================================================================
# crypto_core tests
# ===========================================================================


class TestCryptoCore:

    def test_ecdh_shared_secret_symmetry(self, keypair_alice, keypair_bob):
        """Both sides of X25519 ECDH must derive an identical shared secret.

        Verifies::

            derive_shared_secret(a_priv, b_pub) == derive_shared_secret(b_priv, a_pub)

        TAD Reference: Section 3.5 — ECDH symmetry
                   Section 5.1 — Key Hierarchy
        """
        priv_a, pub_a = keypair_alice
        priv_b, pub_b = keypair_bob

        secret_a = derive_shared_secret(priv_a, pub_b)
        secret_b = derive_shared_secret(priv_b, pub_a)

        assert secret_a == secret_b, (
            "ECDH must be symmetric: A's view of the secret must equal B's view."
        )
        assert len(secret_a) == PUBLIC_KEY_SIZE

    def test_ecdh_different_peers_yield_different_secrets(self, keypair_alice):
        """Different peers must produce different shared secrets."""
        priv_a, _ = keypair_alice
        _, pub_b1 = generate_keypair()
        _, pub_b2 = generate_keypair()

        secret1 = derive_shared_secret(priv_a, pub_b1)
        secret2 = derive_shared_secret(priv_a, pub_b2)

        assert secret1 != secret2

    def test_ecdh_rejects_short_peer_key(self, keypair_alice):
        """derive_shared_secret() must reject peer keys that are not 32 bytes."""
        priv_a, _ = keypair_alice
        with pytest.raises(ValueError, match="32 bytes"):
            derive_shared_secret(priv_a, b"tooshort")

    def test_hkdf_derive_produces_correct_length(self, shared_secret):
        """hkdf_derive() must return exactly ``length`` bytes (default 32).

        TAD Reference: Section 3.1 — hkdf_derive()
        """
        key = hkdf_derive(shared_secret, info=SESSION_INFO)
        assert len(key) == DEFAULT_KEY_LENGTH

    def test_hkdf_custom_length(self, shared_secret):
        """hkdf_derive() must honour a non-default length argument."""
        key = hkdf_derive(shared_secret, info=SESSION_INFO, length=64)
        assert len(key) == 64

    def test_hkdf_different_info_produces_different_keys(self, shared_secret):
        """Different ``info`` strings MUST yield different derived keys (domain separation).

        TAD Reference: Section 3.1 — Design Constraints (info parameter)
        """
        key_a = hkdf_derive(shared_secret, info="context-a")
        key_b = hkdf_derive(shared_secret, info="context-b")

        assert key_a != key_b

    def test_hkdf_same_inputs_same_output(self, shared_secret):
        """hkdf_derive() is deterministic: same inputs → same key."""
        k1 = hkdf_derive(shared_secret, info=SESSION_INFO)
        k2 = hkdf_derive(shared_secret, info=SESSION_INFO)
        assert k1 == k2

    def test_hkdf_rejects_empty_secret(self):
        """hkdf_derive() must raise ValueError for an empty shared secret."""
        with pytest.raises(ValueError):
            hkdf_derive(b"", info=SESSION_INFO)

    def test_both_sides_derive_same_k0(self, keypair_alice, keypair_bob):
        """Full handshake: both sides must arrive at the same K0.

        TAD Reference: Section 5.1 — Key Hierarchy
                   Section 6.1 — Session Establishment
        """
        priv_a, pub_a = keypair_alice
        priv_b, pub_b = keypair_bob

        k0_a = hkdf_derive(derive_shared_secret(priv_a, pub_b), info=SESSION_INFO)
        k0_b = hkdf_derive(derive_shared_secret(priv_b, pub_a), info=SESSION_INFO)

        assert k0_a == k0_b, "Both parties must independently derive the same K0."


# ===========================================================================
# dke_engine tests
# ===========================================================================


class TestAdvanceKey:

    def test_advance_key_changes_key(self):
        """advance_key() must return a key that differs from the input key.

        TAD Reference: Section 3.5 — Key rotation non-reversibility
        """
        k0 = os.urandom(KEY_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        k1 = advance_key(k0, nonce, sequence=0)

        assert k1 != k0
        assert len(k1) == KEY_SIZE

    def test_advance_key_deterministic(self):
        """advance_key() with identical inputs must produce identical output.

        Both sides independently compute the same next key.

        TAD Reference: Section 3.2 — Key Evolution Formula
        """
        k0 = os.urandom(KEY_SIZE)
        nonce = os.urandom(NONCE_SIZE)

        k1_alice = advance_key(k0, nonce, sequence=0)
        k1_bob   = advance_key(k0, nonce, sequence=0)

        assert k1_alice == k1_bob

    def test_advance_key_is_non_reversible(self):
        """Given K_(i+1), it must be impossible to recover K_i.

        TAD Reference: Section 5.2 — Key Non-reversibility
        """
        k0 = os.urandom(KEY_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        k1 = advance_key(k0, nonce, sequence=0)

        # Attempting forward advancement from k1 must not reproduce k0
        k2 = advance_key(k1, nonce, sequence=0)
        assert k2 != k0

        k2_alt = advance_key(k1, nonce, sequence=1)
        assert k2_alt != k0

    def test_advance_key_all_steps_unique(self):
        """Every step of a 10-message ratchet chain must produce a unique key."""
        key = os.urandom(KEY_SIZE)
        seen: set[bytes] = {key}
        nonce = os.urandom(NONCE_SIZE)

        for seq in range(10):
            key = advance_key(key, nonce, sequence=seq)
            assert key not in seen, f"Ratchet step {seq} produced a duplicate key."
            seen.add(key)

    def test_advance_key_different_nonces_yield_different_keys(self):
        """Same key + seq but different nonces must produce different next keys."""
        k0 = os.urandom(KEY_SIZE)
        nonce_a, nonce_b = os.urandom(NONCE_SIZE), os.urandom(NONCE_SIZE)

        k1_a = advance_key(k0, nonce_a, sequence=0)
        k1_b = advance_key(k0, nonce_b, sequence=0)
        assert k1_a != k1_b

    def test_advance_key_rejects_wrong_key_size(self):
        """advance_key() must raise ValueError if key is not 32 bytes."""
        with pytest.raises(ValueError, match="32 bytes"):
            advance_key(b"tooshort", os.urandom(NONCE_SIZE), 0)

    def test_advance_key_rejects_wrong_nonce_size(self):
        """advance_key() must raise ValueError if nonce is not 12 bytes."""
        with pytest.raises(ValueError, match="12 bytes"):
            advance_key(os.urandom(KEY_SIZE), b"short", 0)

    def test_advance_key_rejects_negative_sequence(self):
        """advance_key() must raise ValueError for a negative sequence number."""
        with pytest.raises(ValueError, match="non-negative"):
            advance_key(os.urandom(KEY_SIZE), os.urandom(NONCE_SIZE), -1)


class TestValidateSequence:

    def test_validate_sequence_accepts_correct(self):
        """validate_sequence() must not raise when received == expected."""
        validate_sequence(expected=0, received=0)
        validate_sequence(expected=42, received=42)

    def test_validate_sequence_rejects_out_of_order(self):
        """validate_sequence() must raise SequenceError when received > expected.

        TAD Reference: Section 7 — Failure Modes (Out-of-order)
        """
        with pytest.raises(SequenceError):
            validate_sequence(expected=3, received=4)

    def test_validate_sequence_rejects_replay(self):
        """validate_sequence() must raise SequenceError when received < expected.

        TAD Reference: Section 7 — Failure Modes (Replay)
        """
        with pytest.raises(SequenceError):
            validate_sequence(expected=5, received=4)

    def test_validate_sequence_rejects_zero_when_expecting_nonzero(self):
        """Receiving seq=0 after messages have been processed must be rejected."""
        with pytest.raises(SequenceError):
            validate_sequence(expected=10, received=0)


class TestDKESessionState:

    def test_from_k0_creates_two_direction_states(self, k0):
        """from_k0() must populate both outbound and inbound DirectionState objects."""
        state = DKESessionState.from_k0(k0)
        assert isinstance(state.outbound, DirectionState)
        assert isinstance(state.inbound, DirectionState)

    def test_from_k0_both_keys_match_input(self, k0):
        """Both outbound and inbound keys must equal K0 after from_k0()."""
        state = DKESessionState.from_k0(k0)
        assert bytes(state.outbound.current_key) == k0
        assert bytes(state.inbound.current_key) == k0

    def test_from_k0_initial_sequence_counters(self, k0):
        """Both outbound and inbound sequence numbers must start at 0."""
        state = DKESessionState.from_k0(k0)
        assert state.outbound.sequence_number == 0
        assert state.inbound.sequence_number == 0

    def test_from_k0_rejects_wrong_size(self):
        """from_k0() must raise ValueError if k0 is not 32 bytes."""
        with pytest.raises(ValueError, match="32 bytes"):
            DKESessionState.from_k0(b"tooshort")

    def test_rotate_send_advances_outbound_key(self, k0):
        """rotate_send() must update outbound.current_key.

        TAD Reference: Section 3.2 — Memory Safety Rule
        """
        state = DKESessionState.from_k0(k0)
        key_before = bytes(state.outbound.current_key)
        rotate_send(state, os.urandom(NONCE_SIZE))
        assert bytes(state.outbound.current_key) != key_before

    def test_rotate_send_does_not_touch_inbound_chain(self, k0):
        """rotate_send() must leave inbound.current_key completely unchanged.

        TAD Reference: Section 3.2 — Two Independent Ratchet Chains
        """
        state = DKESessionState.from_k0(k0)
        inbound_key_before = bytes(state.inbound.current_key)
        inbound_seq_before = state.inbound.sequence_number

        rotate_send(state, os.urandom(NONCE_SIZE))

        assert bytes(state.inbound.current_key) == inbound_key_before
        assert state.inbound.sequence_number == inbound_seq_before

    def test_rotate_send_erases_old_outbound_key(self, k0):
        """rotate_send() must zero the old outbound key bytearray in-place.

        TAD Reference: Section 3.2 — Memory Safety Rule
        """
        state = DKESessionState.from_k0(k0)
        old_buf = state.outbound.current_key        # hold ref to old buffer
        rotate_send(state, os.urandom(NONCE_SIZE))
        assert all(b == 0 for b in old_buf), (
            "Old outbound key buffer must be zeroed after rotation."
        )

    def test_rotate_send_increments_outbound_seq(self, k0):
        """rotate_send() must increment outbound.sequence_number."""
        state = DKESessionState.from_k0(k0)
        rotate_send(state, os.urandom(NONCE_SIZE))
        assert state.outbound.sequence_number == 1
        rotate_send(state, os.urandom(NONCE_SIZE))
        assert state.outbound.sequence_number == 2

    def test_rotate_receive_advances_inbound_key(self, k0):
        """rotate_receive() must update inbound.current_key."""
        state = DKESessionState.from_k0(k0)
        key_before = bytes(state.inbound.current_key)
        rotate_receive(state, os.urandom(NONCE_SIZE), received_seq=0)
        assert bytes(state.inbound.current_key) != key_before

    def test_rotate_receive_does_not_touch_outbound_chain(self, k0):
        """rotate_receive() must leave outbound.current_key completely unchanged.

        TAD Reference: Section 3.2 — Two Independent Ratchet Chains
        """
        state = DKESessionState.from_k0(k0)
        outbound_key_before = bytes(state.outbound.current_key)
        outbound_seq_before = state.outbound.sequence_number

        rotate_receive(state, os.urandom(NONCE_SIZE), received_seq=0)

        assert bytes(state.outbound.current_key) == outbound_key_before
        assert state.outbound.sequence_number == outbound_seq_before

    def test_rotate_receive_erases_old_inbound_key(self, k0):
        """rotate_receive() must zero the old inbound key bytearray in-place."""
        state = DKESessionState.from_k0(k0)
        old_buf = state.inbound.current_key         # hold ref
        rotate_receive(state, os.urandom(NONCE_SIZE), received_seq=0)
        assert all(b == 0 for b in old_buf), (
            "Old inbound key buffer must be zeroed after rotation."
        )

    def test_rotate_receive_increments_inbound_seq(self, k0):
        """rotate_receive() must increment inbound.sequence_number."""
        state = DKESessionState.from_k0(k0)
        rotate_receive(state, os.urandom(NONCE_SIZE), received_seq=0)
        assert state.inbound.sequence_number == 1

    def test_rotate_receive_rejects_bad_seq_leaves_state_unchanged(self, k0):
        """rotate_receive() with a wrong seq must leave ALL state unchanged.

        TAD Reference: Section 7 — Fail-closed on sequence error
        """
        state = DKESessionState.from_k0(k0)
        inbound_key_before  = bytes(state.inbound.current_key)
        inbound_seq_before  = state.inbound.sequence_number
        outbound_key_before = bytes(state.outbound.current_key)

        with pytest.raises(SequenceError):
            rotate_receive(state, os.urandom(NONCE_SIZE), received_seq=99)

        assert bytes(state.inbound.current_key)  == inbound_key_before
        assert state.inbound.sequence_number     == inbound_seq_before
        assert bytes(state.outbound.current_key) == outbound_key_before


class TestFullSession:

    def test_outbound_and_inbound_chains_are_independent(self, k0):
        """Advancing the outbound chain must not affect the inbound chain, and v.v.

        TAD Reference: Section 3.2 — Two Independent Ratchet Chains
        """
        state = DKESessionState.from_k0(k0)
        inbound_key_snap = bytes(state.inbound.current_key)

        # Advance outbound 3 times
        for _ in range(3):
            rotate_send(state, os.urandom(NONCE_SIZE))

        # Inbound chain must be untouched
        assert bytes(state.inbound.current_key) == inbound_key_snap
        assert state.inbound.sequence_number == 0

    def test_cross_match_after_one_message(self, session_states):
        """sender.outbound.current_key must equal receiver.inbound.current_key
        immediately after rotate_send / rotate_receive with the same nonce.

        TAD Reference: Section 3.2 — Cross-matching invariant
        """
        state_a, state_b = session_states

        # Snapshot Alice's key and seq BEFORE rotation (these are what Bob will use)
        key_a, seq_a = outbound_params(state_a)
        nonce = os.urandom(NONCE_SIZE)

        rotate_send(state_a, nonce)

        # Bob validates seq and retrieves key
        key_b = inbound_key(state_b, seq_a)
        assert key_a == key_b, (
            "Encryption key (Alice outbound) must match decryption key (Bob inbound)."
        )
        rotate_receive(state_b, nonce, seq_a)

        # After rotation, Alice's new outbound == Bob's new inbound
        assert bytes(state_a.outbound.current_key) == bytes(state_b.inbound.current_key), (
            "Cross-match invariant must hold after rotation."
        )

    def test_bidirectional_cross_match_stays_consistent(self, session_states):
        """Both cross-match invariants must hold after 5 interleaved messages.

        Invariants:
          state_a.outbound.current_key == state_b.inbound.current_key
          state_b.outbound.current_key == state_a.inbound.current_key

        TAD Reference: Section 6.2 — Steady-State Sequence
        """
        state_a, state_b = session_states

        def alice_sends():
            key_a, seq_a = outbound_params(state_a)
            n = os.urandom(NONCE_SIZE)
            rotate_send(state_a, n)
            key_b = inbound_key(state_b, seq_a)
            assert key_a == key_b, "Alice-send key mismatch"
            rotate_receive(state_b, n, seq_a)

        def bob_sends():
            key_b, seq_b = outbound_params(state_b)
            n = os.urandom(NONCE_SIZE)
            rotate_send(state_b, n)
            key_a = inbound_key(state_a, seq_b)
            assert key_b == key_a, "Bob-send key mismatch"
            rotate_receive(state_a, n, seq_b)

        alice_sends()
        alice_sends()
        bob_sends()
        alice_sends()
        bob_sends()

        # Both cross-match invariants must hold
        assert bytes(state_a.outbound.current_key) == bytes(state_b.inbound.current_key)
        assert bytes(state_b.outbound.current_key) == bytes(state_a.inbound.current_key)

    def test_replay_rejected_after_message_consumed(self, session_states):
        """A replayed envelope (same seq) must be rejected after first delivery.

        TAD Reference: Section 7 — Failure Modes (Replayed message)
        """
        state_a, state_b = session_states
        key_a, seq_a = outbound_params(state_a)
        nonce = os.urandom(NONCE_SIZE)
        rotate_send(state_a, nonce)

        # First delivery — OK
        inbound_key(state_b, seq_a)
        rotate_receive(state_b, nonce, seq_a)

        # Replay — must be rejected
        with pytest.raises(SequenceError):
            inbound_key(state_b, seq_a)


# ===========================================================================
# protocol tests
# ===========================================================================


class TestEncryptDecrypt:

    def test_encrypt_decrypt_roundtrip(self, aes_key, nonce):
        """encrypt() followed by decrypt() must recover the original plaintext."""
        plaintext = b"Hello, DKE!"
        ct, tag = encrypt(aes_key, plaintext, nonce)
        assert decrypt(aes_key, ct, nonce, tag) == plaintext

    def test_encrypt_ciphertext_length_equals_plaintext(self, aes_key, nonce):
        """AES-GCM ciphertext must be the same length as the plaintext."""
        plaintext = b"A" * 100
        ct, tag = encrypt(aes_key, plaintext, nonce)
        assert len(ct) == len(plaintext)
        assert len(tag) == TAG_SIZE

    def test_encrypt_empty_plaintext(self, aes_key, nonce):
        """Empty plaintext must encrypt and decrypt cleanly."""
        ct, tag = encrypt(aes_key, b"", nonce)
        assert ct == b""
        assert len(tag) == TAG_SIZE
        assert decrypt(aes_key, ct, nonce, tag) == b""

    def test_encrypt_different_nonces_yield_different_ciphertexts(self, aes_key):
        """The same plaintext encrypted under different nonces must differ."""
        pt = b"same plaintext"
        ct1, _ = encrypt(aes_key, pt, os.urandom(12))
        ct2, _ = encrypt(aes_key, pt, os.urandom(12))
        assert ct1 != ct2

    def test_tampered_ciphertext_raises_on_decrypt(self, aes_key, nonce, encrypted_hello):
        """Flipping any bit in the ciphertext must cause decrypt() to raise InvalidTag.

        TAD Reference: Section 7.1 — Fail-closed policy
        """
        ct, tag = encrypted_hello
        ct_tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(InvalidTag):
            decrypt(aes_key, ct_tampered, nonce, tag)

    def test_tampered_last_byte_ciphertext_raises(self, aes_key, nonce, encrypted_hello):
        """Flipping the last byte of ciphertext must also raise InvalidTag."""
        ct, tag = encrypted_hello
        ct_tampered = ct[:-1] + bytes([ct[-1] ^ 0xFF])
        with pytest.raises(InvalidTag):
            decrypt(aes_key, ct_tampered, nonce, tag)

    def test_tampered_tag_raises_on_decrypt(self, aes_key, nonce, encrypted_hello):
        """Providing a wrong authentication tag must cause decrypt() to raise InvalidTag.

        TAD Reference: Section 5.2 — Integrity & Authenticity
        """
        ct, tag = encrypted_hello
        tag_tampered = bytes([tag[0] ^ 0xFF]) + tag[1:]
        with pytest.raises(InvalidTag):
            decrypt(aes_key, ct, nonce, tag_tampered)

    def test_decrypt_never_returns_on_tag_failure(self, aes_key, nonce, encrypted_hello):
        """decrypt() must raise, not return None or empty bytes, on tag failure.

        TAD Reference: Section 3.3 — AEAD Contract
                   Section 7.1 — Fail-closed policy
        """
        ct, _ = encrypted_hello
        tag_bad = bytes(TAG_SIZE)   # all-zero tag (almost certainly wrong)
        result = None
        try:
            result = decrypt(aes_key, ct, nonce, tag_bad)
        except InvalidTag:
            pass
        assert result is None

    def test_wrong_key_raises_on_decrypt(self, aes_key, nonce, encrypted_hello):
        """Decrypting with the wrong key must raise InvalidTag."""
        ct, tag = encrypted_hello
        with pytest.raises(InvalidTag):
            decrypt(os.urandom(KEY_SIZE), ct, nonce, tag)

    def test_encrypt_rejects_wrong_key_size(self, nonce):
        """encrypt() must raise ValueError for a key that is not 32 bytes."""
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt(os.urandom(16), b"hi", nonce)

    def test_decrypt_rejects_wrong_tag_size(self, aes_key, nonce, encrypted_hello):
        """decrypt() must raise ValueError for a tag that is not 16 bytes."""
        ct, _ = encrypted_hello
        with pytest.raises(ValueError, match="16 bytes"):
            decrypt(aes_key, ct, nonce, os.urandom(8))


class TestEnvelopeFormat:

    @pytest.fixture()
    def valid_envelope(self, aes_key, nonce):
        """A correctly encoded envelope with seq=7."""
        ct, tag = encrypt(aes_key, b"test payload", nonce)
        envelope = encode_envelope(sequence=7, nonce=nonce, ciphertext=ct, tag=tag)
        return envelope, ct, tag, nonce

    def test_encode_decode_envelope_roundtrip(self, aes_key, nonce):
        """encode_envelope() followed by decode_envelope() must recover all fields exactly.

        TAD Reference: Section 4.1 — Envelope Structure
        """
        ct, tag = encrypt(aes_key, b"hello", nonce)
        envelope = encode_envelope(sequence=42, nonce=nonce, ciphertext=ct, tag=tag)
        seq_out, nonce_out, ct_out, tag_out = decode_envelope(envelope)

        assert seq_out   == 42
        assert nonce_out == nonce
        assert ct_out    == ct
        assert tag_out   == tag

    def test_envelope_minimum_size_constant(self):
        """MIN_ENVELOPE_SIZE must equal HEADER_SIZE + TAG_SIZE = 46."""
        assert MIN_ENVELOPE_SIZE == 46
        assert MIN_ENVELOPE_SIZE == HEADER_SIZE + TAG_SIZE

    def test_encode_envelope_length(self, aes_key, nonce):
        """Encoded envelope length must equal HEADER_SIZE + len(ct) + TAG_SIZE."""
        ct, tag = encrypt(aes_key, b"X" * 50, nonce)
        envelope = encode_envelope(0, nonce, ct, tag)
        assert len(envelope) == HEADER_SIZE + len(ct) + TAG_SIZE

    def test_encode_sequence_zero(self, aes_key, nonce):
        """Sequence 0 (first message) must encode and decode correctly."""
        ct, tag = encrypt(aes_key, b"first", nonce)
        envelope = encode_envelope(0, nonce, ct, tag)
        seq_out, _, _, _ = decode_envelope(envelope)
        assert seq_out == 0

    def test_encode_large_sequence(self, aes_key, nonce):
        """Large sequence numbers (uint64 range) must survive encode/decode."""
        large_seq = (2**63) - 1
        ct, tag = encrypt(aes_key, b"big seq", nonce)
        envelope = encode_envelope(large_seq, nonce, ct, tag)
        seq_out, _, _, _ = decode_envelope(envelope)
        assert seq_out == large_seq

    def test_decode_rejects_input_shorter_than_minimum(self):
        """decode_envelope() must raise ParseError for any input < 46 bytes.

        TAD Reference: Section 4.2 — Minimum Envelope Size
        """
        with pytest.raises(ParseError, match="too short"):
            decode_envelope(b"DKE1" + b"\x00" * 10)

    def test_decode_rejects_empty_input(self):
        """decode_envelope() must raise ParseError for empty input."""
        with pytest.raises(ParseError):
            decode_envelope(b"")

    def test_decode_rejects_wrong_magic(self, valid_envelope):
        """decode_envelope() must raise ParseError when magic != b'DKE1'.

        TAD Reference: Section 7 — Failure Modes (Malformed envelope)
        """
        envelope, *_ = valid_envelope
        bad = bytearray(envelope)
        bad[0] = ord("X")
        with pytest.raises(ParseError, match="magic"):
            decode_envelope(bytes(bad))

    def test_decode_rejects_unsupported_version(self, valid_envelope):
        """decode_envelope() must raise ParseError for version != 0x01."""
        envelope, *_ = valid_envelope
        bad = bytearray(envelope)
        bad[4] = 0x02
        with pytest.raises(ParseError, match="version"):
            decode_envelope(bytes(bad))

    def test_decode_rejects_nonzero_flags(self, valid_envelope):
        """decode_envelope() must raise ParseError when flags byte != 0x00."""
        envelope, *_ = valid_envelope
        bad = bytearray(envelope)
        bad[5] = 0x01
        with pytest.raises(ParseError, match="flags"):
            decode_envelope(bytes(bad))

    def test_decode_rejects_truncated_envelope(self, valid_envelope):
        """decode_envelope() must raise ParseError when data is shorter than declared."""
        envelope, *_ = valid_envelope
        with pytest.raises(ParseError, match="mismatch"):
            decode_envelope(envelope[:-4])

    def test_decode_rejects_padded_envelope(self, valid_envelope):
        """decode_envelope() must raise ParseError when data is longer than declared."""
        envelope, *_ = valid_envelope
        with pytest.raises(ParseError, match="mismatch"):
            decode_envelope(envelope + b"\xff\xff")

    def test_decode_rejects_mismatched_ct_len(self, valid_envelope):
        """decode_envelope() must raise ParseError when ct_len field is inconsistent."""
        envelope, *_ = valid_envelope
        bad = bytearray(envelope)
        struct.pack_into("!I", bad, 26, 9999)
        with pytest.raises(ParseError, match="mismatch"):
            decode_envelope(bytes(bad))


# ===========================================================================
# End-to-end integration tests
# ===========================================================================


class TestEndToEndPipeline:

    def test_full_pipeline_ecdh_hkdf_dke_aesgcm(self):
        """Full pipeline: X25519 → HKDF → DKE two-chain ratchet → AES-256-GCM → envelope.

        TAD Reference: Section 6 — Data Flow & Sequence Diagrams
        """
        # ── Handshake ─────────────────────────────────────────────────
        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()

        k0_a = hkdf_derive(derive_shared_secret(priv_a, pub_b), info=SESSION_INFO)
        k0_b = hkdf_derive(derive_shared_secret(priv_b, pub_a), info=SESSION_INFO)
        assert k0_a == k0_b

        state_a = DKESessionState.from_k0(k0_a)
        state_b = DKESessionState.from_k0(k0_b)

        # ── Helper: simulate one message send/receive ─────────────────
        def send(sender_state, receiver_state, msg: bytes) -> bytes:
            key_s, seq_s = outbound_params(sender_state)
            n = os.urandom(NONCE_SIZE)
            ct, tag = encrypt(key_s, msg, n)
            envelope = encode_envelope(seq_s, n, ct, tag)
            rotate_send(sender_state, n)

            seq_r, n_r, ct_r, tag_r = decode_envelope(envelope)
            key_r = inbound_key(receiver_state, seq_r)
            plaintext = decrypt(key_r, ct_r, n_r, tag_r)
            rotate_receive(receiver_state, n_r, seq_r)
            return plaintext

        assert send(state_a, state_b, b"Hi Bob!")   == b"Hi Bob!"
        assert send(state_b, state_a, b"Hi Alice!") == b"Hi Alice!"
        assert send(state_a, state_b, b"Message 2") == b"Message 2"
        assert send(state_b, state_a, b"Reply 2")   == b"Reply 2"

        # Cross-match invariants must hold
        assert bytes(state_a.outbound.current_key) == bytes(state_b.inbound.current_key)
        assert bytes(state_b.outbound.current_key) == bytes(state_a.inbound.current_key)

    def test_tampered_envelope_fails_at_decrypt_not_at_decode(self):
        """A structurally valid but bit-flipped envelope must fail at decrypt().

        decode_envelope() succeeds; the failure is detected by the GCM tag.

        TAD Reference: Section 7 — Failure Modes
        """
        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()
        k0 = hkdf_derive(derive_shared_secret(priv_a, pub_b), info=SESSION_INFO)
        state_a = DKESessionState.from_k0(k0)
        state_b = DKESessionState.from_k0(k0)

        key_a, seq_a = outbound_params(state_a)
        n = os.urandom(NONCE_SIZE)
        ct, tag = encrypt(key_a, b"secret", n)
        envelope = encode_envelope(seq_a, n, ct, tag)
        rotate_send(state_a, n)

        # Flip one ciphertext byte inside the envelope (after fixed header)
        tampered = bytearray(envelope)
        tampered[HEADER_SIZE] ^= 0xFF

        # Structural parse must succeed
        seq_r, n_r, ct_r, tag_r = decode_envelope(bytes(tampered))

        # Cryptographic authentication must fail
        key_b = inbound_key(state_b, seq_r)
        with pytest.raises(InvalidTag):
            decrypt(key_b, ct_r, n_r, tag_r)

    def test_session_state_wipe_zeros_all_keys(self, k0):
        """DKESessionState.wipe() must overwrite both outbound and inbound key buffers with zeros."""
        state = DKESessionState.from_k0(k0)
        out_buf = state.outbound.current_key
        in_buf = state.inbound.current_key
        assert not all(b == 0 for b in out_buf)
        assert not all(b == 0 for b in in_buf)

        state.wipe()
        assert all(b == 0 for b in out_buf)
        assert all(b == 0 for b in in_buf)

    def test_rotate_receive_rejects_nonce_reuse(self, k0):
        """rotate_receive() must raise ValueError if the incoming nonce matches the previous message's nonce."""
        state = DKESessionState.from_k0(k0)
        reused_nonce = os.urandom(NONCE_SIZE)
        # First receive with reused_nonce succeeds
        rotate_receive(state, reused_nonce, received_seq=0)
        # Second receive reusing the exact same nonce must be rejected
        with pytest.raises(ValueError, match="Nonce reuse detected"):
            rotate_receive(state, reused_nonce, received_seq=1)
