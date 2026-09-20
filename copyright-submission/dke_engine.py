"""
dke_engine.py — Dynamic Key Evolution State Machine
=====================================================
TAD Reference: Section 3.2

Responsibility
--------------
Maintains per-session ratchet state and advances the symmetric key after
every successful send or receive, providing **forward secrecy** within a
session.

Key Evolution Formula (TAD Section 3.2)
-----------------------------------------
  K_(i+1) = SHA-256( K_i || nonce_i || seq_i )

where ``||`` is concatenation and ``seq_i`` is encoded as a fixed-width
big-endian unsigned 64-bit integer.

Design: Two Independent Ratchet Chains
---------------------------------------
Each session maintains **two completely independent** key chains:

  Outbound chain  (local send  → peer receive)
    outbound.current_key       — current AES-256 encryption key
    outbound.sequence_number   — next sequence number to embed in envelope
    outbound.last_nonce        — nonce used in the most recent send step

  Inbound chain   (peer send  → local receive)
    inbound.current_key        — current AES-256 decryption key
    inbound.sequence_number    — next sequence number expected from peer
    inbound.last_nonce         — nonce used in the most recent receive step

Both chains are seeded from the same K0 at session start, then diverge
independently.  This means:

  * A long run of outbound-only messages does NOT advance the inbound key
    (no key desynchronisation risk).
  * The outbound and inbound chains cannot interfere with each other.
  * The cross-matching invariant always holds after any exchange:

        sender.outbound.current_key == receiver.inbound.current_key

Memory Safety Rule (TAD Section 3.2)
--------------------------------------
After ``advance_key()`` produces ``K_(i+1)``, the engine overwrites the
memory location of ``K_i`` with zeros before releasing the reference.
``current_key`` is stored as a ``bytearray`` so this zeroing is in-place.

Sequence Number Policy (TAD Section 3.2)
-----------------------------------------
* Outbound and inbound sequence numbers advance independently.
* Sequence numbers are STRICTLY MONOTONIC — no gaps, no reuse.

Ratchet Lifecycle (one direction shown)
-----------------------------------------
  K0  (from hkdf_derive)
   │
   │── send / receive message 0  (nonce_0)
   ▼
  K1 = SHA-256(K0 || nonce_0 || 0)   ← K0 memory overwritten
   │
   │── send / receive message 1  (nonce_1)
   ▼
  K2 = SHA-256(K1 || nonce_1 || 1)   ← K1 memory overwritten
   │
  ...

Typical usage in main_chat.py
------------------------------
Send path::

    key, seq = dke_engine.outbound_params(state)
    nonce    = os.urandom(12)
    ct, tag  = protocol.encrypt(key, plaintext, nonce)
    envelope = protocol.encode_envelope(seq, nonce, ct, tag)
    transport.send(envelope)
    dke_engine.rotate_send(state, nonce)        # erases old outbound key

Receive path::

    seq_r, nonce_r, ct_r, tag_r = protocol.decode_envelope(raw)
    key_r    = dke_engine.inbound_key(state, seq_r)   # validates seq
    plaintext = protocol.decrypt(key_r, ct_r, nonce_r, tag_r)  # raises on fail
    dke_engine.rotate_receive(state, nonce_r, seq_r)  # erases old inbound key
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Expected key size in bytes (AES-256).
KEY_SIZE: int = 32

#: Expected nonce size in bytes (AES-GCM).
NONCE_SIZE: int = 12

#: Width (bytes) used to encode a sequence number in the hash input.
#: uint64 big-endian → 8 bytes.
_SEQ_WIDTH: int = 8


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SequenceError(ValueError):
    """Raised when a received sequence number does not match the expected value.

    This indicates either an out-of-order delivery or a replay attempt.
    The session continues; only the individual message is dropped.

    TAD Reference: Section 7 — Failure Modes (Out-of-order / Replay)
    """


# ---------------------------------------------------------------------------
# Direction State
# ---------------------------------------------------------------------------


@dataclass
class DirectionState:
    """Ratchet state for **one** message direction (outbound or inbound).

    Holds the current symmetric key, the next expected / next-to-use
    sequence number, and the nonce used in the most recent ratchet step
    (kept for audit / logging only).

    ``current_key`` is a :class:`bytearray` so it can be overwritten
    in-place with zeros before the reference is released (best-effort
    memory erasure, TAD Section 3.2).

    Attributes
    ----------
    current_key : bytearray
        The current 32-byte AES-256 symmetric key for this direction.
    sequence_number : int
        For the **outbound** direction: the sequence number that will be
        embedded in the *next* outgoing envelope.
        For the **inbound** direction: the sequence number *expected* in
        the next incoming envelope.
        Starts at 0; strictly monotonically increasing.
    last_nonce : bytes
        The 12-byte nonce from the most recent ratchet step in this
        direction.  Initialised to 12 zero bytes; used for audit only.

    TAD Reference: Section 3.2 — Session State (per-direction variant)
    """

    current_key: bytearray
    sequence_number: int = 0
    last_nonce: bytes = field(default_factory=lambda: b"\x00" * NONCE_SIZE)


# ---------------------------------------------------------------------------
# Session State
# ---------------------------------------------------------------------------


@dataclass
class DKESessionState:
    """Full DKE session state with **separate** outbound and inbound chains.

    Both chains are seeded from the same K0 (from ``crypto_core.hkdf_derive``)
    and then evolve completely independently.  This guarantees:

    * Sending many messages does not advance the receive-side key.
    * The cross-matching invariant always holds after any exchange:

          sender.outbound.current_key == receiver.inbound.current_key

    Attributes
    ----------
    outbound : DirectionState
        Ratchet chain for messages *sent* by this party.
    inbound : DirectionState
        Ratchet chain for messages *received* by this party.

    TAD Reference: Section 3.2 — Session State
               Section 3.2 — Sequence Number Policy
    """

    outbound: DirectionState
    inbound: DirectionState

    # ------------------------------------------------------------------
    # Constructor helper
    # ------------------------------------------------------------------

    @classmethod
    def from_k0(cls, k0: bytes) -> DKESessionState:
        """Create a fresh session state seeded from the initial derived key K0.

        Both the outbound and inbound chains start from the same K0.
        They diverge independently as messages are exchanged.

        Parameters
        ----------
        k0 : bytes
            32-byte initial symmetric key produced by
            ``crypto_core.hkdf_derive()``.  Must be exactly
            :data:`KEY_SIZE` (32) bytes.

        Returns
        -------
        DKESessionState
            Fresh session state with both sequence counters at 0 and both
            chain keys set to mutable copies of ``k0``.

        Raises
        ------
        ValueError
            If ``k0`` is not exactly 32 bytes.

        Examples
        --------
        >>> from crypto_core import generate_keypair, derive_shared_secret, hkdf_derive, SESSION_INFO
        >>> priv_a, pub_a = generate_keypair()
        >>> priv_b, pub_b = generate_keypair()
        >>> secret = derive_shared_secret(priv_a, pub_b)
        >>> k0 = hkdf_derive(secret, info=SESSION_INFO)
        >>> state = DKESessionState.from_k0(k0)
        >>> assert len(state.outbound.current_key) == 32
        >>> assert len(state.inbound.current_key) == 32

        TAD Reference: Section 6.1 — Session Establishment
        """
        if len(k0) != KEY_SIZE:
            raise ValueError(
                f"k0 must be exactly {KEY_SIZE} bytes, got {len(k0)}."
            )
        return cls(
            outbound=DirectionState(current_key=bytearray(k0)),
            inbound=DirectionState(current_key=bytearray(k0)),
        )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _erase(buf: bytearray) -> None:
    """Best-effort in-place zeroing of a ``bytearray`` key buffer.

    Overwrites every byte position with ``0x00``.  Python's object model
    (reference counting, interning, GC) means true cryptographic erasure
    is not possible at the language level; this is the best effort available.

    Parameters
    ----------
    buf : bytearray
        The mutable key buffer to zero.

    TAD Reference: Section 3.2 — Memory Safety Rule
    """
    for i in range(len(buf)):
        buf[i] = 0


# ---------------------------------------------------------------------------
# Core ratchet — pure function
# ---------------------------------------------------------------------------


def advance_key(
    current_key: bytes | bytearray,
    nonce: bytes,
    sequence: int,
) -> bytes:
    """Advance the ratchet and return the next symmetric key.

    Computes the one-way hash chain step::

        next_key = SHA-256(
            current_key                         # 32 bytes
            || nonce                            # 12 bytes
            || sequence.to_bytes(8, 'big')      # 8 bytes
        )

    This is a **pure function** — it does not modify ``current_key`` or
    any session state.  The caller is responsible for:

    1. Zeroing the old key buffer (use :func:`rotate_send` or
       :func:`rotate_receive`, which handle this automatically).
    2. Storing the returned bytes as the new ``DirectionState.current_key``.
    3. Incrementing the appropriate ``sequence_number``.

    The SHA-256 one-way property ensures ``current_key`` (K_i) cannot be
    recovered from ``next_key`` (K_(i+1)), providing forward secrecy
    within a session (TAD Section 5.2).

    Parameters
    ----------
    current_key : bytes or bytearray
        The current 32-byte AES-256 key (K_i) for this direction.
    nonce : bytes
        The 12-byte AES-GCM nonce associated with the message that
        triggers this advance.  Including the nonce makes each step
        unique even across session restarts.
    sequence : int
        The sequence number of the message that triggers this advance.
        Encoded as a big-endian unsigned 64-bit integer before hashing.
        Must satisfy ``0 <= sequence < 2**64``.

    Returns
    -------
    bytes
        32-byte next symmetric key (K_(i+1)).

    Raises
    ------
    ValueError
        If ``current_key`` is not exactly :data:`KEY_SIZE` bytes, ``nonce``
        is not exactly :data:`NONCE_SIZE` bytes, or ``sequence`` is negative.

    Examples
    --------
    >>> import os
    >>> k0 = os.urandom(32)
    >>> nonce = os.urandom(12)
    >>> k1 = advance_key(k0, nonce, sequence=0)
    >>> assert len(k1) == 32
    >>> assert k1 != k0                      # key changed
    >>> assert advance_key(k0, nonce, 0) == k1  # deterministic

    TAD Reference: Section 3.2 — advance_key() & Key Evolution Formula
               Section 5.2 — Forward Secrecy, Key Non-reversibility
    """
    if len(current_key) != KEY_SIZE:
        raise ValueError(
            f"current_key must be {KEY_SIZE} bytes, got {len(current_key)}."
        )
    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}."
        )
    if sequence < 0:
        raise ValueError(
            f"sequence must be non-negative, got {sequence}."
        )

    seq_bytes: bytes = sequence.to_bytes(_SEQ_WIDTH, byteorder="big")
    hash_input: bytes = bytes(current_key) + nonce + seq_bytes
    return hashlib.sha256(hash_input).digest()


# ---------------------------------------------------------------------------
# Sequence validation
# ---------------------------------------------------------------------------


def validate_sequence(expected: int, received: int) -> None:
    """Assert that a received sequence number exactly matches the expected value.

    The inbound chain maintains a strict counter of how many messages
    have been processed from the peer.  Any deviation — caused by loss,
    reordering, or an adversarial replay — is treated as a fatal error for
    that individual message.  The session itself continues (TAD Section 7).

    Parameters
    ----------
    expected : int
        The next sequence number the receiver anticipates, i.e., the
        current value of ``DirectionState.sequence_number`` on the inbound
        chain.
    received : int
        The sequence number extracted from the decoded envelope.

    Raises
    ------
    SequenceError
        If ``received != expected``.

    Examples
    --------
    >>> validate_sequence(expected=3, received=3)   # OK — no exception
    >>> validate_sequence(expected=3, received=4)   # raises SequenceError

    TAD Reference: Section 3.2 — Sequence Number Policy
               Section 7   — Failure Modes (Out-of-order / Replay)
    """
    if received != expected:
        raise SequenceError(
            f"Sequence mismatch: expected {expected}, received {received}. "
            "Message dropped (possible replay or out-of-order delivery)."
        )


# ---------------------------------------------------------------------------
# High-level session helpers (called by main_chat.py)
# ---------------------------------------------------------------------------


def outbound_params(state: DKESessionState) -> tuple[bytes, int]:
    """Return a key snapshot and sequence number for the next outbound message.

    Call this immediately before ``protocol.encrypt()`` to obtain the key
    and sequence number for the current outgoing message.  Returns an
    immutable ``bytes`` snapshot — the outbound chain is **not** advanced.
    Call :func:`rotate_send` after a successful send to advance the chain
    and erase the old key.

    Parameters
    ----------
    state : DKESessionState
        Active session state.

    Returns
    -------
    tuple[bytes, int]
        ``(key_snapshot, outbound_seq)`` where:

        * ``key_snapshot`` — immutable 32-byte copy of
          ``state.outbound.current_key`` for use in ``protocol.encrypt()``.
        * ``outbound_seq`` — the sequence number to embed in the envelope
          (``protocol.encode_envelope()`` argument).

    TAD Reference: Section 6.2 — Steady-State Send
    """
    return bytes(state.outbound.current_key), state.outbound.sequence_number


def inbound_key(state: DKESessionState, received_seq: int) -> bytes:
    """Validate the received sequence number and return the inbound key snapshot.

    Call this immediately before ``protocol.decrypt()`` to get the key
    that should authenticate and decrypt the incoming message.  Raises
    :class:`SequenceError` **before** touching or returning the key if the
    sequence number is wrong, so ratchet state is never modified on a bad
    message.

    Call :func:`rotate_receive` **only after** a successful
    ``protocol.decrypt()`` returns (authentication tag verified).

    Parameters
    ----------
    state : DKESessionState
        Active session state.
    received_seq : int
        Sequence number extracted from the decoded envelope.

    Returns
    -------
    bytes
        Immutable 32-byte copy of ``state.inbound.current_key`` for use in
        ``protocol.decrypt()``.

    Raises
    ------
    SequenceError
        If ``received_seq`` does not equal the expected inbound sequence
        counter.  State is NOT modified when this is raised.

    TAD Reference: Section 3.2 — Sequence Number Policy
               Section 7   — Failure Modes (Out-of-order / Replay)
               Section 6.2 — Steady-State Receive
    """
    validate_sequence(state.inbound.sequence_number, received_seq)
    return bytes(state.inbound.current_key)


def rotate_send(state: DKESessionState, nonce: bytes) -> None:
    """Advance the **outbound** ratchet after a successful send.

    Steps performed atomically from the caller's perspective:

    1. Read ``state.outbound.sequence_number`` (the seq of the just-sent message).
    2. Compute ``K_(i+1) = advance_key(outbound.current_key, nonce, seq)``.
    3. Zero ``state.outbound.current_key`` buffer in-place (best-effort erasure).
    4. Replace ``state.outbound.current_key`` with ``bytearray(K_(i+1))``.
    5. Update ``state.outbound.last_nonce``.
    6. Increment ``state.outbound.sequence_number``.

    The **inbound** chain is not touched.

    .. warning::
        Call this **only after** the envelope has been successfully sent
        over the transport.  If the send fails, leave state unchanged so
        the same key and sequence number can be used for a retry.

    Parameters
    ----------
    state : DKESessionState
        Active session state (``state.outbound`` mutated in-place).
    nonce : bytes
        The 12-byte nonce that was passed to ``protocol.encrypt()`` for
        this message.

    Raises
    ------
    ValueError
        If ``nonce`` is not exactly 12 bytes (propagated from
        :func:`advance_key`).

    TAD Reference: Section 3.2 — Memory Safety Rule & Key Evolution Formula
               Section 6.2 — Steady-State Send
    """
    seq: int = state.outbound.sequence_number
    next_key: bytes = advance_key(state.outbound.current_key, nonce, seq)

    _erase(state.outbound.current_key)          # best-effort erasure
    state.outbound.current_key = bytearray(next_key)
    state.outbound.last_nonce = nonce
    state.outbound.sequence_number += 1


def rotate_receive(
    state: DKESessionState,
    nonce: bytes,
    received_seq: int,
) -> None:
    """Advance the **inbound** ratchet after a successful receive and decrypt.

    Steps performed:

    1. Validate ``received_seq`` against the expected inbound counter —
       raises :class:`SequenceError` if wrong; state is **not** modified.
    2. Compute ``K_(i+1) = advance_key(inbound.current_key, nonce, received_seq)``.
    3. Zero ``state.inbound.current_key`` buffer in-place (best-effort erasure).
    4. Replace ``state.inbound.current_key`` with ``bytearray(K_(i+1))``.
    5. Update ``state.inbound.last_nonce``.
    6. Increment ``state.inbound.sequence_number``.

    The **outbound** chain is not touched.

    .. warning::
        Call this **only after** ``protocol.decrypt()`` has returned
        successfully (authentication tag verified).  If decryption raises,
        do NOT call this function — the old key must remain so the next
        valid message can be processed.

    Parameters
    ----------
    state : DKESessionState
        Active session state (``state.inbound`` mutated in-place).
    nonce : bytes
        The 12-byte nonce extracted from the decoded envelope.
    received_seq : int
        The sequence number extracted from the decoded envelope.

    Raises
    ------
    SequenceError
        If ``received_seq`` does not match the expected inbound counter.
        State is NOT modified when this is raised.
    ValueError
        If ``nonce`` is not exactly 12 bytes (propagated from
        :func:`advance_key`).

    TAD Reference: Section 3.2 — Memory Safety Rule & Key Evolution Formula
               Section 7   — Failure Modes (Out-of-order / Replay)
               Section 6.2 — Steady-State Receive
    """
    validate_sequence(state.inbound.sequence_number, received_seq)  # raises before touching state

    next_key: bytes = advance_key(state.inbound.current_key, nonce, received_seq)

    _erase(state.inbound.current_key)           # best-effort erasure
    state.inbound.current_key = bytearray(next_key)
    state.inbound.last_nonce = nonce
    state.inbound.sequence_number += 1
