"""
protocol.py — Envelope Encoding & AEAD Wrappers
================================================
TAD Reference: Section 3.3, Section 4

Responsibility
--------------
* Serialise and deserialise binary message envelopes (TAD Section 4.1).
* Wrap AES-256-GCM encryption and decryption from the ``cryptography``
  (pyca) library.

This module does NOT implement AES or GCM itself.

Wire Format (TAD Section 4.1)
-------------------------------
All multi-byte integer fields are BIG-ENDIAN.

  Byte offset  Field                Size    struct token
  -----------  -------------------  ------  ------------
  0            Magic  (b"DKE1")     4 B     4s
  4            Version              1 B     B
  5            Flags                1 B     B   (reserved; must be 0x00 in v1)
  6            Sequence Number      8 B     Q   (uint64, big-endian)
  14           Nonce                12 B    12s (AES-GCM nonce)
  26           Ciphertext Length    4 B     I   (uint32, big-endian)
  30           Ciphertext           N B     (variable)
  30+N         Authentication Tag   16 B    (AES-GCM 128-bit tag)

Fixed header = 30 bytes (packed with ``_HEADER_STRUCT``).
Minimum envelope size = 46 bytes (header + empty ciphertext + 16-byte tag).

``decode_envelope()`` validates:
  1. Total length >= 46 bytes (before reading any field).
  2. Magic == b"DKE1".
  3. Version == 0x01.
  4. Flags == 0x00 (reserved in v1).
  5. Total length == 30 + ct_len + 16 (declared vs. actual consistency).

AEAD Contract (TAD Section 3.3)
---------------------------------
* ``encrypt()`` delegates to
  ``cryptography.hazmat.primitives.ciphers.aead.AESGCM``.
* AESGCM.encrypt() returns ``ciphertext || tag`` concatenated; this module
  splits them before returning so the caller handles ciphertext and tag as
  separate fields (matching the envelope wire format).
* ``decrypt()`` re-concatenates ``ciphertext + tag`` before passing to
  AESGCM.decrypt(), which raises ``cryptography.exceptions.InvalidTag`` on
  any authentication failure.
* ``decrypt()`` NEVER returns plaintext on failure (fail-closed, TAD §7.1).
"""

from __future__ import annotations

import struct

from cryptography.exceptions import InvalidTag  # re-exported for callers
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Wire-format constants
# ---------------------------------------------------------------------------

#: 4-byte protocol identifier at the start of every envelope.
MAGIC: bytes = b"DKE1"

#: Current protocol version byte.
VERSION: int = 0x01

#: Size of the AES-GCM authentication tag in bytes.
TAG_SIZE: int = 16

#: Size of the AES-GCM nonce in bytes.
NONCE_SIZE: int = 12

#: Size of the AES-256 key in bytes.
KEY_SIZE: int = 32

#: Minimum legal envelope size in bytes (TAD Section 4.2).
#: = 4 (magic) + 1 (version) + 1 (flags) + 8 (seq) + 12 (nonce)
#:   + 4 (ct_len) + 0 (empty ct) + 16 (tag)
MIN_ENVELOPE_SIZE: int = 46

# ---------------------------------------------------------------------------
# Struct for the fixed-size envelope header (30 bytes)
# ---------------------------------------------------------------------------
# Format characters (all big-endian via '!'):
#   4s  — 4-byte magic string
#   B   — version (uint8)
#   B   — flags   (uint8)
#   Q   — sequence number (uint64)
#   12s — nonce   (12 raw bytes)
#   I   — ciphertext length (uint32)
_HEADER_STRUCT: struct.Struct = struct.Struct("!4sBBQ12sI")

#: Byte length of the fixed header portion (everything before ciphertext).
HEADER_SIZE: int = _HEADER_STRUCT.size   # == 30

assert HEADER_SIZE == 30, "Header struct size mismatch — check format string."
assert MIN_ENVELOPE_SIZE == HEADER_SIZE + TAG_SIZE, (
    "MIN_ENVELOPE_SIZE must equal HEADER_SIZE + TAG_SIZE."
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ParseError(Exception):
    """Raised by :func:`decode_envelope` when the envelope is malformed.

    Covers all structural problems: wrong length, bad magic, unsupported
    version, non-zero reserved flags, or an inconsistent ciphertext-length
    field.

    The session continues after a ``ParseError``; only the individual
    message is dropped.

    TAD Reference: Section 7 — Failure Modes (Malformed envelope)
    """


# Re-export InvalidTag so callers can catch it without importing from
# cryptography directly.
__all__ = [
    "MAGIC", "VERSION", "TAG_SIZE", "NONCE_SIZE", "KEY_SIZE",
    "MIN_ENVELOPE_SIZE", "HEADER_SIZE",
    "ParseError", "InvalidTag",
    "encode_envelope", "decode_envelope",
    "encrypt", "decrypt",
]


# ---------------------------------------------------------------------------
# Envelope encoding
# ---------------------------------------------------------------------------


def encode_envelope(
    sequence: int,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    flags: int = 0x00,
) -> bytes:
    """Serialise message fields into the DKE binary wire format.

    Packs the fixed header using :data:`_HEADER_STRUCT` (big-endian) then
    appends the variable-length ciphertext and the 16-byte authentication
    tag.

    Parameters
    ----------
    sequence : int
        Unsigned 64-bit sequence number for this message direction.
        Must satisfy ``0 <= sequence < 2**64``.
    nonce : bytes
        12-byte AES-GCM nonce for this message (from ``os.urandom(12)``).
        Must be exactly :data:`NONCE_SIZE` bytes.
    ciphertext : bytes
        AES-256-GCM ciphertext returned by :func:`encrypt`.
        May be empty (zero-length plaintext is valid).
    tag : bytes
        16-byte AES-256-GCM authentication tag returned by :func:`encrypt`.
        Must be exactly :data:`TAG_SIZE` bytes.
    flags : int, optional
        Reserved flags byte.  Must be ``0x00`` in protocol version 1.
        Defaults to ``0x00``.

    Returns
    -------
    bytes
        Fully framed binary envelope (>= :data:`MIN_ENVELOPE_SIZE` bytes),
        ready for transmission over the transport.

    Raises
    ------
    ValueError
        If ``nonce`` is not 12 bytes, ``tag`` is not 16 bytes, or
        ``sequence`` is out of the uint64 range.

    Examples
    --------
    >>> import os
    >>> key = os.urandom(32)
    >>> nonce = os.urandom(12)
    >>> ct, tag = encrypt(key, b"hello", nonce)
    >>> envelope = encode_envelope(sequence=0, nonce=nonce, ciphertext=ct, tag=tag)
    >>> assert len(envelope) >= 46

    TAD Reference: Section 3.3 — encode_envelope()
               Section 4.1 — Envelope Structure
    """
    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}."
        )
    if len(tag) != TAG_SIZE:
        raise ValueError(
            f"tag must be {TAG_SIZE} bytes, got {len(tag)}."
        )
    if not (0 <= sequence < 2**64):
        raise ValueError(
            f"sequence must be in [0, 2^64), got {sequence}."
        )

    header: bytes = _HEADER_STRUCT.pack(
        MAGIC,
        VERSION,
        flags,
        sequence,
        nonce,
        len(ciphertext),
    )
    return header + ciphertext + tag


# ---------------------------------------------------------------------------
# Envelope decoding
# ---------------------------------------------------------------------------


def decode_envelope(raw: bytes) -> tuple[int, bytes, bytes, bytes]:
    """Parse and validate a raw binary envelope.

    Performs **strict length checks before parsing any fields** to avoid
    information leakage from partial parsing of malformed input.

    Validation order
    ----------------
    1. ``len(raw) >= 46`` — absolute minimum check (no field reads before this).
    2. Unpack fixed header via :data:`_HEADER_STRUCT`.
    3. ``magic == b"DKE1"`` — protocol identifier.
    4. ``version == 0x01`` — supported version.
    5. ``flags == 0x00`` — reserved bits (v1 must be zero).
    6. ``len(raw) == HEADER_SIZE + ct_len + TAG_SIZE`` — declared vs. actual
       consistency.  Rejects both truncated and padded envelopes.

    Parameters
    ----------
    raw : bytes
        Raw bytes received from the transport.

    Returns
    -------
    tuple[int, bytes, bytes, bytes]
        ``(sequence, nonce, ciphertext, tag)`` where:

        * ``sequence`` — uint64 sequence number.
        * ``nonce`` — 12-byte AES-GCM nonce.
        * ``ciphertext`` — variable-length ciphertext bytes.
        * ``tag`` — 16-byte AES-GCM authentication tag.

    Raises
    ------
    ParseError
        On any structural problem with the envelope.  Plaintext is never
        touched; the failure is purely structural.

    Examples
    --------
    >>> import os
    >>> key = os.urandom(32)
    >>> nonce = os.urandom(12)
    >>> ct, tag = encrypt(key, b"hello", nonce)
    >>> envelope = encode_envelope(0, nonce, ct, tag)
    >>> seq, n, c, t = decode_envelope(envelope)
    >>> assert seq == 0 and n == nonce and c == ct and t == tag

    TAD Reference: Section 3.3 — decode_envelope()
               Section 4.1 — Envelope Structure
               Section 4.2 — Minimum Envelope Size
               Section 7   — Failure Modes (Malformed envelope)
    """
    # ----------------------------------------------------------------
    # Check 1: absolute minimum length (no struct reads before this)
    # ----------------------------------------------------------------
    if len(raw) < MIN_ENVELOPE_SIZE:
        raise ParseError(
            f"Envelope too short: got {len(raw)} bytes, "
            f"minimum is {MIN_ENVELOPE_SIZE}."
        )

    # ----------------------------------------------------------------
    # Check 2: unpack fixed header
    # ----------------------------------------------------------------
    try:
        magic, version, flags, sequence, nonce, ct_len = (
            _HEADER_STRUCT.unpack_from(raw, offset=0)
        )
    except struct.error as exc:
        raise ParseError(f"Header unpack failed: {exc}") from exc

    # ----------------------------------------------------------------
    # Check 3: magic identifier
    # ----------------------------------------------------------------
    if magic != MAGIC:
        raise ParseError(
            f"Bad magic bytes: got {magic!r}, expected {MAGIC!r}."
        )

    # ----------------------------------------------------------------
    # Check 4: version
    # ----------------------------------------------------------------
    if version != VERSION:
        raise ParseError(
            f"Unsupported protocol version: {version:#04x} "
            f"(this implementation supports {VERSION:#04x} only)."
        )

    # ----------------------------------------------------------------
    # Check 5: reserved flags
    # ----------------------------------------------------------------
    if flags != 0x00:
        raise ParseError(
            f"Non-zero flags byte: {flags:#04x}. "
            "Flags are reserved and must be 0x00 in protocol v1."
        )

    # ----------------------------------------------------------------
    # Check 6: declared length vs. actual length
    # ----------------------------------------------------------------
    expected_total: int = HEADER_SIZE + ct_len + TAG_SIZE
    if len(raw) != expected_total:
        raise ParseError(
            f"Length mismatch: header declares {ct_len}-byte ciphertext + "
            f"{TAG_SIZE}-byte tag = {expected_total} bytes total, "
            f"but envelope is {len(raw)} bytes."
        )

    # ----------------------------------------------------------------
    # Slice ciphertext and tag (safe — lengths validated above)
    # ----------------------------------------------------------------
    ct_start: int = HEADER_SIZE
    ct_end: int = ct_start + ct_len
    tag_end: int = ct_end + TAG_SIZE

    ciphertext: bytes = raw[ct_start:ct_end]
    tag: bytes = raw[ct_end:tag_end]

    return sequence, nonce, ciphertext, tag


# ---------------------------------------------------------------------------
# AEAD wrappers
# ---------------------------------------------------------------------------


def encrypt(key: bytes, plaintext: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM.

    Delegates entirely to
    ``cryptography.hazmat.primitives.ciphers.aead.AESGCM``.
    No AES or GCM arithmetic is performed in this module.

    ``AESGCM.encrypt()`` returns ``ciphertext || tag`` concatenated.
    This function splits the combined output into separate ``(ciphertext, tag)``
    fields to match the envelope wire format (TAD Section 4.1).

    Parameters
    ----------
    key : bytes
        32-byte AES-256 symmetric key (current ratchet key K_i, obtained
        from :func:`dke_engine.outbound_params`).  Must be exactly
        :data:`KEY_SIZE` bytes.
    plaintext : bytes
        The message bytes to encrypt.  May be empty.
    nonce : bytes
        12-byte unique nonce for this message.  MUST be generated by the
        caller using ``os.urandom(12)`` immediately before each call.
        Reusing a nonce under the same key is catastrophic for AES-GCM
        security.  Must be exactly :data:`NONCE_SIZE` bytes.

    Returns
    -------
    tuple[bytes, bytes]
        ``(ciphertext, tag)`` where:

        * ``ciphertext`` has the same length as ``plaintext``.
        * ``tag`` is exactly :data:`TAG_SIZE` (16) bytes.

    Raises
    ------
    ValueError
        If ``key`` is not 32 bytes or ``nonce`` is not 12 bytes.

    Examples
    --------
    >>> import os
    >>> key   = os.urandom(32)
    >>> nonce = os.urandom(12)
    >>> ct, tag = encrypt(key, b"hello world", nonce)
    >>> assert len(tag) == 16
    >>> assert len(ct) == len(b"hello world")

    TAD Reference: Section 3.3 — encrypt()
               Section 5.2 — Confidentiality, Integrity & Authenticity
               Section 5.4 — AES-256-GCM algorithm choice
    """
    if len(key) != KEY_SIZE:
        raise ValueError(
            f"key must be {KEY_SIZE} bytes, got {len(key)}."
        )
    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}."
        )

    aesgcm = AESGCM(key)
    # AESGCM.encrypt(nonce, data, aad) returns ciphertext || tag (tag is last 16 B)
    combined: bytes = aesgcm.encrypt(nonce, plaintext, None)

    ciphertext: bytes = combined[:-TAG_SIZE]
    tag: bytes = combined[-TAG_SIZE:]
    return ciphertext, tag


def decrypt(
    key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
) -> bytes:
    """Decrypt and authenticate a ciphertext with AES-256-GCM.

    Delegates entirely to
    ``cryptography.hazmat.primitives.ciphers.aead.AESGCM``.
    No AES or GCM arithmetic is performed in this module.

    Concatenates ``ciphertext + tag`` before passing to
    ``AESGCM.decrypt()``, which requires the combined form.  If the tag
    does not authenticate the ciphertext, ``AESGCM.decrypt()`` raises
    ``cryptography.exceptions.InvalidTag`` **before returning any bytes**.
    This function propagates that exception unchanged — it NEVER returns
    plaintext on an authentication failure (fail-closed, TAD §7.1).

    Parameters
    ----------
    key : bytes
        32-byte AES-256 symmetric key (current ratchet key K_i, obtained
        from :func:`dke_engine.inbound_key`).  Must be exactly
        :data:`KEY_SIZE` bytes.
    ciphertext : bytes
        The ciphertext field from :func:`decode_envelope`.
    nonce : bytes
        The 12-byte nonce field from :func:`decode_envelope`.
    tag : bytes
        The 16-byte authentication tag field from :func:`decode_envelope`.
        Must be exactly :data:`TAG_SIZE` bytes.

    Returns
    -------
    bytes
        Verified plaintext.  Returned only when authentication succeeds.

    Raises
    ------
    cryptography.exceptions.InvalidTag
        If the authentication tag does not match the ciphertext.
        No plaintext (or partial plaintext) is ever returned in this case.
    ValueError
        If ``key`` is not 32 bytes, ``nonce`` is not 12 bytes, or
        ``tag`` is not 16 bytes.

    Examples
    --------
    >>> import os
    >>> key   = os.urandom(32)
    >>> nonce = os.urandom(12)
    >>> ct, tag = encrypt(key, b"hello world", nonce)
    >>> plaintext = decrypt(key, ct, nonce, tag)
    >>> assert plaintext == b"hello world"

    TAD Reference: Section 3.3 — decrypt()
               Section 7   — Failure Modes (Authentication tag mismatch)
               Section 7.1 — Fail-closed policy
    """
    if len(key) != KEY_SIZE:
        raise ValueError(
            f"key must be {KEY_SIZE} bytes, got {len(key)}."
        )
    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}."
        )
    if len(tag) != TAG_SIZE:
        raise ValueError(
            f"tag must be {TAG_SIZE} bytes, got {len(tag)}."
        )

    aesgcm = AESGCM(key)
    # AESGCM.decrypt expects ciphertext || tag concatenated
    combined: bytes = ciphertext + tag
    # Raises cryptography.exceptions.InvalidTag on authentication failure;
    # no plaintext is ever returned in that case.
    plaintext: bytes = aesgcm.decrypt(nonce, combined, None)
    return plaintext
