"""
crypto_core.py — Cryptographic Primitive Wrappers
==================================================
TAD Reference: Section 3.1

Responsibility
--------------
Thin, audited-library-backed wrappers around all raw cryptographic
primitives used by the DKE Messaging Engine.

Design Constraints (from TAD Section 3.1 & 5.3)
-------------------------------------------------
* No hand-rolled ECC — X25519 operations delegate entirely to
  ``cryptography.hazmat.primitives.asymmetric.x25519``.
* No hand-rolled HKDF — uses
  ``cryptography.hazmat.primitives.kdf.hkdf.HKDF``.
* No disk writes — all key material lives in process memory only.
* The ``info`` parameter in ``hkdf_derive()`` MUST be a fixed,
  context-specific ASCII string (e.g., ``"dke-session-init-v1"``) to
  domain-separate different key usages.

Key Hierarchy (TAD Section 5.1)
--------------------------------
  os.urandom()
      │
      └─► X25519 keypair generation
                │
                │  ECDH(a_priv, b_pub) == ECDH(b_priv, a_pub)
                ▼
          Shared Secret (32 bytes raw)
                │
                │  HKDF-SHA256(secret, salt=None, info="dke-session-init-v1")
                ▼
             K0 — Initial Symmetric Key (32 bytes / AES-256)
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Canonical domain-separation label for the initial session key.
#: Both parties MUST use the same string or key derivation will diverge.
SESSION_INFO: str = "dke-session-init-v1"

#: Size of a raw X25519 public key in bytes.
PUBLIC_KEY_SIZE: int = 32

#: Default output length for ``hkdf_derive()``, matching AES-256 key size.
DEFAULT_KEY_LENGTH: int = 32


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Generate an X25519 key pair.

    Delegates entirely to
    ``cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate()``.
    No elliptic-curve arithmetic is performed in this module.

    The private key object is kept in memory only and is never serialised
    to disk by this function.  The caller is responsible for ensuring the
    private key is not persisted beyond the lifetime of the session.

    Returns
    -------
    tuple[X25519PrivateKey, bytes]
        A 2-tuple ``(private_key, public_key_bytes)`` where:

        * ``private_key`` is the opaque ``X25519PrivateKey`` object
          required by :func:`derive_shared_secret`.
        * ``public_key_bytes`` is the raw 32-byte little-endian encoding
          of the corresponding X25519 public key, ready to be sent to the
          peer over the transport.

    Examples
    --------
    >>> priv, pub = generate_keypair()
    >>> assert len(pub) == 32

    TAD Reference: Section 3.1 — generate_keypair()
               Section 5.4 — Algorithm Choices (X25519)
    """
    private_key: X25519PrivateKey = X25519PrivateKey.generate()
    public_key_bytes: bytes = private_key.public_key().public_bytes_raw()
    return private_key, public_key_bytes


def derive_shared_secret(
    private_key: X25519PrivateKey,
    peer_public_key_bytes: bytes,
) -> bytes:
    """Perform X25519 ECDH key agreement and return the raw shared secret.

    Delegates entirely to the ``exchange()`` method of
    ``cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey``.
    No elliptic-curve arithmetic is performed in this module.

    .. warning::
        The returned 32 bytes are the **raw** Diffie-Hellman output.  They
        MUST be passed through :func:`hkdf_derive` before being used as an
        AES-256 key.  Using raw ECDH output directly as a cipher key is a
        cryptographic error.

    Parameters
    ----------
    private_key : X25519PrivateKey
        The local party's X25519 private key, as returned by the first
        element of :func:`generate_keypair`.
    peer_public_key_bytes : bytes
        The peer's raw 32-byte X25519 public key received over the
        transport.  Must be exactly :data:`PUBLIC_KEY_SIZE` (32) bytes.

    Returns
    -------
    bytes
        32-byte raw Diffie-Hellman shared secret.

    Raises
    ------
    ValueError
        If ``peer_public_key_bytes`` is not exactly 32 bytes.
    cryptography.exceptions.InvalidKey
        If the peer's public key is not a valid X25519 point (e.g., the
        low-order point attack).

    Examples
    --------
    >>> priv_a, pub_a = generate_keypair()
    >>> priv_b, pub_b = generate_keypair()
    >>> secret_a = derive_shared_secret(priv_a, pub_b)
    >>> secret_b = derive_shared_secret(priv_b, pub_a)
    >>> assert secret_a == secret_b  # ECDH symmetry

    TAD Reference: Section 3.1 — derive_shared_secret()
               Section 5.1 — Key Hierarchy
               Section 5.2 — Security Properties
    """
    if len(peer_public_key_bytes) != PUBLIC_KEY_SIZE:
        raise ValueError(
            f"peer_public_key_bytes must be exactly {PUBLIC_KEY_SIZE} bytes, "
            f"got {len(peer_public_key_bytes)}."
        )

    peer_public_key: X25519PublicKey = X25519PublicKey.from_public_bytes(
        peer_public_key_bytes
    )
    shared_secret: bytes = private_key.exchange(peer_public_key)
    return shared_secret


def hkdf_derive(
    shared_secret: bytes,
    info: str,
    length: int = DEFAULT_KEY_LENGTH,
) -> bytes:
    """Derive a symmetric key from a raw shared secret using HKDF-SHA-256.

    Delegates entirely to
    ``cryptography.hazmat.primitives.kdf.hkdf.HKDF`` with:

    * ``algorithm`` = SHA-256 (via ``cryptography.hazmat.primitives.hashes.SHA256``)
    * ``salt`` = ``None``  (HKDF spec permits omitting salt; SHA-256 hash
      length is used as the implicit salt per RFC 5869 §2.2)
    * ``info`` = the UTF-8 encoding of the caller-supplied ``info`` string

    No KDF arithmetic is performed in this module.

    Parameters
    ----------
    shared_secret : bytes
        Raw output from :func:`derive_shared_secret`.  Typically 32 bytes
        for X25519, but HKDF-SHA-256 can accept any non-empty input.
    info : str
        Context / domain-separation label that binds the derived key to a
        specific usage.  Both parties MUST supply the identical ``info``
        value or they will derive different keys.

        Recommended value for the initial session key:
        ``"dke-session-init-v1"`` (:data:`SESSION_INFO`).

    length : int, optional
        Number of output key bytes.  Defaults to 32 (:data:`DEFAULT_KEY_LENGTH`),
        matching the AES-256 key size.  Must satisfy
        ``1 <= length <= 255 * 32`` (HKDF-SHA-256 output limit).

    Returns
    -------
    bytes
        ``length``-byte derived symmetric key (K0 for the initial call).

    Raises
    ------
    ValueError
        If ``shared_secret`` is empty or ``length`` is out of range.
    cryptography.exceptions.AlreadyFinalized
        If the internal HKDF object is reused (it is always freshly
        constructed here, so this should never occur).

    Examples
    --------
    >>> priv_a, pub_a = generate_keypair()
    >>> priv_b, pub_b = generate_keypair()
    >>> secret = derive_shared_secret(priv_a, pub_b)
    >>> k0 = hkdf_derive(secret, info=SESSION_INFO)
    >>> assert len(k0) == 32

    TAD Reference: Section 3.1 — hkdf_derive()
               Section 5.1 — Key Hierarchy
               Section 5.4 — Algorithm Choices (HKDF-SHA-256)
    """
    if not shared_secret:
        raise ValueError("shared_secret must not be empty.")

    hkdf = HKDF(
        algorithm=SHA256(),
        length=length,
        salt=None,              # RFC 5869 §2.2: omitted salt → hash-length zeros
        info=info.encode("utf-8"),
    )
    derived_key: bytes = hkdf.derive(shared_secret)
    return derived_key
