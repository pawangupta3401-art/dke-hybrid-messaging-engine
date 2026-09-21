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
  Ed25519 signing/verification delegates entirely to
  ``cryptography.hazmat.primitives.asymmetric.ed25519``.
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
      ├─► Ed25519 identity keypair  (long-term, one per process lifetime)
      │       │
      │       └─► sign(ephemeral ECDH pub)  →  64-byte signature
      │
      └─► X25519 ephemeral keypair (per-session)
                │
                │  ECDH(a_priv, b_pub) == ECDH(b_priv, a_pub)
                ▼
          Shared Secret (32 bytes raw)
                │
                │  HKDF-SHA256(secret, salt=None, info="dke-session-init-v1")
                ▼
             K0 — Initial Symmetric Key (32 bytes / AES-256)

MITM Mitigation (Section 3.1 — Identity Authentication)
---------------------------------------------------------
Before shared-secret derivation, each party signs its ephemeral X25519
public key with its long-term Ed25519 identity private key.  The peer
verifies this signature against the known identity public key.  An
attacker who substitutes a different ephemeral key cannot produce a
valid signature without the identity private key, so the forgery is
detected and the session is aborted.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature  # re-exported for callers
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
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

#: Size of a raw Ed25519 public key in bytes.
IDENTITY_PUBLIC_KEY_SIZE: int = 32

#: Size of an Ed25519 signature in bytes.
SIGNATURE_SIZE: int = 64


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


# ---------------------------------------------------------------------------
# Ed25519 Identity Authentication
# ---------------------------------------------------------------------------


def generate_identity_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Generate a long-term Ed25519 identity key pair.

    Delegates entirely to
    ``cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate()``.
    No elliptic-curve arithmetic is performed in this module.

    The identity key pair is generated **once per process lifetime** and
    never serialised to disk by this function.  It is used only for
    authenticating ephemeral X25519 public keys during session
    establishment (MITM mitigation).

    Returns
    -------
    tuple[Ed25519PrivateKey, bytes]
        A 2-tuple ``(private_key, public_key_bytes)`` where:

        * ``private_key`` is the opaque ``Ed25519PrivateKey`` object
          required by :func:`sign_public_key`.
        * ``public_key_bytes`` is the raw 32-byte encoding of the
          corresponding Ed25519 public key, to be shared out-of-band
          with the peer (the "identity fingerprint").

    Examples
    --------
    >>> id_priv, id_pub = generate_identity_keypair()
    >>> assert len(id_pub) == 32

    TAD Reference: Section 3.1 — Identity Authentication (MITM Mitigation)
    """
    private_key: Ed25519PrivateKey = Ed25519PrivateKey.generate()
    public_key_bytes: bytes = private_key.public_key().public_bytes_raw()
    return private_key, public_key_bytes


def sign_public_key(
    identity_private: Ed25519PrivateKey,
    ecdh_pub_bytes: bytes,
) -> bytes:
    """Sign an ephemeral X25519 public key with the Ed25519 identity private key.

    Produces a 64-byte Ed25519 signature over ``ecdh_pub_bytes``.  The
    peer will verify this signature against the sender's known identity
    public key before accepting the ephemeral key for ECDH.

    Delegates entirely to ``Ed25519PrivateKey.sign()``.  No signing
    arithmetic is performed in this module.

    Parameters
    ----------
    identity_private : Ed25519PrivateKey
        The local party's long-term Ed25519 identity private key, as
        returned by the first element of :func:`generate_identity_keypair`.
    ecdh_pub_bytes : bytes
        The raw 32-byte X25519 ephemeral public key to authenticate.
        Must be exactly :data:`PUBLIC_KEY_SIZE` (32) bytes.

    Returns
    -------
    bytes
        64-byte Ed25519 signature.

    Raises
    ------
    ValueError
        If ``ecdh_pub_bytes`` is not exactly 32 bytes.

    Examples
    --------
    >>> id_priv, id_pub = generate_identity_keypair()
    >>> _, ecdh_pub = generate_keypair()
    >>> sig = sign_public_key(id_priv, ecdh_pub)
    >>> assert len(sig) == 64

    TAD Reference: Section 3.1 — Identity Authentication (MITM Mitigation)
    """
    if len(ecdh_pub_bytes) != PUBLIC_KEY_SIZE:
        raise ValueError(
            f"ecdh_pub_bytes must be exactly {PUBLIC_KEY_SIZE} bytes, "
            f"got {len(ecdh_pub_bytes)}."
        )
    return identity_private.sign(ecdh_pub_bytes)


def verify_public_key(
    identity_pub_bytes: bytes,
    ecdh_pub_bytes: bytes,
    signature: bytes,
) -> None:
    """Verify an Ed25519 signature over an ephemeral X25519 public key.

    Authenticates that ``ecdh_pub_bytes`` was signed by the holder of the
    identity private key corresponding to ``identity_pub_bytes``.  If
    verification succeeds the function returns ``None``; if it fails, it
    raises :class:`cryptography.exceptions.InvalidSignature`.

    Delegates entirely to ``Ed25519PublicKey.verify()``.  No verification
    arithmetic is performed in this module.

    .. warning::
        This function MUST be called before :func:`derive_shared_secret`.
        Proceeding with key derivation on an unauthenticated ephemeral key
        defeats the MITM protection entirely.

    Parameters
    ----------
    identity_pub_bytes : bytes
        The peer's raw 32-byte Ed25519 identity public key, obtained
        out-of-band (e.g. printed at peer startup and manually compared —
        similar to Signal's "safety numbers").
        Must be exactly :data:`IDENTITY_PUBLIC_KEY_SIZE` (32) bytes.
    ecdh_pub_bytes : bytes
        The peer's raw 32-byte X25519 ephemeral public key received over
        the transport.
        Must be exactly :data:`PUBLIC_KEY_SIZE` (32) bytes.
    signature : bytes
        The 64-byte Ed25519 signature received alongside ``ecdh_pub_bytes``.
        Must be exactly :data:`SIGNATURE_SIZE` (64) bytes.

    Returns
    -------
    None
        Returned only when the signature is valid.

    Raises
    ------
    cryptography.exceptions.InvalidSignature
        If the signature does not authenticate ``ecdh_pub_bytes`` under
        ``identity_pub_bytes``.  The caller MUST abort the session.
    ValueError
        If any argument has an unexpected length.

    Examples
    --------
    >>> id_priv, id_pub = generate_identity_keypair()
    >>> _, ecdh_pub = generate_keypair()
    >>> sig = sign_public_key(id_priv, ecdh_pub)
    >>> verify_public_key(id_pub, ecdh_pub, sig)   # returns None — OK

    TAD Reference: Section 3.1 — Identity Authentication (MITM Mitigation)
    """
    if len(identity_pub_bytes) != IDENTITY_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"identity_pub_bytes must be exactly {IDENTITY_PUBLIC_KEY_SIZE} bytes, "
            f"got {len(identity_pub_bytes)}."
        )
    if len(ecdh_pub_bytes) != PUBLIC_KEY_SIZE:
        raise ValueError(
            f"ecdh_pub_bytes must be exactly {PUBLIC_KEY_SIZE} bytes, "
            f"got {len(ecdh_pub_bytes)}."
        )
    if len(signature) != SIGNATURE_SIZE:
        raise ValueError(
            f"signature must be exactly {SIGNATURE_SIZE} bytes, "
            f"got {len(signature)}."
        )

    peer_pub_key: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(identity_pub_bytes)
    # Raises cryptography.exceptions.InvalidSignature on failure.
    peer_pub_key.verify(signature, ecdh_pub_bytes)
