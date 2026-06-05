"""
Ed25519 signing for TrailKit entries.

Uses the vetted, constant-time `cryptography` library by default; falls back to a
pure-Python RFC 8032 reference (NOT constant-time) with a warning if it is absent.
Signatures are RFC-8032 standard, so they interoperate with the TypeScript port.
"""

import base64
import os
import warnings
from typing import Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _BACKEND = "cryptography"
except ImportError:  # pragma: no cover
    from . import ed25519 as _ref

    _BACKEND = "pure-python"
    warnings.warn(
        "trailkit: 'cryptography' is not installed; using a pure-Python Ed25519 "
        "reference that is NOT constant-time. Install 'cryptography' for production.",
        RuntimeWarning,
        stacklevel=2,
    )


def public_from_seed(seed: bytes) -> bytes:
    if _BACKEND == "cryptography":
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return _ref.publickey(seed)


def sign(message: bytes, seed: bytes) -> bytes:
    if _BACKEND == "cryptography":
        return Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    return _ref.sign(message, seed, _ref.publickey(seed))


def verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """Never raises; malformed input returns False."""
    if _BACKEND == "cryptography":
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except Exception:
            return False
    try:
        return _ref.verify(signature, message, public_key)
    except Exception:
        return False


def generate_keypair() -> Tuple[bytes, bytes]:
    """Return (private_seed, public_key) as raw 32-byte values."""
    seed = os.urandom(32)
    return seed, public_from_seed(seed)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def unb64(s: str) -> bytes:
    return base64.b64decode(s)
