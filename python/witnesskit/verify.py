"""
Chain verification.

Walks an audit trail and confirms it is intact: sequence numbers are contiguous,
each entry links to the previous one's hash, each entry's content still matches
its hash, and every entry is signed by a trusted issuer. Any tamper (alter,
delete, insert, reorder) is detected and located.

SECURITY MODEL (learned the hard way on MandateKit):
  * A valid signature proves integrity, not authority. You MUST pin the issuer:
    pass `trusted_keys=[logger_public_key]`. Without it (and without an explicit
    `allow_unverified_issuer=True`), verification FAILS CLOSED.
  * `verify_chain` never raises. Malformed/hostile input returns a verdict.

LIMITATIONS (honest, v0):
  * Tamper-EVIDENT, not tamper-PROOF. A holder of the signing key can rewrite the
    whole chain (re-sign every entry). Preventing that needs external anchoring
    (a witness / transparency log) — roadmap.
  * Truncation/rollback (dropping trailing entries) is not detectable from the
    chain alone; you need a known/anchored head hash to catch it (see `expected_head`).
"""

import base64
from typing import Dict, Iterable, List, Optional, Set, Union

from .chain import entry_hash
from .signing import unb64, verify as _verify

TrustedKeys = Union[str, bytes, Iterable[Union[str, bytes]]]


def _normalize_trusted(trusted_keys: Optional[TrustedKeys]) -> Optional[Set[str]]:
    if trusted_keys is None:
        return None
    if isinstance(trusted_keys, (str, bytes, bytearray)):
        trusted_keys = [trusted_keys]
    out: Set[str] = set()
    for k in trusted_keys:
        out.add(base64.b64encode(k).decode("ascii") if isinstance(k, (bytes, bytearray)) else k)
    return out


def _result(valid: bool, length: int, broken_at: Optional[int], reason: str) -> Dict:
    return {"valid": valid, "length": length, "broken_at": broken_at, "reason": reason}


def verify_chain(
    chain,
    *,
    trusted_keys: Optional[TrustedKeys] = None,
    allow_unverified_issuer: bool = False,
    require_monotonic_time: bool = True,
    expected_head: Optional[str] = None,
) -> Dict:
    """Verify an audit trail. Accepts a Chain, an exported dict, or a list of entries."""
    if hasattr(chain, "entries"):
        entries = chain.entries
    elif isinstance(chain, dict):
        entries = chain.get("entries", [])
    elif isinstance(chain, list):
        entries = chain
    else:
        return _result(False, 0, None, "malformed: not a chain")
    if not isinstance(entries, list):
        return _result(False, 0, None, "malformed: entries is not a list")

    trusted = _normalize_trusted(trusted_keys)
    if trusted is None and not allow_unverified_issuer:
        return _result(False, len(entries), None,
                       "no trusted issuer keys supplied: pass trusted_keys=[...] (recommended) "
                       "or allow_unverified_issuer=True")

    if not entries:
        # Empty chain is structurally valid; only an expected_head can contradict it.
        if expected_head is not None:
            return _result(False, 0, None, "chain is empty but an expected head was given (truncated?)")
        return _result(True, 0, None, "empty chain")

    prev_hash = None
    prev_ts = None
    for i, e in enumerate(entries):
        try:
            if not isinstance(e, dict):
                return _result(False, len(entries), i, "entry is not an object")
            if e.get("seq") != i:
                return _result(False, len(entries), i, f"seq mismatch: expected {i}, got {e.get('seq')!r}")
            if e.get("prev_hash") != prev_hash:
                return _result(False, len(entries), i, "broken chain link: prev_hash does not match")
            recomputed = entry_hash(
                e.get("seq"), e.get("timestamp"), e.get("actor"),
                e.get("action"), e.get("payload"), e.get("prev_hash"),
            )
            if recomputed != e.get("hash"):
                return _result(False, len(entries), i, "content tampered: hash mismatch")
            sig = e.get("signature")
            if not isinstance(sig, dict) or sig.get("alg") != "Ed25519":
                return _result(False, len(entries), i, "missing or unsupported signature")
            pub = sig.get("public_key")
            if trusted is not None and pub not in trusted:
                return _result(False, len(entries), i, "signer is not in the trusted-issuer set")
            if not _verify(unb64(sig.get("value", "")), unb64(e["hash"]), unb64(sig.get("public_key", ""))):
                return _result(False, len(entries), i, "invalid signature")
            if require_monotonic_time and prev_ts is not None and e.get("timestamp") is not None:
                if e["timestamp"] < prev_ts:
                    return _result(False, len(entries), i, "timestamp goes backwards")
            prev_hash = e.get("hash")
            prev_ts = e.get("timestamp")
        except Exception as ex:  # hostile input must never crash verification
            return _result(False, len(entries), i, f"malformed entry: {type(ex).__name__}")

    if expected_head is not None and prev_hash != expected_head:
        return _result(False, len(entries), len(entries) - 1,
                       "head hash does not match expected_head (truncated or forked)")

    return _result(True, len(entries), None, "chain intact")
