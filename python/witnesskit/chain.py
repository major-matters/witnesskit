"""
The tamper-evident chain: signed, hash-linked log entries.

Each entry commits to its content AND the previous entry's hash, then signs that
hash. So altering, deleting, inserting, or reordering any entry breaks the chain
in a way `verify_chain` detects and locates.

Entry shape:

    {
      "version": "witnesskit/v0",
      "seq": 0,
      "timestamp": "2026-06-05T20:00:00Z",
      "actor": "agent-7",
      "action": "tool_call",
      "payload": { ... },              # arbitrary, JSON-serializable
      "prev_hash": null,               # base64 SHA-256 of the previous entry, or null at genesis
      "hash": "base64 sha256(content + prev_hash)",
      "signature": {"alg": "Ed25519", "public_key": "...", "value": "..."}
    }
"""

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .canonical import canonicalize
from .signing import b64, public_from_seed, sign as _sign, unb64

VERSION = "witnesskit/v0"


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


_MAX_SAFE_INT = 2**53 - 1
_MAX_PAYLOAD_DEPTH = 64


def _validate_payload(payload, _depth: int = 0) -> None:
    """Reject payloads that would crash or diverge at canonicalization time, with a
    clear error, so a hostile tool output cannot DoS the logging path or break
    cross-language hashing (audit 2026-06-10 finding #8). Integers must stay within
    the IEEE-754 safe range; nesting is bounded."""
    if _depth > _MAX_PAYLOAD_DEPTH:
        raise ValueError(f"payload nesting exceeds {_MAX_PAYLOAD_DEPTH} levels")
    if isinstance(payload, bool) or payload is None or isinstance(payload, (str, float)):
        return
    if isinstance(payload, int):
        if not -_MAX_SAFE_INT <= payload <= _MAX_SAFE_INT:
            raise ValueError("payload integer outside the JS-safe range (2^53-1); "
                             "stringify large numbers before logging")
        return
    if isinstance(payload, dict):
        for v in payload.values():
            _validate_payload(v, _depth + 1)
        return
    if isinstance(payload, (list, tuple)):
        for v in payload:
            _validate_payload(v, _depth + 1)
        return
    raise ValueError(f"payload contains a non-JSON-serializable type: {type(payload).__name__}")


def entry_hash(seq, timestamp, actor, action, payload, prev_hash) -> str:
    """Deterministic base64 SHA-256 over an entry's content + its chain link.

    Uses RFC 8785 canonicalization so the digest is identical across languages."""
    content = {
        "version": VERSION,
        "seq": seq,
        "timestamp": timestamp,
        "actor": actor,
        "action": action,
        "payload": payload,
        "prev_hash": prev_hash,
    }
    return b64(hashlib.sha256(canonicalize(content)).digest())


def build_entry(*, seq, actor, action, payload, prev_hash, private_key, timestamp=None) -> Dict:
    timestamp = timestamp or _now_iso()
    _validate_payload(payload)
    h = entry_hash(seq, timestamp, actor, action, payload, prev_hash)
    signature = _sign(unb64(h), private_key)  # sign the entry's hash
    return {
        "version": VERSION,
        "seq": seq,
        "timestamp": timestamp,
        "actor": actor,
        "action": action,
        "payload": payload,
        "prev_hash": prev_hash,
        "hash": h,
        "signature": {
            "alg": "Ed25519",
            "public_key": b64(public_from_seed(private_key)),
            "value": b64(signature),
        },
    }


class Chain:
    """An append-only, signed audit trail for one actor."""

    def __init__(self, private_key: Optional[bytes], actor: Optional[str], entries: Optional[List[Dict]] = None):
        self._key = private_key
        self.actor = actor
        self.entries: List[Dict] = list(entries or [])

    @property
    def head_hash(self) -> Optional[str]:
        return self.entries[-1]["hash"] if self.entries else None

    def append(self, action: str, payload: Any = None, *, timestamp: Optional[str] = None) -> Dict:
        if self._key is None:
            raise ValueError("Chain has no signing key; cannot append")
        entry = build_entry(
            seq=len(self.entries),
            actor=self.actor,
            action=action,
            payload=payload if payload is not None else {},
            prev_hash=self.head_hash,
            private_key=self._key,
            timestamp=timestamp,
        )
        self.entries.append(entry)
        return entry

    def to_json(self) -> Dict:
        """Export the evidence pack (entries only; no private key)."""
        return {"version": VERSION, "actor": self.actor, "entries": self.entries}

    @classmethod
    def open(cls, data, private_key: Optional[bytes] = None, actor: Optional[str] = None) -> "Chain":
        """Re-open an exported chain. Pass private_key only if you intend to append."""
        entries = data.get("entries", []) if isinstance(data, dict) else list(data)
        if actor is None and isinstance(data, dict):
            actor = data.get("actor")
        if actor is None and entries:
            actor = entries[-1].get("actor")
        return cls(private_key, actor, entries)
