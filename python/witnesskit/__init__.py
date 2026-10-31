"""
WitnessKit v0 - tamper-evident audit trails for AI agents.

Every action an agent takes becomes a signed, hash-chained log entry. Altering,
deleting, inserting, or reordering any entry is detectable and locatable.

    from witnesskit import Chain, generate_keypair, verify_chain

    key, pub = generate_keypair()
    trail = Chain(key, actor="agent-7")
    trail.append("tool_call", {"tool": "search", "query": "running shoes"})
    trail.append("payment", {"merchant": "Fleet Feet", "amount": 240, "currency": "USD"})

    pack = trail.to_json()                       # export the evidence pack
    verdict = verify_chain(pack, trusted_keys=[pub])
    print(verdict["valid"])                       # True

Since 0.1.0 the kit also reconciles an agent's summary against its own chain
(see reconcile.py): claims of done, failed, declined or not_attempted per step
against the entries, with three finding kinds (no_entry, contradicted,
undisclosed), and `bind_summary` for the `run.completed` fields.

v0, experimental. Tamper-evident, not tamper-proof (see verify.py). Tracks the
agentic-web provenance layer.
"""

from .chain import Chain, VERSION, build_entry, entry_hash
from .reconcile import (
    CLAIMED,
    ENTRY_PARSERS,
    FINDING_KINDS,
    bind_summary,
    normalize_claimed,
    parse_entry_auto,
    parse_entry_harness,
    parse_entry_sandbox,
    reconcile,
)
from .signing import generate_keypair, public_from_seed, b64
from .verify import verify_chain

__version__ = "0.1.1"

__all__ = [
    "Chain",
    "verify_chain",
    "reconcile",
    "bind_summary",
    "normalize_claimed",
    "parse_entry_auto",
    "parse_entry_sandbox",
    "parse_entry_harness",
    "CLAIMED",
    "FINDING_KINDS",
    "ENTRY_PARSERS",
    "generate_keypair",
    "public_from_seed",
    "build_entry",
    "entry_hash",
    "b64",
    "VERSION",
    "__version__",
]
