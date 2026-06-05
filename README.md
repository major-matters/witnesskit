# TrailKit · v0

[![CI](https://github.com/major-matters/trailkit/actions/workflows/ci.yml/badge.svg)](https://github.com/major-matters/trailkit/actions/workflows/ci.yml)

> ⚠️ **Experimental — unaudited, not for production.** A v0 research prototype with
> no third-party security audit. Not yet published to npm or PyPI — install from
> source. The on-the-wire format will change.

**Tamper-evident audit trails for AI agents.**

When an AI agent acts on your behalf — calls a tool, makes a decision, moves money
— you want a record of what it did that someone can't quietly rewrite after the
fact. TrailKit makes that record. Every action becomes a log entry that is
**hash-chained** to the one before it and **signed**. Alter, delete, insert, or
reorder any entry and verification detects it and tells you exactly where.

It ships in **Python** and **TypeScript**, with byte-compatible trails (a trail
signed in one verifies in the other).

> v0 tracks the **provenance layer** of the agentic web. It's the standalone
> "evidence pack": a record that survives a dispute.

## Quick start

```python
from trailkit import Chain, generate_keypair, verify_chain

key, public_key = generate_keypair()        # the signing key stays on-device
trail = Chain(key, actor="agent-7")
trail.append("tool_call", {"tool": "search", "query": "running shoes"})
trail.append("payment",   {"merchant": "Fleet Feet", "amount": 240, "currency": "USD"})

pack = trail.to_json()                       # export the evidence pack
verdict = verify_chain(pack, trusted_keys=[public_key])
print(verdict["valid"])                       # True
```

Flip a logged value, drop an entry, splice one in, reorder, or sign a fake trail
with the wrong key, and `verify_chain` returns `valid: False` with the index it
broke at and why.

## How it works

Each entry commits to its content **and** the previous entry's hash (RFC 8785
canonicalization + SHA-256), then signs that hash with Ed25519. Verification walks
the chain and checks four things: sequence numbers are contiguous, each entry
links to the previous hash, each entry's content still matches its hash, and every
entry is signed by a **trusted issuer**.

## Security model

A valid signature proves **integrity, not authority**. You must pin the issuer:
pass `trusted_keys` / `trustedKeys`. Without it (and without an explicit
`allow_unverified_issuer`), verification **fails closed**. (This lesson is borrowed
from MandateKit's security review.) `verify_chain` never throws on hostile input.

**Honest limitations (v0):**
- **Tamper-evident, not tamper-proof.** A holder of the signing key can rewrite
  the whole chain. Preventing that needs external anchoring (a witness /
  transparency log) — roadmap.
- **Truncation/rollback** (dropping trailing entries) isn't detectable from the
  chain alone; pass a known `expected_head` to catch it.
- **Payloads must be JSON-safe** (numbers within 2⁵³), the inherent limit of
  canonical JSON.

Full notes in [`SECURITY.md`](SECURITY.md).

## Layout

```
trailkit/
  python/        # pip-installable package + tests
  typescript/    # npm package, runs on Node 22+
  LICENSE        # MIT
```

Try it: `cd python && PYTHONPATH=. python3 ../demo.py`

## License

MIT.
