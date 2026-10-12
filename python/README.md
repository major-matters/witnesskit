# WitnessKit (Python) · v0

Tamper-evident **audit trails for AI agents**. Every action becomes a signed,
hash-chained log entry; any later tamper is detected and located.

> **v0, experimental, unaudited.** On PyPI as `witnesskit` since 2026-06-10.

Signing uses the vetted `cryptography` library and RFC 8785 canonicalization;
pure-Python fallbacks keep it runnable with zero deps. The signing key stays local.

## Install

```bash
pip install witnesskit
```

Or from source: `git clone https://github.com/major-matters/witnesskit && pip install -e witnesskit/python`,
or drop the `witnesskit/` folder next to your code.

## Quick start

```python
from witnesskit import Chain, generate_keypair, verify_chain

key, public_key = generate_keypair()
trail = Chain(key, actor="agent-7")
trail.append("tool_call", {"tool": "search", "query": "running shoes"})
trail.append("payment",   {"merchant": "Fleet Feet", "amount": 240, "currency": "USD"})

verdict = verify_chain(trail.to_json(), trusted_keys=[public_key])
print(verdict["valid"], verdict["reason"])   # True  chain intact
```

A tampered entry returns `{"valid": False, "broken_at": <index>, "reason": ...}`.

## Security model

A valid signature proves integrity, not authority: **pin the issuer** with
`trusted_keys`; without it (or `allow_unverified_issuer=True`) verification **fails
closed**. `verify_chain` never throws. Tamper-evident, not tamper-proof; see
[`../SECURITY.md`](../SECURITY.md).

## Reconcile a summary against the chain

Since 0.1.0: `reconcile(claims, chain, parser="auto", summary=None)` diffs an
agent's report against its own chain. Claims are
`{"step", "counterparty", "verb", "claimed"}` with `claimed` one of `done`,
`failed`, `declined`, `not_attempted`; findings are `no_entry`, `contradicted`
or `undisclosed`; `bind_summary(text_or_object, mode=..., encoding=...)` gives
the `run.completed` fields. It never raises. It compares claims to entries and
does not judge the truth of a tool result; run `verify_chain` first. Full notes
in [the repository README](../README.md#reconcile-a-summary-against-the-chain)
and the `witnesskit.reconcile` docstring.

```python
from witnesskit import reconcile
diff = reconcile(claims, chain_json, summary=report_text)
print(diff["result"], diff["summary_bound"])
```

## Tests

```bash
PYTHONPATH=. python3 tests/test_witnesskit.py      # unit (no pytest needed)
PYTHONPATH=. python3 tests/test_reconcile.py       # reconcile, driven by ../fixtures/reconcile.json
PYTHONPATH=. python3 tests/test_properties.py    # property-based (needs hypothesis)
```

## License

MIT.
