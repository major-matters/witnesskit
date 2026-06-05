# TrailKit (Python) · v0

Tamper-evident **audit trails for AI agents**. Every action becomes a signed,
hash-chained log entry; any later tamper is detected and located.

> **v0, experimental, unaudited.** Not yet on PyPI — install from source.

Signing uses the vetted `cryptography` library and RFC 8785 canonicalization;
pure-Python fallbacks keep it runnable with zero deps. The signing key stays local.

## Install

Not yet on PyPI (v0). From source:

```bash
git clone https://github.com/major-matters/trailkit
pip install -e trailkit/python
```

Or drop the `trailkit/` folder next to your code.

## Quick start

```python
from trailkit import Chain, generate_keypair, verify_chain

key, public_key = generate_keypair()
trail = Chain(key, actor="agent-7")
trail.append("tool_call", {"tool": "search", "query": "running shoes"})
trail.append("payment",   {"merchant": "Fleet Feet", "amount": 240, "currency": "USD"})

verdict = verify_chain(trail.to_json(), trusted_keys=[public_key])
print(verdict["valid"], verdict["reason"])   # True  chain intact
```

A tampered entry returns `{"valid": False, "broken_at": <index>, "reason": ...}`.

## Security model

A valid signature proves integrity, not authority — **pin the issuer** with
`trusted_keys`; without it (or `allow_unverified_issuer=True`) verification **fails
closed**. `verify_chain` never throws. Tamper-evident, not tamper-proof; see
[`../SECURITY.md`](../SECURITY.md).

## Tests

```bash
PYTHONPATH=. python3 tests/test_trailkit.py      # unit (no pytest needed)
PYTHONPATH=. python3 tests/test_properties.py    # property-based (needs hypothesis)
```

## License

MIT.
