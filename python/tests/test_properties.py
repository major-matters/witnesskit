"""
Property-based tests (Hypothesis) for WitnessKit. Run:
    pip install hypothesis
    PYTHONPATH=. python3 tests/test_properties.py
"""

import copy

from hypothesis import assume, given, settings, strategies as st

from witnesskit import Chain, verify_chain
from witnesskit.chain import entry_hash
from witnesskit.signing import b64, public_from_seed

seeds = st.binary(min_size=32, max_size=32)
# Payloads must be JSON-safe (numbers within JS's 2**53 range) — the documented
# constraint of any RFC 8785 canonicalization. verify_chain tolerates violations
# (returns invalid); append cannot canonicalize them.
SAFE_INT = st.integers(min_value=-(2 ** 53 - 1), max_value=2 ** 53 - 1)
payloads = st.dictionaries(st.text(max_size=8), SAFE_INT | st.text(max_size=20), max_size=4)
actions = st.lists(st.tuples(st.text(max_size=20), payloads), max_size=8)
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=10),
    lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=6), c, max_size=4),
    max_leaves=30,
)


def _build(seed, acts):
    c = Chain(seed, "agent")
    for i, (action, payload) in enumerate(acts):
        c.append(action, payload, timestamp=f"2026-01-01T00:00:{i:02d}Z")
    return c


@given(seeds, actions)
def test_roundtrip_any_chain(seed, acts):
    pub = b64(public_from_seed(seed))
    assert verify_chain(_build(seed, acts).to_json(), trusted_keys=[pub])["valid"] is True


@given(seeds, actions.filter(lambda a: len(a) >= 1))
def test_any_field_tamper_breaks(seed, acts):
    pub = b64(public_from_seed(seed))
    data = _build(seed, acts).to_json()
    d = copy.deepcopy(data)
    d["entries"][0]["action"] = d["entries"][0]["action"] + "_x"  # change without re-signing
    assert verify_chain(d, trusted_keys=[pub])["valid"] is False


@given(seeds, seeds, st.text(max_size=20))
def test_forgery_iff_same_key(signer, trusted, action):
    c = Chain(signer, "a"); c.append(action, {})
    same = public_from_seed(signer) == public_from_seed(trusted)
    v = verify_chain(c.to_json(), trusted_keys=[b64(public_from_seed(trusted))])
    assert v["valid"] == same


@settings(max_examples=200)
@given(json_values)
def test_never_throws_on_garbage(j):
    assert verify_chain(j, trusted_keys=["AAAA"])["valid"] in (True, False)
    wrapped = {"entries": j if isinstance(j, list) else [j]}
    assert verify_chain(wrapped, trusted_keys=["AAAA"])["valid"] in (True, False)


@given(st.dictionaries(st.text(min_size=1, max_size=6),
                       st.integers(min_value=-(2 ** 53 - 1), max_value=2 ** 53 - 1), max_size=6))
def test_hash_is_key_order_invariant(payload):
    a = entry_hash(0, "t", "actor", "action", payload, None)
    reordered = {k: payload[k] for k in reversed(list(payload))}
    assert a == entry_hash(0, "t", "actor", "action", reordered, None)


if __name__ == "__main__":
    import sys
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    fails = 0
    for t in tests:
        try:
            t(); print(f"  PASS  {t.__name__}")
        except Exception as e:
            fails += 1; print(f"  FAIL  {t.__name__}: {type(e).__name__}: {str(e)[:160]}")
    print(f"\n{len(tests)-fails}/{len(tests)} property tests passed")
    sys.exit(1 if fails else 0)
