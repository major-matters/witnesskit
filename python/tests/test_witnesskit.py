"""
WitnessKit v0 test suite. Runs under pytest, or standalone:
    PYTHONPATH=. python3 tests/test_witnesskit.py

Includes tamper/forge/reorder/truncate regressions from day one.
"""

import copy

from witnesskit import Chain, generate_keypair, verify_chain, build_entry
from witnesskit.signing import b64, public_from_seed

KEY = bytes(range(32))
PUB = b64(public_from_seed(KEY))
TS = ["2026-06-05T20:00:00Z", "2026-06-05T20:00:01Z", "2026-06-05T20:00:02Z"]


def make_chain(key=KEY, actor="agent-7"):
    c = Chain(key, actor=actor)
    c.append("tool_call", {"tool": "search", "q": "running shoes"}, timestamp=TS[0])
    c.append("decision", {"approved": True}, timestamp=TS[1])
    c.append("payment", {"merchant": "Fleet Feet", "amount": 240, "currency": "USD"}, timestamp=TS[2])
    return c


def vrf(chain, **kw):
    kw.setdefault("trusted_keys", [PUB])
    return verify_chain(chain, **kw)


# --- happy path -------------------------------------------------------------

def test_roundtrip_valid():
    v = vrf(make_chain().to_json())
    assert v["valid"] is True
    assert v["length"] == 3
    assert v["broken_at"] is None


def test_empty_chain_valid():
    assert vrf(Chain(KEY, "a").to_json())["valid"] is True


def test_export_import_roundtrip():
    data = make_chain().to_json()
    reopened = Chain.open(data)
    assert len(reopened.entries) == 3
    assert vrf(reopened)["valid"] is True


# --- issuer pinning (the critical lesson) -----------------------------------

def test_unpinned_fails_closed():
    v = verify_chain(make_chain().to_json())  # no trusted_keys, no flag
    assert v["valid"] is False
    assert "trusted issuer" in v["reason"]


def test_allow_unverified_issuer_opt_in():
    assert verify_chain(make_chain().to_json(), allow_unverified_issuer=True)["valid"] is True


def test_forged_chain_rejected_by_pinning():
    attacker = bytes(range(1, 33))
    forged = make_chain(key=attacker).to_json()   # perfectly valid chain, attacker's key
    v = vrf(forged)                                # pinned to victim PUB
    assert v["valid"] is False
    assert v["broken_at"] == 0
    assert "trusted-issuer" in v["reason"]


# --- tamper detection -------------------------------------------------------

def test_altered_payload_detected():
    data = make_chain().to_json()
    data["entries"][1]["payload"]["approved"] = False   # flip a decision
    v = vrf(data)
    assert v["valid"] is False
    assert v["broken_at"] == 1
    assert "hash mismatch" in v["reason"]


def test_deleted_entry_detected():
    data = make_chain().to_json()
    del data["entries"][1]                              # drop the middle entry
    v = vrf(data)
    assert v["valid"] is False
    assert v["broken_at"] == 1   # seq/link breaks where the gap is


def test_inserted_entry_detected():
    data = make_chain().to_json()
    fake = build_entry(seq=1, actor="agent-7", action="payment",
                       payload={"merchant": "Attacker", "amount": 9999, "currency": "USD"},
                       prev_hash=data["entries"][0]["hash"], private_key=KEY, timestamp=TS[1])
    data["entries"].insert(1, fake)                     # splice in an extra signed entry
    v = vrf(data)
    assert v["valid"] is False                          # downstream seqs/links now wrong


def test_reordered_entries_detected():
    data = make_chain().to_json()
    data["entries"][1], data["entries"][2] = data["entries"][2], data["entries"][1]
    v = vrf(data)
    assert v["valid"] is False
    assert v["broken_at"] == 1


def test_truncation_detected_with_expected_head():
    chain = make_chain()
    head = chain.head_hash
    data = chain.to_json()
    data["entries"] = data["entries"][:2]               # drop the last entry
    # Without a known head, a shorter valid chain looks fine:
    assert vrf(data)["valid"] is True
    # With the anchored head, truncation is caught:
    v = vrf(data, expected_head=head)
    assert v["valid"] is False
    assert "head" in v["reason"]


def test_backwards_timestamp_detected():
    data = make_chain().to_json()
    # re-sign an entry with an earlier timestamp so only the time check can catch it
    bad = build_entry(seq=2, actor="agent-7", action="payment",
                      payload=data["entries"][2]["payload"],
                      prev_hash=data["entries"][1]["hash"], private_key=KEY,
                      timestamp="2026-01-01T00:00:00Z")
    data["entries"][2] = bad
    v = vrf(data)
    assert v["valid"] is False
    assert "backwards" in v["reason"]


# --- robustness -------------------------------------------------------------

def test_hostile_input_never_raises():
    for junk in [None, 42, "x", [1, 2, 3], {"entries": "nope"},
                 {"entries": [None, {"seq": "x"}]}, {"entries": [{}]}]:
        v = verify_chain(junk, trusted_keys=[PUB])
        assert v["valid"] in (True, False)  # returned a verdict, did not throw


# --- audit 2026-06-10 medium/low findings -----------------------------------

def test_version_tamper_detected():
    """Rewriting an entry's stored version must be caught (finding #9)."""
    chain = make_chain().to_json()
    chain["entries"][1]["version"] = "witnesskit/v999"
    v = verify_chain(chain, trusted_keys=[PUB])
    assert v["valid"] is False and v["broken_at"] == 1


def test_payload_oversize_int_rejected():
    """An out-of-safe-range int payload must raise a clean error, not crash (finding #8)."""
    c = Chain(KEY, "a")
    try:
        c.append("x", {"n": 2**53})
        assert False, "oversize int payload was not rejected"
    except ValueError:
        pass


def test_payload_deep_nesting_rejected():
    deep = cur = {}
    for _ in range(100):
        cur["x"] = {}
        cur = cur["x"]
    c = Chain(KEY, "a")
    try:
        c.append("x", deep)
        assert False, "deeply nested payload was not rejected"
    except ValueError:
        pass


# --- standalone runner ------------------------------------------------------

if __name__ == "__main__":
    import sys
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    fails = 0
    for t in tests:
        try:
            t(); print(f"  PASS  {t.__name__}")
        except Exception as e:
            fails += 1; print(f"  FAIL  {t.__name__}: {type(e).__name__}: {str(e)[:160]}")
    print(f"\n{len(tests)-fails}/{len(tests)} passed")
    sys.exit(1 if fails else 0)
