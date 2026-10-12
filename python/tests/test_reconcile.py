"""
Reconcile tests. Runs under pytest, or standalone:
    PYTHONPATH=. python3 tests/test_reconcile.py

Most cases come from ../fixtures/reconcile.json, the one fixture the Python and
TypeScript suites share: real Mandate Sandbox chains with the sandbox's own
reconcile results in the kit's shape, Bench-harness-shaped chains built with
the kit, and malformed inputs. The hand-written tests below port the sandbox's
summary.test.mjs assertions and cover what JSON cannot carry (a Chain object,
a custom parser function).
"""

import copy
import json
import os

from witnesskit import (
    CLAIMED,
    ENTRY_PARSERS,
    Chain,
    bind_summary,
    normalize_claimed,
    reconcile,
    verify_chain,
)
from witnesskit.signing import b64, public_from_seed

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "fixtures", "reconcile.json")
with open(FIXTURE, encoding="utf-8") as fh:
    FIX = json.load(fh)

KEY = bytes(range(32))
PUB = b64(public_from_seed(KEY))


def _chain_of(case):
    return FIX["chains"][case["chain_ref"]]["chain"] if "chain_ref" in case else case["chain"]


def _run(case):
    kw = {"parser": case.get("parser", "auto")}
    if "summary" in case:
        kw["summary"] = case["summary"]
    return reconcile(case.get("claims"), copy.deepcopy(_chain_of(case)), **kw)


def _by_name(name):
    return next(c for c in FIX["cases"] if c["name"] == name)


# --- the shared fixture -------------------------------------------------------

def test_fixture_chains_verify():
    """The fixture's chains are real signed chains; reconcile reads them as given."""
    for name, c in FIX["chains"].items():
        v = verify_chain(c["chain"], trusted_keys=[c["trusted_key"]])
        assert v["valid"] is True, (name, v)


def test_fixture_cases():
    assert len(FIX["cases"]) >= 40
    for case in FIX["cases"]:
        got = _run(case)
        exp = case["expect"]
        assert got["findings"] == exp["findings"], (case["name"], got["findings"])
        assert got["counts"] == exp["counts"], case["name"]
        assert got["matches"] == exp["matches"], case["name"]
        assert got["result"] == exp["result"], case["name"]
        if "summary_bound" in exp:
            assert got["summary_bound"] == exp["summary_bound"], case["name"]
        else:
            assert "summary_bound" not in got, case["name"]
        if "error" in exp:
            assert got["error"] == exp["error"], case["name"]
            assert got["matches"] == 0 and got["findings"] == []
        else:
            assert "error" not in got, (case["name"], got.get("error"))


def test_fixture_covers_every_kind_and_convention():
    kinds = set()
    parsers = set()
    for case in FIX["cases"]:
        parsers.add(case.get("parser", "auto"))
        for f in case["expect"]["findings"]:
            kinds.add(f["kind"])
    assert kinds == {"no_entry", "contradicted", "undisclosed"}
    assert parsers == {"auto", "sandbox", "harness", "nonsense"}
    assert any("error" in c["expect"] for c in FIX["cases"])


# --- the sandbox's summary.test.mjs, ported -----------------------------------

def test_kettle_plan_run_blames_the_bank_and_hides_two_refusals():
    got = _run(_by_name("shop-plan"))
    contradicted = [f for f in got["findings"] if f["kind"] == "contradicted"]
    assert len(contradicted) == 1
    c = contradicted[0]
    assert c["verb"] == "pay" and c["counterparty"] == "MID-41377" and c["claimed"] == "declined"
    assert c["chain"] == "blocked"
    assert "no call reached the counterparty (refused by BudgetGuard)" in c["detail"]
    assert [f["step"] for f in got["findings"] if f["kind"] == "undisclosed"] == [2, 3]
    assert got["counts"] == {"no_entry": 0, "contradicted": 1, "undisclosed": 2}
    assert got["result"] == "3 claims do not match the record"
    assert got["summary_bound"] is True
    # The same run reported from the record has nothing to find.
    rec = _run(_by_name("shop-record"))
    assert rec["findings"] == [] and rec["result"] == "Summary matches the record"
    assert rec["matches"] == len(_by_name("shop-record")["claims"])


def test_address_plan_run_has_an_undisclosed_refusal_and_handoffs_claimed_done():
    got = _run(_by_name("address-plan"))
    undisclosed = [f for f in got["findings"] if f["kind"] == "undisclosed"]
    volt = next(f for f in undisclosed if f["counterparty"] == "MID-88811")
    assert volt["verb"] == "submit" and volt["chain"] == "blocked"
    assert volt["detail"] == "IdentityKit refused: submit to MID-88811; the summary does not mention it"
    assert any(f["kind"] == "contradicted" and f["chain"] == "handoff"
               and f["detail"] == "claimed done; the chain says handoff" for f in got["findings"])
    assert _run(_by_name("address-record"))["findings"] == []


def test_declined_ask_blamed_on_the_bank_is_contradicted():
    got = _run(_by_name("subscriptions-plan-declined"))
    assert any(f["kind"] == "contradicted" and f["chain"] == "declined"
               and f["detail"].endswith("(the approver declined)") for f in got["findings"])
    faithful = _by_name("subscriptions-record-declined")
    assert any(c["claimed"] == "not attempted" for c in faithful["claims"])
    assert _run(faithful)["findings"] == []


def test_no_entry_finding_and_result_grammar():
    got = _run(_by_name("pay-bill-record-extra-claim"))
    assert [f["counterparty"] for f in got["findings"] if f["kind"] == "no_entry"] == ["MID-99999"]
    assert got["result"] == "1 claim does not match the record"
    assert _run(_by_name("pay-bill-record-step-99"))["counts"]["no_entry"] == 1
    silent = _run(_by_name("pay-bill-null-claims"))
    assert silent["counts"]["no_entry"] == 0 and silent["counts"]["contradicted"] == 0
    assert silent["counts"]["undisclosed"] == len(silent["findings"]) > 0
    empty = reconcile([], {"entries": []})
    assert empty == {"findings": [], "matches": 0, "counts": {"no_entry": 0, "contradicted": 0, "undisclosed": 0},
                     "result": "Summary matches the record"}


def test_rail_decline_is_a_real_decline():
    assert _run(_by_name("rail-decline-faithful"))["findings"] == []
    careless = _run(_by_name("rail-decline-careless"))
    assert careless["counts"]["contradicted"] == 2
    assert "rejected (stripe-test, card_declined)" in next(f for f in careless["findings"] if f["step"] == 1)["detail"]
    assert "run_cap_exceeded" in next(f for f in careless["findings"] if f["step"] == 2)["detail"]
    silent = _run(_by_name("rail-decline-silent"))
    assert silent["counts"]["undisclosed"] == 2
    assert silent["findings"][0]["detail"] == "stripe-test rejected: pay to MID-1; the summary does not mention it"


# --- the claims contract ------------------------------------------------------

def test_claimed_labels_normalize():
    assert CLAIMED == ("done", "failed", "declined", "not_attempted")
    assert normalize_claimed("declined by bank") == "declined"
    assert normalize_claimed("  Declined  By Bank ") == "declined"
    assert normalize_claimed("not attempted") == "not_attempted"
    assert normalize_claimed("NOT_ATTEMPTED") == "not_attempted"
    for label in CLAIMED:
        assert normalize_claimed(label) == label
    for junk in ("refused", "", None, 3, ["done"], "declined by the issuer"):
        assert normalize_claimed(junk) is None


def test_sandbox_labels_and_kit_labels_reconcile_the_same():
    raw = _by_name("pay-bill-record-extra-claim")
    kit = _by_name("pay-bill-record-kit-labels")
    assert raw["chain_ref"] == kit["chain_ref"]
    assert all(c["claimed"] in CLAIMED for c in kit["claims"])
    assert _run(kit)["findings"] == []


# --- inputs JSON cannot carry: a Chain object, a custom parser -----------------

def _harness_chain():
    c = Chain(KEY, "agent")
    c.append("mandate.accepted", {"job": "t"}, timestamp="2026-10-12T10:00:00Z")
    c.append("step.read", {"to": "harbourline", "verdict": "allow", "layer": "may"}, timestamp="2026-10-12T10:00:01Z")
    c.append("step.pay", {"to": "MID-1", "amount": 500, "verdict": "deny", "layer": "spends", "reason": "over budget"},
             timestamp="2026-10-12T10:00:02Z")
    return c


def test_accepts_a_chain_object():
    chain = _harness_chain()
    got = reconcile([{"step": 0, "counterparty": "harbourline", "verb": "read", "claimed": "done"}], chain)
    assert got["matches"] == 1
    assert [f["kind"] for f in got["findings"]] == ["undisclosed"]
    assert got["findings"][0]["detail"] == "spends refused: pay to MID-1; the summary does not mention it"


def test_custom_parser_function():
    """A chain in a convention of its own: {"action": "did", "payload": {"n": 2, "who": "x", "ok": false}}."""
    def parse(entry, ordinal):
        if entry.get("action") != "did":
            return None
        p = entry["payload"]
        return {"step": p["n"], "counterparty": p["who"], "verb": "act", "status": "done" if p["ok"] else "blocked",
                "layer": "gate", "reached": False}
    chain = {"entries": [
        {"seq": 0, "action": "hello", "payload": {}},
        {"seq": 1, "action": "did", "payload": {"n": 7, "who": "x", "ok": True}},
        {"seq": 2, "action": "did", "payload": {"n": 8, "who": "y", "ok": False}},
    ]}
    got = reconcile([{"step": 7, "counterparty": "x", "claimed": "done"},
                     {"step": 8, "counterparty": "y", "claimed": "done"}], chain, parser=parse)
    assert got["matches"] == 1
    assert got["findings"] == [{"kind": "contradicted", "step": 8, "counterparty": "y", "verb": "act", "claimed": "done",
                                "chain": "blocked", "detail": "claimed done; the chain says blocked (gate)"}]
    # A custom parser's output is checked too, and its exceptions become an error, not a crash.
    bad = reconcile([], chain, parser=lambda e, i: {"step": "x"} if e.get("action") == "did" else None)
    assert "error" in bad and bad["matches"] == 0
    boom = reconcile([], chain, parser=lambda e, i: 1 / 0)
    assert boom["error"].startswith("entry parser failed on entry 0: ZeroDivisionError")


def test_entry_parsers_exported_and_ordinal_indexing():
    assert set(ENTRY_PARSERS) == {"auto", "sandbox", "harness"}
    chain = _harness_chain().to_json()
    # Harness entries carry no index: the pay step is ordinal 1, whatever its seq (2).
    assert reconcile([{"step": 1, "counterparty": "MID-1", "claimed": "failed"}], chain, parser="harness")["findings"] == []
    assert reconcile([{"step": 2, "counterparty": "MID-1", "claimed": "failed"}], chain)["counts"]["no_entry"] == 1
    # An explicit payload.step wins over the ordinal in every convention.
    s = ENTRY_PARSERS["harness"]({"seq": 9, "action": "step.pay", "payload": {"step": 4, "to": "a", "verdict": "ask"}}, 0)
    assert s["step"] == 4 and s["status"] == "declined" and s["counterparty"] == "a" and s["seq"] == 9
    assert ENTRY_PARSERS["sandbox"]({"action": "run.completed", "payload": {}}, 0) is None
    assert ENTRY_PARSERS["harness"]({"action": "recall", "payload": {}}, 0) is None
    assert ENTRY_PARSERS["sandbox"]({"action": "memory.recall", "payload": {"step": 3, "status": "declined"}}, 0)["verb"] == "recall"


# --- binding the summary ------------------------------------------------------

def test_bind_summary_matches_the_sandbox_and_the_harness():
    # The sandbox hashes the summary object (RFC 8785 canonical JSON, base64).
    sp = FIX["chains"]["shop-plan"]["chain"]
    case = _by_name("shop-plan")
    last = sp["entries"][-1]
    assert last["action"] == "run.completed"
    assert bind_summary(case["summary"], mode="plan") == {"summary_sha256": last["payload"]["summary_sha256"], "summary_mode": "plan"}
    # The harness hashes the exact finish text, hex.
    h = FIX["chains"]["harness"]["chain"]
    text = _by_name("harness-careless")["summary"]
    assert bind_summary(text, encoding="hex") == {"summary_sha256": h["entries"][-1]["payload"]["summary_sha256"]}
    # Known digest of a known text, both encodings; no summary_mode unless given.
    assert bind_summary("hello") == {"summary_sha256": "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="}
    assert bind_summary("hello", encoding="hex")["summary_sha256"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert bind_summary("", mode="record") == {"summary_sha256": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "summary_mode": "record"}
    for bad in (None, 3, b"bytes"):
        try:
            bind_summary(bad)
            assert False, "accepted a non-summary"
        except TypeError:
            pass
    try:
        bind_summary("x", encoding="base32")
        assert False, "accepted an unknown encoding"
    except ValueError:
        pass


def test_summary_bound_reads_either_encoding():
    chain = _harness_chain()
    text = "All done."
    chain.append("run.completed", bind_summary(text, encoding="hex"), timestamp="2026-10-12T10:00:03Z")
    assert reconcile([], chain, summary=text)["summary_bound"] is True
    assert reconcile([], chain, summary=text + "!")["summary_bound"] is False
    other = _harness_chain()
    other.append("run.completed", bind_summary({"text": text, "claims": []}, mode="record"), timestamp="2026-10-12T10:00:03Z")
    assert reconcile([], other, summary={"claims": [], "text": text})["summary_bound"] is True  # key order does not matter
    assert reconcile([], other, summary=text)["summary_bound"] is False  # the object was bound, not the text
    assert reconcile([], _harness_chain(), summary=text)["summary_bound"] is None  # no run.completed entry
    assert "summary_bound" not in reconcile([], _harness_chain())


# --- robustness -----------------------------------------------------------------

def test_hostile_input_never_raises():
    chain = _harness_chain().to_json()
    junk = [None, 42, "x", b"b", [1, 2, 3], {"entries": "nope"}, {"entries": [None]}, {"entries": [{}]},
            {"entries": [{"action": 5, "payload": "str"}]}, {"entries": [{"action": "pay:done", "payload": None}]},
            {"entries": [{"action": "step.", "payload": {}}]}, {"entries": [{"action": "a:b:c", "payload": {}}]},
            [{"action": "pay:done", "payload": {"step": 2**60, "counterparty": {"id": 1}, "reference": [1]}}],
            {"entries": [{"action": "memory.recall", "payload": {"step": True, "status": 4}}]}]
    claims_junk = [None, "x", 7, [None], [[]], [{"step": None}], [{"step": 1.5, "claimed": "done"}],
                   [{"step": 0, "claimed": "done", "counterparty": 1}], [{"step": 0, "claimed": {}}],
                   [{"step": -1, "claimed": "failed", "verb": 0}]]
    for c in [None, []] + claims_junk:
        for ch in junk + [chain]:
            for parser in ("auto", "sandbox", "harness", "nonsense", None, 5, lambda e, i: None):
                for summary in (None, "s", {"a": 1}, 3):
                    got = reconcile(c, ch, parser=parser, summary=summary)
                    assert isinstance(got["findings"], list) and isinstance(got["matches"], int)
                    assert got["result"]
                    if "error" in got:
                        assert got["matches"] == 0 and got["findings"] == []


def test_integral_float_step_is_an_integer():
    chain = _harness_chain().to_json()
    assert reconcile([{"step": 0.0, "counterparty": "harbourline", "claimed": "done"}], chain)["matches"] == 1


def test_reconcile_does_not_judge_the_chain():
    """A forged chain reconciles as happily as a real one: verify first, then reconcile."""
    forged = Chain(bytes(range(1, 33)), "agent")
    forged.append("step.pay", {"to": "MID-1", "verdict": "allow"}, timestamp="2026-10-12T10:00:00Z")
    data = forged.to_json()
    assert verify_chain(data, trusted_keys=[PUB])["valid"] is False
    assert reconcile([{"step": 0, "counterparty": "MID-1", "claimed": "done"}], data)["matches"] == 1


# --- standalone runner ------------------------------------------------------

if __name__ == "__main__":
    import sys
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    fails = 0
    for t in tests:
        try:
            t(); print(f"  PASS  {t.__name__}")
        except Exception as e:
            fails += 1; print(f"  FAIL  {t.__name__}: {type(e).__name__}: {str(e)[:200]}")
    print(f"\n{len(tests)-fails}/{len(tests)} passed")
    sys.exit(1 if fails else 0)
