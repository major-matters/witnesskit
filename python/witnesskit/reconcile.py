"""
Reconcile an agent's summary against its own chain.

An agent that acts on someone's behalf ends with a report: what it did, for
whom, and what it could not do. The chain already holds the record: one entry
per step with the verdict that settled it, and a closing `run.completed` entry
whose `summary_sha256` commits to the report. `reconcile` is the diff between
those two lists, the report's claims against the chain's entries. It is a
comparison, not a judgment: it never asks a model whether the agent was right.

Three finding kinds, from the Bench article of 2026-10-12 ("Agent said six
companies, signed record shows three") and the Mandate Sandbox's reference
implementation (lib/reconcile.mjs):

    no_entry       a claim names a step and counterparty the chain has no entry for
    contradicted   a claim the chain disagrees with: claimed done where the chain
                   shows the step refused, declined, rejected or handed off;
                   claimed failed, declined or not attempted where the chain shows
                   it done; or claimed declined where no call ever reached the
                   other side, because a layer's verdict or the approver stopped
                   it first (a rejection by the other side is a real decline and
                   matches that claim, with or without a reference)
    undisclosed    a refusal in the chain (status blocked, declined or rejected)
                   that no claim mentions

Claims shape (one per step the summary speaks about):

    {"step": 3, "counterparty": "MID-41377", "verb": "pay", "claimed": "declined"}

    step          the step index (integer); see "Entry conventions" for how an
                  entry gets its index
    counterparty  who the step was with, or None; compared to the entry exactly
    verb          the step's verb (pay, transfer, submit, recall, ...); carried
                  into findings, not used for matching
    claimed       one of done, failed, declined, not_attempted

The Mandate Sandbox's labels map onto `claimed` like this (`normalize_claimed`):
"done" -> done, "failed" -> failed, "declined by bank" -> declined,
"not attempted" -> not_attempted. Labels are lowercased and whitespace-trimmed
before the lookup. Anything else is a malformed claim.

Entry conventions (the `parser` option). Two chains write steps differently:

    "sandbox"   Mandate Sandbox: action is "<verb>:<status>" (pay:done,
                submit:blocked, transfer:declined, pay:declined-by-rail,
                pay:handoff, pay:pending) or "memory.recall" with the status in
                the payload. Payload fields: step (the index), counterparty, kit
                or layer (who gave the verdict), rail and decline_code (who
                rejected it and why), reference (set when a call reached the
                rail). "declined-by-rail" is read as the kit's "rejected".
    "harness"   Bench harness: action is "step.<verb>" and the payload carries
                to, verdict (allow, deny, ask, handoff, error), layer and
                result_sha256. Verdicts map to statuses: allow -> done,
                deny -> blocked, ask -> declined (asked and declined),
                handoff -> handoff, error -> error. There is no step index in
                the payload, so the index is the entry's ordinal among the
                chain's step entries, counting from 0. "recall" entries are not
                steps (the protocol counts only step.* entries).
    "auto"      (default) per entry: "step.<verb>" is read as harness, anything
                else as sandbox. Entries neither matches (mandate.accepted,
                kill_switch, run.completed, ...) are not steps.

In every convention an entry uses `payload.step` as its index when that is an
integer, and its ordinal among the step entries otherwise. A custom parser is
a function `(entry, ordinal) -> step or None` returning
`{"step", "counterparty", "verb", "status", "layer", "code", "reached"}`.
Statuses the rules know:

    done       the step happened
    blocked    a layer refused it before anything went out
    declined   the approver (the customer, in the sandbox) said no when asked
    rejected   the call went out and the other side said no (a rail or issuer
               decline; the sandbox's "declined-by-rail")
    handoff    handed to a person; the agent did not do it
    pending    still waiting for approval
    error      the tool or runtime failed

Any other string is treated as "not done, not a refusal". `layer` names who
gave the verdict (a kit, a layer, or the rail that rejected it) and `code` a
reason code the chain recorded, both for the finding's detail line.

Binding the summary. `bind_summary` produces the `run.completed` payload
fields (`summary_sha256`, `summary_mode`) exactly as the harness and the
sandbox compute them today: pass the summary text to hash the exact text (the
harness, with encoding="hex"), or the whole summary object to hash its RFC
8785 canonical JSON (the sandbox, base64). The digest is base64 by default,
like every other hash in this kit. Pass `summary=` to `reconcile` to also
check that the chain's `run.completed` entry commits to the summary you are
reconciling (`summary_bound`: True, False, or None when the chain has no such
entry).

Limits (honest, v0): it compares claims to entries. It does not judge whether
a tool result was true, it does not verify the chain (run `verify_chain`
first; a forged chain reconciles as happily as a real one), and it cannot see
a step the agent never logged. `reconcile` never raises: malformed claims or
chains return a result with an `error` field and zero matches.
"""

import hashlib
import re
from typing import Any, Callable, Dict, List, Optional, Union

from .canonical import canonicalize
from .signing import b64

CLAIMED = ("done", "failed", "declined", "not_attempted")
FINDING_KINDS = ("no_entry", "contradicted", "undisclosed")
REFUSALS = ("blocked", "declined", "rejected")

_CLAIMED_ALIASES = {
    "done": "done",
    "failed": "failed",
    "declined": "declined",
    "not_attempted": "not_attempted",
    # Mandate Sandbox labels (lib/summary.mjs CLAIMED)
    "declined by bank": "declined",
    "not attempted": "not_attempted",
}

_HARNESS_VERDICTS = {
    "allow": "done",
    "deny": "blocked",
    "ask": "declined",
    "handoff": "handoff",
    "error": "error",
}

_SANDBOX_STATUSES = {
    "declined-by-rail": "rejected",
}

_SANDBOX_ACTION = re.compile(r"^([^:\s]+):([^:\s]+)$")

Step = Dict[str, Any]
EntryParser = Callable[[Dict[str, Any], int], Optional[Step]]


class _Malformed(Exception):
    pass


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _as_index(x: Any) -> Optional[int]:
    """JSON has one number type; 3.0 is the integer 3 (matches the TypeScript port)."""
    if _is_int(x):
        return x
    if isinstance(x, float) and x.is_integer():
        return int(x)
    return None


def normalize_claimed(label: Any) -> Optional[str]:
    """Map a claim label onto done, failed, declined or not_attempted; None if unknown."""
    if not isinstance(label, str):
        return None
    key = " ".join(label.strip().lower().split())
    return _CLAIMED_ALIASES.get(key)


# --- entry parsers -----------------------------------------------------------

def _payload_of(entry: Dict[str, Any]) -> Dict[str, Any]:
    p = entry.get("payload")
    return p if isinstance(p, dict) else {}


def _step(entry: Dict[str, Any], ordinal: int, *, verb: str, status: Any,
          counterparty: Any, layer: Any, code: Any, reached: bool) -> Step:
    payload = _payload_of(entry)
    idx = _as_index(payload.get("step"))
    return {
        "step": ordinal if idx is None else idx,
        "counterparty": counterparty if isinstance(counterparty, str) else None,
        "verb": verb,
        "status": status if isinstance(status, str) and status else "unknown",
        "layer": layer if isinstance(layer, str) and layer else None,
        "code": code if isinstance(code, str) and code else None,
        "reached": bool(reached),
        "seq": entry.get("seq") if _is_int(entry.get("seq")) else None,
    }


def parse_entry_sandbox(entry: Dict[str, Any], ordinal: int) -> Optional[Step]:
    """Mandate Sandbox convention: "<verb>:<status>", or "memory.recall" with payload.status."""
    action = entry.get("action")
    if not isinstance(action, str):
        return None
    payload = _payload_of(entry)
    if action == "memory.recall":
        verb, status = "recall", payload.get("status")
    else:
        m = _SANDBOX_ACTION.match(action)
        if not m:
            return None
        verb, status = m.group(1), m.group(2)
    if isinstance(status, str):
        status = _SANDBOX_STATUSES.get(status, status)
    # A kit or layer names who refused; when the rail rejected it, the rail does.
    layer = payload.get("kit") or payload.get("layer") or (payload.get("rail") if status == "rejected" else None)
    return _step(entry, ordinal, verb=verb, status=status,
                 counterparty=payload.get("counterparty"), layer=layer,
                 code=payload.get("decline_code"),
                 reached=bool(payload.get("reference")))


def parse_entry_harness(entry: Dict[str, Any], ordinal: int) -> Optional[Step]:
    """Bench harness convention: "step.<verb>" with payload.verdict (allow, deny, ask, handoff, error)."""
    action = entry.get("action")
    if not isinstance(action, str) or not action.startswith("step.") or len(action) == 5:
        return None
    payload = _payload_of(entry)
    verdict = payload.get("verdict")
    status = _HARNESS_VERDICTS.get(verdict, verdict) if isinstance(verdict, str) else None
    return _step(entry, ordinal, verb=action[5:], status=status,
                 counterparty=payload.get("to"),
                 layer=payload.get("kit") or payload.get("layer"),
                 code=payload.get("code"),
                 reached=bool(payload.get("reference")))


def parse_entry_auto(entry: Dict[str, Any], ordinal: int) -> Optional[Step]:
    """Per entry: "step.<verb>" is harness, anything else is tried as sandbox."""
    action = entry.get("action")
    if isinstance(action, str) and action.startswith("step."):
        return parse_entry_harness(entry, ordinal)
    return parse_entry_sandbox(entry, ordinal)


ENTRY_PARSERS: Dict[str, EntryParser] = {
    "auto": parse_entry_auto,
    "sandbox": parse_entry_sandbox,
    "harness": parse_entry_harness,
}


# --- summary binding ---------------------------------------------------------

def _summary_digest(summary: Any) -> bytes:
    if isinstance(summary, str):
        return hashlib.sha256(summary.encode("utf-8")).digest()
    if isinstance(summary, (dict, list)):
        return hashlib.sha256(canonicalize(summary)).digest()
    raise TypeError("summary must be text or a JSON object")


def bind_summary(summary: Union[str, Dict[str, Any], List[Any]], *,
                 mode: Optional[str] = None, encoding: str = "base64") -> Dict[str, str]:
    """The `run.completed` payload fields that bind a summary to the chain.

    Pass the summary text to hash the exact text, or the summary object to hash
    its RFC 8785 canonical JSON. `encoding` is "base64" (default) or "hex".
    `summary_mode` is included only when `mode` is given, so a payload built
    without one keeps its shape."""
    if encoding not in ("base64", "hex"):
        raise ValueError("encoding must be 'base64' or 'hex'")
    digest = _summary_digest(summary)
    out = {"summary_sha256": b64(digest) if encoding == "base64" else digest.hex()}
    if mode is not None:
        out["summary_mode"] = mode
    return out


def _summary_bound(entries: List[Dict[str, Any]], summary: Any) -> Optional[bool]:
    found = None
    for e in entries:
        if e.get("action") == "run.completed":
            sha = _payload_of(e).get("summary_sha256")
            found = sha if isinstance(sha, str) else None
    if found is None:
        return None
    digest = _summary_digest(summary)
    return found in (b64(digest), digest.hex())


# --- the diff ---------------------------------------------------------------

def _normalize_claims(claims: Any) -> List[Dict[str, Any]]:
    if claims is None:
        return []
    if not isinstance(claims, (list, tuple)):
        raise _Malformed("claims must be a list")
    out = []
    for i, c in enumerate(claims):
        if not isinstance(c, dict):
            raise _Malformed(f"claim {i} is not an object")
        step = _as_index(c.get("step"))
        if step is None:
            raise _Malformed(f"claim {i}: step must be an integer")
        claimed = normalize_claimed(c.get("claimed"))
        if claimed is None:
            raise _Malformed(f"claim {i}: claimed must be one of done, failed, declined, not_attempted")
        counterparty = c.get("counterparty")
        if counterparty is not None and not isinstance(counterparty, str):
            raise _Malformed(f"claim {i}: counterparty must be a string or null")
        verb = c.get("verb")
        if verb is not None and not isinstance(verb, str):
            raise _Malformed(f"claim {i}: verb must be a string or null")
        out.append({"step": step, "counterparty": counterparty, "verb": verb, "claimed": claimed})
    return out


def _entries_of(chain: Any) -> List[Dict[str, Any]]:
    if hasattr(chain, "entries"):
        entries = chain.entries
    elif isinstance(chain, dict):
        entries = chain.get("entries")
    elif isinstance(chain, list):
        entries = chain
    else:
        raise _Malformed("chain must be a Chain, an exported chain object, or a list of entries")
    if not isinstance(entries, list):
        raise _Malformed("chain entries must be a list")
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            raise _Malformed(f"chain entry {i} is not an object")
    return entries


def _resolve_parser(parser: Any) -> EntryParser:
    if isinstance(parser, str) and parser in ENTRY_PARSERS:
        return ENTRY_PARSERS[parser]
    if callable(parser):
        return parser
    raise _Malformed("parser must be 'auto', 'sandbox', 'harness' or a function")


def _check_step(s: Any, seq: Any) -> Step:
    if not isinstance(s, dict):
        raise _Malformed(f"entry parser returned a non-object for entry {seq!r}")
    idx = _as_index(s.get("step"))
    if idx is None:
        raise _Malformed(f"entry parser returned a non-integer step for entry {seq!r}")
    status = s.get("status")
    counterparty = s.get("counterparty")
    layer = s.get("layer")
    code = s.get("code")
    return {
        "step": idx,
        "counterparty": counterparty if isinstance(counterparty, str) else None,
        "verb": s.get("verb") if isinstance(s.get("verb"), str) else "step",
        "status": status if isinstance(status, str) and status else "unknown",
        "layer": layer if isinstance(layer, str) and layer else None,
        "code": code if isinstance(code, str) and code else None,
        "reached": bool(s.get("reached")),
        "seq": s.get("seq") if _is_int(s.get("seq")) else None,
    }


def _parse_steps(entries: List[Dict[str, Any]], parse: EntryParser) -> List[Step]:
    steps: List[Step] = []
    for e in entries:
        try:
            s = parse(e, len(steps))
        except Exception as ex:  # a custom parser must not take reconcile down with it
            raise _Malformed(f"entry parser failed on entry {e.get('seq')!r}: {type(ex).__name__}")
        if s is None:
            continue
        steps.append(_check_step(s, e.get("seq")))
    return steps


def _finding(kind: str, *, step: int, counterparty: Optional[str], verb: Optional[str],
             claimed: Optional[str], chain: Optional[str], detail: str) -> Dict[str, Any]:
    return {"kind": kind, "step": step, "counterparty": counterparty, "verb": verb,
            "claimed": claimed, "chain": chain, "detail": detail}


def _to(s: Step) -> str:
    return f" to {s['counterparty']}" if s["counterparty"] else ""


def _who(s: Step) -> str:
    """Who gave the verdict and the code they gave, in parentheses, if the chain says."""
    parts = [p for p in (s["layer"], s["code"]) if p]
    return f" ({', '.join(parts)})" if parts else ""


def _reached(s: Step) -> bool:
    """A call reached the other side: the entry says so, or the other side rejected it."""
    return s["reached"] or s["status"] == "rejected"


def _stopper(s: Step) -> str:
    """Who stopped a step that never reached its counterparty, for the declined rule."""
    if s["status"] == "blocked":
        return f" (refused by {s['layer'] or 'a layer'})"
    if s["status"] == "declined":
        return " (the approver declined)"
    if s["status"] == "handoff":
        return " (handed to a person)"
    if s["status"] == "pending":
        return " (still waiting for approval)"
    return ""


def _refuser(s: Step) -> str:
    if s["status"] == "declined":
        return "the approver declined"
    if s["status"] == "rejected":
        return f"{s['layer']} rejected" if s["layer"] else "rejected"
    return f"{s['layer']} refused" if s["layer"] else "refused"


def _empty_counts() -> Dict[str, int]:
    return {k: 0 for k in FINDING_KINDS}


def _error_result(message: str) -> Dict[str, Any]:
    return {"findings": [], "matches": 0, "counts": _empty_counts(),
            "result": f"Nothing reconciled: {message}", "error": message}


def reconcile(claims: Any, chain: Any, *, parser: Union[str, EntryParser] = "auto",
              summary: Any = None) -> Dict[str, Any]:
    """Diff a summary's claims against the chain's step entries.

    Returns {"findings": [...], "matches": n, "counts": {...}, "result": "..."},
    plus "summary_bound" when `summary` is given, or an "error" field (with
    zero matches and no findings) when the claims or the chain are malformed.
    Never raises."""
    try:
        claims_n = _normalize_claims(claims)
        entries = _entries_of(chain)
        parse = _resolve_parser(parser)
        steps = _parse_steps(entries, parse)
        bound = _summary_bound(entries, summary) if summary is not None else None
    except _Malformed as ex:
        return _error_result(str(ex))
    except Exception as ex:  # e.g. a summary object the canonicalizer refuses
        return _error_result(f"malformed input: {type(ex).__name__}")

    by_index: Dict[int, Step] = {s["step"]: s for s in steps}
    findings: List[Dict[str, Any]] = []
    mentioned = set()
    matches = 0
    for c in claims_n:
        s = by_index.get(c["step"])
        mentioned.add(c["step"])
        if s is None or c["counterparty"] != s["counterparty"]:
            findings.append(_finding("no_entry", step=c["step"], counterparty=c["counterparty"],
                                     verb=c["verb"], claimed=c["claimed"], chain=None,
                                     detail="the summary names a step and counterparty the chain has no entry for"))
            continue
        is_done = s["status"] == "done"
        base = dict(step=s["step"], counterparty=s["counterparty"],
                    verb=c["verb"] if c["verb"] is not None else s["verb"],
                    claimed=c["claimed"], chain=s["status"])
        if c["claimed"] == "done" and not is_done:
            findings.append(_finding("contradicted", detail=f"claimed done; the chain says {s['status']}{_who(s)}", **base))
        elif c["claimed"] != "done" and is_done:
            findings.append(_finding("contradicted", detail=f"claimed {c['claimed']}; the chain says done", **base))
        elif c["claimed"] == "declined" and not _reached(s):
            findings.append(_finding("contradicted",
                                     detail=f"claimed declined; no call reached the counterparty{_stopper(s)}", **base))
        else:
            matches += 1
    for s in steps:
        if s["status"] in REFUSALS and s["step"] not in mentioned:
            findings.append(_finding("undisclosed", step=s["step"], counterparty=s["counterparty"],
                                     verb=s["verb"], claimed=None, chain=s["status"],
                                     detail=f"{_refuser(s)}: {s['verb']}{_to(s)}; the summary does not mention it"))

    counts = _empty_counts()
    for f in findings:
        counts[f["kind"]] += 1
    n = len(findings)
    out: Dict[str, Any] = {
        "findings": findings,
        "matches": matches,
        "counts": counts,
        "result": "Summary matches the record" if n == 0
        else f"{n} claim{' does' if n == 1 else 's do'} not match the record",
    }
    if summary is not None:
        out["summary_bound"] = bound
    return out
