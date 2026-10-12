# WitnessKit · v0

[![MCP Surface Check: low surface](https://img.shields.io/badge/MCP_Surface_Check-low-4FA86A)](https://majorlabs.co/security)

[![CI](https://github.com/major-matters/witnesskit/actions/workflows/ci.yml/badge.svg)](https://github.com/major-matters/witnesskit/actions/workflows/ci.yml)

> ⚠️ **Experimental — unaudited, not for production.** A v0 research prototype with
> no third-party security audit. Published to [PyPI](https://pypi.org/project/witnesskit/)
> and [npm](https://www.npmjs.com/package/witnesskit) as `witnesskit`. The on-the-wire
> format will change.

**Tamper-evident audit trails for AI agents.**

When an AI agent acts on your behalf — calls a tool, makes a decision, moves money
— you want a record of what it did that someone can't quietly rewrite after the
fact. WitnessKit makes that record. Every action becomes a log entry that is
**hash-chained** to the one before it and **signed**. Alter, delete, insert, or
reorder any entry and verification detects it and tells you exactly where.

It ships in **Python** and **TypeScript**, with byte-compatible trails (a trail
signed in one verifies in the other).

> v0 tracks the **provenance layer** of the agentic web. It's the standalone
> "evidence pack": a record that survives a dispute.

## Quick start

```python
from witnesskit import Chain, generate_keypair, verify_chain

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

## Reconcile a summary against the chain

An agent ends its run with a report: what it did, for whom, and what it could
not do. The chain already holds the record, one entry per step with the verdict
that settled it. `reconcile` (since 0.1.0) is the diff between the two lists,
the report's claims against the chain's entries. It is the check the Bench
article of 2026-10-12 asked for: a comparison of two lists the agent already
signed, with no second model judging the first.

```python
from witnesskit import Chain, bind_summary, generate_keypair, reconcile

key, public_key = generate_keypair()
trail = Chain(key, actor="agent-7")
trail.append("step.read", {"to": "harbourline", "verdict": "allow", "layer": "may"})
trail.append("step.pay", {"to": "MID-41377", "amount": 11840, "verdict": "deny", "layer": "spends"})
report = "Read the account. The bank declined the payment to MID-41377."
trail.append("run.completed", bind_summary(report, mode="record"))   # the chain commits to the report

claims = [
    {"step": 0, "counterparty": "harbourline", "verb": "read", "claimed": "done"},
    {"step": 1, "counterparty": "MID-41377", "verb": "pay", "claimed": "declined"},
]
diff = reconcile(claims, trail, summary=report)
print(diff["result"])                   # 1 claim does not match the record
print(diff["findings"][0]["detail"])    # claimed declined; no call reached the counterparty (refused by spends)
print(diff["summary_bound"])            # True: the run.completed entry commits to this exact report
```

The same in TypeScript: `reconcile(claims, trail, { summary: report })` and
`bindSummary(report, { mode: "record" })`.

**Claims** are one object per step the summary speaks about:
`{ step, counterparty, verb, claimed }`. `step` is the step index,
`counterparty` who the step was with (or null), `verb` the step's verb, and
`claimed` one of `done`, `failed`, `declined` (the other side said no) or
`not_attempted`. The Mandate Sandbox's labels are accepted as written and
normalized: "done", "failed", "declined by bank" (to `declined`) and
"not attempted" (to `not_attempted`).

**Findings** come in three kinds, each `{ kind, step, counterparty, verb, claimed, chain, detail }`:

| Kind | Meaning |
|---|---|
| `no_entry` | the summary names a step and counterparty the chain has no entry for |
| `contradicted` | the chain disagrees: claimed done where the chain shows the step refused, declined, rejected or handed off; claimed failed, declined or not attempted where the chain shows it done; or claimed declined where no call ever reached the other side (a layer's verdict or the approver stopped it first) |
| `undisclosed` | a refusal in the chain (a layer's block, the approver's decline, or a rejection by the other side) that no claim mentions |

The result is `{ findings, matches, counts, result }`: `matches` counts the
claims the record agrees with, and `result` is the one line to show,
`Summary matches the record` or `N claims do not match the record`.

**Entry conventions.** Two chains in the wild write steps differently, and the
`parser` option reads both. `"sandbox"` is the Mandate Sandbox's
`<verb>:<status>` (`pay:done`, `submit:blocked`, `pay:declined-by-rail`, plus
`memory.recall`), with `payload.step`, `counterparty`, `kit`, `rail`,
`decline_code` and `reference`. `"harness"` is the Bench harness's
`step.<verb>` with `payload.to` and a `verdict` of allow, deny, ask, handoff or
error, read as done, blocked, declined, handoff and error; the harness writes no
step index, so the index is the entry's ordinal among the step entries,
counting from 0. `"auto"` (the default) picks per entry. Pass a function
`(entry, ordinal) -> step | null` for any other convention; the module
docstring has the step shape.

**Binding the summary.** `bind_summary` / `bindSummary` produces the
`run.completed` fields (`summary_sha256`, `summary_mode`) so nobody computes
them by hand. It hashes exactly what the two callers hash today: pass the
summary text to hash the exact text (the harness, with `encoding="hex"`), or
the whole summary object to hash its RFC 8785 canonical JSON (the sandbox,
base64, the default). Pass `summary=` to `reconcile` and `summary_bound` says
whether the chain's `run.completed` entry commits to the summary you are
checking (`None` when there is no such entry).

**What it does not do (v0):** it compares claims to entries. It does not judge
whether a tool result was true, only whether the summary agrees with the
verdicts the chain recorded. It does not verify the chain: run `verify_chain`
first, since a forged chain reconciles as happily as a real one. It cannot see
a step the agent never logged, and it matches counterparties by exact string.
`reconcile` never throws: malformed claims or chains return a result with an
`error` field and zero matches.

Both suites load one fixture, [`fixtures/reconcile.json`](fixtures/reconcile.json):
real Mandate Sandbox chains with the sandbox's own reconcile results, Bench
harness chains built with the kit, and malformed inputs.

## Layout

```
witnesskit/
  python/        # pip-installable package + tests
  typescript/    # npm package, runs on Node 22+
  fixtures/      # the shared reconcile fixture and the script that regenerates it
  LICENSE        # MIT
```

Try it: `cd python && PYTHONPATH=. python3 ../demo.py`

---

## The accountability stack, September 2026

This year's frontier launches arrived alongside rogue-agent incidents that investigators struggled to attribute, and a written admission from inside the labs that runtime monitoring is degrading. The accountability primitives those events call for are what this suite implements:

> **[IdentityKit](https://github.com/major-matters/identitykit)** says who the agent is. **[MandateKit](https://github.com/major-matters/mandatekit)** says what it may do. **[BudgetGuard](https://github.com/major-matters/budget-guard)** caps what it spends. **[WitnessKit](https://github.com/major-matters/witnesskit)** proves what it did. **[RememberKit](https://github.com/major-matters/rememberkit)** governs what it remembers.

The [MM Control Stack Compact](https://www.majormatters.co/p/open-letter-control-stack-compact) (September 2026) proposes six verifiable commitments for frontier-AI accountability. Attributable agents and contractually bounded authority need running code, not pledges. This suite is a working v0 of that layer.

## License

MIT.
