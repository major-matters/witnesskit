# WitnessKit — Security

## Threat model

WitnessKit records what an AI agent did, in a form that resists after-the-fact
rewriting. The adversary wants to alter a logged action, delete one, insert a
fake one, reorder them, forge a whole trail, or roll the log back — to change the
story of what the agent did.

## What it detects

| Attack | Caught by |
|---|---|
| Alter an entry's content | hash recomputation (content no longer matches its hash) |
| Delete an entry | sequence-number gap + broken prev_hash link |
| Insert a fake entry | downstream seq/link mismatch; a forged entry fails signature/issuer |
| Reorder entries | sequence-number mismatch |
| Forge a whole trail | issuer pinning (signer not in `trusted_keys`) |
| Truncate / roll back | only with a known `expected_head` (see below) |
| Backwards-dated entry | optional monotonic-timestamp check |
| Malformed / hostile input | returns a verdict, never throws |

## Security posture (borrowed from MandateKit's review)

- **Issuer pinning, fail-closed.** A valid signature proves integrity, not
  authority. `verify_chain` requires `trusted_keys` and denies without it unless
  you explicitly pass `allow_unverified_issuer=True`.
- **Deterministic, cross-language hashing.** RFC 8785 (JCS) + SHA-256, byte-identical
  in Python and TypeScript, so a trail signed in one verifies in the other.
- **Vetted crypto.** Constant-time Ed25519 via `cryptography` (Python) / Node's
  built-in crypto (TS); pure-Python reference is a warned fallback only.
- **Never throws.** Property-based tests (Hypothesis) fuzz the verifier with
  arbitrary input; every path returns a verdict.

## Known limitations (by design, v0)

- **Tamper-evident, not tamper-proof.** The signing key-holder can re-sign a
  rewritten chain. True append-only-ness requires external anchoring — periodically
  publishing the head hash to a witness or transparency log. Roadmap.
- **Truncation/rollback** is invisible to the chain alone; anchor a known head and
  pass it as `expected_head` to detect it.
- **Payloads must be JSON-safe** (numbers within 2⁵³), the limit of canonical JSON.
- **Not independently audited.** Automated tooling and property tests are not a
  substitute for a third-party audit.

## Reporting

This is a pre-release v0 prototype. Do not rely on it for anything that matters yet.

## Audit status (v0)

This is a v0 release. It has been independently hardened — CodeQL, bandit, semgrep, property-based tests, and adversarial tier 1-2 reviews, all passing in CI — but it has **not** had a third-party security audit. Treat it accordingly for anything high-stakes.

## Security review welcome

We actively want researcher eyes on this. If you find a fail-open, a signature bypass, an SSRF path, or any way to defeat a guarantee in this document, please open an issue. Credit given. The shared crypto core (Ed25519 + RFC 8785 canonicalization) and the hash-chain verification are the highest-value targets.
