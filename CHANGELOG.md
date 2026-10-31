# Changelog

Notable changes to this repository.

## 0.1.1 (2026-10-31)

Both packages. No change to the chain, the entry hash, the verifier or
`reconcile`: a 0.1.0 chain verifies unchanged. Repository and packaging only.

- `python/LICENSE` is in the package directory, so sdists and wheels carry it.
- Shared Ed25519 reference file: the docstring is generic (the same bytes
  serve all four signing kits; it named MandateKit); CI pins the SHA-256 of
  `ed25519.py`, `canonical.py` and `canonical.ts`.
- CI runs every file under `python/tests` through pytest, installs with
  `npm ci`, pins every action to a commit SHA, declares read-only permissions
  and pins the Semgrep image; Dependabot for npm, pip and Actions; a
  tag-driven Release workflow with Trusted Publishing; SECURITY.md points to
  private vulnerability reporting; CITATION.cff carries the version.

## 0.1.0 (2026-10-12)

Both packages. No change to the chain, the entry hash or the verifier: a
0.0.x chain verifies unchanged. Labels unchanged: v0, experimental, unaudited.

- New: `reconcile(claims, chain, options)` diffs an agent's summary against
  its own chain and returns `findings` of three kinds (`no_entry`,
  `contradicted`, `undisclosed`), a `matches` count, per-kind `counts` and a
  one-line `result`. The rules follow the Bench article of 2026-10-12 and the
  Mandate Sandbox's `lib/reconcile.mjs`, whose results it reproduces on the
  sandbox's own runs. Claims are `{ step, counterparty, verb, claimed }` with
  `claimed` one of done, failed, declined, not_attempted; the sandbox's
  "declined by bank" and "not attempted" labels are accepted and normalized
  (`normalize_claimed` / `normalizeClaimed`).
- New: the `parser` option reads two entry conventions, the Mandate Sandbox's
  `<verb>:<status>` and the Bench harness's `step.<verb>` (`auto`, the
  default, picks per entry); a function can be passed for any other. The
  sandbox's `declined-by-rail` status reads as the kit's `rejected`: a real
  decline, so a declined claim matches it and silence about it is undisclosed.
- New: `bind_summary` / `bindSummary` produces the `run.completed` fields
  (`summary_sha256`, `summary_mode`) exactly as the two callers compute them
  today: the harness hashes the summary text (hex), the sandbox hashes the RFC
  8785 canonical summary object (base64, the kit's default). Passing
  `summary` to `reconcile` adds `summary_bound`, whether the chain's
  `run.completed` entry commits to the summary being checked.
- `reconcile` never throws: malformed claims or chains return a result with
  an `error` field and zero matches.
- One shared fixture, `fixtures/reconcile.json`, drives both test suites: real
  sandbox chains with the sandbox's own reconcile results in the kit's shape,
  harness-shaped chains built with the kit, and malformed inputs.
  `fixtures/make-reconcile-fixture.mjs` regenerates it and stops if the kit
  and the sandbox disagree.
- Versions: the Python `__version__` had stayed at 0.0.1 (pyproject said
  0.0.2) and the npm lock file at 0.0.1; everything now reads 0.1.0.
- README: the reconcile section. The Python and TypeScript READMEs now say
  install from PyPI and npm; both still said "not yet".
- CI: the Python jobs run the reconcile tests, including the dependency-free one.
- No new runtime dependencies.

## 0.0.3 (2026-10-07)

TypeScript package only; no change to the chain, the entry hash or the
verifier.

- `npm test` now passes `--experimental-strip-types`, so it works on Node 22.6
  to 22.17 as the README promised (type stripping is unflagged only from
  22.18).
- The module's exported `__version__` now matches `package.json` (it had
  stayed at 0.0.1 through the 0.0.2 release).
- README: on npm since 2026-06-10 (the TypeScript README still said it was
  not), and the Node version note.

## 2026-09-08

- README: install from PyPI/npm (live since 2026-06-10).
- README: added "The accountability stack, September 2026" positioning section
  linking the suite to the MM Control Stack Compact.
