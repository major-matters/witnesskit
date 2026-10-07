# Changelog

Notable changes to this repository.

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
