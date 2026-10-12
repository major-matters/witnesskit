# WitnessKit (TypeScript) · v0

Tamper-evident **audit trails for AI agents**. TypeScript port of
[WitnessKit](../README.md); trails are wire-compatible with the Python SDK.

> **v0, experimental, unaudited.** On npm as `witnesskit`. Requires Node 22.6+:
> the source runs `.ts` directly via type stripping, unflagged from Node 22.18;
> on 22.6 to 22.17 the repository's `npm test` passes `--experimental-strip-types`
> for you. `npm run build` emits `dist/` + types, and the published package needs no flag.

Crypto uses Node's built-in Ed25519; canonicalization uses `canonicalize` (RFC 8785),
byte-identical to the Python SDK's hashing.

## Install

```bash
npm install witnesskit
```

Or from source: `git clone https://github.com/major-matters/witnesskit && cd witnesskit/typescript && npm install && npm run build`.

## Quick start

```ts
import { Chain, generateKeypair, verifyChain } from "witnesskit";

const { privateKey, publicKey } = generateKeypair();
const trail = new Chain(privateKey, "agent-7");
trail.append("tool_call", { tool: "search", query: "running shoes" });
trail.append("payment", { merchant: "Fleet Feet", amount: 240, currency: "USD" });

const verdict = verifyChain(trail.toJSON(), { trustedKeys: [publicKey] });
console.log(verdict.valid, verdict.reason);   // true  chain intact
```

## Security model

Pin the issuer with `trustedKeys`; without it (or `allowUnverifiedIssuer: true`)
verification **fails closed**. `verifyChain` never throws. Tamper-evident, not
tamper-proof — same model as the Python SDK; see [`../SECURITY.md`](../SECURITY.md).

## Reconcile a summary against the chain

Since 0.1.0: `reconcile(claims, chain, { parser, summary })` diffs an agent's
report against its own chain. Claims are `{ step, counterparty, verb, claimed }`
with `claimed` one of `done`, `failed`, `declined`, `not_attempted`; findings
are `no_entry`, `contradicted` or `undisclosed`;
`bindSummary(textOrObject, { mode, encoding })` gives the `run.completed`
fields. It never throws. It compares claims to entries and does not judge the
truth of a tool result; run `verifyChain` first. Full notes in
[the repository README](../README.md#reconcile-a-summary-against-the-chain)
and the `reconcile.ts` header comment.

```ts
import { reconcile } from "witnesskit";
const diff = reconcile(claims, chainJson, { summary: reportText });
console.log(diff.result, diff.summary_bound);
```

## Tests

```bash
npm test     # includes test/reconcile.test.ts, driven by ../fixtures/reconcile.json
```

## License

MIT.
