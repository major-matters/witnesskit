# TrailKit (TypeScript) · v0

Tamper-evident **audit trails for AI agents**. TypeScript port of
[TrailKit](../README.md); trails are wire-compatible with the Python SDK.

> **v0, experimental, unaudited.** Not yet on npm. Requires Node 22.6+ (runs `.ts`
> directly via type-stripping; `npm run build` emits `dist/` + types).

Crypto uses Node's built-in Ed25519; canonicalization uses `canonicalize` (RFC 8785),
byte-identical to the Python SDK's hashing.

## Install

Not yet on npm (v0). From source:

```bash
git clone https://github.com/major-matters/trailkit
cd trailkit/typescript && npm install && npm run build
```

## Quick start

```ts
import { Chain, generateKeypair, verifyChain } from "trailkit";

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

## Tests

```bash
npm test
```

## License

MIT.
