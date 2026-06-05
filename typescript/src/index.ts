/**
 * TrailKit v0 (TypeScript) - tamper-evident audit trails for AI agents.
 * Wire-compatible with the Python SDK. See the README.
 */

export { Chain, buildEntry, entryHash, VERSION } from "./chain.ts";
export type { Entry } from "./chain.ts";
export { verifyChain } from "./verify.ts";
export type { Verdict, VerifyOptions, TrustedKeys } from "./verify.ts";
export { generateKeypair, publicKeyFromSeed, b64 } from "./signing.ts";

export const __version__ = "0.0.1";
