/**
 * WitnessKit v0 (TypeScript) - tamper-evident audit trails for AI agents.
 * Wire-compatible with the Python SDK. See the README.
 */

export { Chain, buildEntry, entryHash, VERSION } from "./chain.ts";
export type { Entry } from "./chain.ts";
export { verifyChain } from "./verify.ts";
export type { Verdict, VerifyOptions, TrustedKeys } from "./verify.ts";
export { generateKeypair, publicKeyFromSeed, b64 } from "./signing.ts";
export {
  reconcile,
  bindSummary,
  normalizeClaimed,
  parseEntryAuto,
  parseEntrySandbox,
  parseEntryHarness,
  CLAIMED,
  FINDING_KINDS,
  ENTRY_PARSERS,
} from "./reconcile.ts";
export type {
  Claim,
  Claimed,
  Finding,
  FindingKind,
  ReconcileResult,
  ReconcileOptions,
  ParsedStep,
  EntryParser,
  SummaryBinding,
} from "./reconcile.ts";

export const __version__ = "0.1.0";
