/**
 * Chain verification (TypeScript port). Same checks and security model as Python:
 * issuer pinning + fail-closed, full tamper detection (alter / delete / insert /
 * reorder / forge / truncate / backwards-time), and never throws on hostile input.
 */

import { VERSION, entryHash } from "./chain.ts";
import { unb64, verify as verifySig } from "./signing.ts";

export type TrustedKeys = string | Buffer | Array<string | Buffer>;

export interface Verdict {
  valid: boolean;
  length: number;
  broken_at: number | null;
  reason: string;
}

function normalizeTrusted(trustedKeys?: TrustedKeys): Set<string> | null {
  if (trustedKeys == null) return null;
  const arr = Array.isArray(trustedKeys) ? trustedKeys : [trustedKeys];
  return new Set(arr.map((k) => (Buffer.isBuffer(k) ? k.toString("base64") : k)));
}

function result(valid: boolean, length: number, brokenAt: number | null, reason: string): Verdict {
  return { valid, length, broken_at: brokenAt, reason };
}

export interface VerifyOptions {
  trustedKeys?: TrustedKeys;
  allowUnverifiedIssuer?: boolean;
  requireMonotonicTime?: boolean;
  expectedHead?: string | null;
}

export function verifyChain(chain: any, opts: VerifyOptions = {}): Verdict {
  const requireMonotonicTime = opts.requireMonotonicTime ?? true;
  const expectedHead = opts.expectedHead ?? null;

  let entries: any;
  if (chain && Array.isArray(chain.entries)) entries = chain.entries;
  else if (Array.isArray(chain)) entries = chain;
  else if (chain && typeof chain === "object") entries = chain.entries;
  else return result(false, 0, null, "malformed: not a chain");
  if (!Array.isArray(entries)) return result(false, 0, null, "malformed: entries is not a list");

  const trusted = normalizeTrusted(opts.trustedKeys);
  if (trusted === null && !opts.allowUnverifiedIssuer) {
    return result(false, entries.length, null,
      "no trusted issuer keys supplied: pass trustedKeys: [...] (recommended) or allowUnverifiedIssuer: true");
  }

  if (entries.length === 0) {
    if (expectedHead != null) return result(false, 0, null, "chain is empty but an expected head was given (truncated?)");
    return result(true, 0, null, "empty chain");
  }

  let prevHash: string | null = null;
  let prevTs: string | null = null;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    try {
      if (!e || typeof e !== "object" || Array.isArray(e)) return result(false, entries.length, i, "entry is not an object");
      // The stored version is not inside the hash (entryHash pins it), so check
      // it explicitly or it could be rewritten undetected (audit 2026-06-10 #9).
      if (e.version !== VERSION) return result(false, entries.length, i, `unexpected entry version ${JSON.stringify(e.version)}`);
      if (e.seq !== i) return result(false, entries.length, i, `seq mismatch: expected ${i}, got ${JSON.stringify(e.seq)}`);
      if ((e.prev_hash ?? null) !== prevHash) return result(false, entries.length, i, "broken chain link: prev_hash does not match");
      const recomputed = entryHash(e.seq, e.timestamp, e.actor, e.action, e.payload, e.prev_hash ?? null);
      if (recomputed !== e.hash) return result(false, entries.length, i, "content tampered: hash mismatch");
      const sig = e.signature;
      if (!sig || typeof sig !== "object" || sig.alg !== "Ed25519") return result(false, entries.length, i, "missing or unsupported signature");
      if (trusted !== null && !trusted.has(sig.public_key)) return result(false, entries.length, i, "signer is not in the trusted-issuer set");
      if (!verifySig(unb64(sig.value ?? ""), unb64(e.hash), unb64(sig.public_key ?? ""))) {
        return result(false, entries.length, i, "invalid signature");
      }
      if (requireMonotonicTime && prevTs != null && e.timestamp != null && e.timestamp < prevTs) {
        return result(false, entries.length, i, "timestamp goes backwards");
      }
      prevHash = e.hash;
      prevTs = e.timestamp;
    } catch (ex) {
      return result(false, entries.length, i, `malformed entry: ${(ex as Error).name}`);
    }
  }

  if (expectedHead != null && prevHash !== expectedHead) {
    return result(false, entries.length, entries.length - 1, "head hash does not match expectedHead (truncated or forked)");
  }
  return result(true, entries.length, null, "chain intact");
}
