/**
 * The tamper-evident chain (TypeScript port). Mirrors the Python module: each
 * entry commits to its content and the previous entry's hash, then signs the
 * hash. RFC-8785 canonicalization + SHA-256 makes the digest identical across
 * both SDKs.
 */

import { canonicalize } from "./canonical.ts";
import { b64, publicKeyFromSeed, sha256, sign, unb64 } from "./signing.ts";

export const VERSION = "witnesskit/v0";

export interface Entry {
  version: string;
  seq: number;
  timestamp: string;
  actor: string;
  action: string;
  payload: unknown;
  prev_hash: string | null;
  hash: string;
  signature: { alg: "Ed25519"; public_key: string; value: string };
}

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const MAX_PAYLOAD_DEPTH = 64;

/** Reject payloads that would crash or diverge at canonicalization time, with a
 *  clear error, so a hostile tool output cannot DoS the logging path or break
 *  cross-language hashing (audit 2026-06-10 finding #8). */
export function validatePayload(payload: unknown, depth = 0): void {
  if (depth > MAX_PAYLOAD_DEPTH) throw new Error(`payload nesting exceeds ${MAX_PAYLOAD_DEPTH} levels`);
  if (payload === null || typeof payload === "string" || typeof payload === "boolean") return;
  if (typeof payload === "number") {
    if (!Number.isFinite(payload)) throw new Error("payload number must be finite");
    if (Number.isInteger(payload) && Math.abs(payload) > MAX_SAFE) {
      throw new Error("payload integer outside the JS-safe range (2^53-1); stringify large numbers before logging");
    }
    return;
  }
  if (Array.isArray(payload)) {
    for (const v of payload) validatePayload(v, depth + 1);
    return;
  }
  if (typeof payload === "object") {
    for (const v of Object.values(payload as Record<string, unknown>)) validatePayload(v, depth + 1);
    return;
  }
  throw new Error(`payload contains a non-JSON-serializable type: ${typeof payload}`);
}

export function entryHash(
  seq: number,
  timestamp: string,
  actor: string,
  action: string,
  payload: unknown,
  prevHash: string | null,
): string {
  const content = { version: VERSION, seq, timestamp, actor, action, payload, prev_hash: prevHash };
  return b64(sha256(canonicalize(content)));
}

export function buildEntry(opts: {
  seq: number;
  actor: string;
  action: string;
  payload: unknown;
  prevHash: string | null;
  privateKey: Buffer;
  timestamp?: string;
}): Entry {
  const timestamp = opts.timestamp ?? nowIso();
  validatePayload(opts.payload);
  const hash = entryHash(opts.seq, timestamp, opts.actor, opts.action, opts.payload, opts.prevHash);
  const signature = sign(unb64(hash), opts.privateKey);
  return {
    version: VERSION,
    seq: opts.seq,
    timestamp,
    actor: opts.actor,
    action: opts.action,
    payload: opts.payload,
    prev_hash: opts.prevHash,
    hash,
    signature: {
      alg: "Ed25519",
      public_key: b64(publicKeyFromSeed(opts.privateKey)),
      value: b64(signature),
    },
  };
}

export class Chain {
  private key: Buffer | null;
  actor: string | null;
  entries: Entry[];

  constructor(privateKey: Buffer | null, actor: string | null, entries: Entry[] = []) {
    this.key = privateKey;
    this.actor = actor;
    this.entries = [...entries];
  }

  get headHash(): string | null {
    return this.entries.length ? this.entries[this.entries.length - 1].hash : null;
  }

  append(action: string, payload: unknown = {}, opts: { timestamp?: string } = {}): Entry {
    if (this.key == null) throw new Error("Chain has no signing key; cannot append");
    const entry = buildEntry({
      seq: this.entries.length,
      actor: this.actor ?? "",
      action,
      payload: payload ?? {},
      prevHash: this.headHash,
      privateKey: this.key,
      timestamp: opts.timestamp,
    });
    this.entries.push(entry);
    return entry;
  }

  toJSON(): { version: string; actor: string | null; entries: Entry[] } {
    return { version: VERSION, actor: this.actor, entries: this.entries };
  }

  static open(data: any, privateKey: Buffer | null = null, actor: string | null = null): Chain {
    const entries: Entry[] = Array.isArray(data) ? data : (data?.entries ?? []);
    let a = actor;
    if (a == null && data && !Array.isArray(data)) a = data.actor ?? null;
    if (a == null && entries.length) a = entries[entries.length - 1]?.actor ?? null;
    return new Chain(privateKey, a, entries);
  }
}
