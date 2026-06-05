/**
 * The tamper-evident chain (TypeScript port). Mirrors the Python module: each
 * entry commits to its content and the previous entry's hash, then signs the
 * hash. RFC-8785 canonicalization + SHA-256 makes the digest identical across
 * both SDKs.
 */

import { canonicalize } from "./canonical.ts";
import { b64, publicKeyFromSeed, sha256, sign, unb64 } from "./signing.ts";

export const VERSION = "trailkit/v0";

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
