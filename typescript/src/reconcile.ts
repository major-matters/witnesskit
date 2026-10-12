/**
 * Reconcile an agent's summary against its own chain (TypeScript port; same
 * rules, wording and fixtures as the Python module).
 *
 * An agent that acts on someone's behalf ends with a report: what it did, for
 * whom, and what it could not do. The chain already holds the record: one
 * entry per step with the verdict that settled it, and a closing
 * `run.completed` entry whose `summary_sha256` commits to the report.
 * `reconcile` is the diff between those two lists, the report's claims against
 * the chain's entries. It is a comparison, not a judgment.
 *
 * Three finding kinds, from the Bench article of 2026-10-12 ("Agent said six
 * companies, signed record shows three") and the Mandate Sandbox's reference
 * implementation (lib/reconcile.mjs):
 *
 *   no_entry      a claim names a step and counterparty the chain has no entry for
 *   contradicted  a claim the chain disagrees with: claimed done where the chain
 *                 shows the step refused, declined, rejected or handed off;
 *                 claimed failed, declined or not attempted where the chain
 *                 shows it done; or claimed declined where no call ever reached
 *                 the other side, because a layer's verdict or the approver
 *                 stopped it first (a rejection by the other side is a real
 *                 decline and matches that claim, with or without a reference)
 *   undisclosed   a refusal in the chain (status blocked, declined or rejected)
 *                 that no claim mentions
 *
 * Claims: `{ step, counterparty, verb, claimed }`, `claimed` one of done,
 * failed, declined, not_attempted. The Mandate Sandbox's labels map on with
 * `normalizeClaimed`: "done" -> done, "failed" -> failed, "declined by bank" ->
 * declined, "not attempted" -> not_attempted.
 *
 * Entry conventions (`parser` option): "sandbox" reads "<verb>:<status>" and
 * "memory.recall" entries (payload step, counterparty, kit or layer, rail and
 * decline_code, reference; "declined-by-rail" is read as the kit's "rejected");
 * "harness" reads "step.<verb>" entries (payload to, verdict allow -> done,
 * deny -> blocked, ask -> declined, handoff -> handoff, error -> error; the
 * index is the ordinal among step entries since the payload has none); "auto"
 * (default) picks per entry. A custom parser is
 * `(entry, ordinal) => ParsedStep | null`. Statuses the rules know: done,
 * blocked (a layer refused it), declined (the approver said no when asked),
 * rejected (the call went out and the other side said no), handoff, pending,
 * error; any other string is "not done, not a refusal".
 *
 * Limits (honest, v0): it compares claims to entries. It does not judge whether
 * a tool result was true, it does not verify the chain (run `verifyChain`
 * first), and it cannot see a step the agent never logged. `reconcile` never
 * throws: malformed claims or chains return a result with an `error` field.
 */

import { createHash } from "node:crypto";

import { canonicalize } from "./canonical.ts";

export const CLAIMED = ["done", "failed", "declined", "not_attempted"] as const;
export type Claimed = (typeof CLAIMED)[number];

export const FINDING_KINDS = ["no_entry", "contradicted", "undisclosed"] as const;
export type FindingKind = (typeof FINDING_KINDS)[number];

const REFUSALS = new Set(["blocked", "declined", "rejected"]);

export interface Claim {
  step: number;
  counterparty?: string | null;
  verb?: string | null;
  /** done, failed, declined, not_attempted, or a Mandate Sandbox label. */
  claimed: string;
}

export interface Finding {
  kind: FindingKind;
  step: number;
  counterparty: string | null;
  verb: string | null;
  /** The normalized claim; null for an undisclosed refusal (no claim exists). */
  claimed: Claimed | null;
  /** The status the chain recorded; null when the chain has no entry. */
  chain: string | null;
  detail: string;
}

export interface ReconcileResult {
  findings: Finding[];
  /** Claims the record agrees with. */
  matches: number;
  counts: Record<FindingKind, number>;
  result: string;
  /** Present when `summary` was given: null when the chain has no run.completed entry. */
  summary_bound?: boolean | null;
  /** Present only when the claims or the chain were malformed. */
  error?: string;
}

export interface ParsedStep {
  step: number;
  counterparty: string | null;
  verb: string;
  /** done, blocked, declined, rejected, handoff, pending, error, or whatever the chain said. */
  status: string;
  /** Who gave the verdict (a kit, a layer, or the rail that rejected it), if the entry names one. */
  layer: string | null;
  /** A reason code the chain recorded (the sandbox's decline_code), if any. */
  code: string | null;
  /** True when the entry shows a call reached the counterparty (a rail reference). */
  reached: boolean;
  seq: number | null;
}

export type EntryParser = (entry: Record<string, unknown>, ordinal: number) => ParsedStep | null;

export interface ReconcileOptions {
  parser?: "auto" | "sandbox" | "harness" | EntryParser;
  /** The summary text or object, to check the chain's run.completed entry commits to it. */
  summary?: unknown;
}

export interface SummaryBinding {
  summary_sha256: string;
  summary_mode?: string;
}

const CLAIMED_ALIASES: Record<string, Claimed> = {
  done: "done",
  failed: "failed",
  declined: "declined",
  not_attempted: "not_attempted",
  // Mandate Sandbox labels (lib/summary.mjs CLAIMED)
  "declined by bank": "declined",
  "not attempted": "not_attempted",
};

const HARNESS_VERDICTS: Record<string, string> = {
  allow: "done",
  deny: "blocked",
  ask: "declined",
  handoff: "handoff",
  error: "error",
};

const SANDBOX_STATUSES: Record<string, string> = {
  "declined-by-rail": "rejected",
};

const SANDBOX_ACTION = /^([^:\s]+):([^:\s]+)$/;

class Malformed extends Error {}

const isObject = (x: unknown): x is Record<string, unknown> => !!x && typeof x === "object" && !Array.isArray(x);

/** JSON has one number type; 3.0 is the integer 3 (matches the Python port). */
const asIndex = (x: unknown): number | null => (typeof x === "number" && Number.isInteger(x) ? x : null);

/** Map a claim label onto done, failed, declined or not_attempted; null if unknown. */
export function normalizeClaimed(label: unknown): Claimed | null {
  if (typeof label !== "string") return null;
  const key = label.trim().toLowerCase().split(/\s+/).join(" ");
  return CLAIMED_ALIASES[key] ?? null;
}

// --- entry parsers -----------------------------------------------------------

const payloadOf = (entry: Record<string, unknown>): Record<string, unknown> =>
  isObject(entry.payload) ? entry.payload : {};

function step(
  entry: Record<string, unknown>,
  ordinal: number,
  f: { verb: string; status: unknown; counterparty: unknown; layer: unknown; code: unknown; reached: boolean },
): ParsedStep {
  const idx = asIndex(payloadOf(entry).step);
  return {
    step: idx === null ? ordinal : idx,
    counterparty: typeof f.counterparty === "string" ? f.counterparty : null,
    verb: f.verb,
    status: typeof f.status === "string" && f.status ? f.status : "unknown",
    layer: typeof f.layer === "string" && f.layer ? f.layer : null,
    code: typeof f.code === "string" && f.code ? f.code : null,
    reached: !!f.reached,
    seq: asIndex(entry.seq),
  };
}

/** Mandate Sandbox convention: "<verb>:<status>", or "memory.recall" with payload.status. */
export const parseEntrySandbox: EntryParser = (entry, ordinal) => {
  const action = entry.action;
  if (typeof action !== "string") return null;
  const payload = payloadOf(entry);
  let verb: string;
  let status: unknown;
  if (action === "memory.recall") {
    verb = "recall";
    status = payload.status;
  } else {
    const m = SANDBOX_ACTION.exec(action);
    if (!m) return null;
    verb = m[1];
    status = m[2];
  }
  if (typeof status === "string") status = SANDBOX_STATUSES[status] ?? status;
  // A kit or layer names who refused; when the rail rejected it, the rail does.
  const layer = payload.kit || payload.layer || (status === "rejected" ? payload.rail : null);
  return step(entry, ordinal, {
    verb, status,
    counterparty: payload.counterparty,
    layer,
    code: payload.decline_code,
    reached: !!payload.reference,
  });
};

/** Bench harness convention: "step.<verb>" with payload.verdict (allow, deny, ask, handoff, error). */
export const parseEntryHarness: EntryParser = (entry, ordinal) => {
  const action = entry.action;
  if (typeof action !== "string" || !action.startsWith("step.") || action.length === 5) return null;
  const payload = payloadOf(entry);
  const verdict = payload.verdict;
  const status = typeof verdict === "string" ? (HARNESS_VERDICTS[verdict] ?? verdict) : null;
  return step(entry, ordinal, {
    verb: action.slice(5), status,
    counterparty: payload.to,
    layer: payload.kit || payload.layer,
    code: payload.code,
    reached: !!payload.reference,
  });
};

/** Per entry: "step.<verb>" is harness, anything else is tried as sandbox. */
export const parseEntryAuto: EntryParser = (entry, ordinal) => {
  const action = entry.action;
  if (typeof action === "string" && action.startsWith("step.")) return parseEntryHarness(entry, ordinal);
  return parseEntrySandbox(entry, ordinal);
};

export const ENTRY_PARSERS: Record<"auto" | "sandbox" | "harness", EntryParser> = {
  auto: parseEntryAuto,
  sandbox: parseEntrySandbox,
  harness: parseEntryHarness,
};

// --- summary binding ---------------------------------------------------------

function summaryDigest(summary: unknown): Buffer {
  if (typeof summary === "string") return createHash("sha256").update(Buffer.from(summary, "utf8")).digest();
  if (summary && typeof summary === "object") {
    // A JSON round trip first, so undefined fields drop out as they would on the wire.
    return createHash("sha256").update(canonicalize(JSON.parse(JSON.stringify(summary)))).digest();
  }
  throw new TypeError("summary must be text or a JSON object");
}

/**
 * The `run.completed` payload fields that bind a summary to the chain. Pass
 * the summary text to hash the exact text, or the summary object to hash its
 * RFC 8785 canonical JSON. `encoding` is "base64" (default) or "hex".
 * `summary_mode` is included only when `mode` is given.
 */
export function bindSummary(
  summary: string | object,
  opts: { mode?: string; encoding?: "base64" | "hex" } = {},
): SummaryBinding {
  const encoding = opts.encoding ?? "base64";
  if (encoding !== "base64" && encoding !== "hex") throw new Error("encoding must be 'base64' or 'hex'");
  const digest = summaryDigest(summary);
  const out: SummaryBinding = { summary_sha256: digest.toString(encoding) };
  if (opts.mode !== undefined) out.summary_mode = opts.mode;
  return out;
}

function summaryBound(entries: Record<string, unknown>[], summary: unknown): boolean | null {
  let found: string | null = null;
  for (const e of entries) {
    if (e.action === "run.completed") {
      const sha = payloadOf(e).summary_sha256;
      found = typeof sha === "string" ? sha : null;
    }
  }
  if (found === null) return null;
  const digest = summaryDigest(summary);
  return found === digest.toString("base64") || found === digest.toString("hex");
}

// --- the diff ---------------------------------------------------------------

interface NormalizedClaim { step: number; counterparty: string | null; verb: string | null; claimed: Claimed }

function normalizeClaims(claims: unknown): NormalizedClaim[] {
  if (claims == null) return [];
  if (!Array.isArray(claims)) throw new Malformed("claims must be a list");
  return claims.map((c, i) => {
    if (!isObject(c)) throw new Malformed(`claim ${i} is not an object`);
    const idx = asIndex(c.step);
    if (idx === null) throw new Malformed(`claim ${i}: step must be an integer`);
    const claimed = normalizeClaimed(c.claimed);
    if (claimed === null) throw new Malformed(`claim ${i}: claimed must be one of done, failed, declined, not_attempted`);
    const counterparty = c.counterparty ?? null;
    if (counterparty !== null && typeof counterparty !== "string") throw new Malformed(`claim ${i}: counterparty must be a string or null`);
    const verb = c.verb ?? null;
    if (verb !== null && typeof verb !== "string") throw new Malformed(`claim ${i}: verb must be a string or null`);
    return { step: idx, counterparty, verb, claimed };
  });
}

function entriesOf(chain: unknown): Record<string, unknown>[] {
  let entries: unknown;
  if (Array.isArray(chain)) entries = chain;
  else if (isObject(chain)) entries = chain.entries;
  else throw new Malformed("chain must be a Chain, an exported chain object, or a list of entries");
  if (!Array.isArray(entries)) throw new Malformed("chain entries must be a list");
  entries.forEach((e, i) => { if (!isObject(e)) throw new Malformed(`chain entry ${i} is not an object`); });
  return entries as Record<string, unknown>[];
}

function resolveParser(parser: ReconcileOptions["parser"]): EntryParser {
  if (parser === undefined) return parseEntryAuto;
  if (typeof parser === "string" && parser in ENTRY_PARSERS) return ENTRY_PARSERS[parser];
  if (typeof parser === "function") return parser;
  throw new Malformed("parser must be 'auto', 'sandbox', 'harness' or a function");
}

function checkStep(s: unknown, seq: unknown): ParsedStep {
  if (!isObject(s)) throw new Malformed(`entry parser returned a non-object for entry ${JSON.stringify(seq)}`);
  const idx = asIndex(s.step);
  if (idx === null) throw new Malformed(`entry parser returned a non-integer step for entry ${JSON.stringify(seq)}`);
  return {
    step: idx,
    counterparty: typeof s.counterparty === "string" ? s.counterparty : null,
    verb: typeof s.verb === "string" ? s.verb : "step",
    status: typeof s.status === "string" && s.status ? s.status : "unknown",
    layer: typeof s.layer === "string" && s.layer ? s.layer : null,
    code: typeof s.code === "string" && s.code ? s.code : null,
    reached: !!s.reached,
    seq: asIndex(s.seq),
  };
}

function parseSteps(entries: Record<string, unknown>[], parse: EntryParser): ParsedStep[] {
  const steps: ParsedStep[] = [];
  for (const e of entries) {
    let s: ParsedStep | null;
    try {
      s = parse(e, steps.length);
    } catch (ex) { // a custom parser must not take reconcile down with it
      throw new Malformed(`entry parser failed on entry ${JSON.stringify(e.seq)}: ${(ex as Error)?.name ?? "Error"}`);
    }
    if (s === null || s === undefined) continue;
    steps.push(checkStep(s, e.seq));
  }
  return steps;
}

const to = (s: ParsedStep): string => (s.counterparty ? ` to ${s.counterparty}` : "");

/** Who gave the verdict and the code they gave, in parentheses, if the chain says. */
function who(s: ParsedStep): string {
  const parts = [s.layer, s.code].filter((p): p is string => !!p);
  return parts.length ? ` (${parts.join(", ")})` : "";
}

/** A call reached the other side: the entry says so, or the other side rejected it. */
const reached = (s: ParsedStep): boolean => s.reached || s.status === "rejected";

/** Who stopped a step that never reached its counterparty, for the declined rule. */
function stopper(s: ParsedStep): string {
  if (s.status === "blocked") return ` (refused by ${s.layer ?? "a layer"})`;
  if (s.status === "declined") return " (the approver declined)";
  if (s.status === "handoff") return " (handed to a person)";
  if (s.status === "pending") return " (still waiting for approval)";
  return "";
}

function refuser(s: ParsedStep): string {
  if (s.status === "declined") return "the approver declined";
  if (s.status === "rejected") return s.layer ? `${s.layer} rejected` : "rejected";
  return s.layer ? `${s.layer} refused` : "refused";
}

const emptyCounts = (): Record<FindingKind, number> => ({ no_entry: 0, contradicted: 0, undisclosed: 0 });

function errorResult(message: string): ReconcileResult {
  return { findings: [], matches: 0, counts: emptyCounts(), result: `Nothing reconciled: ${message}`, error: message };
}

/**
 * Diff a summary's claims against the chain's step entries. Returns
 * `{ findings, matches, counts, result }`, plus `summary_bound` when
 * `opts.summary` is given, or an `error` field (zero matches, no findings)
 * when the claims or the chain are malformed. Never throws.
 */
export function reconcile(claims: unknown, chain: unknown, opts: ReconcileOptions = {}): ReconcileResult {
  let claimsN: NormalizedClaim[];
  let steps: ParsedStep[];
  let bound: boolean | null = null;
  try {
    claimsN = normalizeClaims(claims);
    const entries = entriesOf(chain);
    const parse = resolveParser(opts.parser);
    steps = parseSteps(entries, parse);
    if (opts.summary !== undefined && opts.summary !== null) bound = summaryBound(entries, opts.summary);
  } catch (ex) {
    if (ex instanceof Malformed) return errorResult(ex.message);
    return errorResult(`malformed input: ${(ex as Error)?.name ?? "Error"}`);
  }

  const byIndex = new Map<number, ParsedStep>(steps.map((s) => [s.step, s]));
  const findings: Finding[] = [];
  const mentioned = new Set<number>();
  let matches = 0;
  for (const c of claimsN) {
    const s = byIndex.get(c.step);
    mentioned.add(c.step);
    if (!s || c.counterparty !== s.counterparty) {
      findings.push({ kind: "no_entry", step: c.step, counterparty: c.counterparty, verb: c.verb, claimed: c.claimed, chain: null,
        detail: "the summary names a step and counterparty the chain has no entry for" });
      continue;
    }
    const isDone = s.status === "done";
    const base = { step: s.step, counterparty: s.counterparty, verb: c.verb ?? s.verb, claimed: c.claimed, chain: s.status };
    if (c.claimed === "done" && !isDone) {
      findings.push({ kind: "contradicted", ...base, detail: `claimed done; the chain says ${s.status}${who(s)}` });
    } else if (c.claimed !== "done" && isDone) {
      findings.push({ kind: "contradicted", ...base, detail: `claimed ${c.claimed}; the chain says done` });
    } else if (c.claimed === "declined" && !reached(s)) {
      findings.push({ kind: "contradicted", ...base, detail: `claimed declined; no call reached the counterparty${stopper(s)}` });
    } else {
      matches += 1;
    }
  }
  for (const s of steps) {
    if (REFUSALS.has(s.status) && !mentioned.has(s.step)) {
      findings.push({ kind: "undisclosed", step: s.step, counterparty: s.counterparty, verb: s.verb, claimed: null, chain: s.status,
        detail: `${refuser(s)}: ${s.verb}${to(s)}; the summary does not mention it` });
    }
  }

  const counts = emptyCounts();
  for (const f of findings) counts[f.kind] += 1;
  const n = findings.length;
  const out: ReconcileResult = {
    findings,
    matches,
    counts,
    result: n === 0 ? "Summary matches the record" : `${n} claim${n === 1 ? " does" : "s do"} not match the record`,
  };
  if (opts.summary !== undefined && opts.summary !== null) out.summary_bound = bound;
  return out;
}
