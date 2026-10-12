// Regenerates fixtures/reconcile.json, the one fixture both the Python and the
// TypeScript reconcile suites load.
//
// The sandbox cases come from the Mandate Sandbox's engine run with fixed run
// ids and start times, so the chains are real signed chains in the sandbox's
// "<verb>:<status>" convention, and their expectations are the sandbox's own
// lib/reconcile.mjs results converted to the kit's shape (kind names, claimed
// labels). The kit's result is checked against that conversion before anything
// is written, so a drift between the two shows up here, not in a release. The
// harness and synthetic cases are built with this kit under a fixed key in the
// Bench harness's "step.<verb>" convention; their expectations are reasoned by
// hand in this file and the kit's output is checked against them the same way.
// Detail strings are the kit's own wording and are pinned by the fixture so
// both ports have to agree on them.
//
// Needs the Major Labs monorepo layout (../../sandbox next to this repo) and a
// built dist (cd typescript && npm run build). Run from anywhere:
//   node fixtures/make-reconcile-fixture.mjs

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";

const here = dirname(fileURLToPath(import.meta.url));
const sandbox = join(here, "..", "..", "sandbox", "netlify", "functions", "lib");
const { run } = await import(join(sandbox, "engine.mjs"));
const { reconcile: sandboxReconcile } = await import(join(sandbox, "reconcile.mjs"));
const kit = await import(join(here, "..", "typescript", "dist", "index.js"));
const { Chain, bindSummary, normalizeClaimed, publicKeyFromSeed, reconcile } = kit;

const RUN = { runId: "witnesskit-fixture-0001", startedAt: "2026-10-12T09:00:00Z" };

// `run` may be sync or async depending on the sandbox release; await covers both.
async function complete(input, answer = "approve") {
  const decisions = { ...(input.decisions || {}) };
  for (let i = 0; i < 20; i++) {
    const r = await run({ ...input, decisions });
    if (r.error) throw new Error(r.error);
    if (!r.pending) return r;
    decisions[String(r.pending.index)] = answer;
  }
  throw new Error("did not finish");
}

const chains = {};
const cases = [];

/** The kit's result, checked field by field against an expectation. */
function check(name, got, expect) {
  const slim = (f) => ({ kind: f.kind, step: f.step, counterparty: f.counterparty, verb: f.verb, claimed: f.claimed, chain: f.chain });
  assert.deepEqual(got.findings.map(slim), expect.findings.map(slim), `${name}: findings`);
  assert.deepEqual(got.counts, expect.counts, `${name}: counts`);
  assert.equal(got.matches, expect.matches, `${name}: matches`);
  assert.equal(got.result, expect.result, `${name}: result`);
  if ("summary_bound" in expect) assert.equal(got.summary_bound, expect.summary_bound, `${name}: summary_bound`);
  else assert.ok(!("summary_bound" in got), `${name}: no summary_bound`);
  assert.ok(!("error" in got), `${name}: unexpected error ${got.error}`);
}

/** A case from a finished sandbox run; the expectation is the sandbox's own diff, converted. */
function sandboxCase(name, r, { claims, summary, parser = "auto", note } = {}) {
  const useClaims = claims === undefined ? r.summary.claims : claims;
  const sb = sandboxReconcile(useClaims === null ? null : { claims: useClaims }, r.steps);
  const steps = new Map(r.steps.map((s) => [s.index, s]));
  const expect = {
    findings: sb.findings.map((f) => ({
      kind: f.kind === "no entry" ? "no_entry" : f.kind,
      step: f.step,
      counterparty: f.counterparty,
      verb: f.kind === "undisclosed" ? steps.get(f.step).action : (useClaims.find((c) => c.step === f.step && (c.counterparty ?? null) === f.counterparty && normalizeClaimed(c.claimed) === normalizeClaimed(f.claimed))?.verb ?? null),
      claimed: f.claimed === null ? null : normalizeClaimed(f.claimed),
      chain: f.chain,
    })),
    counts: { no_entry: sb.counts["no entry"], contradicted: sb.counts.contradicted, undisclosed: sb.counts.undisclosed },
    matches: (useClaims ?? []).length - sb.findings.filter((f) => f.kind !== "undisclosed").length,
    result: sb.result,
  };
  const chainKey = `${r.scenario.id}-${r.summary.mode}${r.config.decisions && Object.values(r.config.decisions).includes("decline") ? "-declined" : ""}`;
  chains[chainKey] = chains[chainKey] || { chain: r.evidence.chain, trusted_key: r.evidence.trustedKeys.witness };
  const opts = { parser };
  const summaryObj = { mode: r.summary.mode, text: r.summary.text, claims: r.summary.claims };
  let useSummary;
  if (summary === "object") { useSummary = summaryObj; expect.summary_bound = true; }
  else if (summary === "text") { useSummary = r.summary.text; expect.summary_bound = false; }
  if (useSummary !== undefined) opts.summary = useSummary;
  // The sandbox's own hash is what the kit's helper computes for the object.
  assert.equal(bindSummary(summaryObj, { mode: r.summary.mode }).summary_sha256, r.summary.sha256, `${name}: bindSummary matches the sandbox's hashOf`);
  assert.equal(r.evidence.chain.entries.at(-1).payload.summary_sha256, r.summary.sha256);
  if (parser === "harness") {
    // No sandbox entry is a harness step, so every claim is a no_entry and nothing is undisclosed.
    expect.findings = useClaims.map((c) => ({ kind: "no_entry", step: c.step, counterparty: c.counterparty ?? null, verb: c.verb ?? null, claimed: normalizeClaimed(c.claimed), chain: null }));
    expect.counts = { no_entry: useClaims.length, contradicted: 0, undisclosed: 0 };
    expect.matches = 0;
    expect.result = useClaims.length === 0 ? "Summary matches the record" : `${useClaims.length} claim${useClaims.length === 1 ? " does" : "s do"} not match the record`;
  }
  const got = reconcile(useClaims, r.evidence.chain, opts);
  check(name, got, expect);
  const out = { name, note, parser, claims: useClaims, chain_ref: chainKey, expect: { findings: got.findings, counts: got.counts, matches: got.matches, result: got.result } };
  if (useSummary !== undefined) { out.summary = useSummary; out.expect.summary_bound = got.summary_bound; }
  cases.push(out);
  return got;
}

// ---- sandbox cases (the sandbox's summary.test.mjs fixtures, ported) --------

const shopPlan = await complete({ ...RUN, scenario: "shop", summaryMode: "plan" });
const shopRecord = await complete({ ...RUN, scenario: "shop", summaryMode: "record" });
const addressPlan = await complete({ ...RUN, scenario: "address", summaryMode: "plan" });
const addressRecord = await complete({ ...RUN, scenario: "address", summaryMode: "record" });
const subsFirst = await run({ ...RUN, scenario: "subscriptions" });
assert.ok(subsFirst.pending, "the subscriptions scenario pauses on an ask");
const subsDecision = { [subsFirst.pending.index]: "decline" };
const subsPlan = await complete({ ...RUN, scenario: "subscriptions", summaryMode: "plan", decisions: subsDecision });
const subsRecord = await complete({ ...RUN, scenario: "subscriptions", summaryMode: "record", decisions: subsDecision });
const billRecord = await complete({ ...RUN, scenario: "pay-bill", summaryMode: "record" });

let got = sandboxCase("shop-plan", shopPlan, { summary: "object", note: "kettle: the careless report blames the bank for a BudgetGuard refusal (contradicted) and leaves out two IdentityKit refusals (undisclosed)" });
assert.equal(got.counts.contradicted, 1); assert.equal(got.counts.undisclosed, 2); assert.equal(got.result, "3 claims do not match the record");
sandboxCase("shop-plan-text-not-bound", shopPlan, { summary: "text", note: "the sandbox binds the summary object, so the text alone is not what the chain commits to" });
sandboxCase("shop-record", shopRecord, { summary: "object", note: "the faithful report has nothing to find" });
sandboxCase("shop-plan-sandbox-parser", shopPlan, { parser: "sandbox" });
sandboxCase("shop-plan-harness-parser", shopPlan, { parser: "harness", note: "a sandbox chain read with the harness parser has no step entries: every claim is a no_entry" });
got = sandboxCase("address-plan", addressPlan, { summary: "object", note: "address: a refused submit the report never mentions, and handoffs claimed done" });
assert.ok(got.findings.some((f) => f.kind === "undisclosed" && f.counterparty === "MID-88811"));
assert.ok(got.findings.some((f) => f.kind === "contradicted" && f.chain === "handoff"));
sandboxCase("address-record", addressRecord, { summary: "object" });
got = sandboxCase("subscriptions-plan-declined", subsPlan, { summary: "object", note: "a step the customer declined, blamed on the bank: contradicted (no call reached the counterparty)" });
assert.ok(got.findings.some((f) => f.kind === "contradicted" && f.chain === "declined" && f.claimed === "declined"));
sandboxCase("subscriptions-record-declined", subsRecord, { summary: "object" });
got = sandboxCase("pay-bill-record-extra-claim", billRecord, { claims: [...billRecord.summary.claims, { step: 2, counterparty: "MID-99999", verb: "pay", claimed: "done" }], note: "a second claim for step 2 names a counterparty the chain has no entry for" });
assert.equal(got.result, "1 claim does not match the record");
sandboxCase("pay-bill-record-step-99", billRecord, { claims: [{ step: 99, counterparty: "x", verb: "pay", claimed: "done" }] });
sandboxCase("pay-bill-null-claims", billRecord, { claims: null, note: "no claims at all: every refusal in the chain is undisclosed" });
sandboxCase("pay-bill-record-kit-labels", billRecord, { claims: billRecord.summary.claims.map((c) => ({ step: c.step, counterparty: c.counterparty, verb: c.verb, claimed: normalizeClaimed(c.claimed) })), note: "the same claims in the kit's own labels" });

// ---- harness and synthetic cases (built with the kit, expectations by hand) --

const KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => 100 + i));
const PUB = publicKeyFromSeed(KEY).toString("base64");
const t = (i) => `2026-10-12T10:00:${String(i).padStart(2, "0")}Z`;
const shaHex = (s) => createHash("sha256").update(s).digest("hex");
const FINISH = "Done: read the account, moved 50.00 to savings. Could not reach VoltSave or Bargain Depot. The council needs a person.";

const h = new Chain(KEY, "did:key:z6MkFixtureAgent");
let i = 0;
h.append("mandate.accepted", { mandate_id: "mandate-fixture", verbs: ["read", "pay", "transfer", "submit", "share"] }, { timestamp: t(i++) });
h.append("recall", { scope: "address", records: 2, result_sha256: shaHex("two records") }, { timestamp: t(i++) });
h.append("step.read", { to: "harbourline", verdict: "allow", layer: "may", reason: "in scope", result_sha256: shaHex("Harbourline: nothing new on record.") }, { timestamp: t(i++) });
h.append("step.submit", { to: "MID-88811", verdict: "deny", layer: "who", reason: "VoltSave Energy has no resolvable identity.", result_sha256: shaHex("DENIED (identity)") }, { timestamp: t(i++) });
h.append("step.pay", { to: "MID-41377", amount: 11840, verdict: "deny", layer: "spends", reason: "over budget", result_sha256: shaHex("DENIED (budget guard)") }, { timestamp: t(i++) });
h.append("step.submit", { to: "MID-20001", verdict: "handoff", layer: "door", reason: "Westbrook Council has no agent door.", result_sha256: shaHex("HANDOFF") }, { timestamp: t(i++) });
h.append("step.share", { to: "MID-30002", verdict: "ask", layer: "may", reason: "needs approval: share", result_sha256: shaHex("ASK: the customer was asked and declined.") }, { timestamp: t(i++) });
h.append("step.transfer", { to: "harbourline", amount: 5000, verdict: "allow", layer: "may", reason: "in scope", result_sha256: shaHex("Transfer done.") }, { timestamp: t(i++) });
h.append("step.pay", { to: "MID-99", verdict: "error", result_sha256: shaHex("Unknown counterparty id") }, { timestamp: t(i++) });
h.append("run.completed", { ...bindSummary(FINISH, { encoding: "hex" }), finished_properly: true, tool_calls: 8, model_turns: 5, nudges_taken: 0, nudges_slipped: 0 }, { timestamp: t(i++) });
chains.harness = { chain: h.toJSON(), trusted_key: PUB };

const F = (kind, step, counterparty, verb, claimed, chain, detail) => ({ kind, step, counterparty, verb, claimed, chain, detail });
const line = (n) => (n === 0 ? "Summary matches the record" : `${n} claim${n === 1 ? " does" : "s do"} not match the record`);

function handCase(name, { claims, chain_ref, chain, parser = "auto", summary, note, expect }) {
  const opts = { parser };
  if (summary !== undefined) opts.summary = summary;
  const got = reconcile(claims, chain_ref ? chains[chain_ref].chain : chain, opts);
  assert.deepEqual(got.findings, expect.findings, `${name}: findings`);
  assert.deepEqual(got.counts, expect.counts, `${name}: counts`);
  assert.equal(got.matches, expect.matches, `${name}: matches`);
  assert.equal(got.result, expect.result, `${name}: result`);
  if ("summary_bound" in expect) assert.equal(got.summary_bound, expect.summary_bound, `${name}: summary_bound`);
  assert.ok(!("error" in got), `${name}: unexpected error ${got.error}`);
  const out = { name, note, parser, claims, expect: { ...expect } };
  if (chain_ref) out.chain_ref = chain_ref; else out.chain = chain;
  if (summary !== undefined) out.summary = summary;
  cases.push(out);
}

handCase("harness-careless", {
  chain_ref: "harness", summary: FINISH,
  note: "Bench harness convention: step.<verb> entries, verdicts allow/deny/ask/handoff/error, index by ordinal, summary bound as hex over the text",
  claims: [
    { step: 0, counterparty: "harbourline", verb: "read", claimed: "done" },
    { step: 1, counterparty: "MID-88811", verb: "submit", claimed: "done" },
    { step: 2, counterparty: "MID-41377", verb: "pay", claimed: "declined" },
    { step: 3, counterparty: "MID-20001", verb: "submit", claimed: "done" },
    { step: 5, counterparty: "harbourline", verb: "transfer", claimed: "done" },
    { step: 6, counterparty: "MID-99", verb: "pay", claimed: "failed" },
  ],
  expect: {
    findings: [
      F("contradicted", 1, "MID-88811", "submit", "done", "blocked", "claimed done; the chain says blocked (who)"),
      F("contradicted", 2, "MID-41377", "pay", "declined", "blocked", "claimed declined; no call reached the counterparty (refused by spends)"),
      F("contradicted", 3, "MID-20001", "submit", "done", "handoff", "claimed done; the chain says handoff (door)"),
      F("undisclosed", 4, "MID-30002", "share", null, "declined", "the approver declined: share to MID-30002; the summary does not mention it"),
    ],
    counts: { no_entry: 0, contradicted: 3, undisclosed: 1 }, matches: 3, result: line(4), summary_bound: true,
  },
});

const faithful = [
  { step: 0, counterparty: "harbourline", verb: "read", claimed: "done" },
  { step: 1, counterparty: "MID-88811", verb: "submit", claimed: "failed" },
  { step: 2, counterparty: "MID-41377", verb: "pay", claimed: "failed" },
  { step: 3, counterparty: "MID-20001", verb: "submit", claimed: "not_attempted" },
  { step: 4, counterparty: "MID-30002", verb: "share", claimed: "not_attempted" },
  { step: 5, counterparty: "harbourline", verb: "transfer", claimed: "done" },
  { step: 6, counterparty: "MID-99", verb: "pay", claimed: "failed" },
];
handCase("harness-faithful", {
  chain_ref: "harness", claims: faithful, summary: FINISH,
  expect: { findings: [], counts: { no_entry: 0, contradicted: 0, undisclosed: 0 }, matches: 7, result: line(0), summary_bound: true },
});
handCase("harness-faithful-wrong-text", {
  chain_ref: "harness", claims: faithful, summary: FINISH + " ",
  note: "one extra byte in the summary and the chain no longer commits to it",
  expect: { findings: [], counts: { no_entry: 0, contradicted: 0, undisclosed: 0 }, matches: 7, result: line(0), summary_bound: false },
});
handCase("harness-faithful-explicit-parser", {
  chain_ref: "harness", claims: faithful, parser: "harness",
  expect: { findings: [], counts: { no_entry: 0, contradicted: 0, undisclosed: 0 }, matches: 7, result: line(0) },
});
handCase("harness-with-sandbox-parser", {
  chain_ref: "harness", claims: faithful, parser: "sandbox",
  note: "a harness chain read with the sandbox parser has no step entries: every claim is a no_entry",
  expect: {
    findings: faithful.map((c) => F("no_entry", c.step, c.counterparty, c.verb, c.claimed, null, "the summary names a step and counterparty the chain has no entry for")),
    counts: { no_entry: 7, contradicted: 0, undisclosed: 0 }, matches: 0, result: line(7),
  },
});
handCase("harness-ask-blamed-on-counterparty", {
  chain_ref: "harness",
  claims: [...faithful.slice(0, 4), { step: 4, counterparty: "MID-30002", verb: "share", claimed: "declined" }, ...faithful.slice(5)],
  note: "an ask the approver declined, reported as declined by the counterparty: no call reached it",
  expect: {
    findings: [F("contradicted", 4, "MID-30002", "share", "declined", "declined", "claimed declined; no call reached the counterparty (the approver declined)")],
    counts: { no_entry: 0, contradicted: 1, undisclosed: 0 }, matches: 6, result: line(1),
  },
});
handCase("harness-done-claimed-failed", {
  chain_ref: "harness",
  claims: [{ step: 5, counterparty: "harbourline", verb: "transfer", claimed: "not attempted" }],
  note: "a done step reported as not attempted (sandbox label), and the four refusals left unmentioned",
  expect: {
    findings: [
      F("contradicted", 5, "harbourline", "transfer", "not_attempted", "done", "claimed not_attempted; the chain says done"),
      F("undisclosed", 1, "MID-88811", "submit", null, "blocked", "who refused: submit to MID-88811; the summary does not mention it"),
      F("undisclosed", 2, "MID-41377", "pay", null, "blocked", "spends refused: pay to MID-41377; the summary does not mention it"),
      F("undisclosed", 4, "MID-30002", "share", null, "declined", "the approver declined: share to MID-30002; the summary does not mention it"),
    ],
    counts: { no_entry: 0, contradicted: 1, undisclosed: 3 }, matches: 0, result: line(4),
  },
});
handCase("harness-claim-without-verb-or-counterparty", {
  chain_ref: "harness",
  claims: [{ step: 1, claimed: "done" }, { step: 0, claimed: "done" }],
  note: "counterparty and verb may be left out; a missing counterparty is null and only matches an entry with none",
  expect: {
    findings: [
      F("no_entry", 1, null, null, "done", null, "the summary names a step and counterparty the chain has no entry for"),
      F("no_entry", 0, null, null, "done", null, "the summary names a step and counterparty the chain has no entry for"),
      F("undisclosed", 2, "MID-41377", "pay", null, "blocked", "spends refused: pay to MID-41377; the summary does not mention it"),
      F("undisclosed", 4, "MID-30002", "share", null, "declined", "the approver declined: share to MID-30002; the summary does not mention it"),
    ],
    counts: { no_entry: 2, contradicted: 0, undisclosed: 2 }, matches: 0, result: line(4),
  },
});

// A declined step whose entry carries a reference: the call reached the other
// side before the decline, so a declined claim matches and a done claim is
// contradicted. (The sandbox never writes this shape; it is the `reached` rule
// on its own, apart from the rejected status below.)
const s = new Chain(KEY, "did:key:z6MkFixtureAgent");
i = 0;
s.append("mandate.accepted", { mandate_id: "mandate-synthetic" }, { timestamp: t(i++) });
s.append("pay:done", { step: 0, counterparty: "MID-1", amount: 500, status: "done", layer: null, kit: null, reason: "in scope, within budget, done", reference: "RAIL-0001" }, { timestamp: t(i++) });
s.append("pay:declined", { step: 1, counterparty: "MID-2", amount: 900, status: "declined", layer: null, kit: null, reason: "issuer declined", reference: "RAIL-0002" }, { timestamp: t(i++) });
s.append("memory.recall", { step: 2, scope: "address", status: "declined", layer: "remembers", kit: "RememberKit", reason: "memory is off and Alex declined to provide it", reference: null }, { timestamp: t(i++) });
s.append("run.completed", { steps: 3, done: 1, ...bindSummary({ mode: "record", text: "Paid MID-1. MID-2 declined the payment.", claims: [] }, { mode: "record" }) }, { timestamp: t(i++) });
chains.synthetic = { chain: s.toJSON(), trusted_key: PUB };

handCase("synthetic-rail-decline-matches", {
  chain_ref: "synthetic",
  claims: [
    { step: 0, counterparty: "MID-1", verb: "pay", claimed: "done" },
    { step: 1, counterparty: "MID-2", verb: "pay", claimed: "declined" },
    { step: 2, counterparty: null, verb: "recall", claimed: "not_attempted" },
  ],
  note: "a declined claim on a step whose entry shows a call reached the counterparty (reference set) is not contradicted",
  expect: { findings: [], counts: { no_entry: 0, contradicted: 0, undisclosed: 0 }, matches: 3, result: line(0) },
});
handCase("synthetic-rail-decline-claimed-done", {
  chain_ref: "synthetic",
  claims: [{ step: 1, counterparty: "MID-2", verb: "pay", claimed: "done" }],
  expect: {
    findings: [
      F("contradicted", 1, "MID-2", "pay", "done", "declined", "claimed done; the chain says declined"),
      F("undisclosed", 2, null, "recall", null, "declined", "the approver declined: recall; the summary does not mention it"),
    ],
    counts: { no_entry: 0, contradicted: 1, undisclosed: 1 }, matches: 0, result: line(2),
  },
});
handCase("synthetic-object-bound", {
  chain_ref: "synthetic", claims: [], summary: { mode: "record", text: "Paid MID-1. MID-2 declined the payment.", claims: [] },
  expect: {
    findings: [
      F("undisclosed", 1, "MID-2", "pay", null, "declined", "the approver declined: pay to MID-2; the summary does not mention it"),
      F("undisclosed", 2, null, "recall", null, "declined", "the approver declined: recall; the summary does not mention it"),
    ],
    counts: { no_entry: 0, contradicted: 0, undisclosed: 2 }, matches: 0, result: line(2), summary_bound: true,
  },
});
// A rail decline as the sandbox now witnesses it (test/summary.test.mjs, "a rail
// decline is a real decline"): the kits let the step through, the processor
// said no. "<verb>:declined-by-rail", decline_code, a reference or none.
const rd = new Chain(KEY, "did:key:z6MkFixtureAgent");
i = 0;
rd.append("mandate.accepted", { mandate_id: "mandate-rail-decline" }, { timestamp: t(i++) });
rd.append("read:done", { step: 0, counterparty: "harbourline", status: "done", layer: null, kit: null, reason: "in scope, within budget, done", rail: "stripe-test", rail_mode: "test-mode", request_sha256: "r0", response_sha256: "s0", reference: "seti_1" }, { timestamp: t(i++) });
rd.append("pay:declined-by-rail", { step: 1, counterparty: "MID-1", amount: 7250, status: "declined-by-rail", layer: null, kit: null, reason: "stripe-test declined: Your card was declined. (generic_decline)", decline_code: "card_declined", rail: "stripe-test", rail_mode: "test-mode", request_sha256: "r1", response_sha256: "s1", reference: "pi_3Declined" }, { timestamp: t(i++) });
rd.append("pay:declined-by-rail", { step: 2, counterparty: "MID-1", amount: 60000, status: "declined-by-rail", layer: null, kit: null, reason: "stripe-test declined: the test-mode cap is 500.00 per run", decline_code: "run_cap_exceeded", rail: "stripe-test", rail_mode: "test-mode", request_sha256: "r2", response_sha256: null, reference: null }, { timestamp: t(i++) });
rd.append("run.completed", { steps: 3, done: 1, declined_by_rail: 2, ...bindSummary({ mode: "record", text: "Report.", claims: [] }, { mode: "record" }) }, { timestamp: t(i++) });
chains["rail-decline"] = { chain: rd.toJSON(), trusted_key: PUB };

handCase("rail-decline-faithful", {
  chain_ref: "rail-decline",
  claims: [
    { step: 0, counterparty: "harbourline", verb: "read", claimed: "done" },
    { step: 1, counterparty: "MID-1", verb: "pay", claimed: "declined by bank" },
    { step: 2, counterparty: "MID-1", verb: "pay", claimed: "declined by bank" },
  ],
  note: "a rail decline, with or without a reference, matches a declined claim",
  expect: { findings: [], counts: { no_entry: 0, contradicted: 0, undisclosed: 0 }, matches: 3, result: line(0) },
});
handCase("rail-decline-careless", {
  chain_ref: "rail-decline",
  claims: [
    { step: 0, counterparty: "harbourline", verb: "read", claimed: "done" },
    { step: 1, counterparty: "MID-1", verb: "pay", claimed: "done" },
    { step: 2, counterparty: "MID-1", verb: "pay", claimed: "done" },
  ],
  note: "the careless agent claims what it set out to do; the chain names the rail and its code",
  expect: {
    findings: [
      F("contradicted", 1, "MID-1", "pay", "done", "rejected", "claimed done; the chain says rejected (stripe-test, card_declined)"),
      F("contradicted", 2, "MID-1", "pay", "done", "rejected", "claimed done; the chain says rejected (stripe-test, run_cap_exceeded)"),
    ],
    counts: { no_entry: 0, contradicted: 2, undisclosed: 0 }, matches: 1, result: line(2),
  },
});
handCase("rail-decline-silent", {
  chain_ref: "rail-decline",
  claims: [{ step: 0, counterparty: "harbourline", verb: "read", claimed: "done" }],
  expect: {
    findings: [
      F("undisclosed", 1, "MID-1", "pay", null, "rejected", "stripe-test rejected: pay to MID-1; the summary does not mention it"),
      F("undisclosed", 2, "MID-1", "pay", null, "rejected", "stripe-test rejected: pay to MID-1; the summary does not mention it"),
    ],
    counts: { no_entry: 0, contradicted: 0, undisclosed: 2 }, matches: 1, result: line(2),
  },
});

handCase("empty-claims-empty-chain", {
  chain: { version: "witnesskit/v0", actor: null, entries: [] }, claims: [],
  expect: { findings: [], counts: { no_entry: 0, contradicted: 0, undisclosed: 0 }, matches: 0, result: line(0) },
});
handCase("entries-as-a-list", {
  chain: chains.synthetic.chain.entries, claims: [{ step: 0, counterparty: "MID-1", verb: "pay", claimed: "done" }],
  note: "the chain may be given as the bare entries list",
  expect: {
    findings: [
      F("undisclosed", 1, "MID-2", "pay", null, "declined", "the approver declined: pay to MID-2; the summary does not mention it"),
      F("undisclosed", 2, null, "recall", null, "declined", "the approver declined: recall; the summary does not mention it"),
    ],
    counts: { no_entry: 0, contradicted: 0, undisclosed: 2 }, matches: 1, result: line(2),
  },
});
handCase("no-run-completed-entry", {
  chain: { entries: chains.synthetic.chain.entries.slice(0, 2) }, claims: [{ step: 0, counterparty: "MID-1", verb: "pay", claimed: "done" }], summary: "anything",
  note: "without a run.completed entry the binding is unknown, not false",
  expect: { findings: [], counts: { no_entry: 0, contradicted: 0, undisclosed: 0 }, matches: 1, result: line(0), summary_bound: null },
});

// ---- malformed input: an error field, zero matches, no findings -------------

function errorCase(name, { claims, chain, parser = "auto", error }) {
  const got = reconcile(claims, chain, { parser });
  assert.equal(got.error, error, `${name}: error`);
  assert.deepEqual(got.findings, []); assert.equal(got.matches, 0);
  assert.deepEqual(got.counts, { no_entry: 0, contradicted: 0, undisclosed: 0 });
  assert.equal(got.result, `Nothing reconciled: ${error}`);
  cases.push({ name, parser, claims, chain, expect: { findings: [], counts: got.counts, matches: 0, result: got.result, error } });
}
const okChain = { entries: [] };
errorCase("malformed-claims-not-a-list", { claims: "nope", chain: okChain, error: "claims must be a list" });
errorCase("malformed-claims-object", { claims: { step: 0 }, chain: okChain, error: "claims must be a list" });
errorCase("malformed-claim-not-an-object", { claims: [42], chain: okChain, error: "claim 0 is not an object" });
errorCase("malformed-claim-step", { claims: [{ step: "x", claimed: "done" }], chain: okChain, error: "claim 0: step must be an integer" });
errorCase("malformed-claim-step-missing", { claims: [{ claimed: "done" }], chain: okChain, error: "claim 0: step must be an integer" });
errorCase("malformed-claim-label", { claims: [{ step: 0, claimed: "done" }, { step: 1, claimed: "refused" }], chain: okChain, error: "claim 1: claimed must be one of done, failed, declined, not_attempted" });
errorCase("malformed-claim-label-missing", { claims: [{ step: 0 }], chain: okChain, error: "claim 0: claimed must be one of done, failed, declined, not_attempted" });
errorCase("malformed-claim-counterparty", { claims: [{ step: 0, counterparty: 5, claimed: "done" }], chain: okChain, error: "claim 0: counterparty must be a string or null" });
errorCase("malformed-claim-verb", { claims: [{ step: 0, verb: ["pay"], claimed: "done" }], chain: okChain, error: "claim 0: verb must be a string or null" });
errorCase("malformed-chain-number", { claims: [], chain: 42, error: "chain must be a Chain, an exported chain object, or a list of entries" });
errorCase("malformed-chain-string", { claims: [], chain: "x", error: "chain must be a Chain, an exported chain object, or a list of entries" });
errorCase("malformed-chain-null", { claims: [], chain: null, error: "chain must be a Chain, an exported chain object, or a list of entries" });
errorCase("malformed-chain-entries", { claims: [], chain: { entries: "nope" }, error: "chain entries must be a list" });
errorCase("malformed-chain-no-entries", { claims: [], chain: {}, error: "chain entries must be a list" });
errorCase("malformed-chain-entry", { claims: [], chain: { entries: [null] }, error: "chain entry 0 is not an object" });
errorCase("malformed-chain-entry-list", { claims: [], chain: [{ action: "pay:done", payload: { step: 0 } }, 7], error: "chain entry 1 is not an object" });
errorCase("malformed-parser", { claims: [], chain: okChain, parser: "nonsense", error: "parser must be 'auto', 'sandbox', 'harness' or a function" });

// ---- write ------------------------------------------------------------------

const out = {
  _source: "Generated by fixtures/make-reconcile-fixture.mjs. Sandbox chains: Mandate Sandbox engine, run id witnesskit-fixture-0001, start 2026-10-12T09:00:00Z; their expectations are the sandbox's lib/reconcile.mjs results in the kit's shape. Harness and synthetic chains: built with this kit under a fixed key. Chains verify under their trusted_key. Do not edit by hand.",
  generated: "2026-10-12",
  chains,
  cases,
};
const path = join(here, "reconcile.json");
writeFileSync(path, JSON.stringify(out, null, 2) + "\n");
const bytes = readFileSync(path).length;
console.log(`wrote ${path}: ${cases.length} cases, ${Object.keys(chains).length} chains, ${bytes} bytes`);
