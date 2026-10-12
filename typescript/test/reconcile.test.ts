/**
 * Reconcile tests (TypeScript). Run: npm test (node --test).
 *
 * Most cases come from ../../fixtures/reconcile.json, the one fixture the
 * Python and TypeScript suites share: real Mandate Sandbox chains with the
 * sandbox's own reconcile results in the kit's shape, Bench-harness-shaped
 * chains built with the kit, and malformed inputs. The hand-written tests port
 * the sandbox's summary.test.mjs assertions and cover what JSON cannot carry
 * (a Chain object, a custom parser function).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  CLAIMED,
  Chain,
  ENTRY_PARSERS,
  bindSummary,
  normalizeClaimed,
  publicKeyFromSeed,
  reconcile,
  verifyChain,
} from "../src/index.ts";
import type { EntryParser, Finding } from "../src/index.ts";

const FIX = JSON.parse(readFileSync(new URL("../../fixtures/reconcile.json", import.meta.url), "utf8"));

const KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const PUB = publicKeyFromSeed(KEY).toString("base64");

const chainOf = (c: any) => ("chain_ref" in c ? FIX.chains[c.chain_ref].chain : c.chain);
const run = (c: any) => {
  const opts: any = { parser: c.parser ?? "auto" };
  if ("summary" in c) opts.summary = c.summary;
  return reconcile(c.claims, structuredClone(chainOf(c)), opts);
};
const byName = (name: string) => FIX.cases.find((c: any) => c.name === name);

// --- the shared fixture -------------------------------------------------------

test("fixture chains are real signed chains", () => {
  for (const [name, c] of Object.entries<any>(FIX.chains)) {
    assert.equal(verifyChain(c.chain, { trustedKeys: [c.trusted_key] }).valid, true, name);
  }
});

test("fixture cases", () => {
  assert.ok(FIX.cases.length >= 40);
  for (const c of FIX.cases) {
    const got: any = run(c);
    const exp = c.expect;
    assert.deepEqual(got.findings, exp.findings, `${c.name}: findings`);
    assert.deepEqual(got.counts, exp.counts, `${c.name}: counts`);
    assert.equal(got.matches, exp.matches, `${c.name}: matches`);
    assert.equal(got.result, exp.result, `${c.name}: result`);
    if ("summary_bound" in exp) assert.equal(got.summary_bound, exp.summary_bound, `${c.name}: summary_bound`);
    else assert.ok(!("summary_bound" in got), c.name);
    if ("error" in exp) {
      assert.equal(got.error, exp.error, c.name);
      assert.equal(got.matches, 0); assert.deepEqual(got.findings, []);
    } else assert.ok(!("error" in got), `${c.name}: ${got.error}`);
  }
});

test("fixture covers every finding kind and both conventions", () => {
  const kinds = new Set<string>(); const parsers = new Set<string>();
  for (const c of FIX.cases) { parsers.add(c.parser ?? "auto"); for (const f of c.expect.findings) kinds.add(f.kind); }
  assert.deepEqual([...kinds].sort(), ["contradicted", "no_entry", "undisclosed"]);
  assert.deepEqual([...parsers].sort(), ["auto", "harness", "nonsense", "sandbox"]);
  assert.ok(FIX.cases.some((c: any) => "error" in c.expect));
});

// --- the sandbox's summary.test.mjs, ported -----------------------------------

test("kettle: the plan-mode run blames the bank and hides two refusals", () => {
  const got = run(byName("shop-plan"));
  const contradicted = got.findings.filter((f) => f.kind === "contradicted");
  assert.equal(contradicted.length, 1);
  const [c] = contradicted;
  assert.equal(c.verb, "pay"); assert.equal(c.counterparty, "MID-41377"); assert.equal(c.claimed, "declined"); assert.equal(c.chain, "blocked");
  assert.match(c.detail, /no call reached the counterparty \(refused by BudgetGuard\)/);
  assert.deepEqual(got.findings.filter((f) => f.kind === "undisclosed").map((f) => f.step), [2, 3]);
  assert.deepEqual(got.counts, { no_entry: 0, contradicted: 1, undisclosed: 2 });
  assert.equal(got.result, "3 claims do not match the record");
  assert.equal(got.summary_bound, true);
  const rec = run(byName("shop-record"));
  assert.deepEqual(rec.findings, []); assert.equal(rec.result, "Summary matches the record");
  assert.equal(rec.matches, byName("shop-record").claims.length);
});

test("address: an undisclosed refusal, and handoffs claimed done", () => {
  const got = run(byName("address-plan"));
  const volt = got.findings.find((f) => f.kind === "undisclosed" && f.counterparty === "MID-88811")!;
  assert.equal(volt.verb, "submit"); assert.equal(volt.chain, "blocked");
  assert.equal(volt.detail, "IdentityKit refused: submit to MID-88811; the summary does not mention it");
  assert.ok(got.findings.some((f) => f.kind === "contradicted" && f.chain === "handoff" && f.detail === "claimed done; the chain says handoff"));
  assert.deepEqual(run(byName("address-record")).findings, []);
});

test("a declined ask blamed on the bank is contradicted", () => {
  const got = run(byName("subscriptions-plan-declined"));
  assert.ok(got.findings.some((f) => f.kind === "contradicted" && f.chain === "declined" && f.detail.endsWith("(the approver declined)")));
  const faithful = byName("subscriptions-record-declined");
  assert.ok(faithful.claims.some((c: any) => c.claimed === "not attempted"));
  assert.deepEqual(run(faithful).findings, []);
});

test("the no_entry finding, and the result line's grammar", () => {
  const got = run(byName("pay-bill-record-extra-claim"));
  assert.deepEqual(got.findings.filter((f) => f.kind === "no_entry").map((f) => f.counterparty), ["MID-99999"]);
  assert.equal(got.result, "1 claim does not match the record");
  assert.equal(run(byName("pay-bill-record-step-99")).counts.no_entry, 1);
  const silent = run(byName("pay-bill-null-claims"));
  assert.equal(silent.counts.no_entry, 0); assert.equal(silent.counts.contradicted, 0);
  assert.ok(silent.counts.undisclosed > 0 && silent.counts.undisclosed === silent.findings.length);
  assert.deepEqual(reconcile([], { entries: [] }), { findings: [], matches: 0, counts: { no_entry: 0, contradicted: 0, undisclosed: 0 }, result: "Summary matches the record" });
});

test("a rail decline is a real decline", () => {
  assert.deepEqual(run(byName("rail-decline-faithful")).findings, []);
  const careless = run(byName("rail-decline-careless"));
  assert.equal(careless.counts.contradicted, 2);
  assert.match(careless.findings.find((f) => f.step === 1)!.detail, /rejected \(stripe-test, card_declined\)/);
  assert.match(careless.findings.find((f) => f.step === 2)!.detail, /run_cap_exceeded/);
  const silent = run(byName("rail-decline-silent"));
  assert.equal(silent.counts.undisclosed, 2);
  assert.equal(silent.findings[0].detail, "stripe-test rejected: pay to MID-1; the summary does not mention it");
});

// --- the claims contract ------------------------------------------------------

test("claimed labels normalize", () => {
  assert.deepEqual([...CLAIMED], ["done", "failed", "declined", "not_attempted"]);
  assert.equal(normalizeClaimed("declined by bank"), "declined");
  assert.equal(normalizeClaimed("  Declined  By Bank "), "declined");
  assert.equal(normalizeClaimed("not attempted"), "not_attempted");
  assert.equal(normalizeClaimed("NOT_ATTEMPTED"), "not_attempted");
  for (const l of CLAIMED) assert.equal(normalizeClaimed(l), l);
  for (const junk of ["refused", "", null, undefined, 3, ["done"], "declined by the issuer"]) assert.equal(normalizeClaimed(junk), null);
});

test("sandbox labels and kit labels reconcile the same", () => {
  const raw = byName("pay-bill-record-extra-claim"); const kit = byName("pay-bill-record-kit-labels");
  assert.equal(raw.chain_ref, kit.chain_ref);
  assert.ok(kit.claims.every((c: any) => (CLAIMED as readonly string[]).includes(c.claimed)));
  assert.deepEqual(run(kit).findings, []);
});

// --- inputs JSON cannot carry: a Chain object, a custom parser -----------------

function harnessChain() {
  const c = new Chain(KEY, "agent");
  c.append("mandate.accepted", { job: "t" }, { timestamp: "2026-10-12T10:00:00Z" });
  c.append("step.read", { to: "harbourline", verdict: "allow", layer: "may" }, { timestamp: "2026-10-12T10:00:01Z" });
  c.append("step.pay", { to: "MID-1", amount: 500, verdict: "deny", layer: "spends", reason: "over budget" }, { timestamp: "2026-10-12T10:00:02Z" });
  return c;
}

test("accepts a Chain object", () => {
  const got = reconcile([{ step: 0, counterparty: "harbourline", verb: "read", claimed: "done" }], harnessChain());
  assert.equal(got.matches, 1);
  assert.deepEqual(got.findings.map((f) => f.kind), ["undisclosed"]);
  assert.equal(got.findings[0].detail, "spends refused: pay to MID-1; the summary does not mention it");
});

test("custom parser function", () => {
  const parse: EntryParser = (entry, _ordinal) => {
    if (entry.action !== "did") return null;
    const p = entry.payload as any;
    return { step: p.n, counterparty: p.who, verb: "act", status: p.ok ? "done" : "blocked", layer: "gate", code: null, reached: false, seq: null };
  };
  const chain = { entries: [
    { seq: 0, action: "hello", payload: {} },
    { seq: 1, action: "did", payload: { n: 7, who: "x", ok: true } },
    { seq: 2, action: "did", payload: { n: 8, who: "y", ok: false } },
  ] };
  const got = reconcile([{ step: 7, counterparty: "x", claimed: "done" }, { step: 8, counterparty: "y", claimed: "done" }], chain, { parser: parse });
  assert.equal(got.matches, 1);
  const expected: Finding[] = [{ kind: "contradicted", step: 8, counterparty: "y", verb: "act", claimed: "done", chain: "blocked", detail: "claimed done; the chain says blocked (gate)" }];
  assert.deepEqual(got.findings, expected);
  // A custom parser's output is checked too, and its exceptions become an error, not a crash.
  const bad = reconcile([], chain, { parser: ((e: any) => (e.action === "did" ? { step: "x" } : null)) as any });
  assert.ok(bad.error); assert.equal(bad.matches, 0);
  const boom = reconcile([], chain, { parser: () => { throw new RangeError("no"); } });
  assert.equal(boom.error, "entry parser failed on entry 0: RangeError");
});

test("entry parsers are exported; harness steps index by ordinal", () => {
  assert.deepEqual(Object.keys(ENTRY_PARSERS).sort(), ["auto", "harness", "sandbox"]);
  const chain = harnessChain().toJSON();
  assert.deepEqual(reconcile([{ step: 1, counterparty: "MID-1", claimed: "failed" }], chain, { parser: "harness" }).findings, []);
  assert.equal(reconcile([{ step: 2, counterparty: "MID-1", claimed: "failed" }], chain).counts.no_entry, 1);
  const s = ENTRY_PARSERS.harness({ seq: 9, action: "step.pay", payload: { step: 4, to: "a", verdict: "ask" } }, 0)!;
  assert.equal(s.step, 4); assert.equal(s.status, "declined"); assert.equal(s.counterparty, "a"); assert.equal(s.seq, 9);
  assert.equal(ENTRY_PARSERS.sandbox({ action: "run.completed", payload: {} }, 0), null);
  assert.equal(ENTRY_PARSERS.harness({ action: "recall", payload: {} }, 0), null);
  assert.equal(ENTRY_PARSERS.sandbox({ action: "memory.recall", payload: { step: 3, status: "declined" } }, 0)!.verb, "recall");
});

// --- binding the summary ------------------------------------------------------

test("bindSummary matches the sandbox and the harness", () => {
  const sp = FIX.chains["shop-plan"].chain; const c = byName("shop-plan");
  const last = sp.entries.at(-1);
  assert.equal(last.action, "run.completed");
  assert.deepEqual(bindSummary(c.summary, { mode: "plan" }), { summary_sha256: last.payload.summary_sha256, summary_mode: "plan" });
  const h = FIX.chains.harness.chain; const text = byName("harness-careless").summary;
  assert.deepEqual(bindSummary(text, { encoding: "hex" }), { summary_sha256: h.entries.at(-1).payload.summary_sha256 });
  assert.deepEqual(bindSummary("hello"), { summary_sha256: "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=" });
  assert.equal(bindSummary("hello", { encoding: "hex" }).summary_sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  assert.deepEqual(bindSummary("", { mode: "record" }), { summary_sha256: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", summary_mode: "record" });
  // Undefined fields drop out before hashing, as they would on the wire.
  assert.equal(bindSummary({ text: "a", extra: undefined }).summary_sha256, bindSummary({ text: "a" }).summary_sha256);
  for (const bad of [null, 3, undefined]) assert.throws(() => bindSummary(bad as any), TypeError);
  assert.throws(() => bindSummary("x", { encoding: "base32" as any }));
});

test("summary_bound reads either encoding", () => {
  const chain = harnessChain(); const text = "All done.";
  chain.append("run.completed", bindSummary(text, { encoding: "hex" }), { timestamp: "2026-10-12T10:00:03Z" });
  assert.equal(reconcile([], chain, { summary: text }).summary_bound, true);
  assert.equal(reconcile([], chain, { summary: text + "!" }).summary_bound, false);
  const other = harnessChain();
  other.append("run.completed", bindSummary({ text, claims: [] }, { mode: "record" }), { timestamp: "2026-10-12T10:00:03Z" });
  assert.equal(reconcile([], other, { summary: { claims: [], text } }).summary_bound, true); // key order does not matter
  assert.equal(reconcile([], other, { summary: text }).summary_bound, false); // the object was bound, not the text
  assert.equal(reconcile([], harnessChain(), { summary: text }).summary_bound, null); // no run.completed entry
  assert.ok(!("summary_bound" in reconcile([], harnessChain())));
});

// --- robustness -----------------------------------------------------------------

test("hostile input never throws", () => {
  const chain = harnessChain().toJSON();
  const junk: any[] = [null, undefined, 42, "x", [1, 2, 3], { entries: "nope" }, { entries: [null] }, { entries: [{}] },
    { entries: [{ action: 5, payload: "str" }] }, { entries: [{ action: "pay:done", payload: null }] },
    { entries: [{ action: "step.", payload: {} }] }, { entries: [{ action: "a:b:c", payload: {} }] },
    [{ action: "pay:done", payload: { step: 2 ** 60, counterparty: { id: 1 }, reference: [1] } }],
    { entries: [{ action: "memory.recall", payload: { step: true, status: 4 } }] }];
  const claimsJunk: any[] = [undefined, null, "x", 7, [null], [[]], [{ step: null }], [{ step: 1.5, claimed: "done" }],
    [{ step: 0, claimed: "done", counterparty: 1 }], [{ step: 0, claimed: {} }], [{ step: -1, claimed: "failed", verb: 0 }], []];
  for (const c of claimsJunk) for (const ch of [...junk, chain]) {
    for (const parser of ["auto", "sandbox", "harness", "nonsense", null, 5, () => null] as any[]) {
      for (const summary of [undefined, null, "s", { a: 1 }, 3]) {
        const got: any = reconcile(c, ch, { parser, summary });
        assert.ok(Array.isArray(got.findings) && Number.isInteger(got.matches) && got.result);
        if ("error" in got) { assert.equal(got.matches, 0); assert.deepEqual(got.findings, []); }
      }
    }
  }
});

test("reconcile does not judge the chain: verify first", () => {
  const forged = new Chain(Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1)), "agent");
  forged.append("step.pay", { to: "MID-1", verdict: "allow" }, { timestamp: "2026-10-12T10:00:00Z" });
  const data = forged.toJSON();
  assert.equal(verifyChain(data, { trustedKeys: [PUB] }).valid, false);
  assert.equal(reconcile([{ step: 0, counterparty: "MID-1", claimed: "done" }], data).matches, 1);
});
