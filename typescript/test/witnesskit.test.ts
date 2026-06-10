/**
 * WitnessKit v0 (TypeScript) test suite. Run: npm test (node --test).
 * Mirrors the Python attack regressions.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { Chain, buildEntry, verifyChain, publicKeyFromSeed } from "../src/index.ts";

const KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const PUB = publicKeyFromSeed(KEY).toString("base64");
const TS = ["2026-06-05T20:00:00Z", "2026-06-05T20:00:01Z", "2026-06-05T20:00:02Z"];

function makeChain(key: Buffer = KEY, actor = "agent-7") {
  const c = new Chain(key, actor);
  c.append("tool_call", { tool: "search", q: "running shoes" }, { timestamp: TS[0] });
  c.append("decision", { approved: true }, { timestamp: TS[1] });
  c.append("payment", { merchant: "Fleet Feet", amount: 240, currency: "USD" }, { timestamp: TS[2] });
  return c;
}

const vrf = (chain: any, opts: any = {}) => verifyChain(chain, { trustedKeys: [PUB], ...opts });

test("roundtrip valid", () => {
  const v = vrf(makeChain().toJSON());
  assert.equal(v.valid, true);
  assert.equal(v.length, 3);
});

test("empty chain valid", () => {
  assert.equal(vrf(new Chain(KEY, "a").toJSON()).valid, true);
});

test("unpinned fails closed", () => {
  const v = verifyChain(makeChain().toJSON());
  assert.equal(v.valid, false);
  assert.match(v.reason, /trusted issuer/);
});

test("allowUnverifiedIssuer opt-in", () => {
  assert.equal(verifyChain(makeChain().toJSON(), { allowUnverifiedIssuer: true }).valid, true);
});

test("forged chain rejected by pinning", () => {
  const attacker = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1));
  const v = vrf(makeChain(attacker).toJSON());
  assert.equal(v.valid, false);
  assert.equal(v.broken_at, 0);
  assert.match(v.reason, /trusted-issuer/);
});

test("altered payload detected", () => {
  const data = makeChain().toJSON();
  (data.entries[1].payload as any).approved = false;
  const v = vrf(data);
  assert.equal(v.valid, false);
  assert.equal(v.broken_at, 1);
  assert.match(v.reason, /hash mismatch/);
});

test("deleted entry detected", () => {
  const data = makeChain().toJSON();
  data.entries.splice(1, 1);
  assert.equal(vrf(data).valid, false);
});

test("inserted entry detected", () => {
  const data = makeChain().toJSON();
  const fake = buildEntry({ seq: 1, actor: "agent-7", action: "payment",
    payload: { merchant: "Attacker", amount: 9999, currency: "USD" },
    prevHash: data.entries[0].hash, privateKey: KEY, timestamp: TS[1] });
  data.entries.splice(1, 0, fake);
  assert.equal(vrf(data).valid, false);
});

test("reordered entries detected", () => {
  const data = makeChain().toJSON();
  [data.entries[1], data.entries[2]] = [data.entries[2], data.entries[1]];
  const v = vrf(data);
  assert.equal(v.valid, false);
  assert.equal(v.broken_at, 1);
});

test("truncation detected with expectedHead", () => {
  const chain = makeChain();
  const head = chain.headHash!;
  const data = chain.toJSON();
  data.entries = data.entries.slice(0, 2);
  assert.equal(vrf(data).valid, true); // shorter valid chain looks fine without anchor
  const v = vrf(data, { expectedHead: head });
  assert.equal(v.valid, false);
  assert.match(v.reason, /head/);
});

test("backwards timestamp detected", () => {
  const data = makeChain().toJSON();
  const bad = buildEntry({ seq: 2, actor: "agent-7", action: "payment",
    payload: data.entries[2].payload, prevHash: data.entries[1].hash, privateKey: KEY,
    timestamp: "2026-01-01T00:00:00Z" });
  data.entries[2] = bad;
  const v = vrf(data);
  assert.equal(v.valid, false);
  assert.match(v.reason, /backwards/);
});

test("hostile input never throws", () => {
  for (const junk of [null, 42, "x", [1, 2, 3], { entries: "nope" }, { entries: [null, { seq: "x" }] }, { entries: [{}] }]) {
    const v = verifyChain(junk as any, { trustedKeys: [PUB] });
    assert.ok(v.valid === true || v.valid === false);
  }
});

// --- audit 2026-06-10 medium/low findings -----------------------------------

test("version tamper is detected (finding #9)", () => {
  const data = makeChain().toJSON();
  data.entries[1].version = "witnesskit/v999";
  const v = vrf(data);
  assert.equal(v.valid, false);
  assert.equal(v.broken_at, 1);
});

test("oversize int payload is rejected, not crashed (finding #8)", () => {
  const c = new Chain(KEY, "a");
  assert.throws(() => c.append("x", { n: 2 ** 53 }));
});

test("deeply nested payload is rejected (finding #8)", () => {
  let deep: any = {};
  let cur = deep;
  for (let i = 0; i < 100; i++) { cur.x = {}; cur = cur.x; }
  const c = new Chain(KEY, "a");
  assert.throws(() => c.append("x", deep));
});
