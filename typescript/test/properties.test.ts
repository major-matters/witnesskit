/**
 * Property-based tests (fast-check) for WitnessKit. Mirrors the Python Hypothesis
 * suite: roundtrip, any-tamper-breaks, forgery, never-throws, hash-order-invariance.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { Chain, verifyChain, publicKeyFromSeed, entryHash } from "../src/index.ts";

const seed = () => fc.uint8Array({ minLength: 32, maxLength: 32 }).map((a) => Buffer.from(a));
const payload = () => fc.dictionary(fc.string(), fc.oneof(fc.integer(), fc.string()), { maxKeys: 4 });
const actions = () => fc.array(fc.tuple(fc.string(), payload()), { maxLength: 8 });

function build(s: Buffer, acts: Array<[string, any]>) {
  const c = new Chain(s, "agent");
  acts.forEach(([action, p], i) => c.append(action, p, { timestamp: `2026-01-01T00:00:0${i}Z` }));
  return c;
}

test("property: roundtrip any chain verifies", () => {
  fc.assert(fc.property(seed(), actions(), (s, acts) => {
    const pub = publicKeyFromSeed(s).toString("base64");
    return verifyChain(build(s, acts).toJSON(), { trustedKeys: [pub] }).valid === true;
  }));
});

test("property: any field tamper breaks the chain", () => {
  fc.assert(fc.property(seed(), actions().filter((a) => a.length >= 1), (s, acts) => {
    const pub = publicKeyFromSeed(s).toString("base64");
    const data = build(s, acts).toJSON();
    data.entries[0].action = data.entries[0].action + "_x"; // change without re-signing
    return verifyChain(data, { trustedKeys: [pub] }).valid === false;
  }));
});

test("property: forgery accepted iff signer is the pinned key", () => {
  fc.assert(fc.property(seed(), seed(), fc.string(), (signer, trusted, action) => {
    const c = new Chain(signer, "a");
    c.append(action, {});
    const same = publicKeyFromSeed(signer).equals(publicKeyFromSeed(trusted));
    const v = verifyChain(c.toJSON(), { trustedKeys: [publicKeyFromSeed(trusted).toString("base64")] });
    return v.valid === same;
  }));
});

test("property: verify never throws on hostile input", () => {
  fc.assert(fc.property(fc.jsonValue(), (j) => {
    const a = verifyChain(j as any, { trustedKeys: ["AAAA"] });
    const wrapped = { entries: Array.isArray(j) ? j : [j] };
    const b = verifyChain(wrapped as any, { trustedKeys: ["AAAA"] });
    return (a.valid === true || a.valid === false) && (b.valid === true || b.valid === false);
  }));
});

test("property: entry hash is key-order invariant", () => {
  fc.assert(fc.property(fc.dictionary(fc.string({ minLength: 1 }), fc.integer(), { maxKeys: 6 }), (p) => {
    const a = entryHash(0, "t", "actor", "action", p, null);
    const reordered = Object.fromEntries(Object.entries(p).reverse());
    return a === entryHash(0, "t", "actor", "action", reordered, null);
  }));
});
