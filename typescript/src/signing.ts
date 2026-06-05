/**
 * Ed25519 signing for WitnessKit entries, backed by Node's built-in crypto (no
 * external dependency). Raw 32-byte keys, RFC-8032 signatures, wire-compatible
 * with the Python port.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function generateKeypair(): { privateKey: Buffer; publicKey: Buffer } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return { privateKey: Buffer.from(seed), publicKey: Buffer.from(pub) };
}

function privFromSeed(seed: Buffer) {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
}

function pubFromRaw(pub: Buffer) {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, pub]), format: "der", type: "spki" });
}

export function publicKeyFromSeed(seed: Buffer): Buffer {
  return Buffer.from(createPublicKey(privFromSeed(seed)).export({ format: "der", type: "spki" }).subarray(-32));
}

export function sign(message: Buffer, seed: Buffer): Buffer {
  return Buffer.from(nodeSign(null, message, privFromSeed(seed)));
}

export function verify(signature: Buffer, message: Buffer, publicKey: Buffer): boolean {
  try {
    return nodeVerify(null, message, pubFromRaw(publicKey), signature);
  } catch {
    return false;
  }
}

export function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

export const b64 = (b: Buffer): string => b.toString("base64");
export const unb64 = (s: string): Buffer => Buffer.from(s, "base64");
