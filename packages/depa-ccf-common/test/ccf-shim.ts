// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Node implementation of the subset of the CCF JS globals used by the apps,
// for unit tests. Mirrors CCF 6.0 behaviour verified on the runtime:
// ECDSA signatures are IEEE P1363 (raw r||s) for both sign and verify.
// KV state lives on globalThis so that every module instance shares it.

import {
  constants,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  publicEncrypt,
  randomBytes,
  sign as nodeSign,
  verify as nodeVerify,
} from "crypto";

type Entry = { value: ArrayBuffer; version: number };
type Store = Map<string, Map<string, Entry>>;

const g = globalThis as unknown as { __ccfKv: Store; __ccfVersion: number; ccf: unknown; snp_attestation: unknown };
g.__ccfKv = g.__ccfKv ?? new Map();
g.__ccfVersion = g.__ccfVersion ?? 1;

function toAb(b: Uint8Array): ArrayBuffer {
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
}
function key(k: ArrayBuffer): string {
  return Buffer.from(k).toString("latin1");
}

function kvMap(name: string) {
  if (!g.__ccfKv.has(name)) g.__ccfKv.set(name, new Map());
  const m = g.__ccfKv.get(name) as Map<string, Entry>;
  return {
    has: (k: ArrayBuffer) => m.has(key(k)),
    get: (k: ArrayBuffer) => m.get(key(k))?.value,
    getVersionOfPreviousWrite: (k: ArrayBuffer) => m.get(key(k))?.version,
    set(k: ArrayBuffer, v: ArrayBuffer) {
      m.set(key(k), { value: v.slice(0), version: g.__ccfVersion++ });
      return this;
    },
    delete: (k: ArrayBuffer) => void m.delete(key(k)),
    clear: () => m.clear(),
    forEach(cb: (v: ArrayBuffer, k: ArrayBuffer) => void) {
      for (const [k, e] of Array.from(m.entries())) cb(e.value, toAb(Buffer.from(k, "latin1")));
    },
    get size() {
      return m.size;
    },
  };
}

const CURVES: Record<string, string> = { secp256r1: "P-256", secp384r1: "P-384" };

function hashName(h?: string): string {
  return (h ?? "SHA-256").replace("-", "").toLowerCase();
}

function ecJwk(k: KeyObject, kid?: string): Record<string, string> {
  const jwk = k.export({ format: "jwk" }) as Record<string, string>;
  return { ...jwk, ...(kid ? { kid } : {}) };
}

g.ccf = {
  strToBuf: (s: string) => toAb(Buffer.from(s, "utf8")),
  bufToStr: (b: ArrayBuffer) => Buffer.from(b).toString("utf8"),
  jsonCompatibleToBuf: (v: unknown) => toAb(Buffer.from(JSON.stringify(v), "utf8")),
  bufToJsonCompatible: (b: ArrayBuffer) => JSON.parse(Buffer.from(b).toString("utf8")),
  enableUntrustedDateTime: () => true,
  rpc: { setClaimsDigest: () => undefined, setApplyWrites: () => undefined },
  kv: new Proxy({}, { get: (_t, name: string) => kvMap(name) }),
  crypto: {
    digest: (alg: string, data: ArrayBuffer) => toAb(createHash(hashName(alg)).update(Buffer.from(data)).digest()),
    sign(alg: { name: string; hash?: string }, pem: string, data: ArrayBuffer) {
      if (alg.name !== "ECDSA") throw new Error(`shim: unsupported ${alg.name}`);
      return toAb(nodeSign(hashName(alg.hash), Buffer.from(data), { key: createPrivateKey(pem), dsaEncoding: "ieee-p1363" }));
    },
    verifySignature(alg: { name: string; hash?: string }, pem: string, sig: ArrayBuffer, data: ArrayBuffer) {
      if (alg.name !== "ECDSA") throw new Error(`shim: unsupported ${alg.name}`);
      return nodeVerify(hashName(alg.hash), Buffer.from(data), { key: createPublicKey(pem), dsaEncoding: "ieee-p1363" }, Buffer.from(sig));
    },
    generateEcdsaKeyPair(curve: string) {
      const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: CURVES[curve] });
      return {
        privateKey: privateKey.export({ format: "pem", type: "pkcs8" }) as string,
        publicKey: publicKey.export({ format: "pem", type: "spki" }) as string,
      };
    },
    generateEddsaKeyPair(curve: string) {
      if (curve !== "x25519") throw new Error("shim: only x25519");
      const { privateKey, publicKey } = generateKeyPairSync("x25519");
      return {
        privateKey: privateKey.export({ format: "pem", type: "pkcs8" }) as string,
        publicKey: publicKey.export({ format: "pem", type: "spki" }) as string,
      };
    },
    eddsaPemToJwk: (pem: string, kid?: string) => ecJwk(createPrivateKey(pem), kid),
    pubPemToJwk: (pem: string, kid?: string) => ecJwk(createPublicKey(pem), kid),
    pubRsaPemToJwk: (pem: string, kid?: string) => {
      const k = createPublicKey(pem);
      if (k.asymmetricKeyType !== "rsa") throw new Error("not an RSA key");
      return ecJwk(k, kid);
    },
    pubJwkToPem: (jwk: Record<string, string>) =>
      createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: "jwk" }).export({ format: "pem", type: "spki" }) as string,
    generateAesKey: (bits: number) => toAb(randomBytes(bits / 8)),
    wrapKey(k: ArrayBuffer, wrappingPem: ArrayBuffer, alg: { name: string }) {
      if (alg.name !== "RSA-OAEP") throw new Error("shim: only RSA-OAEP");
      const pub = createPublicKey(Buffer.from(wrappingPem).toString("utf8"));
      return toAb(publicEncrypt({ key: pub, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from(k)));
    },
  },
};

g.snp_attestation = {
  verifySnpAttestation: () => {
    throw new Error("verifySnpAttestation is not available in unit tests");
  },
};
