// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.

import { beforeEach, describe, expect, it } from "@jest/globals";
import { generateKeyPairSync, sign } from "crypto";
import { b64Decode, b64urlDecode, b64urlEncode, hexDecode } from "../src/encoding";
import { jwkThumbprint, parseJws, signJwsEs256, validateEcPublicJwk, verifyJws } from "../src/jws";
import { generateEs256KeyPair } from "../src/service_keys";
import { b64url, resetKv, TestParty } from "./helpers";

beforeEach(resetKv);

describe("encoding", () => {
  it("round-trips base64url and rejects non-canonical input", () => {
    for (let n = 0; n < 40; n++) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff);
      const s = b64urlEncode(bytes);
      expect(s).toBe(Buffer.from(bytes).toString("base64url"));
      expect(Buffer.from(b64urlDecode(s)).equals(Buffer.from(bytes))).toBe(true);
    }
    expect(() => b64urlDecode("AB==")).toThrow(); // padding not allowed
    expect(() => b64urlDecode("A")).toThrow(); // impossible length
    expect(() => b64urlDecode("AB+/")).toThrow(); // std alphabet
    expect(() => b64urlDecode("AB")).toThrow(); // non-zero trailing bits ("AA" is canonical)
    expect(b64urlDecode("AA")).toEqual(new Uint8Array([0]));
    expect(b64Decode("AB+/")).toEqual(new Uint8Array([0x00, 0x1f, 0xbf]));
    expect(() => hexDecode("abc")).toThrow();
  });
});

describe("JWS ES256", () => {
  const party = new TestParty("bank-a", ["tdp"]);

  it("verifies a raw r||s signature produced outside CCF", () => {
    const jws = party.jws({ typ: "t" }, { a: 1 });
    const parsed = parseJws(jws, "t");
    expect(parsed.payload).toEqual({ a: 1 });
    expect(verifyJws(parsed, party.jwk)).toBe(true);
  });

  it("rejects a DER-encoded signature", () => {
    const parsed = parseJws(party.jws({ typ: "t" }, { a: 1 }, { der: true }), "t");
    expect(parsed.signature.length).not.toBe(64);
    expect(verifyJws(parsed, party.jwk)).toBe(false);
  });

  it("rejects tampering, wrong keys and wrong curves", () => {
    const jws = party.jws({ typ: "t" }, { a: 1 });
    const [h, , s] = jws.split(".");
    const tampered = parseJws(`${h}.${b64url(JSON.stringify({ a: 2 }))}.${s}`, "t");
    expect(verifyJws(tampered, party.jwk)).toBe(false);
    expect(verifyJws(parseJws(jws, "t"), new TestParty("other", ["tdp"]).jwk)).toBe(false);
    const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" }).publicKey.export({ format: "jwk" }) as { x: string; y: string };
    expect(verifyJws(parseJws(jws, "t"), { kty: "EC", crv: "P-384", x: p384.x, y: p384.y })).toBe(false);
  });

  it("verifies ES384 with a P-384 key", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const h = b64url(JSON.stringify({ alg: "ES384", typ: "t" }));
    const p = b64url(JSON.stringify({ x: 1 }));
    const sig = sign("sha384", Buffer.from(`${h}.${p}`), { key: privateKey, dsaEncoding: "ieee-p1363" });
    const j = publicKey.export({ format: "jwk" }) as { x: string; y: string };
    expect(verifyJws(parseJws(`${h}.${p}.${b64url(sig)}`, "t"), { kty: "EC", crv: "P-384", x: j.x, y: j.y })).toBe(true);
  });

  it.each([
    ["alg none", { alg: "none", typ: "t" }],
    ["alg HS256", { alg: "HS256", typ: "t" }],
    ["wrong typ", { alg: "ES256", typ: "other" }],
    ["crit", { alg: "ES256", typ: "t", crit: ["b64"] }],
    ["b64=false", { alg: "ES256", typ: "t", b64: false }],
  ])("rejects header: %s", (_name, header) => {
    const jws = `${b64url(JSON.stringify(header))}.${b64url("{}")}.${b64url(Buffer.alloc(64))}`;
    expect(() => parseJws(jws, "t")).toThrow();
  });

  it("rejects malformed compact serializations", () => {
    expect(() => parseJws("a.b", "t")).toThrow();
    expect(() => parseJws("a..c", "t")).toThrow();
    expect(() => parseJws(`${b64url('{"alg":"ES256","typ":"t"}')}.${b64url("[1]")}.AA`, "t")).toThrow();
    expect(() => parseJws(123, "t")).toThrow();
  });

  it("signs with CCF-style keys and computes RFC 7638 thumbprints", () => {
    const kp = generateEs256KeyPair();
    const jws = signJwsEs256({ typ: "x", kid: kp.jwk.kid }, { hello: "world" }, kp.private_key_pem);
    expect(verifyJws(parseJws(jws, "x"), kp.jwk)).toBe(true);
    expect(kp.jwk.kid).toBe(jwkThumbprint(kp.jwk));
    // RFC 7515 A.3 key; expected value computed independently (Python, sorted members).
    const jwk = { kty: "EC" as const, crv: "P-256" as const, x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" };
    expect(jwkThumbprint(jwk)).toBe("oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U");
  });

  it("validates public JWKs and refuses private members and off-curve points", () => {
    expect(validateEcPublicJwk(party.jwk, "k", { requireKid: true }).kid).toBe("k1");
    expect(() => validateEcPublicJwk({ ...party.jwk, d: "AA" }, "k", { requireKid: true })).toThrow();
    expect(() => validateEcPublicJwk({ ...party.jwk, kid: undefined }, "k", { requireKid: true })).toThrow();
    const y = Buffer.from(party.jwk.y, "base64url");
    y[31] ^= 1;
    expect(() => validateEcPublicJwk({ ...party.jwk, y: b64url(y) }, "k", { requireKid: true })).toThrow();
  });
});
