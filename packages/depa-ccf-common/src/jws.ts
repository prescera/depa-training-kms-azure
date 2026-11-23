// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// JWS Compact Serialization (RFC 7515) restricted to ECDSA ES256/ES384.
//
// CCF 6.0 facts (verified on the runtime): ccf.crypto.sign({name:"ECDSA"})
// returns the IEEE P1363 raw r||s encoding and ccf.crypto.verifySignature
// accepts only that encoding (a DER signature verifies as false). This is
// exactly the JWS encoding, so no DER conversion is needed; DER-encoded
// signatures are rejected by the length check below.

import { ccf, DigestAlgorithm } from "@microsoft/ccf-app/global";
import { ApiError } from "./errors";
import { b64urlDecode, b64urlEncode, toArrayBuffer, utf8Decode, utf8Encode } from "./encoding";
import { canonicalize, sha256 } from "./jcs";
import { isObject, JsonObject, KID_RE, keys, obj, optStr, str } from "./validate";

export type JwsAlg = "ES256" | "ES384";

interface AlgInfo {
  crv: "P-256" | "P-384";
  hash: DigestAlgorithm;
  coordLen: number;
}

const ALGS: Record<JwsAlg, AlgInfo> = {
  ES256: { crv: "P-256", hash: "SHA-256", coordLen: 32 },
  ES384: { crv: "P-384", hash: "SHA-384", coordLen: 48 },
};

export interface EcPublicJwk {
  kty: "EC";
  crv: "P-256" | "P-384";
  x: string;
  y: string;
  kid?: string;
}

export interface ParsedJws {
  raw: string;
  alg: JwsAlg;
  header: JsonObject;
  payload: JsonObject;
  signingInput: Uint8Array;
  signature: Uint8Array;
}

const B64URL_SEGMENT = /^[A-Za-z0-9_-]+$/;
const DEFAULT_MAX_JWS = 512 * 1024;

function decodeJsonSegment(seg: string, what: string): JsonObject {
  const bytes = b64urlDecode(seg, `JWS ${what}`);
  let value: unknown;
  try {
    value = JSON.parse(utf8Decode(bytes));
  } catch {
    throw ApiError.badRequest(`JWS ${what} is not valid JSON`, "invalid_jws");
  }
  if (!isObject(value)) throw ApiError.badRequest(`JWS ${what} must be a JSON object`, "invalid_jws");
  return value;
}

/**
 * Parses a compact JWS and enforces the header rules common to every DEPA
 * token: alg ∈ {ES256, ES384}, exact `typ`, no `crit`, attached payload.
 * The signature is NOT verified here; call verifyJws.
 */
export function parseJws(raw: unknown, expectedTyp: string, maxLength = DEFAULT_MAX_JWS): ParsedJws {
  if (typeof raw !== "string") throw ApiError.badRequest("JWS must be a string", "invalid_jws");
  if (raw.length > maxLength) throw ApiError.badRequest("JWS too large", "invalid_jws");
  const parts = raw.split(".");
  if (parts.length !== 3) throw ApiError.badRequest("JWS must have three segments", "invalid_jws");
  const [h, p, s] = parts;
  if (!B64URL_SEGMENT.test(h) || !B64URL_SEGMENT.test(p) || !B64URL_SEGMENT.test(s)) {
    throw ApiError.badRequest("JWS segments must be non-empty base64url", "invalid_jws");
  }
  const header = decodeJsonSegment(h, "header");
  const alg = header.alg;
  if (alg !== "ES256" && alg !== "ES384") throw ApiError.badRequest("JWS alg must be ES256 or ES384", "invalid_jws");
  if (header.typ !== expectedTyp) {
    throw ApiError.badRequest(`JWS typ must be ${expectedTyp}`, "invalid_jws");
  }
  if ("crit" in header || "b64" in header) {
    throw ApiError.badRequest("JWS crit/b64 header parameters are not supported", "invalid_jws");
  }
  const payload = decodeJsonSegment(p, "payload");
  const signature = b64urlDecode(s, "JWS signature");
  return {
    raw,
    alg,
    header,
    payload,
    signingInput: utf8Encode(`${h}.${p}`),
    signature,
  };
}

/** Verifies the JWS signature with an EC public JWK. Returns false on mismatch. */
export function verifyJws(jws: ParsedJws, jwk: EcPublicJwk): boolean {
  const info = ALGS[jws.alg];
  if (jwk.kty !== "EC" || jwk.crv !== info.crv) return false;
  // Raw r||s only; a DER signature has a different (variable) length.
  if (jws.signature.length !== 2 * info.coordLen) return false;
  let pem: string;
  try {
    pem = ccf.crypto.pubJwkToPem({ kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y });
  } catch {
    return false;
  }
  try {
    return ccf.crypto.verifySignature(
      { name: "ECDSA", hash: info.hash },
      pem,
      toArrayBuffer(jws.signature),
      toArrayBuffer(jws.signingInput),
    );
  } catch {
    return false;
  }
}

/** Produces an ES256 compact JWS with the given protected header fields. */
export function signJwsEs256(header: JsonObject, payload: unknown, privateKeyPem: string): string {
  const h = b64urlEncode(utf8Encode(JSON.stringify({ ...header, alg: "ES256" })));
  const p = b64urlEncode(utf8Encode(JSON.stringify(payload)));
  const sig = ccf.crypto.sign({ name: "ECDSA", hash: "SHA-256" }, privateKeyPem, toArrayBuffer(utf8Encode(`${h}.${p}`)));
  return `${h}.${p}.${b64urlEncode(new Uint8Array(sig))}`;
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url). */
export function jwkThumbprint(jwk: EcPublicJwk): string {
  return b64urlEncode(sha256(utf8Encode(canonicalize({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))));
}

/**
 * Validates an EC public JWK (P-256 or P-384). Private members are rejected so
 * that a private key can never be registered by mistake.
 */
export function validateEcPublicJwk(
  v: unknown,
  path: string,
  opts: { requireKid: boolean; allowP384?: boolean },
): EcPublicJwk {
  const o = obj(v, path);
  keys(o, path, ["kty", "crv", "x", "y"], ["kid", "alg", "use"]);
  if (o.kty !== "EC") throw ApiError.badRequest(`${path}.kty: must be EC`, "invalid_input");
  const allowed = opts.allowP384 === false ? ["P-256"] : ["P-256", "P-384"];
  if (!allowed.includes(o.crv as string)) {
    throw ApiError.badRequest(`${path}.crv: must be one of ${allowed.join(", ")}`, "invalid_input");
  }
  const crv = o.crv as "P-256" | "P-384";
  const coordLen = crv === "P-256" ? 32 : 48;
  const x = str(o.x, `${path}.x`, { max: 128 });
  const y = str(o.y, `${path}.y`, { max: 128 });
  if (b64urlDecode(x, `${path}.x`).length !== coordLen || b64urlDecode(y, `${path}.y`).length !== coordLen) {
    throw ApiError.badRequest(`${path}: coordinates have the wrong length for ${crv}`, "invalid_input");
  }
  if (o.alg !== undefined && o.alg !== (crv === "P-256" ? "ES256" : "ES384")) {
    throw ApiError.badRequest(`${path}.alg: does not match crv`, "invalid_input");
  }
  if (o.use !== undefined && o.use !== "sig") throw ApiError.badRequest(`${path}.use: must be sig`, "invalid_input");
  const kid = opts.requireKid ? str(o.kid, `${path}.kid`, { re: KID_RE }) : optStr(o.kid, `${path}.kid`, { max: 128 });
  try {
    // Rejects points that are not on the curve.
    ccf.crypto.pubJwkToPem({ kty: "EC", crv, x, y });
  } catch {
    throw ApiError.badRequest(`${path}: not a valid ${crv} public key`, "invalid_input");
  }
  const jwk: EcPublicJwk = { kty: "EC", crv, x, y };
  if (kid !== undefined) jwk.kid = kid;
  return jwk;
}
