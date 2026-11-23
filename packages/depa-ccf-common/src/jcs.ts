// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// RFC 8785 JSON Canonicalization Scheme (JCS) and the protocol digest
//   digest(x) = "sha256:" + hex(SHA-256(JCS(x)))

import { ccf } from "@microsoft/ccf-app/global";
import { ApiError } from "./errors";
import { hexEncode, toArrayBuffer, utf8Encode } from "./encoding";

function serializeString(s: string): string {
  // Lone surrogates cannot be represented in UTF-8; RFC 8785 §3.2.2.2 requires
  // rejecting them.
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) throw ApiError.badRequest("JCS: lone surrogate in string");
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw ApiError.badRequest("JCS: lone surrogate in string");
    }
  }
  // JSON.stringify (ES2019+) emits exactly the RFC 8785 escapes for
  // well-formed strings: \" \\ \b \f \n \r \t and \u00xx (lowercase) for the
  // remaining control characters; everything else is emitted verbatim.
  return JSON.stringify(s);
}

function serializeNumber(n: number): string {
  if (!isFinite(n)) throw ApiError.badRequest("JCS: non-finite number");
  // ECMAScript Number-to-String is exactly the RFC 8785 number format; -0 → "0".
  return Object.is(n, -0) ? "0" : String(n);
}

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return serializeNumber(value);
    case "string":
      return serializeString(value);
    case "object": {
      if (Array.isArray(value)) {
        return "[" + value.map((v) => canonicalize(v)).join(",") + "]";
      }
      const obj = value as Record<string, unknown>;
      // Default string ordering compares UTF-16 code units, as RFC 8785 §3.2.3 requires.
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      return "{" + keys.map((k) => serializeString(k) + ":" + canonicalize(obj[k])).join(",") + "}";
    }
    default:
      throw ApiError.badRequest(`JCS: unsupported value of type ${typeof value}`);
  }
}

export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(ccf.crypto.digest("SHA-256", toArrayBuffer(data)));
}

export function sha256Hex(data: Uint8Array): string {
  return hexEncode(sha256(data));
}

/** SHA-256 over JCS(value), raw bytes. */
export function jcsHash(value: unknown): Uint8Array {
  return sha256(utf8Encode(canonicalize(value)));
}

/** Protocol digest: "sha256:" + hex(SHA-256(JCS(value))). */
export function digest(value: unknown): string {
  return "sha256:" + hexEncode(jcsHash(value));
}

export const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
