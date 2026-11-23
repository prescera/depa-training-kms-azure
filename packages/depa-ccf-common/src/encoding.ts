// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Byte encodings used by the DEPA Training v2 protocol. The CCF QuickJS
// runtime has no atob/btoa/TextEncoder, so everything is implemented here.
// UTF-8 conversion goes through ccf.strToBuf / ccf.bufToStr.

import { ccf } from "@microsoft/ccf-app/global";
import { ApiError } from "./errors";

const B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function buildDecodeTable(alphabet: string): Int16Array {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < alphabet.length; i++) t[alphabet.charCodeAt(i)] = i;
  return t;
}
const DEC_STD = buildDecodeTable(B64_STD);
const DEC_URL = buildDecodeTable(B64_URL);

function encode(bytes: Uint8Array, alphabet: string, pad: boolean): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63] + alphabet[(n >> 6) & 63] + alphabet[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63] + (pad ? "==" : "");
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63] + alphabet[(n >> 6) & 63] + (pad ? "=" : "");
  }
  return out;
}

/**
 * Strict base64 decoder: rejects characters outside the alphabet, impossible
 * lengths and non-zero trailing bits (so every byte string has exactly one
 * accepted encoding).
 */
function decode(input: string, table: Int16Array, allowPadding: boolean, what: string): Uint8Array {
  let s = input;
  if (allowPadding && s.length % 4 === 0 && s.length > 0) {
    if (s.endsWith("==")) s = s.slice(0, -2);
    else if (s.endsWith("=")) s = s.slice(0, -1);
  }
  if (s.length % 4 === 1) throw ApiError.badRequest(`invalid ${what} encoding (length)`);
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? table[c] : -1;
    if (v < 0) throw ApiError.badRequest(`invalid ${what} encoding (character)`);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
    acc &= (1 << bits) - 1;
  }
  if (acc !== 0) throw ApiError.badRequest(`invalid ${what} encoding (trailing bits)`);
  return out.subarray(0, o);
}

export function b64urlEncode(bytes: Uint8Array | ArrayBuffer): string {
  return encode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), B64_URL, false);
}

/** base64url without padding (RFC 7515 §2). */
export function b64urlDecode(s: string, what = "base64url"): Uint8Array {
  if (typeof s !== "string") throw ApiError.badRequest(`${what} must be a string`);
  return decode(s, DEC_URL, false, what);
}

export function b64Encode(bytes: Uint8Array | ArrayBuffer): string {
  return encode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), B64_STD, true);
}

/** Standard base64; padding optional. */
export function b64Decode(s: string, what = "base64"): Uint8Array {
  if (typeof s !== "string") throw ApiError.badRequest(`${what} must be a string`);
  return decode(s, DEC_STD, true, what);
}

export function hexEncode(bytes: Uint8Array | ArrayBuffer): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  for (let i = 0; i < b.length; i++) out += (b[i] < 16 ? "0" : "") + b[i].toString(16);
  return out;
}

export function hexDecode(s: string, what = "hex"): Uint8Array {
  if (typeof s !== "string" || s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) {
    throw ApiError.badRequest(`invalid ${what} encoding`);
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

export function utf8Encode(s: string): Uint8Array {
  return new Uint8Array(ccf.strToBuf(s));
}

export function utf8Decode(b: Uint8Array): string {
  return ccf.bufToStr(toArrayBuffer(b));
}

/** Returns an ArrayBuffer containing exactly the bytes of the view. */
export function toArrayBuffer(b: Uint8Array): ArrayBuffer {
  if (b.byteOffset === 0 && b.byteLength === b.buffer.byteLength) return b.buffer as ArrayBuffer;
  return b.slice().buffer as ArrayBuffer;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Constant-time comparison of two equal-length byte strings / hex strings. */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
