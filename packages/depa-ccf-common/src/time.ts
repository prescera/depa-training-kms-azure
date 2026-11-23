// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.

import { ccf } from "@microsoft/ccf-app/global";
import { ApiError } from "./errors";

/**
 * Current time in seconds (NumericDate). CCF exposes only untrusted host time;
 * fail closed if it is unavailable rather than evaluating windows against 0.
 */
export function nowSeconds(): number {
  ccf.enableUntrustedDateTime(true);
  const ms = Date.now();
  if (!(ms > 0)) throw ApiError.internal("host time source unavailable", "time_unavailable");
  return Math.floor(ms / 1000);
}

/** RFC 4122 version-4 UUID from the enclave CSPRNG. */
export function uuid4(): string {
  const b = new Uint8Array(ccf.crypto.generateAesKey(128));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  let h = "";
  for (let i = 0; i < 16; i++) h += (b[i] < 16 ? "0" : "") + b[i].toString(16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
