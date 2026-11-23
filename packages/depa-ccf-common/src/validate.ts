// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Minimal strict input validation helpers. Every helper throws a 400 ApiError
// naming the offending JSON path.

import { ApiError } from "./errors";

export type JsonObject = Record<string, unknown>;

function fail(path: string, msg: string): never {
  throw ApiError.badRequest(`${path}: ${msg}`, "invalid_input");
}

export function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function obj(v: unknown, path: string): JsonObject {
  if (!isObject(v)) fail(path, "must be an object");
  return v;
}

/** Rejects unknown members. `required` members must be present. */
export function keys(o: JsonObject, path: string, required: readonly string[], optional: readonly string[] = []): void {
  for (const k of required) if (!(k in o) || o[k] === undefined) fail(`${path}.${k}`, "is required");
  for (const k of Object.keys(o)) {
    if (!required.includes(k) && !optional.includes(k)) fail(`${path}.${k}`, "unknown member");
  }
}

export interface StrOpts {
  re?: RegExp;
  min?: number;
  max?: number;
}

export function str(v: unknown, path: string, opts: StrOpts = {}): string {
  if (typeof v !== "string") fail(path, "must be a string");
  const min = opts.min ?? 1;
  const max = opts.max ?? 4096;
  if (v.length < min) fail(path, `must be at least ${min} characters`);
  if (v.length > max) fail(path, `must be at most ${max} characters`);
  if (opts.re && !opts.re.test(v)) fail(path, `must match ${opts.re.source}`);
  return v;
}

export function optStr(v: unknown, path: string, opts: StrOpts = {}): string | undefined {
  return v === undefined ? undefined : str(v, path, opts);
}

export function bool(v: unknown, path: string): boolean {
  if (typeof v !== "boolean") fail(path, "must be a boolean");
  return v;
}

export interface NumOpts {
  min?: number;
  max?: number;
  /** Lower bound is exclusive. */
  gt?: number;
  /** Upper bound is exclusive. */
  lt?: number;
}

export function num(v: unknown, path: string, opts: NumOpts = {}): number {
  if (typeof v !== "number" || !isFinite(v)) fail(path, "must be a finite number");
  if (opts.min !== undefined && v < opts.min) fail(path, `must be >= ${opts.min}`);
  if (opts.max !== undefined && v > opts.max) fail(path, `must be <= ${opts.max}`);
  if (opts.gt !== undefined && !(v > opts.gt)) fail(path, `must be > ${opts.gt}`);
  if (opts.lt !== undefined && !(v < opts.lt)) fail(path, `must be < ${opts.lt}`);
  return v;
}

export function int(v: unknown, path: string, opts: NumOpts = {}): number {
  const n = num(v, path, opts);
  if (!Number.isSafeInteger(n)) fail(path, "must be an integer");
  return n;
}

export interface ArrOpts {
  min?: number;
  max?: number;
  unique?: boolean;
}

export function arr<T>(v: unknown, path: string, item: (x: unknown, p: string) => T, opts: ArrOpts = {}): T[] {
  if (!Array.isArray(v)) fail(path, "must be an array");
  const min = opts.min ?? 0;
  const max = opts.max ?? 256;
  if (v.length < min) fail(path, `must have at least ${min} items`);
  if (v.length > max) fail(path, `must have at most ${max} items`);
  const out = v.map((x, i) => item(x, `${path}[${i}]`));
  if (opts.unique) {
    const seen = new Set<string>();
    for (const x of out) {
      const k = typeof x === "string" ? x : JSON.stringify(x);
      if (seen.has(k)) fail(path, "items must be unique");
      seen.add(k);
    }
  }
  return out;
}

export function oneOf<T extends string | number>(v: unknown, path: string, values: readonly T[]): T {
  if (!values.includes(v as T)) fail(path, `must be one of ${values.join(", ")}`);
  return v as T;
}

const RFC3339_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

/** Parses an RFC 3339 timestamp and returns seconds since the epoch. */
export function parseRfc3339(v: unknown, path: string): number {
  if (typeof v !== "string" || !RFC3339_RE.test(v)) fail(path, "must be an RFC 3339 timestamp");
  const ms = Date.parse(v);
  if (!isFinite(ms)) fail(path, "must be an RFC 3339 timestamp");
  return Math.floor(ms / 1000);
}

/** Formats seconds since the epoch as an RFC 3339 UTC timestamp (second precision). */
export function formatRfc3339(seconds: number): string {
  return new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const UUID4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const PARTY_ID_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;
export const KID_RE = /^[A-Za-z0-9._-]{1,64}$/;
// Dataset name <= 55 chars so the OIDC subject "dataset:<owner>/<name>" fits
// GCP's 127-byte google.subject limit (8 + 63 + 1 + 55 = 127).
export const DATASET_ID_RE = /^[a-z0-9][a-z0-9-]{1,62}\/[a-z0-9][a-z0-9._-]{0,54}$/;
export const HEX64_RE = /^[0-9a-f]{64}$/;
export const RELEASE_ID_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/;
export const HTTPS_URL_RE = /^https:\/\/[^\s/?#]+(\/[^\s?#]*)?$/;
