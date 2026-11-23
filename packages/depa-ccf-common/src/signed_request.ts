// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Signed requests (spec §3.2): every party- and member-initiated mutation is
// a body {"jws": "<compact JWS>"} with typ "depa-request+jws", signed by a
// registered, active party key, bound to this service (aud) and operation
// (op), fresh (|now - iat| <= 300 s) and never seen before (jti).

import * as ccfapp from "@microsoft/ccf-app";
import { ApiError } from "./errors";
import { jsonBody } from "./http";
import { parseJws, verifyJws } from "./jws";
import { JsonTable } from "./kv";
import { getParty, Party, Role } from "./party";
import { nowSeconds } from "./time";
import { isObject, JsonObject, KID_RE, PARTY_ID_RE, UUID_RE } from "./validate";

export const SIGNED_REQUEST_TYP = "depa-request+jws";
export const IAT_WINDOW_S = 300;
export const REPLAY_RETENTION_S = 600;
const MAX_PRUNE_PER_REQUEST = 64;

export interface SignedPayload {
  aud: string;
  op: string;
  iat: number;
  jti: string;
  body: unknown;
}

export interface VerifiedRequest {
  party: Party;
  /** "<party_id>#<kid>" */
  key_ref: string;
  payload: SignedPayload;
  /** The raw compact JWS, stored with the resulting state change for audit. */
  jws: string;
}

interface ReplayEntry {
  iat: number;
  seen_at: number;
}

export const replayTable = new JsonTable<ReplayEntry>("public:depa.replay");

export interface SignedRequestOptions {
  service: string;
  op: string;
  /** Party must hold at least one of these roles. */
  roles: readonly Role[];
}

/** Parses `{"jws": ...}` from the request body. */
export function signedEnvelope(request: ccfapp.Request): string {
  const body = jsonBody(request);
  if (!isObject(body) || typeof body.jws !== "string" || Object.keys(body).length !== 1) {
    throw ApiError.badRequest('body must be {"jws": "<compact JWS>"}', "invalid_signed_request");
  }
  return body.jws;
}

function pruneReplayTable(now: number): void {
  let pruned = 0;
  const stale: string[] = [];
  replayTable.forEach((v, k) => {
    if (pruned < MAX_PRUNE_PER_REQUEST && v.seen_at < now - REPLAY_RETENTION_S && v.iat < now - REPLAY_RETENTION_S) {
      stale.push(k);
      pruned++;
    }
  });
  for (const k of stale) replayTable.delete(k);
}

/**
 * Enforces the §3.2 freshness and replay rules for a signed message and
 * records its jti (in the caller's transaction, so a failed request does not
 * consume it).
 */
export function consumeFreshJti(iat: unknown, jti: unknown): void {
  if (typeof iat !== "number" || !Number.isSafeInteger(iat)) {
    throw ApiError.badRequest("signed payload iat must be an integer", "invalid_signed_request");
  }
  if (typeof jti !== "string" || !UUID_RE.test(jti)) {
    throw ApiError.badRequest("signed payload jti must be a UUID", "invalid_signed_request");
  }
  const now = nowSeconds();
  if (Math.abs(now - iat) > IAT_WINDOW_S) {
    throw ApiError.unauthorized("signed request is outside the 300 s iat window", "stale_request");
  }
  if (replayTable.has(jti)) throw ApiError.unauthorized("signed request replayed (jti seen before)", "replay");
  pruneReplayTable(now);
  replayTable.set(jti, { iat, seen_at: now });
}

/**
 * Verifies a compact signed-request JWS. Records the jti in the replay table
 * (in the caller's transaction, so a failed request does not consume it).
 */
export function verifySignedJws(jws: string, opts: SignedRequestOptions): VerifiedRequest {
  const parsed = parseJws(jws, SIGNED_REQUEST_TYP);
  const kidRef = parsed.header.kid;
  if (typeof kidRef !== "string") throw ApiError.unauthorized("JWS kid is required", "invalid_signature");
  const hash = kidRef.indexOf("#");
  const partyId = hash < 0 ? "" : kidRef.slice(0, hash);
  const kid = hash < 0 ? "" : kidRef.slice(hash + 1);
  if (!PARTY_ID_RE.test(partyId) || !KID_RE.test(kid)) {
    throw ApiError.unauthorized('JWS kid must be "<party_id>#<kid>"', "invalid_signature");
  }
  const party = getParty(partyId);
  if (!party) throw ApiError.unauthorized(`unknown party ${partyId}`, "invalid_signature");
  if (party.status !== "active") throw ApiError.forbidden(`party ${partyId} is suspended`, "party_suspended");
  const key = party.signing_keys.find((k) => k.kid === kid);
  if (!key) throw ApiError.unauthorized(`unknown key ${kidRef}`, "invalid_signature");
  if (!verifyJws(parsed, key)) throw ApiError.unauthorized("signature verification failed", "invalid_signature");

  const p: JsonObject = parsed.payload;
  const allowed = ["aud", "op", "iat", "jti", "body"];
  for (const k of Object.keys(p)) {
    if (!allowed.includes(k)) throw ApiError.badRequest(`signed payload: unknown member ${k}`, "invalid_signed_request");
  }
  if (p.aud !== opts.service) throw ApiError.unauthorized(`signed payload aud must be ${opts.service}`, "wrong_audience");
  if (p.op !== opts.op) throw ApiError.unauthorized(`signed payload op must be ${opts.op}`, "wrong_operation");
  if (typeof p.iat !== "number" || !Number.isSafeInteger(p.iat)) {
    throw ApiError.badRequest("signed payload iat must be an integer", "invalid_signed_request");
  }
  if (typeof p.jti !== "string" || !UUID_RE.test(p.jti)) {
    throw ApiError.badRequest("signed payload jti must be a UUID", "invalid_signed_request");
  }
  if (!("body" in p)) throw ApiError.badRequest("signed payload body is required", "invalid_signed_request");

  if (!opts.roles.some((r) => party.roles.includes(r))) {
    throw ApiError.forbidden(`party ${partyId} lacks a required role (${opts.roles.join(" | ")})`, "missing_role");
  }
  consumeFreshJti(p.iat, p.jti);
  return {
    party,
    key_ref: kidRef,
    payload: { aud: p.aud, op: p.op, iat: p.iat, jti: p.jti, body: p.body },
    jws,
  };
}

export function verifySignedRequest(request: ccfapp.Request, opts: SignedRequestOptions): VerifiedRequest {
  return verifySignedJws(signedEnvelope(request), opts);
}
