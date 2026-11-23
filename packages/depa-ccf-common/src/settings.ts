// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Governance-controlled configuration shared by both services: settings,
// JWT validation policies, pinned peer services and approved app digests.

import { ApiError } from "./errors";
import { EcPublicJwk, validateEcPublicJwk } from "./jws";
import { JsonTable } from "./kv";
import { DIGEST_RE } from "./jcs";
import { arr, bool, HTTPS_URL_RE, isObject, keys, obj, str } from "./validate";

export interface CommonSettings {
  /** Development only: accept platform "virtual" attestation (spec §1). */
  allow_virtual_attestation: boolean;
  /**
   * Public base URL of this service, e.g. https://<ledger>.confidential-ledger.azure.com/app.
   * Used as RAT `iss` (CS), GCP attestation-token audience and receipt `iss`.
   */
  base_url: string | null;
  /**
   * digest(trust bundle) expected in every run binding (spec §9.1). Required for
   * non-virtual platforms; checked for virtual only when set.
   */
  trust_bundle_digest: string | null;
}

const DEFAULT_SETTINGS: CommonSettings = { allow_virtual_attestation: false, base_url: null, trust_bundle_digest: null };

export const settingsTable = new JsonTable<CommonSettings>("public:depa.settings");

export function getSettings(): CommonSettings {
  return { ...DEFAULT_SETTINGS, ...(settingsTable.get("settings") ?? {}) };
}

export function requireBaseUrl(): string {
  const url = getSettings().base_url;
  if (!url) throw ApiError.conflict("settings.base_url is not configured", "not_configured");
  return url;
}

export function validateSettingsPatch(v: unknown, path: string): Partial<CommonSettings> {
  const o = obj(v, path);
  keys(o, path, [], ["allow_virtual_attestation", "base_url", "trust_bundle_digest"]);
  const out: Partial<CommonSettings> = {};
  if (o.allow_virtual_attestation !== undefined) {
    out.allow_virtual_attestation = bool(o.allow_virtual_attestation, `${path}.allow_virtual_attestation`);
  }
  if (o.base_url !== undefined) {
    const u = str(o.base_url, `${path}.base_url`, { re: HTTPS_URL_RE, max: 512 });
    if (u.endsWith("/")) throw ApiError.badRequest(`${path}.base_url: must not end with /`, "invalid_input");
    out.base_url = u;
  }
  if (o.trust_bundle_digest !== undefined) {
    out.trust_bundle_digest = str(o.trust_bundle_digest, `${path}.trust_bundle_digest`, { re: DIGEST_RE });
  }
  return out;
}

export function applySettingsPatch(patch: Partial<CommonSettings>): void {
  settingsTable.set("settings", { ...getSettings(), ...patch });
}

// ---------------------------------------------------------------- JWT policies

export type ClaimConstraint = string | number | boolean | Array<string | number | boolean>;

export interface JwtValidationPolicy {
  issuer: string;
  claims: Record<string, ClaimConstraint>;
}

export const jwtPolicyTable = new JsonTable<JwtValidationPolicy>("public:depa.jwt_validation_policies");

function scalar(v: unknown, path: string): string | number | boolean {
  if (typeof v === "string" || typeof v === "boolean" || (typeof v === "number" && isFinite(v))) return v;
  throw ApiError.badRequest(`${path}: must be a string, number or boolean`, "invalid_input");
}

export function validateJwtValidationPolicy(v: unknown, path: string): JwtValidationPolicy {
  const o = obj(v, path);
  keys(o, path, ["issuer", "claims"]);
  const issuer = str(o.issuer, `${path}.issuer`, { re: HTTPS_URL_RE, max: 512 });
  const c = obj(o.claims, `${path}.claims`);
  const claims: Record<string, ClaimConstraint> = {};
  for (const k of Object.keys(c)) {
    str(k, `${path}.claims key`, { re: /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$/, max: 128 });
    claims[k] = Array.isArray(c[k])
      ? arr(c[k], `${path}.claims.${k}`, scalar, { min: 1, max: 64 })
      : scalar(c[k], `${path}.claims.${k}`);
  }
  return { issuer, claims };
}

function claimAt(payload: unknown, dotted: string): unknown {
  let cur: unknown = payload;
  for (const part of dotted.split(".")) {
    if (!isObject(cur)) return undefined;
    cur = cur[part];
  }
  return cur;
}

/**
 * Enforces the governance JWT validation policy for `issuer` (as in the
 * DEPA-inferencing KMS). Fail closed: an issuer without a policy is rejected.
 * A constraint matches if the claim equals the value, or is one of the listed
 * values; if the claim itself is an array, any element may match.
 */
export function enforceJwtValidationPolicy(issuer: string, payload: unknown): void {
  const policy = jwtPolicyTable.get(issuer);
  if (!policy) throw ApiError.forbidden(`no JWT validation policy for issuer ${issuer}`, "jwt_policy_missing");
  for (const [k, expected] of Object.entries(policy.claims)) {
    const actual = claimAt(payload, k);
    const accepted = Array.isArray(expected) ? expected : [expected];
    const values = Array.isArray(actual) ? actual : [actual];
    if (!values.some((x) => accepted.includes(x as string | number | boolean))) {
      throw ApiError.forbidden(`JWT claim ${k} does not satisfy the validation policy`, "jwt_policy_violation");
    }
  }
}

// --------------------------------------------------------------- Peer services

export interface PeerService {
  name: string;
  url: string;
  jwks: EcPublicJwk[];
  proposal_id: string;
}

export const peerTable = new JsonTable<PeerService>("public:depa.peer_services");

export function validatePeerService(v: unknown, path: string, allowedName: string): Omit<PeerService, "proposal_id"> {
  const o = obj(v, path);
  keys(o, path, ["name", "url", "jwks"]);
  if (o.name !== allowedName) throw ApiError.badRequest(`${path}.name: must be ${allowedName}`, "invalid_input");
  const url = str(o.url, `${path}.url`, { re: HTTPS_URL_RE, max: 512 });
  const jwks = arr(
    o.jwks,
    `${path}.jwks`,
    (x, p) => validateEcPublicJwk(x, p, { requireKid: true, allowP384: false }),
    { min: 1, max: 8 },
  );
  if (new Set(jwks.map((k) => k.kid)).size !== jwks.length) {
    throw ApiError.badRequest(`${path}.jwks: kids must be unique`, "invalid_input");
  }
  return { name: allowedName, url, jwks };
}

export function requirePeer(name: string): PeerService {
  const p = peerTable.get(name);
  if (!p) throw ApiError.conflict(`peer service ${name} is not pinned`, "peer_not_pinned");
  return p;
}

// ----------------------------------------------------------- App digests

export interface ApprovedDigest {
  digest: string;
  proposal_id: string;
}

export const approvedDigestTable = new JsonTable<ApprovedDigest>("public:depa.approved_app_digests");

export function validateAppDigest(v: unknown, path: string): string {
  const o = obj(v, path);
  keys(o, path, ["digest"]);
  return str(o.digest, `${path}.digest`, { re: DIGEST_RE });
}
