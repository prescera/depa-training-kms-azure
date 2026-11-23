// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Service-to-service tokens: the Run Authorization Token (RAT, CS → KMS,
// spec §9.3) and the key-release receipt (KMS → CS, spec §9.4/§9.5). Both are
// verified only against the peer's JWKS pinned by governance (spec §5).

import { ApiError } from "./errors";
import { RunBinding } from "./binding";
import { DIGEST_RE } from "./jcs";
import { parseJws, verifyJws } from "./jws";
import { AttestedClaims, Platform, PLATFORMS } from "./platforms";
import { PeerService } from "./settings";
import {
  arr,
  bool,
  DATASET_ID_RE,
  HEX64_RE,
  int,
  JsonObject,
  num,
  obj,
  oneOf,
  PARTY_ID_RE,
  RELEASE_ID_RE,
  str,
  UUID4_RE,
} from "./validate";

export const RAT_TYP = "depa-rat+jwt";
export const RELEASE_RECEIPT_TYP = "depa-key-release+jwt";
export const EXEC_RECEIPT_TYP = "depa-exec-receipt+jwt";
export const RUN_EVENT_TYP = "depa-run-event+jws";
export const RAT_AUDIENCE = "depa-kms";
export const RAT_LIFETIME_S = 300;
const CLOCK_SKEW_S = 60;

function tokenError(message: string): ApiError {
  return new ApiError(401, "invalid_token", message);
}

/** Verifies a peer-signed JWS against the pinned JWKS and returns its payload. */
export function verifyPeerJws(jws: unknown, peer: PeerService, typ: string): JsonObject {
  const parsed = parseJws(jws, typ);
  if (parsed.alg !== "ES256") throw tokenError(`${typ} must be ES256`);
  const kid = parsed.header.kid;
  const key = typeof kid === "string" ? peer.jwks.find((k) => k.kid === kid) : undefined;
  if (!key) throw tokenError(`${typ} kid is not a pinned key of ${peer.name}`);
  if (!verifyJws(parsed, key)) throw tokenError(`${typ} signature verification failed`);
  if (parsed.payload.iss !== peer.url) throw tokenError(`${typ} iss does not match pinned ${peer.name} url`);
  return parsed.payload;
}

export interface RatDataset {
  dataset_id: string;
  version: string;
  manifest_digest: string;
}

export interface RatPrivacy {
  mode: "dp" | "none";
  epsilon?: number;
  delta?: number;
}

export interface RatClaims {
  iss: string;
  aud: string;
  sub: string;
  iat: number;
  exp: number;
  contract_id: string;
  contract_digest: string;
  run_id: string;
  binding_hash: string;
  platform: Platform;
  measurement_id: string;
  tier: 1 | 2 | 3;
  custom_measurement: boolean;
  ccr_releases: string[];
  recipe_digest: string;
  tdc: string;
  purpose: string;
  datasets: RatDataset[];
  privacy: RatPrivacy;
  output: { mode: "tdc" | "tee-only"; recipients: string[] };
  deadline: number;
}

export function validatePrivacy(v: unknown, path: string): RatPrivacy {
  const o = obj(v, path);
  const mode = oneOf(o.mode, `${path}.mode`, ["dp", "none"] as const);
  if (mode === "none") {
    for (const k of Object.keys(o)) if (k !== "mode") throw ApiError.badRequest(`${path}.${k}: not allowed when mode is none`, "invalid_input");
    return { mode };
  }
  for (const k of Object.keys(o)) {
    if (!["mode", "epsilon", "delta"].includes(k)) throw ApiError.badRequest(`${path}.${k}: unknown member`, "invalid_input");
  }
  return {
    mode,
    epsilon: num(o.epsilon, `${path}.epsilon`, { gt: 0, max: 1000 }),
    delta: num(o.delta, `${path}.delta`, { min: 0, lt: 1 }),
  };
}

/** Validates RAT structure and time/audience/issuer claims (spec §9.3, §9.4 step 3). */
export function validateRatClaims(p: JsonObject, now: number): RatClaims {
  try {
    const iat = int(p.iat, "rat.iat");
    const exp = int(p.exp, "rat.exp");
    if (p.aud !== RAT_AUDIENCE) throw tokenError("RAT aud must be depa-kms");
    if (exp <= now) throw tokenError("RAT expired");
    if (iat > now + CLOCK_SKEW_S) throw tokenError("RAT issued in the future");
    if (exp - iat > RAT_LIFETIME_S) throw tokenError("RAT lifetime exceeds 300 s");
    const tier = oneOf(p.tier, "rat.tier", [1, 2, 3] as const);
    const custom = bool(p.custom_measurement, "rat.custom_measurement");
    if ((tier === 3) !== custom) throw tokenError("RAT custom_measurement must be set exactly for tier 3");
    const out = obj(p.output, "rat.output");
    const claims: RatClaims = {
      iss: str(p.iss, "rat.iss", { max: 512 }),
      aud: RAT_AUDIENCE,
      sub: str(p.sub, "rat.sub", { re: UUID4_RE }),
      iat,
      exp,
      contract_id: str(p.contract_id, "rat.contract_id", { re: UUID4_RE }),
      contract_digest: str(p.contract_digest, "rat.contract_digest", { re: DIGEST_RE }),
      run_id: str(p.run_id, "rat.run_id", { re: UUID4_RE }),
      binding_hash: str(p.binding_hash, "rat.binding_hash", { re: HEX64_RE }),
      platform: oneOf(p.platform, "rat.platform", PLATFORMS),
      measurement_id: str(p.measurement_id, "rat.measurement_id", { max: 256 }),
      tier,
      custom_measurement: custom,
      ccr_releases: arr(p.ccr_releases, "rat.ccr_releases", (x, q) => str(x, q, { re: RELEASE_ID_RE }), { max: 32 }),
      recipe_digest: str(p.recipe_digest, "rat.recipe_digest", { re: DIGEST_RE }),
      tdc: str(p.tdc, "rat.tdc", { re: PARTY_ID_RE }),
      purpose: str(p.purpose, "rat.purpose", { max: 64 }),
      datasets: arr(
        p.datasets,
        "rat.datasets",
        (x, q) => {
          const d = obj(x, q);
          return {
            dataset_id: str(d.dataset_id, `${q}.dataset_id`, { re: DATASET_ID_RE }),
            version: str(d.version, `${q}.version`, { max: 64 }),
            manifest_digest: str(d.manifest_digest, `${q}.manifest_digest`, { re: DIGEST_RE }),
          };
        },
        { min: 1, max: 64 },
      ),
      privacy: validatePrivacy(p.privacy, "rat.privacy"),
      output: {
        mode: oneOf(out.mode, "rat.output.mode", ["tdc", "tee-only"] as const),
        recipients: arr(out.recipients, "rat.output.recipients", (x, q) => str(x, q, { max: 256 }), { max: 32 }),
      },
      deadline: int(p.deadline, "rat.deadline"),
    };
    if (claims.sub !== claims.run_id) throw tokenError("RAT sub must equal run_id");
    return claims;
  } catch (e) {
    if (e instanceof ApiError && e.statusCode === 400) throw tokenError(`malformed RAT: ${e.message}`);
    throw e;
  }
}

/**
 * Spec §9.4 step 4 plus consistency with the binding: the RAT must have been
 * issued for exactly this binding and this attested workload.
 */
export function checkRatMatchesRun(rat: RatClaims, binding: RunBinding, bindingHash: string, claims: AttestedClaims): void {
  if (rat.binding_hash !== bindingHash) throw ApiError.forbidden("RAT binding_hash does not match the binding", "rat_mismatch");
  if (rat.measurement_id !== claims.measurement_id) {
    throw ApiError.forbidden("RAT measurement_id does not match the attested measurement", "rat_mismatch");
  }
  if (rat.platform !== claims.platform) throw ApiError.forbidden("RAT platform does not match the attested platform", "rat_mismatch");
  if (rat.run_id !== binding.run_id) throw ApiError.forbidden("RAT run_id does not match binding.run_id", "rat_mismatch");
  if (rat.contract_id !== binding.contract_id || rat.contract_digest !== binding.contract_digest) {
    throw ApiError.forbidden("RAT contract does not match the binding", "rat_mismatch");
  }
  if (rat.recipe_digest !== binding.recipe_digest) throw ApiError.forbidden("RAT recipe does not match the binding", "rat_mismatch");
}

export interface ReleaseReceiptClaims {
  iss: string;
  release_id: string;
  run_id: string;
  contract_id: string;
  dataset_id: string;
  kids: string[];
  binding_hash: string;
  measurement_id: string;
  platform: Platform;
  iat: number;
}

export function validateReleaseReceiptClaims(p: JsonObject): ReleaseReceiptClaims {
  try {
    return {
      iss: str(p.iss, "receipt.iss", { max: 512 }),
      release_id: str(p.release_id, "receipt.release_id", { re: UUID4_RE }),
      run_id: str(p.run_id, "receipt.run_id", { re: UUID4_RE }),
      contract_id: str(p.contract_id, "receipt.contract_id", { re: UUID4_RE }),
      dataset_id: str(p.dataset_id, "receipt.dataset_id", { re: DATASET_ID_RE }),
      kids: arr(p.kids, "receipt.kids", (x, q) => str(x, q, { max: 200 }), { min: 1, max: 64 }),
      binding_hash: str(p.binding_hash, "receipt.binding_hash", { re: HEX64_RE }),
      measurement_id: str(p.measurement_id, "receipt.measurement_id", { max: 256 }),
      platform: oneOf(p.platform, "receipt.platform", PLATFORMS),
      iat: int(p.iat, "receipt.iat"),
    };
  } catch (e) {
    if (e instanceof ApiError && e.statusCode === 400) throw tokenError(`malformed release receipt: ${e.message}`);
    throw e;
  }
}

export interface RunIdentity {
  run_id: string;
  contract_id: string;
  binding_hash: string;
  measurement_id: string;
  platform: Platform;
}

/** Spec §9.5: a release receipt must belong to this run and dataset. */
export function checkReleaseReceiptForRun(r: ReleaseReceiptClaims, run: RunIdentity, datasetId: string): void {
  if (r.run_id !== run.run_id) throw ApiError.forbidden("release receipt run_id does not match the run", "receipt_mismatch");
  if (r.binding_hash !== run.binding_hash) {
    throw ApiError.forbidden("release receipt binding_hash does not match the run", "receipt_mismatch");
  }
  if (r.contract_id !== run.contract_id) throw ApiError.forbidden("release receipt contract does not match", "receipt_mismatch");
  if (r.dataset_id !== datasetId) throw ApiError.forbidden("release receipt dataset does not match the input", "receipt_mismatch");
  if (r.measurement_id !== run.measurement_id || r.platform !== run.platform) {
    throw ApiError.forbidden("release receipt workload does not match the run", "receipt_mismatch");
  }
}
