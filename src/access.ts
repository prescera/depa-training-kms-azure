// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// The run-access checks shared by /keys/release, /oidc/token and
// /outputs/{contract_id}/key (spec §9.4 steps 1–7). All checks run inside the
// caller's single transaction.

import * as ccfapp from "@microsoft/ccf-app";
import { ccf } from "@microsoft/ccf-app/global";
import {
  ApiError,
  AttestedClaims,
  CcrRelease,
  checkTrustBundle,
  checkRatMatchesRun,
  constantTimeEqual,
  getSettings,
  JsonTable,
  matchingApprovedReleases,
  RAT_TYP,
  RatClaims,
  requirePeer,
  RunBinding,
  sha256Hex,
  str,
  utf8Encode,
  validateRatClaims,
  validateRunBinding,
  verifyAttestation,
  verifyPeerJws,
} from "../packages/depa-ccf-common/src/index";
import { PEER_NAME } from "./constants";
import { DatasetRecord, datasetState, requireDataset } from "./datasets";
import { evaluateReleasePolicy } from "./policy";

export interface RunAccess {
  binding: RunBinding;
  binding_hash: string;
  claims: AttestedClaims;
  rat: RatClaims;
  /** Matched registry release (tier 1/2). */
  release?: CcrRelease;
}

const MIN_WRAPPING_KEY_BITS = 3072;

/** Distinct run_ids that obtained keys, per (dataset, contract). */
interface RunCounter {
  run_ids: string[];
}
const runCounters = new JsonTable<RunCounter>("public:depa.dataset_contract_runs");

function counterKey(datasetId: string, contractId: string): string {
  return `${datasetId}|${contractId}`;
}

/**
 * Steps 1, 3, 4 and the registry part of step 5: attestation proves the
 * binding, the RAT is a fresh CS-signed token for exactly this binding and
 * workload, and (tier 1/2) the measurement belongs to an approved,
 * non-revoked release listed in the RAT for the RAT's tier.
 */
export function verifyRunAccess(request: ccfapp.Request, body: Record<string, unknown>, now: number): RunAccess {
  const { binding, binding_hash } = validateRunBinding(body.binding);
  const settings = getSettings();
  checkTrustBundle(binding, settings);
  const claims = verifyAttestation(body.attestation, binding_hash, request, settings, now);
  if (claims.platform !== binding.platform) throw ApiError.forbidden("attested platform does not match binding.platform", "platform_mismatch");
  const rat = validateRatClaims(verifyPeerJws(body.rat, requirePeer(PEER_NAME), RAT_TYP), now);
  checkRatMatchesRun(rat, binding, binding_hash, claims);
  if (rat.deadline <= now) throw ApiError.forbidden("run deadline has passed", "deadline_passed");
  if (rat.tier === 3) return { binding, binding_hash, claims, rat };
  const release = matchingApprovedReleases(claims).find(
    (r) => rat.ccr_releases.includes(r.release_id) && (r.tiers as number[]).includes(rat.tier),
  );
  if (!release) {
    throw ApiError.forbidden(
      "attested measurement is not in an approved, non-revoked release listed in the RAT for its tier",
      "measurement_not_approved",
    );
  }
  return { binding, binding_hash, claims, rat, release };
}

/** Step 2: SHA-256 of the exact PEM string equals binding.wrapping_key_sha256; RSA >= 3072 bits. */
export function checkWrappingKey(pemValue: unknown, binding: { wrapping_key_sha256: string }): string {
  const pem = str(pemValue, "wrappingKey", { max: 8192 });
  if (!constantTimeEqual(sha256Hex(utf8Encode(pem)), binding.wrapping_key_sha256)) {
    throw ApiError.forbidden("SHA-256(wrappingKey) does not match binding.wrapping_key_sha256", "wrapping_key_mismatch");
  }
  let n: string;
  try {
    n = ccf.crypto.pubRsaPemToJwk(pem).n;
  } catch {
    throw ApiError.badRequest("wrappingKey must be a PEM RSA public key", "invalid_wrapping_key");
  }
  // base64url length → modulus bits (leading zero octets are not encoded in JWK).
  const bits = Math.floor((n.replace(/=+$/, "").length * 6) / 8) * 8;
  if (bits < MIN_WRAPPING_KEY_BITS) throw ApiError.badRequest("wrappingKey must be RSA-3072 or larger", "invalid_wrapping_key");
  return pem;
}

export interface DatasetAccess {
  dataset: DatasetRecord;
  prior_runs: string[];
  new_run: boolean;
}

/** Steps 5 (tier 3), 6 and 7 for one dataset. Does not record anything. */
export function checkDatasetAccess(access: RunAccess, datasetId: string, now: number): DatasetAccess {
  const { rat, claims } = access;
  if (!rat.datasets.some((d) => d.dataset_id === datasetId)) {
    throw ApiError.forbidden(`dataset ${datasetId} is not part of the authorized run`, "dataset_not_in_rat");
  }
  const dataset = requireDataset(datasetId);
  if (datasetState(dataset) !== "active") throw ApiError.forbidden(`dataset ${datasetId} is suspended`, "dataset_suspended");
  const prior = runCounters.get(counterKey(datasetId, rat.contract_id))?.run_ids ?? [];
  const newRun = !prior.includes(rat.run_id);
  evaluateReleasePolicy(dataset.policy, {
    platform: claims.platform,
    tier: rat.tier,
    custom_measurement: rat.custom_measurement,
    measurement_id: claims.measurement_id,
    tdc: rat.tdc,
    purpose: rat.purpose,
    privacy: rat.privacy,
    output_mode: rat.output.mode,
    now,
    prior_runs: prior.length,
    new_run: newRun,
  });
  return { dataset, prior_runs: prior, new_run: newRun };
}

/** Records the run against the per-(dataset, contract) counter. */
export function recordRun(access: RunAccess, da: DatasetAccess): void {
  if (!da.new_run) return;
  runCounters.set(counterKey(da.dataset.dataset_id, access.rat.contract_id), { run_ids: [...da.prior_runs, access.rat.run_id] });
}
