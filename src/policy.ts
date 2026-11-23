// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Release Policy v1 (spec §7.1). Authored only by the dataset owner (TDP).
// All present conditions must hold; absent conditions take the most
// restrictive default. Evaluation is pure so every deny path is unit-tested.

import {
  ApiError,
  arr,
  bool,
  DATASET_ID_RE,
  formatRfc3339,
  int,
  keys,
  num,
  obj,
  oneOf,
  parseRfc3339,
  PARTY_ID_RE,
  Platform,
  PLATFORMS,
  RatPrivacy,
  str,
} from "../packages/depa-ccf-common/src/index";

export const OUTPUT_MODES = ["tdc", "tee-only"] as const;
export type OutputMode = (typeof OUTPUT_MODES)[number];

export interface PrivacyRequirement {
  require_dp: boolean;
  max_epsilon?: number;
  max_delta?: number;
}

export interface ReleasePolicy {
  version: 1;
  allowed_platforms: Platform[];
  allowed_tiers: Array<1 | 2 | 3>;
  allowed_tdcs: string[];
  allowed_purposes: string[];
  privacy?: PrivacyRequirement;
  allowed_output_modes: OutputMode[];
  allowed_audiences: string[];
  allowed_custom_measurements: string[];
  max_runs_per_contract?: number;
  not_after?: string;
}

const PURPOSE_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

/** Validates a policy and returns it with every default made explicit. */
export function validateReleasePolicy(v: unknown, path = "policy"): ReleasePolicy {
  const o = obj(v, path);
  keys(
    o,
    path,
    ["version"],
    [
      "allowed_platforms",
      "allowed_tiers",
      "allowed_tdcs",
      "allowed_purposes",
      "privacy",
      "allowed_output_modes",
      "allowed_audiences",
      "allowed_custom_measurements",
      "max_runs_per_contract",
      "not_after",
    ],
  );
  oneOf(o.version, `${path}.version`, [1] as const);
  const list = <T>(key: string, item: (x: unknown, p: string) => T, dflt: T[]): T[] =>
    o[key] === undefined ? dflt : arr(o[key], `${path}.${key}`, item, { max: 256, unique: true });
  const policy: ReleasePolicy = {
    version: 1,
    allowed_platforms: list("allowed_platforms", (x, p) => oneOf(x, p, PLATFORMS), []),
    allowed_tiers: list("allowed_tiers", (x, p) => oneOf(x, p, [1, 2, 3] as const), [1]),
    allowed_tdcs: list("allowed_tdcs", (x, p) => (x === "*" ? "*" : str(x, p, { re: PARTY_ID_RE })), []),
    allowed_purposes: list("allowed_purposes", (x, p) => str(x, p, { re: PURPOSE_RE }), []),
    allowed_output_modes: list("allowed_output_modes", (x, p) => oneOf(x, p, OUTPUT_MODES), ["tee-only"]),
    allowed_audiences: list("allowed_audiences", (x, p) => str(x, p, { max: 512 }), []),
    allowed_custom_measurements: list("allowed_custom_measurements", (x, p) => str(x, p, { max: 256 }), []),
  };
  if (o.privacy !== undefined) {
    const pr = obj(o.privacy, `${path}.privacy`);
    keys(pr, `${path}.privacy`, ["require_dp"], ["max_epsilon", "max_delta"]);
    const privacy: PrivacyRequirement = { require_dp: bool(pr.require_dp, `${path}.privacy.require_dp`) };
    if (pr.max_epsilon !== undefined) privacy.max_epsilon = num(pr.max_epsilon, `${path}.privacy.max_epsilon`, { gt: 0, max: 1000 });
    if (pr.max_delta !== undefined) privacy.max_delta = num(pr.max_delta, `${path}.privacy.max_delta`, { min: 0, lt: 1 });
    policy.privacy = privacy;
  }
  if (o.max_runs_per_contract !== undefined) {
    policy.max_runs_per_contract = int(o.max_runs_per_contract, `${path}.max_runs_per_contract`, { min: 1, max: 1_000_000 });
  }
  if (o.not_after !== undefined) {
    policy.not_after = formatRfc3339(parseRfc3339(o.not_after, `${path}.not_after`));
  }
  return policy;
}

export interface ReleaseRequestContext {
  platform: Platform;
  tier: 1 | 2 | 3;
  custom_measurement: boolean;
  measurement_id: string;
  tdc: string;
  purpose: string;
  privacy: RatPrivacy;
  output_mode: OutputMode;
  now: number;
  /** Distinct run_ids already released for this (dataset, contract). */
  prior_runs: number;
  /** Whether this run_id is not yet among prior_runs. */
  new_run: boolean;
}

function deny(reason: string): never {
  throw ApiError.forbidden(`release policy: ${reason}`, "policy_denied");
}

/** Throws 403 policy_denied with the first failing condition. */
export function evaluateReleasePolicy(policy: ReleasePolicy | null, c: ReleaseRequestContext): void {
  if (!policy) deny("dataset has no release policy");
  if (!policy.allowed_platforms.includes(c.platform)) deny(`platform ${c.platform} not allowed`);
  if (!policy.allowed_tiers.includes(c.tier)) deny(`tier ${c.tier} not allowed`);
  if (c.tier === 3) {
    if (!c.custom_measurement) deny("tier 3 requires a custom measurement");
    if (!policy.allowed_custom_measurements.includes(c.measurement_id)) deny("custom measurement not allowed");
  }
  if (!policy.allowed_tdcs.includes("*") && !policy.allowed_tdcs.includes(c.tdc)) deny(`tdc ${c.tdc} not allowed`);
  if (!policy.allowed_purposes.includes(c.purpose)) deny(`purpose ${c.purpose} not allowed`);
  const pr = policy.privacy;
  if (pr) {
    if (pr.require_dp && c.privacy.mode !== "dp") deny("differential privacy is required");
    if (c.privacy.mode === "dp") {
      if (pr.max_epsilon !== undefined && !((c.privacy.epsilon as number) <= pr.max_epsilon)) deny("epsilon exceeds max_epsilon");
      if (pr.max_delta !== undefined && !((c.privacy.delta as number) <= pr.max_delta)) deny("delta exceeds max_delta");
    }
  }
  if (!policy.allowed_output_modes.includes(c.output_mode)) deny(`output mode ${c.output_mode} not allowed`);
  if (policy.not_after !== undefined && c.now > parseRfc3339(policy.not_after, "policy.not_after")) deny("policy not_after has passed");
  if (policy.max_runs_per_contract !== undefined && c.new_run && c.prior_runs >= policy.max_runs_per_contract) {
    deny("max_runs_per_contract reached");
  }
}

/** OIDC token audience check for dataset resources (spec §10). */
export function checkDatasetAudience(policy: ReleasePolicy | null, audience: string): void {
  if (!policy || !policy.allowed_audiences.includes(audience)) deny(`audience ${audience} not allowed`);
}

export function datasetOwner(datasetId: string): string {
  if (!DATASET_ID_RE.test(datasetId)) throw ApiError.badRequest("invalid dataset_id", "invalid_input");
  return datasetId.slice(0, datasetId.indexOf("/"));
}
