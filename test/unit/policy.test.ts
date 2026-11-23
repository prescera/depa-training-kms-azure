// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.

import { describe, expect, it } from "@jest/globals";
import { checkDatasetAudience, evaluateReleasePolicy, ReleasePolicy, ReleaseRequestContext, validateReleasePolicy } from "../../src/policy";

const NOW = Date.parse("2026-11-23T00:00:00Z") / 1000;

const policy: ReleasePolicy = validateReleasePolicy({
  version: 1,
  allowed_platforms: ["aci-snp", "gcp-cs-tdx"],
  allowed_tiers: [1, 2],
  allowed_tdcs: ["fintech-x"],
  allowed_purposes: ["TRAINING"],
  privacy: { require_dp: true, max_epsilon: 5.0, max_delta: 1e-5 },
  allowed_output_modes: ["tdc"],
  allowed_audiences: ["sts.amazonaws.com"],
  allowed_custom_measurements: ["custom-m"],
  max_runs_per_contract: 2,
  not_after: "2027-12-31T00:00:00Z",
});

const ctx: ReleaseRequestContext = {
  platform: "aci-snp",
  tier: 1,
  custom_measurement: false,
  measurement_id: "m",
  tdc: "fintech-x",
  purpose: "TRAINING",
  privacy: { mode: "dp", epsilon: 4, delta: 1e-5 },
  output_mode: "tdc",
  now: NOW,
  prior_runs: 0,
  new_run: true,
};

describe("release policy evaluation", () => {
  it("allows a request satisfying every condition", () => {
    expect(() => evaluateReleasePolicy(policy, ctx)).not.toThrow();
    expect(() => evaluateReleasePolicy(policy, { ...ctx, prior_runs: 2, new_run: false })).not.toThrow(); // same run again
  });

  it.each<[string, Partial<ReleaseRequestContext>, RegExp]>([
    ["platform not allowed", { platform: "virtual" }, /platform virtual not allowed/],
    ["tier not allowed", { tier: 3, custom_measurement: true, measurement_id: "custom-m" }, /tier 3 not allowed/],
    ["tdc not allowed", { tdc: "other-tdc" }, /tdc other-tdc not allowed/],
    ["purpose not allowed", { purpose: "MARKETING" }, /purpose MARKETING not allowed/],
    ["dp required", { privacy: { mode: "none" } }, /differential privacy is required/],
    ["epsilon too large", { privacy: { mode: "dp", epsilon: 5.5, delta: 1e-5 } }, /epsilon/],
    ["delta too large", { privacy: { mode: "dp", epsilon: 1, delta: 1e-4 } }, /delta/],
    ["output mode not allowed", { output_mode: "tee-only" }, /output mode tee-only/],
    ["not_after passed", { now: Date.parse("2028-01-01T00:00:00Z") / 1000 }, /not_after/],
    ["max runs reached", { prior_runs: 2, new_run: true }, /max_runs_per_contract/],
  ])("denies: %s", (_n, override, re) => {
    expect(() => evaluateReleasePolicy(policy, { ...ctx, ...override })).toThrow(re);
  });

  it("denies tier 3 unless the custom measurement is explicitly allowed", () => {
    const p3 = { ...policy, allowed_tiers: [1, 2, 3] as Array<1 | 2 | 3> };
    expect(() => evaluateReleasePolicy(p3, { ...ctx, tier: 3, custom_measurement: true, measurement_id: "custom-m" })).not.toThrow();
    expect(() => evaluateReleasePolicy(p3, { ...ctx, tier: 3, custom_measurement: true, measurement_id: "other" })).toThrow(/custom measurement not allowed/);
    expect(() => evaluateReleasePolicy(p3, { ...ctx, tier: 3, custom_measurement: false, measurement_id: "custom-m" })).toThrow(/requires a custom measurement/);
  });

  it("denies everything without a policy and applies restrictive defaults", () => {
    expect(() => evaluateReleasePolicy(null, ctx)).toThrow(/no release policy/);
    const minimal = validateReleasePolicy({ version: 1 });
    expect(minimal).toMatchObject({ allowed_platforms: [], allowed_tiers: [1], allowed_tdcs: [], allowed_output_modes: ["tee-only"], allowed_audiences: [] });
    expect(() => evaluateReleasePolicy(minimal, ctx)).toThrow(/platform/);
    const wildcard = validateReleasePolicy({ version: 1, allowed_platforms: ["aci-snp"], allowed_tdcs: ["*"], allowed_purposes: ["TRAINING"], allowed_output_modes: ["tdc"] });
    expect(() => evaluateReleasePolicy(wildcard, { ...ctx, tdc: "anyone", privacy: { mode: "none" } })).not.toThrow();
  });

  it("checks OIDC audiences", () => {
    expect(() => checkDatasetAudience(policy, "sts.amazonaws.com")).not.toThrow();
    expect(() => checkDatasetAudience(policy, "api://AzureADTokenExchange")).toThrow(/audience/);
    expect(() => checkDatasetAudience(null, "sts.amazonaws.com")).toThrow();
  });

  it("validates policies strictly", () => {
    expect(() => validateReleasePolicy({ version: 2 })).toThrow();
    expect(() => validateReleasePolicy({ version: 1, allowed_platforms: ["sgx"] })).toThrow();
    expect(() => validateReleasePolicy({ version: 1, allowed_tiers: [4] })).toThrow();
    expect(() => validateReleasePolicy({ version: 1, unknown: true })).toThrow();
    expect(() => validateReleasePolicy({ version: 1, privacy: { max_epsilon: 1 } })).toThrow();
    expect(() => validateReleasePolicy({ version: 1, not_after: "tomorrow" })).toThrow();
    expect(() => validateReleasePolicy({ version: 1, allowed_tdcs: ["Bad_Id"] })).toThrow();
  });
});
