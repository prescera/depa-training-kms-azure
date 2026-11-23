// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.

import { beforeEach, describe, expect, it } from "@jest/globals";
import { randomUUID } from "crypto";
import { RunBinding } from "../src/binding";
import { AttestedClaims } from "../src/platforms";
import { PeerService } from "../src/settings";
import {
  checkRatMatchesRun,
  checkReleaseReceiptForRun,
  RAT_TYP,
  RELEASE_RECEIPT_TYP,
  validateRatClaims,
  validateReleaseReceiptClaims,
  verifyPeerJws,
} from "../src/tokens";
import { resetKv, TestParty } from "./helpers";

beforeEach(resetKv);

const NOW = 1_800_000_000;
const runId = randomUUID();
const contractId = randomUUID();
const D = (c: string) => "sha256:" + c.repeat(64);

function rat(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: "https://cs.example/app",
    aud: "depa-kms",
    sub: runId,
    iat: NOW,
    exp: NOW + 300,
    contract_id: contractId,
    contract_digest: D("1"),
    run_id: runId,
    binding_hash: "ab".repeat(32),
    platform: "virtual",
    measurement_id: "virtual-dev",
    tier: 1,
    custom_measurement: false,
    ccr_releases: ["r1"],
    recipe_digest: D("2"),
    tdc: "fintech-x",
    purpose: "TRAINING",
    datasets: [{ dataset_id: "bank-a/ds", version: "v1", manifest_digest: D("3") }],
    privacy: { mode: "dp", epsilon: 4, delta: 1e-5 },
    output: { mode: "tdc", recipients: ["party:fintech-x#h1"] },
    deadline: NOW + 3600,
    ...overrides,
  };
}

describe("RAT claims", () => {
  it("accepts a well-formed fresh RAT", () => {
    expect(validateRatClaims(rat(), NOW + 10).run_id).toBe(runId);
  });

  it.each([
    ["expired", rat({ exp: NOW }), NOW],
    ["wrong audience", rat({ aud: "depa-contract-service" }), NOW],
    ["lifetime > 300 s", rat({ exp: NOW + 301 }), NOW],
    ["issued in the future", rat({ iat: NOW + 120, exp: NOW + 400 }), NOW],
    ["tier 3 without custom measurement", rat({ tier: 3 }), NOW],
    ["custom measurement on tier 1", rat({ custom_measurement: true }), NOW],
    ["sub != run_id", rat({ sub: randomUUID() }), NOW],
    ["missing datasets", rat({ datasets: [] }), NOW],
    ["bad privacy", rat({ privacy: { mode: "dp" } }), NOW],
  ])("rejects %s", (_n, claims, now) => {
    expect(() => validateRatClaims(claims, now as number)).toThrow();
  });

  const binding: RunBinding = {
    v: 1,
    contract_id: contractId,
    contract_digest: D("1"),
    run_id: runId,
    recipe_digest: D("2"),
    platform: "virtual",
    wrapping_key_sha256: "cd".repeat(32),
    run_key: { kty: "EC", crv: "P-256", x: "x", y: "y" },
    trust_bundle_digest: D("8"),
  };
  const claims: AttestedClaims = { platform: "virtual", measurement_id: "virtual-dev", binding_hash: "ab".repeat(32), debug: true, raw: {} };

  it("binds the RAT to the binding and the attested workload", () => {
    const r = validateRatClaims(rat(), NOW);
    expect(() => checkRatMatchesRun(r, binding, "ab".repeat(32), claims)).not.toThrow();
    expect(() => checkRatMatchesRun(r, binding, "ff".repeat(32), claims)).toThrow(/binding_hash/);
    expect(() => checkRatMatchesRun(r, binding, "ab".repeat(32), { ...claims, measurement_id: "other" })).toThrow(/measurement/);
    expect(() => checkRatMatchesRun(r, binding, "ab".repeat(32), { ...claims, platform: "aci-snp" })).toThrow(/platform/);
    expect(() => checkRatMatchesRun(r, { ...binding, run_id: randomUUID() }, "ab".repeat(32), claims)).toThrow(/run_id/);
    expect(() => checkRatMatchesRun(r, { ...binding, contract_digest: D("9") }, "ab".repeat(32), claims)).toThrow(/contract/);
    expect(() => checkRatMatchesRun(r, { ...binding, recipe_digest: D("9") }, "ab".repeat(32), claims)).toThrow(/recipe/);
  });
});

describe("release receipts", () => {
  const receipt = {
    iss: "https://kms.example/app",
    release_id: randomUUID(),
    run_id: runId,
    contract_id: contractId,
    dataset_id: "bank-a/ds",
    kids: ["bank-a/ds#1"],
    binding_hash: "ab".repeat(32),
    measurement_id: "virtual-dev",
    platform: "virtual",
    iat: NOW,
  };
  const run = { run_id: runId, contract_id: contractId, binding_hash: "ab".repeat(32), measurement_id: "virtual-dev", platform: "virtual" as const };

  it("must belong to the run and dataset", () => {
    const r = validateReleaseReceiptClaims(receipt);
    expect(() => checkReleaseReceiptForRun(r, run, "bank-a/ds")).not.toThrow();
    expect(() => checkReleaseReceiptForRun(r, { ...run, run_id: randomUUID() }, "bank-a/ds")).toThrow(/run_id/);
    expect(() => checkReleaseReceiptForRun(r, { ...run, binding_hash: "00".repeat(32) }, "bank-a/ds")).toThrow(/binding_hash/);
    expect(() => checkReleaseReceiptForRun(r, { ...run, contract_id: randomUUID() }, "bank-a/ds")).toThrow(/contract/);
    expect(() => checkReleaseReceiptForRun(r, run, "bank-a/other")).toThrow(/dataset/);
    expect(() => checkReleaseReceiptForRun(r, { ...run, measurement_id: "x" }, "bank-a/ds")).toThrow(/workload/);
    expect(() => validateReleaseReceiptClaims({ ...receipt, kids: [] })).toThrow();
  });
});

describe("peer JWS verification", () => {
  const kms = new TestParty("kms", ["auditor"], "kms-key");
  const peer: PeerService = { name: "depa-kms", url: "https://kms.example/app", jwks: [kms.jwk], proposal_id: "p" };
  const payload = { iss: "https://kms.example/app", x: 1 };

  it("accepts pinned keys only", () => {
    expect(verifyPeerJws(kms.jws({ typ: RELEASE_RECEIPT_TYP, kid: "kms-key" }, payload), peer, RELEASE_RECEIPT_TYP).x).toBe(1);
    const other = new TestParty("evil", ["auditor"], "kms-key");
    expect(() => verifyPeerJws(other.jws({ typ: RELEASE_RECEIPT_TYP, kid: "kms-key" }, payload), peer, RELEASE_RECEIPT_TYP)).toThrow(/signature/);
    expect(() => verifyPeerJws(kms.jws({ typ: RELEASE_RECEIPT_TYP, kid: "unpinned" }, payload), peer, RELEASE_RECEIPT_TYP)).toThrow(/pinned/);
    expect(() => verifyPeerJws(kms.jws({ typ: RELEASE_RECEIPT_TYP, kid: "kms-key" }, { ...payload, iss: "https://evil" }), peer, RELEASE_RECEIPT_TYP)).toThrow(/iss/);
    expect(() => verifyPeerJws(kms.jws({ typ: RAT_TYP, kid: "kms-key" }, payload), peer, RELEASE_RECEIPT_TYP)).toThrow(/typ/);
  });
});
