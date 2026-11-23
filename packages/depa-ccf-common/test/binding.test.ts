// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.

import { beforeEach, describe, expect, it } from "@jest/globals";
import { randomUUID } from "crypto";
import { bindingHashHex, checkTrustBundle, validateRunBinding } from "../src/binding";
import { digest } from "../src/jcs";
import { CommonSettings } from "../src/settings";
import { consumeFreshJti } from "../src/signed_request";
import { DATASET_ID_RE } from "../src/validate";
import { resetKv, TestParty } from "./helpers";

beforeEach(resetKv);

const bundle = { v: 1, cs: { url: "https://cs/app", service_cert_pem: "c", jwks: [] }, kms: { url: "https://kms/app", service_cert_pem: "k", jwks: [] } };
const TB = digest(bundle);
const settings = (tb: string | null): CommonSettings => ({ allow_virtual_attestation: true, base_url: null, trust_bundle_digest: tb });

function binding(platform: string, tb = TB): Record<string, unknown> {
  const { kid: _kid, ...runKey } = new TestParty("ccr", ["tdc"]).jwk;
  return {
    v: 1,
    contract_id: randomUUID(),
    contract_digest: "sha256:" + "1".repeat(64),
    run_id: randomUUID(),
    recipe_digest: "sha256:" + "2".repeat(64),
    platform,
    wrapping_key_sha256: "ab".repeat(32),
    run_key: runKey,
    trust_bundle_digest: tb,
  };
}

describe("run binding", () => {
  it("hashes the binding as supplied and requires trust_bundle_digest", () => {
    const b = binding("aci-snp");
    expect(validateRunBinding(b).binding_hash).toBe(bindingHashHex(b));
    const { trust_bundle_digest: _t, ...without } = b;
    expect(() => validateRunBinding(without)).toThrow(/trust_bundle_digest/);
    expect(() => validateRunBinding({ ...b, trust_bundle_digest: "sha256:xyz" })).toThrow();
    expect(() => validateRunBinding({ ...b, extra: 1 })).toThrow(/unknown member/);
  });
});

describe("trust bundle check (spec §9.1)", () => {
  it.each(["aci-snp", "gcp-cs-tdx"])("%s: requires the setting and an exact match", (platform) => {
    const ok = validateRunBinding(binding(platform)).binding;
    expect(() => checkTrustBundle(ok, settings(TB))).not.toThrow();
    expect(() => checkTrustBundle(ok, settings(null))).toThrow(/not configured/);
    const bad = validateRunBinding(binding(platform, "sha256:" + "9".repeat(64))).binding;
    expect(() => checkTrustBundle(bad, settings(TB))).toThrow(/does not match/);
  });

  it("virtual: checked only when the setting is set", () => {
    const bad = validateRunBinding(binding("virtual", "sha256:" + "9".repeat(64))).binding;
    expect(() => checkTrustBundle(bad, settings(null))).not.toThrow();
    expect(() => checkTrustBundle(bad, settings(TB))).toThrow(/does not match/);
  });
});

describe("freshness and replay (spec §3.2, reused by RAT refresh)", () => {
  it("accepts a fresh jti once and rejects stale or malformed values", () => {
    const now = Math.floor(Date.now() / 1000);
    const jti = randomUUID();
    consumeFreshJti(now, jti);
    expect(() => consumeFreshJti(now, jti)).toThrow(/replayed/);
    expect(() => consumeFreshJti(now - 301, randomUUID())).toThrow(/iat window/);
    expect(() => consumeFreshJti("now", randomUUID())).toThrow(/integer/);
    expect(() => consumeFreshJti(now, "not-a-uuid")).toThrow(/UUID/);
  });
});

describe("dataset id bounds (spec §7.1)", () => {
  it("limits the name to 55 characters so dataset:<id> fits GCP's 127-byte subject", () => {
    const owner = "a" + "b".repeat(62); // longest party id (63)
    const longest = `${owner}/${"n".repeat(55)}`;
    expect(DATASET_ID_RE.test(longest)).toBe(true);
    expect(Buffer.byteLength(`dataset:${longest}`)).toBe(127);
    expect(DATASET_ID_RE.test(`${owner}/${"n".repeat(56)}`)).toBe(false);
    expect(DATASET_ID_RE.test("bank-a/credit-applications")).toBe(true);
    expect(DATASET_ID_RE.test("bank-a/.hidden")).toBe(false);
    expect(DATASET_ID_RE.test("bank-a/a/b")).toBe(false);
  });
});
