// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.

import { beforeEach, describe, expect, it } from "@jest/globals";
import { readFileSync } from "fs";
import { join } from "path";
import { SnpAttestationResult } from "@microsoft/ccf-app/global";
import { checkGcaCaller, checkSnpReport, checkVirtual, GCA_ISSUER, parseEnvelope } from "../src/attestation";
import { approveRelease, CcrRelease, checkReleaseApprovable, releaseMatchesClaims, revokeRelease, validateRelease } from "../src/releases";
import { AttestedClaims } from "../src/platforms";
import { resetKv } from "./helpers";

beforeEach(resetKv);

// Recorded ACI SEV-SNP attestation (DEPA-inferencing KMS test sample, MIT).
// verifySnpAttestation itself runs only inside CCF (see the integration
// tests); here the verified report structure is rebuilt from the raw report
// bytes (AMD SEV-SNP ABI, ATTESTATION_REPORT layout) to test our claim checks.
const fixture = JSON.parse(readFileSync(join(process.cwd(), "packages/depa-ccf-common/test/fixtures/snp-aci.json"), "utf-8"));
const report = Buffer.from(fixture.evidence, "base64");
const UVM = { did: "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2", feed: "ContainerPlat-AMD-UVM", svn: "101" };

function snpResult(overrides: { reportData?: Buffer; debug?: number; uvm?: unknown } = {}): SnpAttestationResult {
  const ab = (b: Buffer) => b.buffer.slice(b.byteOffset, b.byteOffset + b.length) as ArrayBuffer;
  const policy = report.readBigUInt64LE(0x08);
  return {
    attestation: {
      guest_svn: report.readUInt32LE(0x04),
      policy: { debug: overrides.debug ?? Number((policy >> 19n) & 1n) },
      report_data: ab(overrides.reportData ?? report.subarray(0x50, 0x90)),
      measurement: ab(report.subarray(0x90, 0xc0)),
      host_data: ab(report.subarray(0xc0, 0xe0)),
      reported_tcb: {},
    },
    uvm_endorsements: overrides.uvm === undefined ? UVM : overrides.uvm,
  } as unknown as SnpAttestationResult;
}

const fixtureBinding = report.subarray(0x50, 0x70).toString("hex");
const hostData = report.subarray(0xc0, 0xe0).toString("hex");

describe("aci-snp claim checks", () => {
  it("normalizes a verified report", () => {
    const claims = checkSnpReport(snpResult({ reportData: Buffer.concat([report.subarray(0x50, 0x70), Buffer.alloc(32)]) }), fixtureBinding);
    expect(claims).toMatchObject({ platform: "aci-snp", measurement_id: hostData, binding_hash: fixtureBinding, debug: false, uvm: UVM });
  });

  it("rejects a report_data that does not carry the binding", () => {
    expect(() => checkSnpReport(snpResult(), "00".repeat(32))).toThrow(/REPORT_DATA\[0..32\]/);
  });

  it("requires REPORT_DATA[32..64] to be zero", () => {
    const rd = Buffer.alloc(64, 1);
    expect(() => checkSnpReport(snpResult({ reportData: rd }), "01".repeat(32))).toThrow(/must be zero/);
  });

  it("rejects debuggable guests and missing UVM endorsements", () => {
    const rd = Buffer.concat([Buffer.alloc(32, 2), Buffer.alloc(32)]);
    expect(() => checkSnpReport(snpResult({ reportData: rd, debug: 1 }), "02".repeat(32))).toThrow(/debug/);
    expect(() => checkSnpReport(snpResult({ reportData: rd, uvm: null }), "02".repeat(32))).toThrow(/UVM/);
  });
});

function gcaCaller(overrides: Record<string, unknown> = {}, keyIssuer = GCA_ISSUER) {
  const payload: Record<string, unknown> = {
    iss: GCA_ISSUER,
    aud: "https://cs.example/app",
    exp: 2000,
    nbf: 900,
    hwmodel: "GCP_INTEL_TDX",
    swname: "CONFIDENTIAL_SPACE",
    dbgstat: "disabled-since-boot",
    secboot: true,
    eat_nonce: ["aa".repeat(32)],
    submods: { container: { image_digest: "sha256:" + "ab".repeat(32) }, confidential_space: { support_attributes: ["STABLE", "USABLE"] } },
    ...overrides,
  };
  return { policy: "jwt", jwt: { keyIssuer, header: {}, payload } } as never;
}

describe("gcp-cs-tdx claim checks", () => {
  const ok = (c: unknown) => checkGcaCaller(c as never, "aa".repeat(32), "https://cs.example/app", 1000);

  it("normalizes a valid token", () => {
    expect(ok(gcaCaller())).toMatchObject({ platform: "gcp-cs-tdx", measurement_id: "sha256:" + "ab".repeat(32), support_attributes: ["STABLE", "USABLE"] });
    expect(ok(gcaCaller({ eat_nonce: "AA".repeat(32) })).binding_hash).toBe("aa".repeat(32));
  });

  it.each([
    ["no jwt caller", { policy: "no_auth" }],
    ["other key issuer", gcaCaller({}, "https://login.microsoftonline.com/x/v2.0")],
    ["other iss", gcaCaller({ iss: "https://evil" })],
    ["wrong audience", gcaCaller({ aud: "https://kms.example/app" })],
    ["expired", gcaCaller({ exp: 999 })],
    ["not yet valid", gcaCaller({ nbf: 1100 })],
    ["hwmodel", gcaCaller({ hwmodel: "GCP_AMD_SEV" })],
    ["swname", gcaCaller({ swname: "GCE" })],
    ["debug", gcaCaller({ dbgstat: "enabled" })],
    ["secure boot off", gcaCaller({ secboot: false })],
    ["nonce", gcaCaller({ eat_nonce: ["bb".repeat(32)] })],
    ["no image digest", gcaCaller({ submods: {} })],
  ])("rejects %s", (_n, caller) => {
    expect(() => ok(caller)).toThrow();
  });

  it("fails closed without a configured base_url", () => {
    expect(() => checkGcaCaller(gcaCaller(), "aa".repeat(32), null, 1000)).toThrow(/base_url/);
  });
});

describe("virtual attestation", () => {
  const env = parseEnvelope({ platform: "virtual", binding_hash: "cc".repeat(32), virtual_id: "virtual-dev" });
  it("is accepted only when enabled and bound", () => {
    expect(checkVirtual(env, "cc".repeat(32), { allow_virtual_attestation: true, base_url: null, trust_bundle_digest: null }).measurement_id).toBe("virtual-dev");
    expect(() => checkVirtual(env, "cc".repeat(32), { allow_virtual_attestation: false, base_url: null, trust_bundle_digest: null })).toThrow(/disabled/);
    expect(() => checkVirtual(env, "dd".repeat(32), { allow_virtual_attestation: true, base_url: null, trust_bundle_digest: null })).toThrow(/binding/);
  });
  it("rejects malformed envelopes", () => {
    expect(() => parseEnvelope({ platform: "sgx" })).toThrow();
    expect(() => parseEnvelope({ platform: "virtual", binding_hash: "zz", virtual_id: "v" })).toThrow();
    expect(() => parseEnvelope({ platform: "gcp-cs-tdx", token: "x" })).toThrow();
    expect(() => parseEnvelope({ platform: "aci-snp", evidence: "x" })).toThrow();
  });
});

describe("release registry", () => {
  const aci: CcrRelease = validateRelease({
    release_id: "depa-ccr-torch-2.0.0-aci",
    platform: "aci-snp",
    families: ["torch"],
    tiers: [1, 2],
    measurements: { host_data: [hostData], uvm: { did: UVM.did, feed: UVM.feed, min_svn: "100" } },
    provenance: { source: "https://github.com/iSPIRT/depa-training" },
  });
  const aciClaims: AttestedClaims = { platform: "aci-snp", measurement_id: hostData, binding_hash: "", debug: false, uvm: UVM, raw: {} };

  it("matches aci-snp on host_data, UVM did/feed and svn >= min_svn", () => {
    expect(releaseMatchesClaims(aci, aciClaims)).toBe(true);
    expect(releaseMatchesClaims(aci, { ...aciClaims, measurement_id: "00".repeat(32) })).toBe(false);
    expect(releaseMatchesClaims(aci, { ...aciClaims, uvm: { ...UVM, svn: "99" } })).toBe(false);
    expect(releaseMatchesClaims(aci, { ...aciClaims, uvm: { ...UVM, feed: "other" } })).toBe(false);
    expect(releaseMatchesClaims(aci, { ...aciClaims, uvm: { ...UVM, did: "did:x509:other" } })).toBe(false);
    expect(releaseMatchesClaims(aci, { ...aciClaims, debug: true })).toBe(false);
    expect(releaseMatchesClaims(aci, { ...aciClaims, platform: "virtual" })).toBe(false);
  });

  it("matches gcp-cs-tdx on image digest and required support attributes", () => {
    const gcp = validateRelease({
      release_id: "r-gcp",
      platform: "gcp-cs-tdx",
      families: ["classic"],
      tiers: [1],
      measurements: { image_digests: ["sha256:" + "ab".repeat(32)], support_attributes: ["STABLE"], require_debug_disabled: true },
      provenance: {},
    });
    const claims: AttestedClaims = { platform: "gcp-cs-tdx", measurement_id: "sha256:" + "ab".repeat(32), binding_hash: "", debug: false, support_attributes: ["STABLE", "LATEST"], raw: {} };
    expect(releaseMatchesClaims(gcp, claims)).toBe(true);
    expect(releaseMatchesClaims(gcp, { ...claims, support_attributes: ["USABLE"] })).toBe(false);
    expect(releaseMatchesClaims(gcp, { ...claims, measurement_id: "sha256:" + "cd".repeat(32) })).toBe(false);
  });

  it("validates per-platform measurement schemas", () => {
    expect(() => validateRelease({ ...aci, tiers: [3] })).toThrow();
    expect(() => validateRelease({ ...aci, measurements: { virtual_ids: ["v"] } })).toThrow();
    expect(() => validateRelease({ ...aci, platform: "gcp-cs-tdx", measurements: { image_digests: ["sha256:" + "ab".repeat(32)], require_debug_disabled: false } })).toThrow();
    expect(() => validateRelease({ ...aci, release_id: "Bad ID" })).toThrow();
  });

  it("makes release ids immutable and revocation permanent", () => {
    approveRelease(aci, "p1");
    expect(() => checkReleaseApprovable(aci)).not.toThrow(); // identical: no-op
    const changed = { ...aci, measurements: { ...aci.measurements, host_data: ["11".repeat(32)] } } as CcrRelease;
    expect(() => checkReleaseApprovable(changed)).toThrow(/immutable/);
    revokeRelease(aci.release_id, "p2");
    expect(() => checkReleaseApprovable(aci)).toThrow(/never be re-approved/);
  });
});
