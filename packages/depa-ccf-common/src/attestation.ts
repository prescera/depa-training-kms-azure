// Copyright (c) Microsoft Corporation.
// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Attestation verification and normalization (spec §9.2), identical in the
// KMS and the CS. SNP verification uses CCF's snp_attestation module as in the
// DEPA-inferencing KMS; GCP Confidential Space tokens are authenticated by the
// CCF "jwt" authentication policy (issuer registered at ledger level) and the
// platform rules are enforced here.

import * as ccfapp from "@microsoft/ccf-app";
import { snp_attestation, SnpAttestationResult } from "@microsoft/ccf-app/global";
import { ApiError } from "./errors";
import { b64Decode, constantTimeEqual, hexEncode, toArrayBuffer } from "./encoding";
import { AttestedClaims, Platform, PLATFORMS } from "./platforms";
import { CommonSettings, enforceJwtValidationPolicy } from "./settings";
import { HEX64_RE, isObject, keys, obj, oneOf, optStr, str } from "./validate";

export const GCA_ISSUER = "https://confidentialcomputing.googleapis.com";
const CLOCK_SKEW_S = 60;

export interface AttestationEnvelope {
  platform: Platform;
  evidence?: string;
  endorsements?: string;
  uvm_endorsements?: string;
  endorsed_tcb?: string;
  binding_hash?: string;
  virtual_id?: string;
}

function attestationError(message: string): ApiError {
  return new ApiError(401, "attestation_invalid", message);
}

export function parseEnvelope(v: unknown, path = "attestation"): AttestationEnvelope {
  const o = obj(v, path);
  const platform = oneOf(o.platform, `${path}.platform`, PLATFORMS);
  if (platform === "aci-snp") {
    keys(o, path, ["platform", "evidence", "endorsements", "uvm_endorsements"], ["endorsed_tcb"]);
    return {
      platform,
      evidence: str(o.evidence, `${path}.evidence`, { max: 65536 }),
      endorsements: str(o.endorsements, `${path}.endorsements`, { max: 262144 }),
      uvm_endorsements: str(o.uvm_endorsements, `${path}.uvm_endorsements`, { max: 262144 }),
      endorsed_tcb: optStr(o.endorsed_tcb, `${path}.endorsed_tcb`, { re: /^[0-9a-fA-F]{16}$/ }),
    };
  }
  if (platform === "gcp-cs-tdx") {
    keys(o, path, ["platform"]);
    return { platform };
  }
  keys(o, path, ["platform", "binding_hash", "virtual_id"]);
  return {
    platform,
    binding_hash: str(o.binding_hash, `${path}.binding_hash`, { re: HEX64_RE }),
    virtual_id: str(o.virtual_id, `${path}.virtual_id`, { re: /^[a-z0-9][a-z0-9._-]{0,63}$/ }),
  };
}

/** Checks a verified SNP report against the expected binding (pure). */
export function checkSnpReport(report: SnpAttestationResult, expectedBindingHash: string): AttestedClaims {
  const a = report.attestation;
  const reportData = new Uint8Array(a.report_data);
  if (reportData.length !== 64) throw attestationError("SNP report_data must be 64 bytes");
  const bound = hexEncode(reportData.subarray(0, 32));
  if (!constantTimeEqual(bound, expectedBindingHash)) {
    throw attestationError("SNP REPORT_DATA[0..32] does not match the binding hash");
  }
  for (let i = 32; i < 64; i++) {
    if (reportData[i] !== 0) throw attestationError("SNP REPORT_DATA[32..64] must be zero");
  }
  if (a.policy.debug !== 0) throw attestationError("SNP guest policy allows debugging");
  const uvm = report.uvm_endorsements;
  if (!uvm || typeof uvm.did !== "string" || typeof uvm.feed !== "string" || typeof uvm.svn !== "string") {
    throw attestationError("SNP UVM endorsements are required");
  }
  const hostData = hexEncode(new Uint8Array(a.host_data));
  return {
    platform: "aci-snp",
    measurement_id: hostData,
    binding_hash: bound,
    debug: false,
    uvm: { did: uvm.did, feed: uvm.feed, svn: uvm.svn },
    raw: {
      host_data: hostData,
      measurement: hexEncode(new Uint8Array(a.measurement)),
      report_data: hexEncode(reportData),
      guest_svn: a.guest_svn,
      reported_tcb: a.reported_tcb,
      uvm_endorsements: { did: uvm.did, feed: uvm.feed, svn: uvm.svn },
    },
  };
}

/**
 * Checks Google Cloud Attestation token claims (pure). `caller` is the CCF
 * authentication identity; only a CCF-validated JWT from the GCA issuer is
 * accepted.
 */
export function checkGcaCaller(
  caller: ccfapp.AuthnIdentity | undefined,
  expectedBindingHash: string,
  expectedAudience: string | null,
  now: number,
): AttestedClaims {
  if (!caller || caller.policy !== "jwt") {
    throw attestationError("gcp-cs-tdx requires a Google Cloud Attestation token (Authorization: Bearer)");
  }
  const jwt = (caller as ccfapp.JwtAuthnIdentity).jwt;
  const p = jwt?.payload;
  if (!isObject(p)) throw attestationError("attestation token payload missing");
  if (jwt.keyIssuer !== GCA_ISSUER || p.iss !== GCA_ISSUER) {
    throw attestationError("attestation token was not issued by Google Cloud Attestation");
  }
  if (!expectedAudience) throw new ApiError(409, "not_configured", "settings.base_url is not configured");
  const aud = p.aud;
  const audOk = typeof aud === "string" ? aud === expectedAudience : Array.isArray(aud) && aud.includes(expectedAudience);
  if (!audOk) throw attestationError("attestation token audience does not match this service");
  if (typeof p.exp !== "number" || p.exp <= now) throw attestationError("attestation token expired");
  if (typeof p.nbf === "number" && p.nbf > now + CLOCK_SKEW_S) throw attestationError("attestation token not yet valid");
  if (p.hwmodel !== "GCP_INTEL_TDX") throw attestationError("attestation token hwmodel must be GCP_INTEL_TDX");
  if (p.swname !== "CONFIDENTIAL_SPACE") throw attestationError("attestation token swname must be CONFIDENTIAL_SPACE");
  if (p.dbgstat !== "disabled-since-boot") throw attestationError("attestation token dbgstat must be disabled-since-boot");
  if (p.secboot !== true) throw attestationError("attestation token requires secure boot");
  const nonces = typeof p.eat_nonce === "string" ? [p.eat_nonce] : Array.isArray(p.eat_nonce) ? p.eat_nonce : [];
  if (!nonces.some((n) => typeof n === "string" && constantTimeEqual(n.toLowerCase(), expectedBindingHash))) {
    throw attestationError("attestation token eat_nonce does not contain the binding hash");
  }
  const submods = isObject(p.submods) ? p.submods : {};
  const container = isObject(submods.container) ? submods.container : {};
  const cs = isObject(submods.confidential_space) ? submods.confidential_space : {};
  const imageDigest = container.image_digest;
  if (typeof imageDigest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(imageDigest)) {
    throw attestationError("attestation token lacks submods.container.image_digest");
  }
  const attrs = Array.isArray(cs.support_attributes)
    ? cs.support_attributes.filter((x): x is string => typeof x === "string")
    : [];
  return {
    platform: "gcp-cs-tdx",
    measurement_id: imageDigest,
    binding_hash: expectedBindingHash,
    debug: false,
    support_attributes: attrs,
    raw: {
      iss: p.iss,
      sub: p.sub,
      swversion: p.swversion,
      image_reference: container.image_reference,
      image_digest: imageDigest,
      support_attributes: attrs,
      gce: submods.gce,
    },
  };
}

/** Checks a development-only virtual attestation (pure). */
export function checkVirtual(
  env: AttestationEnvelope,
  expectedBindingHash: string,
  settings: CommonSettings,
): AttestedClaims {
  if (settings.allow_virtual_attestation !== true) {
    throw attestationError("virtual attestation is disabled (settings.allow_virtual_attestation)");
  }
  if (!constantTimeEqual(env.binding_hash as string, expectedBindingHash)) {
    throw attestationError("virtual attestation binding_hash does not match the binding");
  }
  return {
    platform: "virtual",
    measurement_id: env.virtual_id as string,
    binding_hash: expectedBindingHash,
    debug: true,
    raw: { virtual_id: env.virtual_id },
  };
}

/**
 * Verifies an attestation envelope and that it proves `expectedBindingHash`
 * (hex SHA-256 of JCS(binding)). Throws 401 attestation_invalid on failure.
 */
export function verifyAttestation(
  envelopeValue: unknown,
  expectedBindingHash: string,
  request: ccfapp.Request,
  settings: CommonSettings,
  now: number,
): AttestedClaims {
  const env = parseEnvelope(envelopeValue);
  if (env.platform === "aci-snp") {
    let report: SnpAttestationResult;
    try {
      report = snp_attestation.verifySnpAttestation(
        toArrayBuffer(b64Decode(env.evidence as string, "attestation.evidence")),
        toArrayBuffer(b64Decode(env.endorsements as string, "attestation.endorsements")),
        toArrayBuffer(b64Decode(env.uvm_endorsements as string, "attestation.uvm_endorsements")),
        env.endorsed_tcb,
      );
    } catch (e) {
      if (e instanceof ApiError) throw e;
      throw attestationError(`SNP attestation verification failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    return checkSnpReport(report, expectedBindingHash);
  }
  if (env.platform === "gcp-cs-tdx") {
    const claims = checkGcaCaller(request.caller, expectedBindingHash, settings.base_url, now);
    enforceJwtValidationPolicy(GCA_ISSUER, (request.caller as ccfapp.JwtAuthnIdentity).jwt.payload);
    return claims;
  }
  return checkVirtual(env, expectedBindingHash, settings);
}
