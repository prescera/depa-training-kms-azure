// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Per-contract output keys for output mode "tee-only" (spec §11).
//
//  - POST /outputs/{contract_id}/key: an attested, RAT-authorized CCR of that
//    contract obtains (creating on first use) the contract's X25519 public key.
//  - POST /outputs/{contract_id}/release: the private key is released only to
//    an attested workload whose measurement belongs to an approved,
//    non-revoked release with family "inference" (DEPA-inferencing
//    integration point). It is never released to a party.
//
// The release request carries an output-release binding (not defined by the
// protocol spec, see README):
//   {"v":1,"purpose":"depa-output-release","contract_id","platform",
//    "wrapping_key_sha256","nonce"}
// whose SHA-256(JCS) must be proven by the attestation, exactly like a run
// binding.

import {
  ApiError,
  bindClaim,
  bindingHashHex,
  endpoint,
  formatRfc3339,
  getSettings,
  HEX64_RE,
  JsonTable,
  jsonBody,
  keys,
  matchingApprovedReleases,
  nowSeconds,
  obj,
  oneOf,
  pathParam,
  PLATFORMS,
  RELEASE_RECEIPT_TYP,
  requireBaseUrl,
  requireBootstrapped,
  serviceSigningKey,
  str,
  UUID4_RE,
  uuid4,
  verifyAttestation,
} from "../packages/depa-ccf-common/src/index";
import { checkWrappingKey, verifyRunAccess } from "./access";
import { generateX25519, privateKeyOf, X25519PrivateKey } from "./datasets";
import { keyReleasesTable, wrapRawKey } from "./key_release";

interface OutputKeyRecord {
  contract_id: string;
  kid: string;
  x25519: string;
  created_at: string;
  created_for_run: string;
}

const outputKeysTable = new JsonTable<OutputKeyRecord>("public:depa.output_keys");
const outputPrivateKeys = new JsonTable<X25519PrivateKey>("depa.private.output_keys");

function contractIdFromPath(request: Parameters<typeof pathParam>[0]): string {
  const id = pathParam(request, "contract_id");
  if (!UUID4_RE.test(id)) throw ApiError.badRequest("invalid contract_id");
  return id;
}

function keyView(k: OutputKeyRecord): Record<string, unknown> {
  return { contract_id: k.contract_id, kid: k.kid, x25519: k.x25519, recipient: `kms:${k.kid}`, created_at: k.created_at };
}

export const getOrCreateOutputKey = endpoint("outputs.key", (request) => {
  requireBootstrapped();
  const contractId = contractIdFromPath(request);
  const body = obj(jsonBody(request), "body");
  keys(body, "body", ["binding", "attestation", "rat"]);
  const now = nowSeconds();
  const access = verifyRunAccess(request, body, now);
  if (access.rat.contract_id !== contractId) throw ApiError.forbidden("RAT is for a different contract", "rat_mismatch");
  if (access.rat.output.mode !== "tee-only") throw ApiError.forbidden("contract output mode is not tee-only", "output_mode");
  const existing = outputKeysTable.get(contractId);
  if (existing) return keyView(existing);
  const kid = `output:${contractId}#1`;
  const record: OutputKeyRecord = {
    contract_id: contractId,
    kid,
    x25519: generateX25519(kid, outputPrivateKeys),
    created_at: formatRfc3339(now),
    created_for_run: access.rat.run_id,
  };
  outputKeysTable.set(contractId, record);
  return keyView(record);
});

export const releaseOutputKey = endpoint("outputs.release", (request) => {
  requireBootstrapped();
  const contractId = contractIdFromPath(request);
  const body = obj(jsonBody(request), "body");
  keys(body, "body", ["binding", "attestation", "wrappingKey"]);
  const b = obj(body.binding, "body.binding");
  keys(b, "body.binding", ["v", "purpose", "contract_id", "platform", "wrapping_key_sha256", "nonce"]);
  oneOf(b.v, "body.binding.v", [1] as const);
  oneOf(b.purpose, "body.binding.purpose", ["depa-output-release"] as const);
  if (b.contract_id !== contractId) throw ApiError.badRequest("binding.contract_id must equal the path contract_id", "invalid_input");
  const platform = oneOf(b.platform, "body.binding.platform", PLATFORMS);
  const wrappingKeySha256 = str(b.wrapping_key_sha256, "body.binding.wrapping_key_sha256", { re: HEX64_RE });
  str(b.nonce, "body.binding.nonce", { re: /^[A-Za-z0-9_-]{16,128}$/ });
  const bindingHash = bindingHashHex(b);
  const now = nowSeconds();
  const claims = verifyAttestation(body.attestation, bindingHash, request, getSettings(), now);
  if (claims.platform !== platform) throw ApiError.forbidden("attested platform does not match binding.platform", "platform_mismatch");
  const pem = checkWrappingKey(body.wrappingKey, { wrapping_key_sha256: wrappingKeySha256 });
  const release = matchingApprovedReleases(claims).find((r) => r.families.includes("inference"));
  if (!release) throw ApiError.forbidden("measurement is not in an approved inference release", "measurement_not_approved");
  const key = outputKeysTable.get(contractId);
  if (!key) throw ApiError.notFound(`no output key for contract ${contractId}`);

  const releaseId = uuid4();
  const receiptClaims = {
    iss: requireBaseUrl(),
    release_id: releaseId,
    contract_id: contractId,
    kids: [key.kid],
    binding_hash: bindingHash,
    measurement_id: claims.measurement_id,
    platform: claims.platform,
    iat: now,
  };
  keyReleasesTable.set(releaseId, {
    release_id: releaseId,
    run_id: null,
    contract_id: contractId,
    dataset_id: `output:${contractId}`,
    kids: [key.kid],
    measurement_id: claims.measurement_id,
    platform: claims.platform,
    binding_hash: bindingHash,
    release: release.release_id,
    at: now,
  });
  bindClaim(receiptClaims);
  return {
    release_id: releaseId,
    keys: [{ kid: key.kid, wrapped: wrapRawKey(privateKeyOf(key.kid, outputPrivateKeys), pem) }],
    release_receipt: serviceSigningKey.sign(RELEASE_RECEIPT_TYP, receiptClaims),
  };
});
