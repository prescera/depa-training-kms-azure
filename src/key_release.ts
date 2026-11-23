// Copyright (c) Microsoft Corporation.
// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// POST /keys/release — the single atomic key-release check (spec §9.4).
// Private keys are wrapped with RSA-OAEP-SHA256 for the CCR's attested
// wrapping key, as in the DEPA-inferencing KMS KeyWrapper.

import { ccf } from "@microsoft/ccf-app/global";
import {
  ApiError,
  arr,
  b64Encode,
  b64urlDecode,
  bindClaim,
  DATASET_ID_RE,
  endpoint,
  JsonTable,
  jsonBody,
  keys,
  nowSeconds,
  obj,
  pathParam,
  Platform,
  RELEASE_RECEIPT_TYP,
  requireBaseUrl,
  requireBootstrapped,
  serviceSigningKey,
  str,
  toArrayBuffer,
  utf8Encode,
  uuid4,
} from "../packages/depa-ccf-common/src/index";
import { checkDatasetAccess, checkWrappingKey, recordRun, verifyRunAccess } from "./access";
import { privateKeyOf } from "./datasets";

export interface KeyReleaseRecord {
  release_id: string;
  /** null for output-key releases to inference workloads. */
  run_id: string | null;
  contract_id: string;
  dataset_id: string;
  kids: string[];
  measurement_id: string;
  platform: Platform;
  binding_hash: string;
  release: string | null;
  at: number;
}

export const keyReleasesTable = new JsonTable<KeyReleaseRecord>("public:depa.key_releases");

/** RSA-OAEP (SHA-256) wrap of a raw base64url-encoded key for a PEM RSA public key. */
export function wrapRawKey(rawB64url: string, wrappingPem: string): string {
  const wrapped = ccf.crypto.wrapKey(
    toArrayBuffer(b64urlDecode(rawB64url)),
    toArrayBuffer(utf8Encode(wrappingPem)),
    { name: "RSA-OAEP" },
  );
  return b64Encode(new Uint8Array(wrapped));
}

export const releaseKeys = endpoint("keys.release", (request) => {
  requireBootstrapped();
  const body = obj(jsonBody(request), "body");
  keys(body, "body", ["binding", "attestation", "rat", "dataset_id", "wrappingKey"], ["kids"]);
  const now = nowSeconds();
  const datasetId = str(body.dataset_id, "body.dataset_id", { re: DATASET_ID_RE });

  const access = verifyRunAccess(request, body, now); // steps 1, 3, 4, 5 (registry)
  const pem = checkWrappingKey(body.wrappingKey, access.binding); // step 2
  const da = checkDatasetAccess(access, datasetId, now); // steps 5 (tier 3), 6, 7

  const releasable = da.dataset.keys.filter((k) => k.state !== "retired");
  let kids: string[];
  if (body.kids === undefined) {
    kids = releasable.map((k) => k.kid);
  } else {
    kids = arr(body.kids, "body.kids", (x, p) => str(x, p, { max: 200 }), { min: 1, max: 64, unique: true });
    for (const kid of kids) {
      const k = da.dataset.keys.find((x) => x.kid === kid);
      if (!k) throw ApiError.notFound(`key ${kid} not found`);
      if (k.state === "retired") throw ApiError.forbidden(`key ${kid} is retired`, "key_retired");
    }
  }
  if (kids.length === 0) throw ApiError.forbidden("dataset has no releasable keys", "no_keys");

  // Step 8: record the release in the same transaction.
  recordRun(access, da);
  const releaseId = uuid4();
  const iss = requireBaseUrl();
  const receiptClaims = {
    iss,
    release_id: releaseId,
    run_id: access.rat.run_id,
    contract_id: access.rat.contract_id,
    dataset_id: datasetId,
    kids,
    binding_hash: access.binding_hash,
    measurement_id: access.claims.measurement_id,
    platform: access.claims.platform,
    iat: now,
  };
  keyReleasesTable.set(releaseId, {
    release_id: releaseId,
    run_id: access.rat.run_id,
    contract_id: access.rat.contract_id,
    dataset_id: datasetId,
    kids,
    measurement_id: access.claims.measurement_id,
    platform: access.claims.platform,
    binding_hash: access.binding_hash,
    release: access.release?.release_id ?? null,
    at: now,
  });
  bindClaim(receiptClaims);

  const wrapped = kids.map((kid) => ({ kid, wrapped: wrapRawKey(privateKeyOf(kid), pem) }));
  return {
    release_id: releaseId,
    keys: wrapped,
    release_receipt: serviceSigningKey.sign(RELEASE_RECEIPT_TYP, receiptClaims),
  };
});

export const getKeyRelease = endpoint("keys.release_record", (request) => {
  const id = pathParam(request, "release_id");
  const r = keyReleasesTable.get(id);
  if (!r) throw ApiError.notFound(`release ${id} not found`);
  return r;
});
