// Copyright (c) Microsoft Corporation.
// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Endpoints common to both services: GET /info (spec §5) and
// GET /receipt?transaction_id= (ledger inclusion proof via CCF historical
// queries, as in the DEPA-inferencing KMS key store).

import * as ccfapp from "@microsoft/ccf-app";
import { ccf } from "@microsoft/ccf-app/global";
import { ApiError } from "./errors";
import { toArrayBuffer } from "./encoding";
import { isBootstrapped, ServiceDescriptor } from "./governance";
import { endpoint, queryParam, Reply } from "./http";
import { jcsHash } from "./jcs";
import { serviceSigningKey } from "./service_keys";
import { approvedDigestTable } from "./settings";

const HISTORICAL_CACHE_S = 1800;

export function makeInfoEndpoint(svc: ServiceDescriptor, extra: () => Record<string, unknown> = () => ({})): ccfapp.EndpointFn {
  return endpoint("info", () => ({
    service: svc.name,
    version: svc.version,
    bundle_digest: svc.bundleDigest,
    bundle_digest_approved: approvedDigestTable.has(svc.bundleDigest),
    bootstrapped: isBootstrapped(),
    jwks: serviceSigningKey.jwks(),
    ...extra(),
  }));
}

/**
 * Binds a claim to the current transaction so that its CCF receipt proves the
 * claim (receipt.leaf_components.claims_digest = SHA-256(JCS(claim))).
 */
export function bindClaim(claim: unknown): void {
  ccf.rpc.setClaimsDigest(toArrayBuffer(jcsHash(claim)));
}

export const receiptEndpoint = endpoint("receipt", (request) => {
  const txid = queryParam(request, "transaction_id");
  const m = txid === undefined ? null : /^(\d{1,15})\.(\d{1,15})$/.exec(txid);
  if (!m) throw ApiError.badRequest('transaction_id must be "<view>.<seqno>"');
  const view = parseInt(m[1], 10);
  const seqno = parseInt(m[2], 10);
  const status = ccf.consensus.getStatusForTxId(view, seqno);
  if (status === "Pending" || status === "Unknown") {
    return new Reply({ transaction_id: txid, status }, 202, { "retry-after": "1" });
  }
  if (status !== "Committed") throw ApiError.notFound(`transaction ${txid} is ${status}`);
  const states = ccf.historical.getStateRange(seqno, seqno, seqno, HISTORICAL_CACHE_S);
  if (states === null) {
    return new Reply({ transaction_id: txid, status: "Fetching" }, 202, { "retry-after": "1" });
  }
  return { transaction_id: states[0].transactionId, receipt: states[0].receipt };
});
