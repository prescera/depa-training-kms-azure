// Copyright (c) Microsoft Corporation.
// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Azure Confidential Ledger operator identity (spec §3.3). Adapted from the
// DEPA-inferencing KMS proposals endpoint: on ACL the ledger exposes a global
// `acl` module and the role mapping table below; on a plain CCF sandbox the
// CCF-authenticated user certificate identity is the operator.

import * as ccfapp from "@microsoft/ccf-app";
import { ccf } from "@microsoft/ccf-app/global";
import { ApiError } from "./errors";
import { jsonBody } from "./http";

// Provided by the ACL runtime; undefined on plain CCF.
declare const acl: unknown;

const ACL_ROLE_MAPPING_TABLE = "public:confidentialledger.roles.user_roles_mapping";

export function isAcl(): boolean {
  return typeof acl === "object" && acl !== null;
}

/** "12ab34cd…" → "12:AB:34:CD:…" (ACL certificate-user key format). */
function toColonFingerprint(hexId: string): string {
  return (hexId.toUpperCase().match(/.{1,2}/g) ?? []).join(":");
}

function aclRoles(userId: string): string[] {
  const raw = ccf.kv[ACL_ROLE_MAPPING_TABLE].get(ccf.strToBuf(JSON.stringify(userId)));
  if (raw === undefined) return [];
  const roles = ccf.bufToJsonCompatible<unknown>(raw);
  return Array.isArray(roles) ? roles.filter((r): r is string => typeof r === "string") : [];
}

export interface OperatorRequest {
  operator: string;
  body: unknown;
}

/**
 * Authenticates the DC operator for /gov/bootstrap and returns the request
 * body. On ACL the caller must hold the ledger "Administrator" role; on a
 * plain CCF sandbox the caller must be a CCF user (authenticated by CCF).
 */
export function requireOperator(request: ccfapp.Request): OperatorRequest {
  const caller = request.caller;
  if (!caller) throw ApiError.unauthorized("operator authentication required");
  const policy = caller.policy;
  let id: string;
  let body: unknown;
  if (policy === "user_cose_sign1") {
    const c = caller as ccfapp.UserCOSESign1AuthnIdentity;
    id = c.id;
    try {
      body = JSON.parse(ccf.bufToStr(c.cose.content));
    } catch {
      throw ApiError.badRequest("COSE payload is not valid JSON");
    }
  } else if (policy === "user_cert") {
    id = (caller as ccfapp.UserCertAuthnIdentity).id;
    body = jsonBody(request);
  } else if (policy === "jwt" && isAcl()) {
    // ACL Entra ID principals are keyed by object id.
    const payload = (caller as ccfapp.JwtAuthnIdentity).jwt.payload;
    if (typeof payload?.oid !== "string" || typeof payload?.tid !== "string") {
      throw ApiError.unauthorized("operator token must be an Entra ID token with oid/tid");
    }
    id = payload.oid;
    body = jsonBody(request);
  } else {
    throw ApiError.unauthorized(`authentication policy ${String(policy)} is not accepted for operator calls`);
  }
  if (isAcl()) {
    const key = policy === "jwt" ? id : toColonFingerprint(id);
    if (!aclRoles(key).includes("Administrator")) {
      throw ApiError.forbidden("caller does not hold the ACL Administrator role");
    }
    return { operator: key, body };
  }
  return { operator: id, body };
}
