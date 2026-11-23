// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// KMS as OIDC issuer for storage federation (spec §10).
//
// Signing algorithm: ES256. CCF 6.0's ccf.crypto.sign supports RSA-PSS,
// ECDSA, EdDSA and HMAC only (RSASSA-PKCS1-v1_5 is rejected by the runtime),
// so RS256 cannot be produced without a hand-written RSA implementation
// (rejected: not constant-time inside the enclave). See README for cloud
// compatibility of ES256-signed federation tokens.

import {
  ActionHandler,
  ApiError,
  arr,
  bindClaim,
  DATASET_ID_RE,
  endpoint,
  HTTPS_URL_RE,
  int,
  JsonTable,
  jsonBody,
  keys,
  nowSeconds,
  obj,
  requireBootstrapped,
  SigningKeyStore,
  str,
  uuid4,
} from "../packages/depa-ccf-common/src/index";
import { checkDatasetAccess, verifyRunAccess } from "./access";
import { checkDatasetAudience } from "./policy";

export interface OidcSettings {
  issuer_url: string;
  token_ttl_s: number;
  allowed_audiences_global: string[];
}

export const OIDC_ALG = "ES256";
export const MAX_TOKEN_TTL_S = 900;
export const oidcSigningKey = new SigningKeyStore("oidc_signing_key");
const oidcSettingsTable = new JsonTable<OidcSettings>("public:depa.oidc_settings");

/** Audit log of issued federation tokens (never the token itself). */
interface IssuedToken {
  jti: string;
  sub: string;
  aud: string;
  contract_id: string;
  run_id: string;
  iat: number;
  exp: number;
}
const issuedTokensTable = new JsonTable<IssuedToken>("public:depa.oidc_issued_tokens");

export function getOidcSettings(): OidcSettings | undefined {
  return oidcSettingsTable.get("settings");
}

function requireOidcSettings(): OidcSettings {
  const s = getOidcSettings();
  if (!s) throw ApiError.conflict("OIDC issuer is not configured (set_oidc_settings)", "not_configured");
  return s;
}

export const oidcGovernanceActions: Array<ActionHandler<OidcSettings>> = [
  {
    name: "set_oidc_settings",
    validate: (args) => {
      const o = obj(args, "args");
      keys(o, "args", ["issuer_url", "token_ttl_s", "allowed_audiences_global"]);
      const issuer_url = str(o.issuer_url, "args.issuer_url", { re: HTTPS_URL_RE, max: 512 });
      if (issuer_url.endsWith("/")) throw ApiError.badRequest("args.issuer_url: must not end with /", "invalid_input");
      return {
        issuer_url,
        token_ttl_s: int(o.token_ttl_s, "args.token_ttl_s", { min: 60, max: MAX_TOKEN_TTL_S }),
        allowed_audiences_global: arr(o.allowed_audiences_global, "args.allowed_audiences_global", (x, p) => str(x, p, { max: 512 }), {
          max: 32,
          unique: true,
        }),
      };
    },
    apply: (s) => oidcSettingsTable.set("settings", s),
  },
];

export const openidConfiguration = endpoint("oidc.configuration", () => {
  const s = requireOidcSettings();
  return {
    issuer: s.issuer_url,
    jwks_uri: `${s.issuer_url}/jwks`,
    response_types_supported: ["id_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: [OIDC_ALG],
    claims_supported: ["iss", "sub", "aud", "iat", "nbf", "exp", "jti", "contract_id", "run_id", "platform", "measurement_id"],
  };
});

export const oidcJwks = endpoint("oidc.jwks", () => ({ keys: oidcSigningKey.jwks() }));

export const issueToken = endpoint("oidc.token", (request) => {
  requireBootstrapped();
  const settings = requireOidcSettings();
  const body = obj(jsonBody(request), "body");
  keys(body, "body", ["binding", "attestation", "rat", "resource", "audience"]);
  const audience = str(body.audience, "body.audience", { max: 512 });
  const resource = obj(body.resource, "body.resource");
  const now = nowSeconds();
  const access = verifyRunAccess(request, body, now); // steps 1, 3, 4, 5 (registry)

  let sub: string;
  if (resource.output !== undefined) {
    keys(resource, "body.resource", ["output"]);
    if (resource.output !== true) throw ApiError.badRequest("body.resource.output must be true", "invalid_input");
    if (!settings.allowed_audiences_global.includes(audience)) {
      throw ApiError.forbidden(`audience ${audience} not allowed for outputs`, "audience_denied");
    }
    sub = `output:${access.rat.tdc}`;
  } else {
    keys(resource, "body.resource", ["dataset_id"]);
    const datasetId = str(resource.dataset_id, "body.resource.dataset_id", { re: DATASET_ID_RE });
    // Steps 5 (tier 3), 6 and the release policy; the run counter is not
    // advanced by token issuance.
    const da = checkDatasetAccess(access, datasetId, now);
    checkDatasetAudience(da.dataset.policy, audience);
    sub = `dataset:${datasetId}`;
  }
  // The token never outlives the run deadline.
  const exp = Math.min(now + settings.token_ttl_s, access.rat.deadline);
  const claims = {
    iss: settings.issuer_url,
    sub,
    aud: audience,
    iat: now,
    nbf: now,
    exp,
    jti: uuid4(),
    contract_id: access.rat.contract_id,
    run_id: access.rat.run_id,
    platform: access.claims.platform,
    measurement_id: access.claims.measurement_id,
  };
  const record: IssuedToken = {
    jti: claims.jti,
    sub,
    aud: audience,
    contract_id: claims.contract_id,
    run_id: claims.run_id,
    iat: now,
    exp,
  };
  issuedTokensTable.set(claims.jti, record);
  bindClaim(record);
  return {
    token: oidcSigningKey.sign("JWT", claims),
    token_type: "urn:ietf:params:oauth:token-type:jwt",
    expires_at: exp,
  };
});
