// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Run binding (spec §9.1). binding_hash = SHA-256(JCS(binding)) computed over
// the binding exactly as supplied by the CCR.

import { constantTimeEqual, hexEncode } from "./encoding";
import { ApiError } from "./errors";
import { DIGEST_RE, jcsHash } from "./jcs";
import { EcPublicJwk, validateEcPublicJwk } from "./jws";
import { Platform, PLATFORMS } from "./platforms";
import { CommonSettings } from "./settings";
import { HEX64_RE, JsonObject, keys, obj, oneOf, str, UUID4_RE } from "./validate";

export interface RunBinding {
  v: 1;
  contract_id: string;
  contract_digest: string;
  run_id: string;
  recipe_digest: string;
  platform: Platform;
  wrapping_key_sha256: string;
  run_key: EcPublicJwk;
  trust_bundle_digest: string;
}

export interface ValidatedBinding {
  binding: RunBinding;
  /** Hex SHA-256 of JCS(binding as supplied). */
  binding_hash: string;
}

export function bindingHashHex(binding: JsonObject): string {
  return hexEncode(jcsHash(binding));
}

export function validateRunBinding(v: unknown, path = "binding"): ValidatedBinding {
  const o = obj(v, path);
  keys(o, path, ["v", "contract_id", "contract_digest", "run_id", "recipe_digest", "platform", "wrapping_key_sha256", "run_key", "trust_bundle_digest"]);
  oneOf(o.v, `${path}.v`, [1] as const);
  const binding: RunBinding = {
    v: 1,
    contract_id: str(o.contract_id, `${path}.contract_id`, { re: UUID4_RE }),
    contract_digest: str(o.contract_digest, `${path}.contract_digest`, { re: DIGEST_RE }),
    run_id: str(o.run_id, `${path}.run_id`, { re: UUID4_RE }),
    recipe_digest: str(o.recipe_digest, `${path}.recipe_digest`, { re: DIGEST_RE }),
    platform: oneOf(o.platform, `${path}.platform`, PLATFORMS),
    wrapping_key_sha256: str(o.wrapping_key_sha256, `${path}.wrapping_key_sha256`, { re: HEX64_RE }),
    run_key: validateEcPublicJwk(o.run_key, `${path}.run_key`, { requireKid: false, allowP384: false }),
    trust_bundle_digest: str(o.trust_bundle_digest, `${path}.trust_bundle_digest`, { re: DIGEST_RE }),
  };
  return { binding, binding_hash: bindingHashHex(o) };
}

/**
 * Spec §9.1: the binding must carry the governance-approved trust bundle
 * digest. Mandatory for every non-virtual platform (fail closed while the
 * setting is unset); for virtual it is checked only when the setting is set.
 */
export function checkTrustBundle(binding: RunBinding, settings: CommonSettings): void {
  const expected = settings.trust_bundle_digest;
  if (!expected) {
    if (binding.platform === "virtual") return;
    throw ApiError.forbidden("settings.trust_bundle_digest is not configured; non-virtual runs are refused", "trust_bundle_not_configured");
  }
  if (!constantTimeEqual(binding.trust_bundle_digest, expected)) {
    throw ApiError.forbidden("binding.trust_bundle_digest does not match the approved trust bundle", "trust_bundle_mismatch");
  }
}
