// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Party registry (spec §3.1). Identical records are registered by DC
// governance in both services. DC members are parties holding the
// "dc-member" role.

import { ApiError } from "./errors";
import { b64urlDecode } from "./encoding";
import { EcPublicJwk, validateEcPublicJwk } from "./jws";
import { JsonTable } from "./kv";
import { arr, keys, KID_RE, obj, oneOf, PARTY_ID_RE, str } from "./validate";

export const ROLES = ["tdp", "tdc", "ccrp", "dc-member", "auditor"] as const;
export type Role = (typeof ROLES)[number];

export interface HpkePublicKey {
  kid: string;
  x25519: string;
}

export interface Party {
  party_id: string;
  name: string;
  roles: Role[];
  signing_keys: Array<EcPublicJwk & { kid: string }>;
  hpke_public_keys: HpkePublicKey[];
  status: "active" | "suspended";
}

export const partiesTable = new JsonTable<Party>("public:depa.parties");

export function validateHpkePublicKey(v: unknown, path: string): HpkePublicKey {
  const o = obj(v, path);
  keys(o, path, ["kid", "x25519"]);
  const kid = str(o.kid, `${path}.kid`, { re: KID_RE });
  const x25519 = str(o.x25519, `${path}.x25519`, { max: 64 });
  if (b64urlDecode(x25519, `${path}.x25519`).length !== 32) {
    throw ApiError.badRequest(`${path}.x25519: must encode 32 bytes`, "invalid_input");
  }
  return { kid, x25519 };
}

export function validateParty(v: unknown, path = "party"): Party {
  const o = obj(v, path);
  keys(o, path, ["party_id", "name", "roles", "signing_keys"], ["hpke_public_keys", "status"]);
  const party_id = str(o.party_id, `${path}.party_id`, { re: PARTY_ID_RE });
  const name = str(o.name, `${path}.name`, { max: 256 });
  const roles = arr(o.roles, `${path}.roles`, (x, p) => oneOf(x, p, ROLES), { min: 1, max: ROLES.length, unique: true });
  const signing_keys = arr(
    o.signing_keys,
    `${path}.signing_keys`,
    (x, p) => validateEcPublicJwk(x, p, { requireKid: true }) as EcPublicJwk & { kid: string },
    { min: 1, max: 8 },
  );
  if (new Set(signing_keys.map((k) => k.kid)).size !== signing_keys.length) {
    throw ApiError.badRequest(`${path}.signing_keys: kids must be unique`, "invalid_input");
  }
  const hpke_public_keys =
    o.hpke_public_keys === undefined
      ? []
      : arr(o.hpke_public_keys, `${path}.hpke_public_keys`, validateHpkePublicKey, { max: 8 });
  if (new Set(hpke_public_keys.map((k) => k.kid)).size !== hpke_public_keys.length) {
    throw ApiError.badRequest(`${path}.hpke_public_keys: kids must be unique`, "invalid_input");
  }
  const status = o.status === undefined ? "active" : oneOf(o.status, `${path}.status`, ["active", "suspended"] as const);
  return { party_id, name, roles, signing_keys, hpke_public_keys, status };
}

export function getParty(partyId: string): Party | undefined {
  return partiesTable.get(partyId);
}

export function requireActiveParty(partyId: string, role?: Role): Party {
  const p = partiesTable.get(partyId);
  if (!p) throw ApiError.badRequest(`unknown party ${partyId}`, "unknown_party");
  if (p.status !== "active") throw ApiError.forbidden(`party ${partyId} is suspended`, "party_suspended");
  if (role && !p.roles.includes(role)) {
    throw ApiError.badRequest(`party ${partyId} does not hold role ${role}`, "missing_role");
  }
  return p;
}

export function isActiveMember(p: Party | undefined): boolean {
  return !!p && p.status === "active" && p.roles.includes("dc-member");
}

/** Active DC members, sorted by party_id. */
export function activeMembers(): Party[] {
  const out: Party[] = [];
  partiesTable.forEach((p) => {
    if (isActiveMember(p)) out.push(p);
  });
  return out.sort((a, b) => (a.party_id < b.party_id ? -1 : 1));
}
