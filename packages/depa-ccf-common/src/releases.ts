// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// CCR release registry (spec §6). Kept, governed and checked independently by
// both services. A release_id is immutable: re-approval with different content
// is rejected and a revoked release_id can never be approved again.

import { ApiError } from "./errors";
import { canonicalize } from "./jcs";
import { JsonTable } from "./kv";
import { AttestedClaims, Platform, PLATFORMS } from "./platforms";
import { arr, bool, HEX64_RE, JsonObject, keys, obj, oneOf, RELEASE_ID_RE, str } from "./validate";

export const FAMILIES = ["classic", "torch", "llm", "custom", "inference"] as const;
export type Family = (typeof FAMILIES)[number];

export interface AciMeasurements {
  host_data: string[];
  uvm: { did: string; feed: string; min_svn: string };
}
export interface GcpMeasurements {
  image_digests: string[];
  support_attributes: string[];
  require_debug_disabled: true;
}
export interface VirtualMeasurements {
  virtual_ids: string[];
}

export interface CcrRelease {
  release_id: string;
  platform: Platform;
  families: Family[];
  tiers: Array<1 | 2>;
  measurements: AciMeasurements | GcpMeasurements | VirtualMeasurements;
  provenance: Record<string, string>;
}

export interface ReleaseEntry {
  release: CcrRelease;
  state: "approved" | "revoked";
  approved_by_proposal: string;
  revoked_by_proposal?: string;
}

export const releasesTable = new JsonTable<ReleaseEntry>("public:depa.ccr_releases");

const IMAGE_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const SVN_RE = /^[0-9]{1,10}$/;

function validateMeasurements(platform: Platform, v: unknown, path: string): CcrRelease["measurements"] {
  const o = obj(v, path);
  if (platform === "aci-snp") {
    keys(o, path, ["host_data", "uvm"]);
    const host_data = arr(o.host_data, `${path}.host_data`, (x, p) => str(x, p, { re: HEX64_RE }), {
      min: 1,
      max: 32,
      unique: true,
    });
    const u = obj(o.uvm, `${path}.uvm`);
    keys(u, `${path}.uvm`, ["did", "feed", "min_svn"]);
    return {
      host_data,
      uvm: {
        did: str(u.did, `${path}.uvm.did`, { re: /^did:x509:/, max: 2048 }),
        feed: str(u.feed, `${path}.uvm.feed`, { max: 256 }),
        min_svn: str(u.min_svn, `${path}.uvm.min_svn`, { re: SVN_RE }),
      },
    };
  }
  if (platform === "gcp-cs-tdx") {
    keys(o, path, ["image_digests", "require_debug_disabled"], ["support_attributes"]);
    const image_digests = arr(o.image_digests, `${path}.image_digests`, (x, p) => str(x, p, { re: IMAGE_DIGEST_RE }), {
      min: 1,
      max: 32,
      unique: true,
    });
    const support_attributes =
      o.support_attributes === undefined
        ? []
        : arr(o.support_attributes, `${path}.support_attributes`, (x, p) => str(x, p, { re: /^[A-Z_]{1,32}$/ }), {
            max: 8,
            unique: true,
          });
    if (bool(o.require_debug_disabled, `${path}.require_debug_disabled`) !== true) {
      throw ApiError.badRequest(`${path}.require_debug_disabled: must be true`, "invalid_input");
    }
    return { image_digests, support_attributes, require_debug_disabled: true };
  }
  keys(o, path, ["virtual_ids"]);
  return {
    virtual_ids: arr(o.virtual_ids, `${path}.virtual_ids`, (x, p) => str(x, p, { re: /^[a-z0-9][a-z0-9._-]{0,63}$/ }), {
      min: 1,
      max: 16,
      unique: true,
    }),
  };
}

export function validateRelease(v: unknown, path = "release"): CcrRelease {
  const o = obj(v, path);
  keys(o, path, ["release_id", "platform", "families", "tiers", "measurements", "provenance"]);
  const release_id = str(o.release_id, `${path}.release_id`, { re: RELEASE_ID_RE });
  const platform = oneOf(o.platform, `${path}.platform`, PLATFORMS);
  const families = arr(o.families, `${path}.families`, (x, p) => oneOf(x, p, FAMILIES), {
    min: 1,
    max: FAMILIES.length,
    unique: true,
  });
  const tiers = arr(o.tiers, `${path}.tiers`, (x, p) => oneOf(x, p, [1, 2] as const), { min: 1, max: 2, unique: true });
  const measurements = validateMeasurements(platform, o.measurements, `${path}.measurements`);
  const prov: JsonObject = obj(o.provenance, `${path}.provenance`);
  const provenance: Record<string, string> = {};
  for (const k of Object.keys(prov)) {
    str(k, `${path}.provenance key`, { re: /^[a-z_]{1,32}$/ });
    provenance[k] = str(prov[k], `${path}.provenance.${k}`, { max: 2048 });
  }
  return { release_id, platform, families, tiers, measurements, provenance };
}

/** Validates approve_ccr_release against the immutability rules. */
export function checkReleaseApprovable(release: CcrRelease): void {
  const existing = releasesTable.get(release.release_id);
  if (!existing) return;
  if (existing.state === "revoked") {
    throw ApiError.conflict(`release ${release.release_id} was revoked and can never be re-approved`, "release_revoked");
  }
  if (canonicalize(existing.release) !== canonicalize(release)) {
    throw ApiError.conflict(`release ${release.release_id} exists with different content (immutable)`, "release_immutable");
  }
}

export function approveRelease(release: CcrRelease, proposalId: string): void {
  checkReleaseApprovable(release);
  if (releasesTable.has(release.release_id)) return; // identical re-approval is a no-op
  releasesTable.set(release.release_id, { release, state: "approved", approved_by_proposal: proposalId });
}

export function validateRevokeRelease(v: unknown, path: string): string {
  const o = obj(v, path);
  keys(o, path, ["release_id"]);
  const id = str(o.release_id, `${path}.release_id`, { re: RELEASE_ID_RE });
  const existing = releasesTable.get(id);
  if (!existing) throw ApiError.notFound(`release ${id} not found`);
  if (existing.state === "revoked") throw ApiError.conflict(`release ${id} is already revoked`, "release_revoked");
  return id;
}

export function revokeRelease(releaseId: string, proposalId: string): void {
  const existing = releasesTable.get(releaseId);
  if (!existing) throw ApiError.notFound(`release ${releaseId} not found`);
  releasesTable.set(releaseId, { ...existing, state: "revoked", revoked_by_proposal: proposalId });
}

function svnAtLeast(actual: string | undefined, min: string): boolean {
  if (actual === undefined || !SVN_RE.test(actual) || !SVN_RE.test(min)) return false;
  return parseInt(actual, 10) >= parseInt(min, 10);
}

/** True iff the attested claims satisfy the release's measurements. */
export function releaseMatchesClaims(release: CcrRelease, claims: AttestedClaims): boolean {
  if (release.platform !== claims.platform) return false;
  if (release.platform === "aci-snp") {
    const m = release.measurements as AciMeasurements;
    return (
      m.host_data.includes(claims.measurement_id) &&
      claims.uvm !== undefined &&
      claims.uvm.did === m.uvm.did &&
      claims.uvm.feed === m.uvm.feed &&
      svnAtLeast(claims.uvm.svn, m.uvm.min_svn) &&
      !claims.debug
    );
  }
  if (release.platform === "gcp-cs-tdx") {
    const m = release.measurements as GcpMeasurements;
    const attrs = claims.support_attributes ?? [];
    return (
      m.image_digests.includes(claims.measurement_id) &&
      m.support_attributes.every((a) => attrs.includes(a)) &&
      !claims.debug
    );
  }
  const m = release.measurements as VirtualMeasurements;
  return m.virtual_ids.includes(claims.measurement_id);
}

/** Approved (non-revoked) releases whose measurements match the claims. */
export function matchingApprovedReleases(claims: AttestedClaims): CcrRelease[] {
  const out: CcrRelease[] = [];
  releasesTable.forEach((e) => {
    if (e.state === "approved" && releaseMatchesClaims(e.release, claims)) out.push(e.release);
  });
  return out;
}
