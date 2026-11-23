// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.

export const PLATFORMS = ["aci-snp", "gcp-cs-tdx", "virtual"] as const;
export type Platform = (typeof PLATFORMS)[number];

/** Normalized result of attestation verification (spec §9.2). */
export interface AttestedClaims {
  platform: Platform;
  /** aci-snp: host_data hex; gcp-cs-tdx: container image digest; virtual: virtual id. */
  measurement_id: string;
  /** Hex SHA-256 binding hash proven by the evidence. */
  binding_hash: string;
  debug: boolean;
  /** aci-snp only: UVM endorsement identity. */
  uvm?: { did: string; feed: string; svn: string };
  /** gcp-cs-tdx only: Confidential Space support attributes. */
  support_attributes?: string[];
  /** Non-secret subset of the evidence, recorded for audit. */
  raw: Record<string, unknown>;
}
