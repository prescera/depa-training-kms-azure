// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// KMS dataset records (spec §7.1): per-dataset X25519 HPKE key pairs and the
// owner-authored release policy. Governance may only suspend/resume (tighten);
// policy and keys change only through the owner's signed requests.

import * as ccfapp from "@microsoft/ccf-app";
import { ccf } from "@microsoft/ccf-app/global";
import {
  ActionHandler,
  ApiError,
  bool,
  DATASET_ID_RE,
  endpoint,
  formatRfc3339,
  JsonTable,
  keys,
  nowSeconds,
  obj,
  pathParam,
  requireBootstrapped,
  str,
  verifySignedRequest,
  VerifiedRequest,
} from "../packages/depa-ccf-common/src/index";
import { datasetOwner, ReleasePolicy, validateReleasePolicy } from "./policy";
import { SERVICE_NAME } from "./constants";

export interface DatasetKey {
  kid: string;
  x25519: string;
  created_at: string;
  /** current: used for new ciphertexts; previous: still releasable; retired: never released again. */
  state: "current" | "previous" | "retired";
}

export interface Suspension {
  reason: string;
  at: string;
  by: string;
}

export interface DatasetRecord {
  dataset_id: string;
  owner: string;
  description: string;
  keys: DatasetKey[];
  policy: ReleasePolicy | null;
  policy_version: number;
  owner_suspension: Suspension | null;
  dc_suspension: Suspension | null;
  created_at: string;
  create_jws: string;
}

interface PolicyHistoryEntry {
  dataset_id: string;
  version: number;
  policy: ReleasePolicy;
  set_at: string;
  jws: string;
}

export interface X25519PrivateKey {
  /** base64url raw 32-byte X25519 private key. */
  d: string;
}

export const datasetsTable = new JsonTable<DatasetRecord>("public:depa.datasets");
const policyHistoryTable = new JsonTable<PolicyHistoryEntry>("public:depa.dataset_policy_history");
const datasetPrivateKeys = new JsonTable<X25519PrivateKey>("depa.private.dataset_keys");

/** Generates an X25519 key pair; stores the private key; returns the public part. */
export function generateX25519(kid: string, store: JsonTable<X25519PrivateKey>): string {
  const kp = ccf.crypto.generateEddsaKeyPair("x25519");
  const jwk = ccf.crypto.eddsaPemToJwk(kp.privateKey);
  if (jwk.crv !== "X25519" || typeof jwk.d !== "string" || typeof jwk.x !== "string") {
    throw ApiError.internal("X25519 key generation failed");
  }
  store.set(kid, { d: jwk.d });
  return jwk.x;
}

export function privateKeyOf(kid: string, store: JsonTable<X25519PrivateKey> = datasetPrivateKeys): string {
  const k = store.get(kid);
  if (!k) throw ApiError.internal(`private key ${kid} missing`);
  return k.d;
}

export function datasetState(d: DatasetRecord): "active" | "suspended" {
  return d.owner_suspension || d.dc_suspension ? "suspended" : "active";
}

export function requireDataset(datasetId: string): DatasetRecord {
  const d = datasetsTable.get(datasetId);
  if (!d) throw ApiError.notFound(`dataset ${datasetId} not found`);
  return d;
}

function datasetView(d: DatasetRecord): Record<string, unknown> {
  return {
    dataset_id: d.dataset_id,
    owner: d.owner,
    description: d.description,
    keys: d.keys,
    policy: d.policy,
    policy_version: d.policy_version,
    state: datasetState(d),
    owner_suspension: d.owner_suspension,
    dc_suspension: d.dc_suspension,
    created_at: d.created_at,
  };
}

function datasetIdFromPath(request: ccfapp.Request): string {
  const id = `${pathParam(request, "owner")}/${pathParam(request, "name")}`;
  if (!DATASET_ID_RE.test(id)) throw ApiError.badRequest("invalid dataset id in path");
  return id;
}

/**
 * Verifies an owner-signed request whose body names the dataset in the path
 * (`body.dataset_id`), so a signature can never be redirected to another
 * dataset of the same owner.
 */
function verifyOwnerRequest(request: ccfapp.Request, op: string): { v: VerifiedRequest; d: DatasetRecord; body: Record<string, unknown> } {
  requireBootstrapped();
  const id = datasetIdFromPath(request);
  const v = verifySignedRequest(request, { service: SERVICE_NAME, op, roles: ["tdp", "tdc"] });
  const body = obj(v.payload.body, "body");
  if (body.dataset_id !== id) throw ApiError.badRequest("body.dataset_id must equal the dataset in the path", "invalid_input");
  const d = requireDataset(id);
  if (v.party.party_id !== d.owner) throw ApiError.forbidden("only the dataset owner may perform this operation", "not_owner");
  return { v, d, body };
}

export const createDataset = endpoint("datasets.create", (request) => {
  requireBootstrapped();
  const v = verifySignedRequest(request, { service: SERVICE_NAME, op: "dataset.create", roles: ["tdp", "tdc"] });
  const b = obj(v.payload.body, "body");
  keys(b, "body", ["dataset_id"], ["description"]);
  const datasetId = str(b.dataset_id, "body.dataset_id", { re: DATASET_ID_RE });
  const description = b.description === undefined ? "" : str(b.description, "body.description", { min: 0, max: 2048 });
  if (datasetOwner(datasetId) !== v.party.party_id) {
    throw ApiError.forbidden("dataset_id must be prefixed with the signer's party_id", "not_owner");
  }
  if (datasetsTable.has(datasetId)) throw ApiError.conflict(`dataset ${datasetId} already exists`, "exists");
  const now = formatRfc3339(nowSeconds());
  const kid = `${datasetId}#1`;
  const x25519 = generateX25519(kid, datasetPrivateKeys);
  const record: DatasetRecord = {
    dataset_id: datasetId,
    owner: v.party.party_id,
    description,
    keys: [{ kid, x25519, created_at: now, state: "current" }],
    policy: null,
    policy_version: 0,
    owner_suspension: null,
    dc_suspension: null,
    created_at: now,
    create_jws: v.jws,
  };
  datasetsTable.set(datasetId, record);
  return datasetView(record);
});

export const getDataset = endpoint("datasets.get", (request) => datasetView(requireDataset(datasetIdFromPath(request))));

export const setDatasetPolicy = endpoint("datasets.set_policy", (request) => {
  const { v, d, body } = verifyOwnerRequest(request, "dataset.set_policy");
  keys(body, "body", ["dataset_id", "policy"]);
  const policy = validateReleasePolicy(body.policy, "body.policy");
  const version = d.policy_version + 1;
  const now = formatRfc3339(nowSeconds());
  policyHistoryTable.set(`${d.dataset_id}#v${version}`, { dataset_id: d.dataset_id, version, policy, set_at: now, jws: v.jws });
  const updated: DatasetRecord = { ...d, policy, policy_version: version };
  datasetsTable.set(d.dataset_id, updated);
  return datasetView(updated);
});

export const getDatasetPolicyHistory = endpoint("datasets.policy_history", (request) => {
  const d = requireDataset(datasetIdFromPath(request));
  const out: PolicyHistoryEntry[] = [];
  for (let n = 1; n <= d.policy_version; n++) {
    const e = policyHistoryTable.get(`${d.dataset_id}#v${n}`);
    if (e) out.push(e);
  }
  return { dataset_id: d.dataset_id, versions: out };
});

export const rotateDatasetKey = endpoint("datasets.rotate", (request) => {
  const { d, body } = verifyOwnerRequest(request, "dataset.rotate");
  keys(body, "body", ["dataset_id"], ["retire_previous"]);
  const retire = body.retire_previous === undefined ? false : bool(body.retire_previous, "body.retire_previous");
  const now = formatRfc3339(nowSeconds());
  const kid = `${d.dataset_id}#${d.keys.length + 1}`;
  const x25519 = generateX25519(kid, datasetPrivateKeys);
  const prior: DatasetKey[] = d.keys.map((k) => ({
    ...k,
    state: retire || k.state === "retired" ? "retired" : "previous",
  }));
  const updated: DatasetRecord = { ...d, keys: [...prior, { kid, x25519, created_at: now, state: "current" }] };
  datasetsTable.set(d.dataset_id, updated);
  return datasetView(updated);
});

function suspendEndpoint(name: string, op: string, suspend: boolean): ccfapp.EndpointFn {
  return endpoint(name, (request) => {
    const { v, d, body } = verifyOwnerRequest(request, op);
    keys(body, "body", ["dataset_id"], ["reason"]);
    const reason = body.reason === undefined ? "" : str(body.reason, "body.reason", { min: 0, max: 1024 });
    const updated: DatasetRecord = {
      ...d,
      owner_suspension: suspend ? { reason, at: formatRfc3339(nowSeconds()), by: v.party.party_id } : null,
    };
    datasetsTable.set(d.dataset_id, updated);
    return datasetView(updated);
  });
}

export const suspendDataset = suspendEndpoint("datasets.suspend", "dataset.suspend", true);
export const resumeDataset = suspendEndpoint("datasets.resume", "dataset.resume", false);

// ------------------------------------------------- DC governance (tighten only)

interface DcSuspendArgs {
  dataset_id: string;
  reason: string;
}

function dcSuspendArgs(args: unknown): DcSuspendArgs {
  const o = obj(args, "args");
  keys(o, "args", ["dataset_id", "reason"]);
  const dataset_id = str(o.dataset_id, "args.dataset_id", { re: DATASET_ID_RE });
  requireDataset(dataset_id);
  return { dataset_id, reason: str(o.reason, "args.reason", { max: 1024 }) };
}

export const datasetGovernanceActions: Array<ActionHandler<DcSuspendArgs>> = [
  {
    name: "suspend_dataset",
    validate: dcSuspendArgs,
    apply: (a, ctx) => {
      const d = requireDataset(a.dataset_id);
      datasetsTable.set(a.dataset_id, {
        ...d,
        dc_suspension: { reason: a.reason, at: formatRfc3339(ctx.now), by: `proposal:${ctx.proposal_id}` },
      });
    },
  },
  {
    name: "resume_dataset",
    validate: (args) => {
      const a = dcSuspendArgs(args);
      if (!requireDataset(a.dataset_id).dc_suspension) {
        throw ApiError.conflict("dataset has no DC suspension (owner suspensions cannot be lifted by governance)", "not_suspended");
      }
      return a;
    },
    apply: (a) => {
      const d = requireDataset(a.dataset_id);
      datasetsTable.set(a.dataset_id, { ...d, dc_suspension: null });
    },
  },
];
