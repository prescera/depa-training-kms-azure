// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// App-level n-of-m governance (spec §4). CCF member governance is not
// exposed on Azure Confidential Ledger, so proposals and ballots are signed
// requests from DC members and are resolved inside the application.
//
// Resolution rules:
//  - required(t, m): majority = floor(m/2)+1, unanimous = m, {n:k} = k, where
//    m is the number of ACTIVE members at evaluation time and only ballots of
//    active members count;
//  - a proposal's threshold is the strictest threshold of its actions;
//  - accepted when approvals >= required, in the same transaction as that
//    ballot; actions are validated and applied sequentially in that
//    transaction. If any action cannot be applied in the current state the
//    whole transaction (including the ballot) is rolled back with 409 and the
//    proposal stays open;
//  - rejected when (m - rejections) < required;
//  - expired (computed on read) when still open after expires_at.

import * as ccfapp from "@microsoft/ccf-app";
import { requireOperator } from "./acl";
import { approveRelease, checkReleaseApprovable, CcrRelease, releasesTable, revokeRelease, validateRelease, validateRevokeRelease } from "./releases";
import { ApiError } from "./errors";
import { endpoint, pathParam } from "./http";
import { digest, DIGEST_RE } from "./jcs";
import { JsonTable } from "./kv";
import { activeMembers, Party, partiesTable, validateParty } from "./party";
import { serviceSigningKey } from "./service_keys";
import {
  applySettingsPatch,
  approvedDigestTable,
  CommonSettings,
  getSettings,
  jwtPolicyTable,
  JwtValidationPolicy,
  peerTable,
  PeerService,
  validateAppDigest,
  validateJwtValidationPolicy,
  validatePeerService,
  validateSettingsPatch,
} from "./settings";
import { verifySignedRequest } from "./signed_request";
import { nowSeconds } from "./time";
import { arr, int, keys, obj, oneOf, PARTY_ID_RE, str } from "./validate";

export type Threshold = "majority" | "unanimous" | { n: number };

export interface Constitution {
  default: Threshold;
  thresholds: Record<string, Threshold>;
}

export interface GovAction {
  name: string;
  args: unknown;
}

export interface ActionContext {
  proposal_id: string;
  now: number;
}

export interface ActionHandler<A = unknown> {
  name: string;
  /** Validates args against the current state and returns normalized args. */
  validate(args: unknown, ctx: ActionContext): A;
  apply(args: A, ctx: ActionContext): void;
}

export interface ServiceDescriptor {
  name: "depa-kms" | "depa-contract-service";
  version: string;
  bundleDigest: string;
  /** Name of the peer service this service pins. */
  peerName: "depa-kms" | "depa-contract-service";
  actions: Array<ActionHandler<any>>;
  /** Extra bootstrap work (e.g. KMS OIDC key generation). */
  onBootstrap?: () => void;
}

export type ProposalState = "open" | "accepted" | "rejected" | "expired";

export interface ProposalRecord {
  proposal_id: string;
  proposer: string;
  actions: GovAction[];
  created_at: number;
  expires_at: number;
  state: "open" | "accepted" | "rejected";
  ballots: Record<string, "approve" | "reject">;
  proposal_jws: string;
  ballot_jws: Record<string, string>;
  resolved_at?: number;
}

interface BootstrapRecord {
  at: number;
  operator: string;
  members: string[];
}

export const constitutionTable = new JsonTable<Constitution>("public:depa.constitution");
export const proposalsTable = new JsonTable<ProposalRecord>("public:depa.proposals");
const bootstrapTable = new JsonTable<BootstrapRecord>("public:depa.bootstrap");

export const UNANIMOUS_BY_DEFAULT = ["set_member", "remove_member", "set_constitution", "set_settings"];
const DEFAULT_EXPIRY_S = 604800;
const MAX_EXPIRY_S = 30 * 86400;
const MIN_EXPIRY_S = 60;
const MAX_ACTIONS = 16;

export function isBootstrapped(): boolean {
  return bootstrapTable.has("bootstrap");
}

export function requireBootstrapped(): void {
  if (!isBootstrapped()) throw ApiError.conflict("service is not bootstrapped", "not_bootstrapped");
}

export function validateThreshold(v: unknown, path: string, memberCount: number): Threshold {
  if (v === "majority" || v === "unanimous") return v;
  const o = obj(v, path);
  keys(o, path, ["n"]);
  const n = int(o.n, `${path}.n`, { min: 1 });
  if (n > memberCount) {
    throw ApiError.badRequest(`${path}.n: ${n} exceeds the number of active members (${memberCount})`, "invalid_input");
  }
  return { n };
}

export function requiredApprovals(t: Threshold, memberCount: number): number {
  if (t === "majority") return Math.floor(memberCount / 2) + 1;
  if (t === "unanimous") return memberCount;
  return t.n;
}

export function getConstitution(): Constitution {
  return constitutionTable.get("constitution") ?? { default: "majority", thresholds: {} };
}

export function thresholdFor(action: string, c: Constitution): Threshold {
  if (c.thresholds[action] !== undefined) return c.thresholds[action];
  return UNANIMOUS_BY_DEFAULT.includes(action) ? "unanimous" : c.default;
}

/** The strictest threshold (largest approval count) over the actions. */
export function proposalRequired(actions: GovAction[], c: Constitution, memberCount: number): number {
  let req = 1;
  for (const a of actions) req = Math.max(req, requiredApprovals(thresholdFor(a.name, c), memberCount));
  return req;
}

export function effectiveState(p: ProposalRecord, now: number): ProposalState {
  if (p.state === "open" && now > p.expires_at) return "expired";
  return p.state;
}

export interface Tally {
  approvals: number;
  rejections: number;
  required: number;
  members: number;
}

export function tally(p: ProposalRecord, members: string[], c: Constitution): Tally {
  let approvals = 0;
  let rejections = 0;
  for (const m of members) {
    if (p.ballots[m] === "approve") approvals++;
    else if (p.ballots[m] === "reject") rejections++;
  }
  return { approvals, rejections, required: proposalRequired(p.actions, c, members.length), members: members.length };
}

/** Resolution of a tally: accepted, rejected or still open. */
export function resolve(t: Tally): "accepted" | "rejected" | "open" {
  if (t.required > t.members) return "rejected";
  if (t.approvals >= t.required) return "accepted";
  if (t.members - t.rejections < t.required) return "rejected";
  return "open";
}

// ------------------------------------------------------------------ actions

function checkConstitutionFeasible(c: Constitution, memberCount: number, path: string): void {
  const all: Threshold[] = [c.default, ...Object.values(c.thresholds)];
  for (const t of all) {
    if (typeof t === "object" && t.n > memberCount) {
      throw ApiError.conflict(`${path}: constitution threshold n=${t.n} would exceed ${memberCount} active members`, "infeasible_threshold");
    }
  }
}

function partyIdArg(args: unknown, path: string): string {
  const o = obj(args, path);
  keys(o, path, ["party_id"]);
  return str(o.party_id, `${path}.party_id`, { re: PARTY_ID_RE });
}

function commonActions(svc: ServiceDescriptor, allActionNames: () => string[]): Array<ActionHandler<any>> {
  const setMember: ActionHandler<Party> = {
    name: "set_member",
    validate: (args) => {
      const p = validateParty(args, "args");
      if (!p.roles.includes("dc-member")) throw ApiError.badRequest("set_member: party must hold role dc-member", "invalid_input");
      if (p.status !== "active") throw ApiError.badRequest("set_member: status must be active", "invalid_input");
      return p;
    },
    apply: (p) => partiesTable.set(p.party_id, p),
  };
  const removeMember: ActionHandler<string> = {
    name: "remove_member",
    validate: (args) => {
      const id = partyIdArg(args, "args");
      const p = partiesTable.get(id);
      if (!p || !p.roles.includes("dc-member")) throw ApiError.notFound(`remove_member: ${id} is not a member`);
      const remaining = activeMembers().filter((m) => m.party_id !== id).length;
      if (remaining < 1) throw ApiError.conflict("remove_member: at least one member must remain", "last_member");
      checkConstitutionFeasible(getConstitution(), remaining, "remove_member");
      return id;
    },
    apply: (id) => {
      const p = partiesTable.get(id) as Party;
      const roles = p.roles.filter((r) => r !== "dc-member");
      if (roles.length === 0) partiesTable.delete(id);
      else partiesTable.set(id, { ...p, roles });
    },
  };
  const setParty: ActionHandler<Party> = {
    name: "set_party",
    validate: (args) => {
      const p = validateParty(args, "args");
      if (p.roles.includes("dc-member")) throw ApiError.badRequest("set_party: use set_member for dc-member", "invalid_input");
      if (partiesTable.get(p.party_id)?.roles.includes("dc-member")) {
        throw ApiError.conflict("set_party: party is a DC member; use set_member / remove_member", "is_member");
      }
      return p;
    },
    apply: (p) => partiesTable.set(p.party_id, p),
  };
  const removeParty: ActionHandler<string> = {
    name: "remove_party",
    validate: (args) => {
      const id = partyIdArg(args, "args");
      const p = partiesTable.get(id);
      if (!p) throw ApiError.notFound(`remove_party: ${id} not found`);
      if (p.roles.includes("dc-member")) throw ApiError.conflict("remove_party: party is a DC member; use remove_member", "is_member");
      return id;
    },
    apply: (id) => partiesTable.delete(id),
  };
  const setConstitution: ActionHandler<Constitution> = {
    name: "set_constitution",
    validate: (args) => {
      const o = obj(args, "args");
      keys(o, "args", ["default"], ["thresholds"]);
      const m = activeMembers().length;
      const known = allActionNames();
      const def = validateThreshold(o.default, "args.default", m);
      const thresholds: Record<string, Threshold> = {};
      const t = o.thresholds === undefined ? {} : obj(o.thresholds, "args.thresholds");
      for (const k of Object.keys(t)) {
        if (!known.includes(k)) throw ApiError.badRequest(`args.thresholds: unknown action ${k}`, "invalid_input");
        thresholds[k] = validateThreshold(t[k], `args.thresholds.${k}`, m);
      }
      return { default: def, thresholds };
    },
    apply: (c) => constitutionTable.set("constitution", c),
  };
  const setPeer: ActionHandler<Omit<PeerService, "proposal_id">> = {
    name: "set_peer_service",
    validate: (args) => validatePeerService(args, "args", svc.peerName),
    apply: (p, ctx) => peerTable.set(p.name, { ...p, proposal_id: ctx.proposal_id }),
  };
  const setJwtPolicy: ActionHandler<JwtValidationPolicy> = {
    name: "set_jwt_validation_policy",
    validate: (args) => validateJwtValidationPolicy(args, "args"),
    apply: (p) => jwtPolicyTable.set(p.issuer, p),
  };
  const setSettings: ActionHandler<Partial<CommonSettings>> = {
    name: "set_settings",
    validate: (args) => validateSettingsPatch(args, "args"),
    apply: (patch) => applySettingsPatch(patch),
  };
  const approveDigest: ActionHandler<string> = {
    name: "approve_app_digest",
    validate: (args) => validateAppDigest(args, "args"),
    apply: (d, ctx) => approvedDigestTable.set(d, { digest: d, proposal_id: ctx.proposal_id }),
  };
  const approveCcr: ActionHandler<CcrRelease> = {
    name: "approve_ccr_release",
    validate: (args) => {
      const r = validateRelease(args, "args");
      checkReleaseApprovable(r);
      return r;
    },
    apply: (r, ctx) => approveRelease(r, ctx.proposal_id),
  };
  const revokeCcr: ActionHandler<string> = {
    name: "revoke_ccr_release",
    validate: (args) => validateRevokeRelease(args, "args"),
    apply: (id, ctx) => revokeRelease(id, ctx.proposal_id),
  };
  return [setMember, removeMember, setParty, removeParty, setConstitution, setPeer, setJwtPolicy, setSettings, approveDigest, approveCcr, revokeCcr];
}

// ---------------------------------------------------------------- engine

export interface Governance {
  actions: Map<string, ActionHandler<any>>;
  endpoints: Record<string, ccfapp.EndpointFn>;
}

function proposalView(p: ProposalRecord, now: number): Record<string, unknown> {
  const members = activeMembers().map((m) => m.party_id);
  const t = tally(p, members, getConstitution());
  return {
    proposal_id: p.proposal_id,
    proposer: p.proposer,
    actions: p.actions,
    created_at: p.created_at,
    expires_at: p.expires_at,
    state: effectiveState(p, now),
    ballots: p.ballots,
    tally: t,
    resolved_at: p.resolved_at,
    proposal_jws: p.proposal_jws,
    ballot_jws: p.ballot_jws,
  };
}

export function createGovernance(svc: ServiceDescriptor): Governance {
  const actions = new Map<string, ActionHandler<any>>();
  const names = () => Array.from(actions.keys());
  for (const a of [...commonActions(svc, names), ...svc.actions]) {
    if (actions.has(a.name)) throw new Error(`duplicate governance action ${a.name}`);
    actions.set(a.name, a);
  }

  function parseActions(v: unknown): GovAction[] {
    return arr(
      v,
      "body.actions",
      (x, p) => {
        const o = obj(x, p);
        keys(o, p, ["name"], ["args"]);
        const name = str(o.name, `${p}.name`, { max: 64 });
        if (!actions.has(name)) throw ApiError.badRequest(`${p}.name: unknown action ${name}`, "unknown_action");
        return { name, args: o.args ?? {} };
      },
      { min: 1, max: MAX_ACTIONS },
    );
  }

  function applyActions(p: ProposalRecord, now: number): void {
    const ctx: ActionContext = { proposal_id: p.proposal_id, now };
    for (const a of p.actions) {
      const handler = actions.get(a.name) as ActionHandler<any>;
      let normalized: unknown;
      try {
        normalized = handler.validate(a.args, ctx);
      } catch (e) {
        if (e instanceof ApiError) {
          throw ApiError.conflict(
            `proposal cannot be applied in the current state (${a.name}: ${e.message}); ballot not recorded`,
            "proposal_not_applicable",
          );
        }
        throw e;
      }
      handler.apply(normalized, ctx);
    }
  }

  const bootstrap = endpoint("gov.bootstrap", (request) => {
    if (isBootstrapped()) throw ApiError.forbidden("service is already bootstrapped", "already_bootstrapped");
    const { operator, body } = requireOperator(request);
    const o = obj(body, "body");
    keys(o, "body", ["members"], ["threshold", "settings"]);
    const members = arr(o.members, "body.members", (x, p) => validateParty(x, p), { min: 1, max: 64 });
    if (new Set(members.map((m) => m.party_id)).size !== members.length) {
      throw ApiError.badRequest("body.members: duplicate party_id", "invalid_input");
    }
    for (const m of members) {
      if (!m.roles.includes("dc-member") || m.status !== "active") {
        throw ApiError.badRequest(`body.members: ${m.party_id} must be an active dc-member`, "invalid_input");
      }
    }
    let def: Threshold = "majority";
    if (o.threshold !== undefined) {
      const t = obj(o.threshold, "body.threshold");
      keys(t, "body.threshold", [], ["default"]);
      if (t.default !== undefined) def = validateThreshold(t.default, "body.threshold.default", members.length);
    }
    const settings = o.settings === undefined ? {} : validateSettingsPatch(o.settings, "body.settings");
    const now = nowSeconds();
    for (const m of members) partiesTable.set(m.party_id, m);
    constitutionTable.set("constitution", { default: def, thresholds: {} });
    applySettingsPatch(settings);
    const jwk = serviceSigningKey.create();
    if (svc.onBootstrap) svc.onBootstrap();
    bootstrapTable.set("bootstrap", { at: now, operator, members: members.map((m) => m.party_id) });
    return { service: svc.name, jwks: [jwk], members: members.map((m) => m.party_id) };
  });

  const propose = endpoint("gov.propose", (request) => {
    requireBootstrapped();
    const v = verifySignedRequest(request, { service: svc.name, op: "gov.propose", roles: ["dc-member"] });
    const b = obj(v.payload.body, "body");
    keys(b, "body", ["actions"], ["expires_in_s"]);
    const proposalActions = parseActions(b.actions);
    const expiresIn =
      b.expires_in_s === undefined ? DEFAULT_EXPIRY_S : int(b.expires_in_s, "body.expires_in_s", { min: MIN_EXPIRY_S, max: MAX_EXPIRY_S });
    const now = nowSeconds();
    const proposalId = digest(v.payload);
    if (proposalsTable.has(proposalId)) throw ApiError.conflict("proposal already exists", "duplicate_proposal");
    const ctx: ActionContext = { proposal_id: proposalId, now };
    // Early feedback: every action must be valid in the current state.
    for (const a of proposalActions) (actions.get(a.name) as ActionHandler<any>).validate(a.args, ctx);
    const record: ProposalRecord = {
      proposal_id: proposalId,
      proposer: v.party.party_id,
      actions: proposalActions,
      created_at: now,
      expires_at: now + expiresIn,
      state: "open",
      ballots: {},
      proposal_jws: v.jws,
      ballot_jws: {},
    };
    proposalsTable.set(proposalId, record);
    return { proposal_id: proposalId, state: "open" };
  });

  const vote = endpoint("gov.vote", (request) => {
    requireBootstrapped();
    const id = pathParam(request, "proposal_id");
    if (!DIGEST_RE.test(id)) throw ApiError.badRequest("invalid proposal_id");
    const v = verifySignedRequest(request, { service: svc.name, op: "gov.vote", roles: ["dc-member"] });
    const b = obj(v.payload.body, "body");
    keys(b, "body", ["vote", "proposal_id"]);
    // The ballot is bound to the proposal so it cannot be replayed onto another one.
    if (b.proposal_id !== id) throw ApiError.badRequest("body.proposal_id must equal the proposal in the path", "invalid_input");
    const choice = oneOf(b.vote, "body.vote", ["approve", "reject"] as const);
    const p = proposalsTable.get(id);
    if (!p) throw ApiError.notFound(`proposal ${id} not found`);
    const now = nowSeconds();
    const state = effectiveState(p, now);
    if (state !== "open") throw ApiError.conflict(`proposal is ${state}`, "proposal_closed");
    p.ballots[v.party.party_id] = choice;
    p.ballot_jws[v.party.party_id] = v.jws;
    const members = activeMembers().map((m) => m.party_id);
    const outcome = resolve(tally(p, members, getConstitution()));
    if (outcome === "accepted") {
      applyActions(p, now);
      p.state = "accepted";
      p.resolved_at = now;
    } else if (outcome === "rejected") {
      p.state = "rejected";
      p.resolved_at = now;
    }
    proposalsTable.set(id, p);
    return proposalView(p, now);
  });

  const listProposals = endpoint("gov.proposals", () => {
    const now = nowSeconds();
    const out: Array<Record<string, unknown>> = [];
    proposalsTable.forEach((p) => out.push(proposalView(p, now)));
    out.sort((a, b) => (a.created_at as number) - (b.created_at as number));
    return { proposals: out };
  });

  const getProposal = endpoint("gov.proposal", (request) => {
    const id = pathParam(request, "proposal_id");
    const p = proposalsTable.get(id);
    if (!p) throw ApiError.notFound(`proposal ${id} not found`);
    return proposalView(p, nowSeconds());
  });

  const members = endpoint("gov.members", () => ({ members: activeMembers() }));

  const constitution = endpoint("gov.constitution", () => {
    const c = getConstitution();
    const effective: Record<string, Threshold> = {};
    for (const n of names()) effective[n] = thresholdFor(n, c);
    return { constitution: c, effective_thresholds: effective, actions: names() };
  });

  const state = endpoint("gov.state", () => ({
    bootstrapped: isBootstrapped(),
    settings: getSettings(),
    peer_services: peerTable.entries().map(([, p]) => p),
    jwt_validation_policies: jwtPolicyTable.entries().map(([, p]) => p),
    approved_app_digests: approvedDigestTable.entries().map(([, d]) => d),
  }));

  const listParties = endpoint("parties.list", () => ({ parties: partiesTable.entries().map(([, p]) => p) }));
  const getPartyEp = endpoint("parties.get", (request) => {
    const id = pathParam(request, "party_id");
    const p = partiesTable.get(id);
    if (!p) throw ApiError.notFound(`party ${id} not found`);
    return p;
  });

  const listReleases = endpoint("releases.list", () => ({ releases: releasesTable.entries().map(([, e]) => e) }));
  const getRelease = endpoint("releases.get", (request) => {
    const id = pathParam(request, "release_id");
    const e = releasesTable.get(id);
    if (!e) throw ApiError.notFound(`release ${id} not found`);
    return e;
  });

  return {
    actions,
    endpoints: {
      bootstrap,
      propose,
      vote,
      listProposals,
      getProposal,
      members,
      constitution,
      state,
      listParties,
      getParty: getPartyEp,
      listReleases,
      getRelease,
    },
  };
}
