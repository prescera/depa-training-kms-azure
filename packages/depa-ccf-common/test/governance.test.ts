// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.

import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import {
  createGovernance,
  effectiveState,
  ProposalRecord,
  proposalRequired,
  requiredApprovals,
  resolve,
  thresholdFor,
} from "../src/governance";
import { partiesTable } from "../src/party";
import { verifySignedJws } from "../src/signed_request";
import { call, fakeRequest, resetKv, TestParty } from "./helpers";

const SVC = "depa-kms";
const gov = createGovernance({
  name: SVC,
  version: "test",
  bundleDigest: "sha256:" + "0".repeat(64),
  peerName: "depa-contract-service",
  actions: [],
});
const E = gov.endpoints;
const userCaller = { policy: "user_cert", id: "ab".repeat(32) };

function bootstrap(members: TestParty[], extra: Record<string, unknown> = {}) {
  return call(E.bootstrap, fakeRequest({ caller: userCaller, body: { members: members.map((m) => m.record()), ...extra } }));
}
function signed(fn: Parameters<typeof call>[0], party: TestParty, op: string, body: unknown, params: Record<string, string> = {}) {
  return call(fn, fakeRequest({ body: { jws: party.signRequest(SVC, op, body) }, params }));
}
function propose(p: TestParty, actions: unknown[], extra: Record<string, unknown> = {}) {
  return signed(E.propose, p, "gov.propose", { actions, ...extra });
}
function vote(p: TestParty, id: string, v: "approve" | "reject") {
  return signed(E.vote, p, "gov.vote", { proposal_id: id, vote: v }, { proposal_id: id });
}

beforeEach(resetKv);
afterEach(() => {
  jest.restoreAllMocks();
});

describe("threshold arithmetic", () => {
  it("computes required approvals", () => {
    expect([1, 2, 3, 4, 5].map((m) => requiredApprovals("majority", m))).toEqual([1, 2, 2, 3, 3]);
    expect(requiredApprovals("unanimous", 4)).toBe(4);
    expect(requiredApprovals({ n: 2 }, 5)).toBe(2);
  });

  it("applies default and per-action thresholds; strictest action wins", () => {
    const c = { default: "majority" as const, thresholds: { set_party: { n: 1 } } };
    expect(thresholdFor("set_member", c)).toBe("unanimous");
    expect(thresholdFor("set_settings", c)).toBe("unanimous");
    expect(thresholdFor("set_party", c)).toEqual({ n: 1 });
    expect(thresholdFor("approve_ccr_release", c)).toBe("majority");
    expect(proposalRequired([{ name: "set_party", args: {} }, { name: "set_member", args: {} }], c, 3)).toBe(3);
  });

  it("resolves accept / reject / open", () => {
    expect(resolve({ approvals: 2, rejections: 0, required: 2, members: 3 })).toBe("accepted");
    expect(resolve({ approvals: 1, rejections: 1, required: 2, members: 3 })).toBe("open");
    expect(resolve({ approvals: 0, rejections: 2, required: 2, members: 3 })).toBe("rejected");
    expect(resolve({ approvals: 0, rejections: 0, required: 4, members: 3 })).toBe("rejected");
  });

  it("expires open proposals on read", () => {
    const p = { state: "open", expires_at: 100 } as ProposalRecord;
    expect(effectiveState(p, 100)).toBe("open");
    expect(effectiveState(p, 101)).toBe("expired");
    expect(effectiveState({ ...p, state: "accepted" }, 101)).toBe("accepted");
  });
});

describe("governance engine", () => {
  const m1 = new TestParty("member-1", ["dc-member"]);
  const m2 = new TestParty("member-2", ["dc-member"]);
  const m3 = new TestParty("member-3", ["dc-member"]);
  const tdp = new TestParty("bank-a", ["tdp"]);

  it("bootstraps exactly once and only for the operator", () => {
    expect(call(E.bootstrap, fakeRequest({ body: { members: [m1.record()] } })).status).toBe(401);
    expect(bootstrap([tdp]).status).toBe(400); // members must be dc-members
    const r = bootstrap([m1, m2, m3]);
    expect(r.status).toBe(200);
    expect(r.body.jwks).toHaveLength(1);
    expect(bootstrap([m1]).body.error.code).toBe("already_bootstrapped");
  });

  it("accepts atomically on the threshold ballot and applies the actions", () => {
    bootstrap([m1, m2, m3]);
    const id = propose(m1, [{ name: "set_party", args: tdp.record() }]).body.proposal_id;
    expect(vote(m1, id, "approve").body.state).toBe("open");
    expect(partiesTable.get("bank-a")).toBeUndefined();
    const r = vote(m2, id, "approve");
    expect(r.body.state).toBe("accepted");
    expect(partiesTable.get("bank-a")?.roles).toEqual(["tdp"]);
    expect(vote(m3, id, "approve").body.error.code).toBe("proposal_closed");
  });

  it("last ballot wins while open; rejection when acceptance is impossible", () => {
    bootstrap([m1, m2, m3]);
    const id = propose(m1, [{ name: "set_party", args: tdp.record() }]).body.proposal_id;
    expect(vote(m1, id, "reject").body.state).toBe("open");
    expect(vote(m1, id, "approve").body.tally.approvals).toBe(1);
    expect(vote(m2, id, "reject").body.state).toBe("open");
    expect(vote(m3, id, "reject").body.state).toBe("rejected");
  });

  it("requires unanimity for membership changes", () => {
    bootstrap([m1, m2, m3]);
    const m4 = new TestParty("member-4", ["dc-member"]);
    const id = propose(m1, [{ name: "set_member", args: m4.record() }]).body.proposal_id;
    vote(m1, id, "approve");
    expect(vote(m2, id, "approve").body.state).toBe("open");
    expect(vote(m3, id, "approve").body.state).toBe("accepted");
    expect(partiesTable.get("member-4")?.roles).toEqual(["dc-member"]);
  });

  it("rejects ballots after expiry", () => {
    bootstrap([m1, m2]);
    const id = propose(m1, [{ name: "set_party", args: tdp.record() }], { expires_in_s: 60 }).body.proposal_id;
    const now = Date.now();
    jest.spyOn(Date, "now").mockReturnValue(now + 61_000);
    // Freshness of the signed ballot is relative to the mocked clock.
    const ballot = m2.signRequest(SVC, "gov.vote", { proposal_id: id, vote: "approve" }, { iat: Math.floor((now + 61_000) / 1000) });
    const r = call(E.vote, fakeRequest({ body: { jws: ballot }, params: { proposal_id: id } }));
    expect(r.status).toBe(409);
    expect(call(E.getProposal, fakeRequest({ params: { proposal_id: id } })).body.state).toBe("expired");
  });

  it("rolls back the ballot when an action no longer applies", () => {
    bootstrap([m1, m2]);
    const id = propose(m1, [{ name: "remove_party", args: { party_id: "nobody" } }]);
    expect(id.status).toBe(404); // validated at proposal time
    signed(E.propose, m1, "gov.propose", { actions: [{ name: "set_party", args: tdp.record() }] });
    const rm = propose(m1, [{ name: "remove_member", args: { party_id: "member-2" } }, { name: "remove_member", args: { party_id: "member-1" } }]);
    expect(rm.status).toBe(200);
    vote(m1, rm.body.proposal_id, "approve");
    const r = vote(m2, rm.body.proposal_id, "approve");
    expect(r.status).toBe(409);
    expect(r.body.error.code).toBe("proposal_not_applicable");
    expect(partiesTable.get("member-2")?.roles).toEqual(["dc-member"]); // nothing applied
    expect(call(E.getProposal, fakeRequest({ params: { proposal_id: rm.body.proposal_id } })).body.ballots["member-2"]).toBeUndefined();
  });

  it("keeps membership changes out of majority actions", () => {
    bootstrap([m1, m2, m3]);
    expect(propose(m1, [{ name: "set_party", args: { ...m1.record(), roles: ["dc-member", "tdp"] } }]).status).toBe(400);
    expect(propose(m1, [{ name: "set_party", args: { ...m1.record(), roles: ["tdp"] } }]).body.error.code).toBe("is_member");
    expect(propose(m1, [{ name: "remove_party", args: { party_id: "member-2" } }]).body.error.code).toBe("is_member");
  });

  it("only members may propose or vote; ballots are bound to the proposal", () => {
    bootstrap([m1, m2]);
    const id = propose(m1, [{ name: "set_party", args: tdp.record() }]).body.proposal_id;
    const id2 = propose(m1, [{ name: "set_party", args: new TestParty("bank-b", ["tdp"]).record() }]).body.proposal_id;
    const r = call(E.vote, fakeRequest({ body: { jws: m2.signRequest(SVC, "gov.vote", { proposal_id: id2, vote: "approve" }) }, params: { proposal_id: id } }));
    expect(r.status).toBe(400);
    expect(propose(tdp, [{ name: "set_party", args: tdp.record() }]).status).toBe(401); // not registered
  });

  it("validates constitutions against the member count", () => {
    bootstrap([m1, m2]);
    expect(propose(m1, [{ name: "set_constitution", args: { default: { n: 3 } } }]).status).toBe(400);
    expect(propose(m1, [{ name: "set_constitution", args: { default: "majority", thresholds: { nope: "majority" } } }]).status).toBe(400);
    const id = propose(m1, [{ name: "set_constitution", args: { default: { n: 1 } } }]).body.proposal_id;
    vote(m1, id, "approve");
    expect(vote(m2, id, "approve").body.state).toBe("accepted");
    const id2 = propose(m1, [{ name: "set_party", args: tdp.record() }]).body.proposal_id;
    expect(vote(m1, id2, "approve").body.state).toBe("accepted");
  });
});

describe("signed requests", () => {
  const m1 = new TestParty("member-1", ["dc-member"]);
  const opts = { service: SVC, op: "gov.propose", roles: ["dc-member"] as const };

  beforeEach(() => {
    partiesTable.set("member-1", m1.record() as never);
  });

  it("accepts a fresh request once", () => {
    const jws = m1.signRequest(SVC, "gov.propose", {});
    expect(verifySignedJws(jws, opts).party.party_id).toBe("member-1");
    expect(() => verifySignedJws(jws, opts)).toThrow(/replayed/);
  });

  it.each([
    ["wrong aud", () => m1.signRequest("depa-contract-service", "gov.propose", {}), /aud/],
    ["wrong op", () => m1.signRequest(SVC, "gov.vote", {}), /op/],
    ["stale iat", () => m1.signRequest(SVC, "gov.propose", {}, { iat: Math.floor(Date.now() / 1000) - 301 }), /iat window/],
    ["future iat", () => m1.signRequest(SVC, "gov.propose", {}, { iat: Math.floor(Date.now() / 1000) + 301 }), /iat window/],
    ["non-uuid jti", () => m1.signRequest(SVC, "gov.propose", {}, { jti: "x" }), /jti/],
    ["DER signature", () => m1.signRequest(SVC, "gov.propose", {}, { der: true }), /signature/],
    ["unknown key", () => new TestParty("member-1", ["dc-member"], "k9").signRequest(SVC, "gov.propose", {}), /unknown key/],
    ["key of another party", () => new TestParty("member-1", ["dc-member"]).signRequest(SVC, "gov.propose", {}), /signature/],
  ])("rejects %s", (_n, make, re) => {
    expect(() => verifySignedJws(make(), opts)).toThrow(re);
  });

  it("enforces roles and party status", () => {
    expect(() => verifySignedJws(m1.signRequest(SVC, "gov.propose", {}), { ...opts, roles: ["tdp"] })).toThrow(/role/);
    partiesTable.set("member-1", m1.record({ status: "suspended" }) as never);
    expect(() => verifySignedJws(m1.signRequest(SVC, "gov.propose", {}), opts)).toThrow(/suspended/);
  });
});
