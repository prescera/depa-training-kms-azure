# Copyright (c) iSPIRT Foundation.
# Licensed under the MIT license.
"""End-to-end DEPA Training v2 flow across the KMS and contract-service
sandboxes. Tests are ordered and share state through the `world` fixture."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

from depa_client import (
    Ccr,
    Signer,
    b64url,
    b64url_decode,
    binding_hash,
    digest,
    jws_es256,
    jws_es256_der,
    jws_payload,
    trust_bundle,
    verify_jws,
)

SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
DATASET = "bank-a/credit-applications"
VERSION = "2026-11-01"
VIRTUAL_RELEASE = "depa-ccr-classic-2.0.0-virtual"
GCP_RELEASE = "depa-ccr-classic-2.0.0-gcp"
INFER_RELEASE = "depa-inference-1.0.0-virtual"
GCP_IMAGE = "sha256:" + "ab" * 32


def ok(r, status: int = 200) -> dict:
    assert r.status_code == status, f"{r.status_code} {r.text}"
    return r.json()


def err(r, status: int, code: str | None = None) -> dict:
    assert r.status_code == status, f"expected {status}, got {r.status_code} {r.text}"
    body = r.json()
    if code is not None:
        assert body["error"]["code"] == code, body
    return body


M1 = Signer("dc-member-1", ["dc-member"])
M2 = Signer("dc-member-2", ["dc-member"])
TDP = Signer("bank-a", ["tdp"], hpke_x25519=b64url(X25519PrivateKey.generate().public_key().public_bytes_raw()))
TDC = Signer("fintech-x", ["tdc"], hpke_x25519=b64url(X25519PrivateKey.generate().public_key().public_bytes_raw()))
MEMBERS = [M1, M2]

VIRTUAL_RELEASE_RECORD = {
    "release_id": VIRTUAL_RELEASE,
    "platform": "virtual",
    "families": ["classic"],
    "tiers": [1, 2],
    "measurements": {"virtual_ids": ["virtual-dev"]},
    "provenance": {"source": "https://github.com/iSPIRT/depa-training", "commit": "0" * 40},
}
GCP_RELEASE_RECORD = {
    "release_id": GCP_RELEASE,
    "platform": "gcp-cs-tdx",
    "families": ["classic"],
    "tiers": [1, 2],
    "measurements": {"image_digests": [GCP_IMAGE], "support_attributes": ["STABLE"], "require_debug_disabled": True},
    "provenance": {"source": "https://github.com/iSPIRT/depa-training", "image": "ghcr.io/ispirt/depa-ccr-classic@" + GCP_IMAGE},
}
INFER_RELEASE_RECORD = {
    "release_id": INFER_RELEASE,
    "platform": "virtual",
    "families": ["inference"],
    "tiers": [1],
    "measurements": {"virtual_ids": ["virtual-infer"]},
    "provenance": {"source": "https://github.com/iSPIRT/depa-inferencing"},
}
RECIPE = {"family": "classic", "trainer": "xgboost", "params": {"max_depth": 6}}
MANIFEST = {"format": "dedf/1", "dataset_id": DATASET, "version": VERSION, "owner": "bank-a", "files": []}


def make_contract(output_mode: str = "tdc", releases=(VIRTUAL_RELEASE, GCP_RELEASE)) -> dict:
    now = int(time.time())
    output = {
        "mode": output_mode,
        "allowed_formats": ["xgboost-json", "onnx"],
        "max_bytes": 1 << 30,
        "metrics_allowlist": ["accuracy", "roc_auc"],
        "location": {"connector": "azure-blob", "uri": "https://acct.blob.core.windows.net/out/"},
    }
    if output_mode == "tdc":
        output["recipients"] = ["party:fintech-x#h1"]
    return {
        "schema": "depa-training/contract/v2",
        "contract_id": str(uuid.uuid4()),
        "title": "Credit risk model 2026",
        "description": "integration test",
        "purpose": "TRAINING",
        "parties": {"tdc": "fintech-x", "tdps": ["bank-a"]},
        "validity": {
            "not_before": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 60)),
            "not_after": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 86400)),
        },
        "datasets": [{"dataset_id": DATASET, "version": VERSION, "manifest_digest": digest(MANIFEST)}],
        "computation": {
            "tier": 1,
            "platforms": ["virtual", "gcp-cs-tdx"],
            "ccr_releases": list(releases),
            "recipes": [{"digest": digest(RECIPE), "document": RECIPE}],
            "max_runs": 20,
            "max_duration_minutes": 60,
        },
        "privacy": {"mode": "dp", "epsilon": 4.0, "delta": 1e-5},
        "output": output,
        "terms": {"governing_law": "IN"},
    }


# --------------------------------------------------------------- bootstrap


def test_bootstrap(kms, cs):
    for svc in (kms, cs):
        info = ok(svc.get("/info"))
        assert info["bootstrapped"] is False and info["bundle_digest"] == svc.info["bundle_digest"]
        body = ok(svc.bootstrap(MEMBERS, {"base_url": svc.url, "allow_virtual_attestation": True}))
        assert len(body["jwks"]) == 1
        err(svc.bootstrap(MEMBERS, {}), 403, "already_bootstrapped")
        info = ok(svc.get("/info"))
        assert info["bootstrapped"] is True and info["jwks"] == body["jwks"]
        assert [m["party_id"] for m in ok(svc.get("/gov/members"))["members"]] == ["dc-member-1", "dc-member-2"]


def test_bootstrap_requires_operator(kms):
    err(kms.post("/gov/bootstrap", {"members": []}), 401)


def test_governance_thresholds_and_party_registration(kms, cs):
    for svc in (kms, cs):
        r = ok(svc.propose(M1, [{"name": "set_party", "args": TDP.record()}, {"name": "set_party", "args": TDC.record()}]))
        pid = r["proposal_id"]
        assert r["state"] == "open"
        # majority of 2 = 2 approvals
        v = ok(svc.vote(M1, pid))
        assert v["state"] == "open" and v["tally"]["required"] == 2
        err(svc.get(f"/parties/{TDP.party_id}"), 404)
        v = ok(svc.vote(M2, pid))
        assert v["state"] == "accepted"
        assert ok(svc.get(f"/parties/{TDP.party_id}"))["roles"] == ["tdp"]
        err(svc.vote(M1, pid), 409, "proposal_closed")

        # rejection: one reject makes 2 approvals impossible
        pid = ok(svc.propose(M1, [{"name": "remove_party", "args": {"party_id": TDC.party_id}}]))["proposal_id"]
        assert ok(svc.vote(M2, pid, "reject"))["state"] == "rejected"
        assert ok(svc.get(f"/parties/{TDC.party_id}"))["party_id"] == TDC.party_id

        # non-members cannot propose; members cannot be added by majority set_party
        err(svc.propose(TDP, [{"name": "set_party", "args": TDP.record()}]), 403, "missing_role")
        err(svc.propose(M1, [{"name": "set_party", "args": {**TDP.record(), "roles": ["dc-member"]}}]), 400)
        # unknown action / unknown member fields
        err(svc.propose(M1, [{"name": "set_dataset_policy", "args": {}}]), 400, "unknown_action")
        # ballots are bound to the proposal id
        r = svc.signed("POST", f"/gov/proposals/{pid}/ballots", M1, "gov.vote", {"proposal_id": "sha256:" + "0" * 64, "vote": "approve"})
        err(r, 400)
        c = ok(svc.get("/gov/constitution"))
        assert c["effective_thresholds"]["set_member"] == "unanimous"
        assert c["effective_thresholds"]["set_party"] == "majority"


def test_pin_peers_and_registry(kms, cs, world):
    kms_info, cs_info = ok(kms.get("/info")), ok(cs.get("/info"))
    kms.govern(MEMBERS, [{"name": "set_peer_service", "args": {"name": "depa-contract-service", "url": cs.url, "jwks": cs_info["jwks"]}}])
    cs.govern(MEMBERS, [{"name": "set_peer_service", "args": {"name": "depa-kms", "url": kms.url, "jwks": kms_info["jwks"]}}])
    # A service only pins its own peer.
    err(kms.propose(M1, [{"name": "set_peer_service", "args": {"name": "depa-kms", "url": kms.url, "jwks": kms_info["jwks"]}}]), 400)
    gca_policy = {"name": "set_jwt_validation_policy", "args": {"issuer": "https://confidentialcomputing.googleapis.com", "claims": {"submods.gce.project_id": "depa-test"}}}
    for svc in (kms, cs):
        svc.govern(
            MEMBERS,
            [
                {"name": "approve_ccr_release", "args": VIRTUAL_RELEASE_RECORD},
                {"name": "approve_ccr_release", "args": GCP_RELEASE_RECORD},
                gca_policy,
            ],
        )
        assert ok(svc.get(f"/releases/{VIRTUAL_RELEASE}"))["state"] == "approved"
    kms.govern(
        MEMBERS,
        [
            {"name": "approve_ccr_release", "args": INFER_RELEASE_RECORD},
            {
                "name": "set_oidc_settings",
                "args": {"issuer_url": kms.url + "/oidc", "token_ttl_s": 600, "allowed_audiences_global": ["api://AzureADTokenExchange"]},
            },
            {"name": "approve_app_digest", "args": {"digest": kms.info["bundle_digest"]}},
        ],
    )
    assert ok(kms.get("/info"))["bundle_digest_approved"] is True
    world["kms_jwks"], world["cs_jwks"] = kms_info["jwks"], cs_info["jwks"]


def test_release_ids_are_immutable(kms, cs):
    changed = {**VIRTUAL_RELEASE_RECORD, "measurements": {"virtual_ids": ["virtual-evil"]}}
    for svc in (kms, cs):
        # identical re-approval is a no-op; different content is rejected
        err(svc.propose(M1, [{"name": "approve_ccr_release", "args": changed}]), 409, "release_immutable")
        tmp = {**VIRTUAL_RELEASE_RECORD, "release_id": "tmp-release"}
        svc.govern(MEMBERS, [{"name": "approve_ccr_release", "args": tmp}])
        svc.govern(MEMBERS, [{"name": "revoke_ccr_release", "args": {"release_id": "tmp-release"}}])
        assert ok(svc.get("/releases/tmp-release"))["state"] == "revoked"
        err(svc.propose(M1, [{"name": "approve_ccr_release", "args": tmp}]), 409, "release_revoked")


# ----------------------------------------------------------------- datasets


def test_dataset_and_policy(kms, world):
    err(kms.signed("POST", "/datasets", TDC, "dataset.create", {"dataset_id": DATASET}), 403, "not_owner")
    d = ok(kms.signed("POST", "/datasets", TDP, "dataset.create", {"dataset_id": DATASET, "description": "test"}))
    assert d["keys"][0]["kid"] == f"{DATASET}#1" and d["policy"] is None and d["state"] == "active"
    policy = {
        "version": 1,
        "allowed_platforms": ["virtual", "gcp-cs-tdx"],
        "allowed_tiers": [1, 2],
        "allowed_tdcs": ["fintech-x"],
        "allowed_purposes": ["TRAINING"],
        "privacy": {"require_dp": True, "max_epsilon": 5.0, "max_delta": 1e-5},
        "allowed_output_modes": ["tdc", "tee-only"],
        "allowed_audiences": ["sts.amazonaws.com"],
        "max_runs_per_contract": 10,
    }
    path = f"/datasets/{DATASET}/policy"
    # the signed body names the dataset, so a signature cannot be redirected
    err(kms.signed("PUT", path, TDP, "dataset.set_policy", {"dataset_id": "bank-a/other", "policy": policy}), 400)
    err(kms.signed("PUT", path, TDC, "dataset.set_policy", {"dataset_id": DATASET, "policy": policy}), 403)
    d = ok(kms.signed("PUT", path, TDP, "dataset.set_policy", {"dataset_id": DATASET, "policy": policy}))
    assert d["policy_version"] == 1 and d["policy"]["allowed_custom_measurements"] == []
    # governance cannot modify TDP policy: no such action exists
    err(kms.propose(M1, [{"name": "set_dataset_policy", "args": {}}]), 400, "unknown_action")
    # TDP seals a DEK to the dataset key (spec §7.3)
    pk = SUITE.kem.deserialize_public_key(b64url_decode(d["keys"][0]["x25519"]))
    dek = hashlib.sha256(b"dek").digest()
    info = f"depa-training/dedf/1/dek|{DATASET}|{VERSION}".encode()
    enc, sender = SUITE.create_sender_context(pk, info=info)
    world["dek"], world["wrapped_dek"] = dek, (enc, sender.seal(dek, aad=b""))


def test_catalog(cs):
    desc = {
        "dataset_id": DATASET,
        "version": VERSION,
        "name": "Credit applications",
        "format": "dedf/1",
        "manifest_digest": digest(MANIFEST),
        "schema": {"type": "tabular", "files": ["*.parquet"]},
        "location": {"connector": "s3", "uri": "s3://bucket/prefix/", "region": "ap-south-1"},
        "federation": {"aws": {"role_arn": "arn:aws:iam::123456789012:role/depa-reader"}},
        "kms": {"url": "https://kms.example", "kid": f"{DATASET}#1"},
    }
    err(cs.signed("POST", "/catalog/datasets", TDC, "catalog.publish", desc), 403, "not_owner")
    r = ok(cs.signed("POST", "/catalog/datasets", TDP, "catalog.publish", desc))
    assert r["manifest_digest"] == digest(MANIFEST)
    err(cs.signed("POST", "/catalog/datasets", TDP, "catalog.publish", desc), 409, "exists")
    assert ok(cs.get(f"/catalog/datasets/{DATASET}"))["latest_version"] == VERSION
    ok(cs.get(f"/catalog/datasets/{DATASET}/versions/{VERSION}"))


# ---------------------------------------------------------------- contracts


def activate(cs, contract: dict) -> str:
    view = ok(cs.signed("POST", "/contracts", TDC, "contract.propose", contract))
    assert view["state"] == "draft" and view["contract_digest"] == digest(contract)
    cid, d = contract["contract_id"], view["contract_digest"]
    err(cs.signed("POST", f"/contracts/{cid}/signatures", TDP, "contract.sign", {"contract_digest": "sha256:" + "1" * 64}), 409)
    assert ok(cs.signed("POST", f"/contracts/{cid}/signatures", TDC, "contract.sign", {"contract_digest": d}))["state"] == "draft"
    assert ok(cs.signed("POST", f"/contracts/{cid}/signatures", TDP, "contract.sign", {"contract_digest": d}))["state"] == "active"
    return d


def test_contract_lifecycle(cs, world):
    bad = make_contract()
    bad["computation"]["recipes"][0]["digest"] = "sha256:" + "2" * 64
    err(cs.signed("POST", "/contracts", TDC, "contract.propose", bad), 400, "recipe_digest_mismatch")
    bad = make_contract(releases=("unknown-release",))
    err(cs.signed("POST", "/contracts", TDC, "contract.propose", bad), 400, "release_not_approved")
    bad = make_contract()
    bad["datasets"][0]["manifest_digest"] = "sha256:" + "3" * 64
    err(cs.signed("POST", "/contracts", TDC, "contract.propose", bad), 400, "manifest_mismatch")
    err(cs.signed("POST", "/contracts", TDP, "contract.propose", make_contract()), 403)

    contract = make_contract()
    world["contract"], world["contract_digest"] = contract, activate(cs, contract)
    lst = ok(cs.get("/contracts", params={"party": "bank-a"}))["contracts"]
    assert any(c["contract"]["contract_id"] == contract["contract_id"] for c in lst)


# --------------------------------------------------------------------- runs


def authorize(cs, contract, digest_, platform="virtual", attestation=None, headers=None, ccr=None):
    ccr = ccr or Ccr(contract["contract_id"], digest_, digest(RECIPE), platform)
    att = attestation if attestation is not None else ccr.virtual_attestation()
    r = cs.post(f"/contracts/{contract['contract_id']}/runs", {"binding": ccr.binding, "attestation": att}, headers=headers or {})
    return ccr, r


def test_authorize_run(cs, world):
    contract, d = world["contract"], world["contract_digest"]
    # attestation must prove the binding
    ccr = Ccr(contract["contract_id"], d, digest(RECIPE), "virtual")
    bad_att = {**ccr.virtual_attestation(), "binding_hash": "0" * 64}
    err(cs.post(f"/contracts/{contract['contract_id']}/runs", {"binding": ccr.binding, "attestation": bad_att}), 401, "attestation_invalid")
    # unapproved measurement
    r = cs.post(f"/contracts/{contract['contract_id']}/runs", {"binding": ccr.binding, "attestation": ccr.virtual_attestation("virtual-other")})
    err(r, 403, "measurement_not_approved")
    # recipe not in contract
    other = Ccr(contract["contract_id"], d, digest({"x": 1}), "virtual")
    err(cs.post(f"/contracts/{contract['contract_id']}/runs", {"binding": other.binding, "attestation": other.virtual_attestation()}), 403, "recipe_not_allowed")

    ccr, r = authorize(cs, contract, d, ccr=ccr)
    body = ok(r)
    rat = verify_jws(body["rat"], world["cs_jwks"], "depa-rat+jwt")
    assert rat["aud"] == "depa-kms" and rat["iss"] == cs.url and rat["binding_hash"] == ccr.binding_hash
    assert rat["ccr_releases"] == [VIRTUAL_RELEASE, GCP_RELEASE] and rat["measurement_id"] == "virtual-dev"
    assert rat["exp"] - rat["iat"] == 300
    world["ccr"], world["rat"] = ccr, body["rat"]
    world["txid"] = r.headers["x-ms-ccf-transaction-id"]
    # run_id reuse is rejected
    err(cs.post(f"/contracts/{contract['contract_id']}/runs", {"binding": ccr.binding, "attestation": ccr.virtual_attestation()}), 409, "run_exists")
    assert ok(cs.get(f"/contracts/{contract['contract_id']}"))["runs_used"] == 1  # failed attempts are rolled back


def release_body(ccr, rat, dataset=DATASET, attestation=None, wrapping=None):
    return {
        "binding": ccr.binding,
        "attestation": attestation if attestation is not None else ccr.virtual_attestation(),
        "rat": rat,
        "dataset_id": dataset,
        "wrappingKey": wrapping or ccr.wrapping_pem,
    }


def test_key_release(kms, world):
    ccr, rat = world["ccr"], world["rat"]
    # wrapping key must match the binding
    other = Ccr(ccr.binding["contract_id"], ccr.binding["contract_digest"], ccr.binding["recipe_digest"], "virtual")
    err(kms.post("/keys/release", release_body(ccr, rat, wrapping=other.wrapping_pem)), 403, "wrapping_key_mismatch")
    # RAT bound to a different binding
    err(kms.post("/keys/release", release_body(other, rat)), 403, "rat_mismatch")
    # dataset not in the run
    err(kms.post("/keys/release", release_body(ccr, rat, dataset="bank-a/other")), 403, "dataset_not_in_rat")
    # tampered RAT
    h, p, s = rat.split(".")
    forged = json.loads(b64url_decode(p))
    forged["tier"] = 2
    err(kms.post("/keys/release", release_body(ccr, f"{h}.{b64url(json.dumps(forged).encode())}.{s}")), 401, "invalid_token")

    body = ok(kms.post("/keys/release", release_body(ccr, rat)))
    assert [k["kid"] for k in body["keys"]] == [f"{DATASET}#1"]
    raw = ccr.unwrap(body["keys"][0]["wrapped"])
    assert len(raw) == 32
    sk = SUITE.kem.deserialize_private_key(raw)
    enc, ct = world["wrapped_dek"]
    recipient = SUITE.create_recipient_context(enc, sk, info=f"depa-training/dedf/1/dek|{DATASET}|{VERSION}".encode())
    assert recipient.open(ct, aad=b"") == world["dek"]
    receipt = verify_jws(body["release_receipt"], world["kms_jwks"], "depa-key-release+jwt")
    assert receipt["run_id"] == ccr.run_id and receipt["binding_hash"] == ccr.binding_hash and receipt["iss"] == kms.url
    assert ok(kms.get(f"/key-releases/{body['release_id']}"))["run_id"] == ccr.run_id
    world["release_receipt"] = body["release_receipt"]


def test_oidc_token(kms, world):
    ccr, rat = world["ccr"], world["rat"]
    conf = ok(kms.get("/oidc/.well-known/openid-configuration"))
    assert conf["issuer"] == kms.url + "/oidc" and conf["id_token_signing_alg_values_supported"] == ["ES256"]
    jwks = ok(kms.get("/oidc/jwks"))["keys"]
    base = {"binding": ccr.binding, "attestation": ccr.virtual_attestation(), "rat": rat}
    err(kms.post("/oidc/token", {**base, "resource": {"dataset_id": DATASET}, "audience": "evil"}), 403, "policy_denied")
    tok = ok(kms.post("/oidc/token", {**base, "resource": {"dataset_id": DATASET}, "audience": "sts.amazonaws.com"}))
    claims = verify_jws(tok["token"], jwks, "JWT")
    assert claims["sub"] == f"dataset:{DATASET}" and claims["aud"] == "sts.amazonaws.com" and claims["iss"] == conf["issuer"]
    assert claims["exp"] - claims["iat"] <= 600 and claims["run_id"] == ccr.run_id
    out = ok(kms.post("/oidc/token", {**base, "resource": {"output": True}, "audience": "api://AzureADTokenExchange"}))
    assert verify_jws(out["token"], jwks, "JWT")["sub"] == "output:fintech-x"
    err(kms.post("/oidc/token", {**base, "resource": {"output": True}, "audience": "sts.amazonaws.com"}), 403, "audience_denied")
    assert ok(kms.get("/info"))["oidc_jwks"] == jwks


def receipt_for(world, ccr, release_receipts: list[str]) -> dict:
    contract = world["contract"]
    return {
        "run_id": ccr.run_id,
        "contract_id": contract["contract_id"],
        "contract_digest": world["contract_digest"],
        "recipe_digest": digest(RECIPE),
        "platform": ccr.binding["platform"],
        "measurement_id": "virtual-dev",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "inputs": [
            {"dataset_id": DATASET, "version": VERSION, "manifest_digest": digest(MANIFEST), "release_receipt": rr}
            for rr in release_receipts
        ],
        "privacy_spent": {"mode": "dp", "epsilon": 3.97, "delta": 1e-5, "accountant": "rdp"},
        "outputs": [
            {"name": "model", "format": "xgboost-json", "manifest_digest": "sha256:" + "4" * 64, "location": "https://acct.blob.core.windows.net/out/model", "recipients": ["party:fintech-x#h1"]}
        ],
        "metrics": {"accuracy": 0.91},
        "status": "succeeded",
    }


def test_run_events_and_execution_receipt(cs, kms, world):
    ccr, contract = world["ccr"], world["contract"]
    path = f"/contracts/{contract['contract_id']}/runs/{ccr.run_id}/events"
    ok(cs.post(path, {"jws": ccr.event("started", {})}))
    ok(cs.post(path, {"jws": ccr.event("progress", {"epoch": 1})}))
    # replayed / non-increasing seq
    err(cs.post(path, {"jws": ccr.event("progress", {"epoch": 1}, seq=1)}), 409, "stale_seq")
    # event signed with another key
    impostor = Ccr(contract["contract_id"], world["contract_digest"], digest(RECIPE), "virtual")
    impostor.run_id = ccr.run_id
    err(cs.post(path, {"jws": impostor.event("failed", {"x": 1}, seq=50)}), 401, "invalid_signature")

    # completed without a release receipt for every dataset is rejected
    err(cs.post(path, {"jws": ccr.event("completed", receipt_for(world, ccr, []), seq=10)}), 400, "receipt_inputs")
    # a release receipt of another run is rejected
    ccr2, r2 = authorize(cs, contract, world["contract_digest"])
    rat2 = ok(r2)["rat"]
    rr2 = ok(kms.post("/keys/release", release_body(ccr2, rat2)))["release_receipt"]
    err(cs.post(path, {"jws": ccr.event("completed", receipt_for(world, ccr, [rr2]), seq=11)}), 403, "receipt_mismatch")
    # a forged release receipt (signed by an unpinned key) is rejected
    forged_key = ec.generate_private_key(ec.SECP256R1())
    forged = jws_es256({"typ": "depa-key-release+jwt", "kid": world["kms_jwks"][0]["kid"]}, jws_payload(world["release_receipt"]), forged_key)
    err(cs.post(path, {"jws": ccr.event("completed", receipt_for(world, ccr, [forged]), seq=12)}), 401, "invalid_token")
    # metrics outside the allowlist / privacy over budget
    bad = receipt_for(world, ccr, [world["release_receipt"]])
    bad["metrics"] = {"secret_stat": 1.0}
    err(cs.post(path, {"jws": ccr.event("completed", bad, seq=13)}), 403, "metric_not_allowed")
    bad = receipt_for(world, ccr, [world["release_receipt"]])
    bad["privacy_spent"]["epsilon"] = 4.5
    err(cs.post(path, {"jws": ccr.event("completed", bad, seq=14)}), 403, "privacy_exceeded")

    # RAT refresh (spec §9.3a): same claims, fresh window, no run consumed, no replay
    cid = contract["contract_id"]
    used = ok(cs.get(f"/contracts/{cid}"))["runs_used"]
    req = ccr.refresh_request()
    fresh = ok(cs.post(f"/contracts/{cid}/runs/{ccr.run_id}/rat", {"jws": req}))
    new, old = verify_jws(fresh["rat"], world["cs_jwks"], "depa-rat+jwt"), jws_payload(world["rat"])
    assert {k: v for k, v in new.items() if k not in ("iat", "exp")} == {k: v for k, v in old.items() if k not in ("iat", "exp")}
    assert new["exp"] - new["iat"] <= 300 and new["exp"] <= new["deadline"]
    assert ok(cs.get(f"/contracts/{cid}"))["runs_used"] == used
    err(cs.post(f"/contracts/{cid}/runs/{ccr.run_id}/rat", {"jws": req}), 401, "replay")
    err(cs.post(f"/contracts/{cid}/runs/{ccr.run_id}/rat", {"jws": ccr.refresh_request(op="run.other")}), 401, "wrong_operation")
    err(cs.post(f"/contracts/{cid}/runs/{ccr.run_id}/rat", {"jws": impostor.refresh_request()}), 401, "invalid_signature")
    err(cs.post(f"/contracts/{cid}/runs/{ccr.run_id}/rat", {"jws": ccr.refresh_request(iat=int(time.time()) - 600)}), 401, "stale_request")
    ok(kms.post("/keys/release", release_body(ccr, fresh["rat"])))  # the KMS accepts the refreshed RAT

    good = receipt_for(world, ccr, [world["release_receipt"]])
    body = ok(cs.post(path, {"jws": ccr.event("completed", good, seq=20)}))
    signed = verify_jws(body["receipt_jws"], world["cs_jwks"], "depa-exec-receipt+jwt")
    assert signed["receipt"] == good and signed["receipt_digest"] == digest(good) and signed["iss"] == cs.url
    err(cs.post(path, {"jws": ccr.event("failed", {"x": 1}, seq=21)}), 409, "run_terminal")
    err(cs.post(f"/contracts/{cid}/runs/{ccr.run_id}/rat", {"jws": ccr.refresh_request()}), 409, "run_terminal")
    run = ok(cs.get(f"/runs/{ccr.run_id}"))
    assert run["state"] == "completed" and [e["type"] for e in run["events"]] == ["started", "progress", "completed"]
    world["ccr2"], world["rat2"] = ccr2, rat2


def test_trust_bundle(cs, kms, world, gca):
    """Spec §9.1: the binding carries digest(trust bundle); governance pins it."""
    contract, d = world["contract"], world["contract_digest"]
    url = f"/contracts/{contract['contract_id']}/runs"
    # unset: non-virtual runs are refused, virtual runs are not checked
    g = Ccr(contract["contract_id"], d, digest(RECIPE), "gcp-cs-tdx")
    r = cs.post(url, {"binding": g.binding, "attestation": {"platform": "gcp-cs-tdx"}}, headers={"Authorization": f"Bearer {gca.token(cs.url, g.binding_hash)}"})
    err(r, 403, "trust_bundle_not_configured")
    early, r = authorize(cs, contract, d)
    early_rat = ok(r)["rat"]

    tb = digest(trust_bundle(cs, kms))
    for svc in (kms, cs):
        svc.govern(MEMBERS, [{"name": "set_settings", "args": {"trust_bundle_digest": tb}}])
        assert ok(svc.get("/gov/state"))["settings"]["trust_bundle_digest"] == tb
    Ccr.default_trust_bundle_digest = tb
    # the KMS independently rejects a binding with another trust bundle, even with a valid RAT
    err(kms.post("/keys/release", release_body(early, early_rat)), 403, "trust_bundle_mismatch")
    # once set, the CS checks it for every platform, including virtual
    wrong = Ccr(contract["contract_id"], d, digest(RECIPE), "virtual", trust_bundle_digest="sha256:" + "9" * 64)
    err(authorize(cs, contract, d, ccr=wrong)[1], 403, "trust_bundle_mismatch")
    ccr, r = authorize(cs, contract, d)
    ok(kms.post("/keys/release", release_body(ccr, ok(r)["rat"])))


def test_gcp_confidential_space_path(cs, kms, world, gca):
    contract, d = world["contract"], world["contract_digest"]
    ccr = Ccr(contract["contract_id"], d, digest(RECIPE), "gcp-cs-tdx")
    url = f"/contracts/{contract['contract_id']}/runs"
    body = {"binding": ccr.binding, "attestation": {"platform": "gcp-cs-tdx"}}
    # no token / debug / wrong nonce / wrong audience / disallowed project
    err(cs.post(url, body), 401, "attestation_invalid")
    for bad in (
        gca.token(cs.url, ccr.binding_hash, dbgstat="enabled"),
        gca.token(cs.url, "0" * 64),
        gca.token(kms.url, ccr.binding_hash),
        gca.token(cs.url, ccr.binding_hash, submods={"container": {"image_digest": GCP_IMAGE}, "confidential_space": {"support_attributes": ["STABLE"]}, "gce": {"project_id": "other"}}),
    ):
        r = cs.post(url, body, headers={"Authorization": f"Bearer {bad}"})
        assert r.status_code in (401, 403), r.text
    r = ok(cs.post(url, body, headers={"Authorization": f"Bearer {gca.token(cs.url, ccr.binding_hash)}"}))
    rat = verify_jws(r["rat"], world["cs_jwks"], "depa-rat+jwt")
    assert rat["platform"] == "gcp-cs-tdx" and rat["measurement_id"] == GCP_IMAGE
    rel = release_body(ccr, r["rat"], attestation={"platform": "gcp-cs-tdx"})
    # the KMS requires a token whose audience is the KMS
    err(kms.post("/keys/release", rel, headers={"Authorization": f"Bearer {gca.token(cs.url, ccr.binding_hash)}"}), 401)
    keys = ok(kms.post("/keys/release", rel, headers={"Authorization": f"Bearer {gca.token(kms.url, ccr.binding_hash)}"}))
    assert len(ccr.unwrap(keys["keys"][0]["wrapped"])) == 32


def test_tee_only_output_keys(cs, kms, world):
    contract = make_contract(output_mode="tee-only")
    d = activate(cs, contract)
    ccr, r = authorize(cs, contract, d)
    rat = ok(r)["rat"]
    base = {"binding": ccr.binding, "attestation": ccr.virtual_attestation(), "rat": rat}
    # the tdc-mode contract's RAT cannot obtain an output key
    tdc_run, r = authorize(cs, world["contract"], world["contract_digest"])
    tdc_rat = ok(r)["rat"]
    err(kms.post(f"/outputs/{world['contract']['contract_id']}/key", {"binding": tdc_run.binding, "attestation": tdc_run.virtual_attestation(), "rat": tdc_rat}), 403, "output_mode")
    key = ok(kms.post(f"/outputs/{contract['contract_id']}/key", base))
    assert ok(kms.post(f"/outputs/{contract['contract_id']}/key", base))["kid"] == key["kid"]
    assert key["recipient"] == f"kms:output:{contract['contract_id']}#1"

    # release only to an attested inference workload
    infer = Ccr(contract["contract_id"], d, digest(RECIPE), "virtual")
    binding = {
        "v": 1,
        "purpose": "depa-output-release",
        "contract_id": contract["contract_id"],
        "platform": "virtual",
        "wrapping_key_sha256": infer.binding["wrapping_key_sha256"],
        "nonce": b64url(uuid.uuid4().bytes),
    }
    bh = binding_hash(binding)
    rel = {"binding": binding, "wrappingKey": infer.wrapping_pem}
    err(kms.post(f"/outputs/{contract['contract_id']}/release", {**rel, "attestation": {"platform": "virtual", "binding_hash": bh, "virtual_id": "virtual-dev"}}), 403, "measurement_not_approved")
    out = ok(kms.post(f"/outputs/{contract['contract_id']}/release", {**rel, "attestation": {"platform": "virtual", "binding_hash": bh, "virtual_id": "virtual-infer"}}))
    raw = infer.unwrap(out["keys"][0]["wrapped"])
    pub = X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes_raw()
    assert b64url(pub) == key["x25519"]
    world["tee_contract"], world["tee_digest"] = contract, d


def test_suspend_dataset(cs, kms, world):
    contract, d = world["tee_contract"], world["tee_digest"]

    def try_release():
        ccr, r = authorize(cs, contract, d)
        return kms.post("/keys/release", release_body(ccr, ok(r)["rat"]))

    path = f"/datasets/{DATASET}"
    ok(kms.signed("POST", f"{path}/suspend", TDP, "dataset.suspend", {"dataset_id": DATASET, "reason": "incident"}))
    err(try_release(), 403, "dataset_suspended")
    # governance cannot lift an owner suspension
    err(kms.propose(M1, [{"name": "resume_dataset", "args": {"dataset_id": DATASET, "reason": "x"}}]), 409, "not_suspended")
    ok(kms.signed("POST", f"{path}/resume", TDP, "dataset.resume", {"dataset_id": DATASET}))
    ok(try_release())
    kms.govern(MEMBERS, [{"name": "suspend_dataset", "args": {"dataset_id": DATASET, "reason": "dc"}}])
    assert ok(kms.get(path))["state"] == "suspended"
    err(try_release(), 403, "dataset_suspended")
    kms.govern(MEMBERS, [{"name": "resume_dataset", "args": {"dataset_id": DATASET, "reason": "ok"}}])
    ok(try_release())


def test_key_rotation(kms):
    d = ok(kms.signed("POST", f"/datasets/{DATASET}/rotate", TDP, "dataset.rotate", {"dataset_id": DATASET}))
    assert [k["state"] for k in d["keys"]] == ["previous", "current"]


def test_policy_denies(cs, kms, world):
    """Owner tightens the policy; releases fail immediately."""
    contract, d = world["tee_contract"], world["tee_digest"]
    policy = ok(kms.get(f"/datasets/{DATASET}"))["policy"]
    tight = {**policy, "allowed_output_modes": ["tdc"]}
    ok(kms.signed("PUT", f"/datasets/{DATASET}/policy", TDP, "dataset.set_policy", {"dataset_id": DATASET, "policy": tight}))
    ccr, r = authorize(cs, contract, d)
    err(kms.post("/keys/release", release_body(ccr, ok(r)["rat"])), 403, "policy_denied")
    ok(kms.signed("PUT", f"/datasets/{DATASET}/policy", TDP, "dataset.set_policy", {"dataset_id": DATASET, "policy": policy}))
    assert len(ok(kms.get(f"/datasets/{DATASET}/policy/history"))["versions"]) == 3


def test_revoke_contract(cs, kms, world):
    contract, d = world["contract"], world["contract_digest"]
    cid = contract["contract_id"]
    err(cs.signed("POST", f"/contracts/{cid}/revoke", TDP, "contract.revoke", {"contract_id": str(uuid.uuid4()), "reason": "x"}), 400)
    ok(cs.signed("POST", f"/contracts/{cid}/revoke", TDP, "contract.revoke", {"contract_id": cid, "reason": "consent withdrawn"}))
    assert ok(cs.get(f"/contracts/{cid}"))["state"] == "revoked"
    err(authorize(cs, contract, d)[1], 403, "contract_not_active")
    # an in-flight run cannot refresh its RAT after revocation
    ccr2 = world["ccr2"]
    err(cs.post(f"/contracts/{cid}/runs/{ccr2.run_id}/rat", {"jws": ccr2.refresh_request()}), 403, "contract_not_active")
    # governance revocation of the second contract
    tee = world["tee_contract"]
    cs.govern(MEMBERS, [{"name": "revoke_contract", "args": {"contract_id": tee["contract_id"], "reason": "dc decision"}}])
    assert ok(cs.get(f"/contracts/{tee['contract_id']}"))["revocation"]["by"] == "dc-governance"
    err(authorize(cs, tee, world["tee_digest"])[1], 403, "contract_not_active")


def test_revoked_release_blocks_new_runs(cs, kms, world):
    """Revoking the release in the KMS registry blocks key release even with a valid RAT."""
    contract = make_contract(releases=(VIRTUAL_RELEASE,))
    d = activate(cs, contract)
    ccr, r = authorize(cs, contract, d)
    rat = ok(r)["rat"]
    kms.govern(MEMBERS, [{"name": "revoke_ccr_release", "args": {"release_id": VIRTUAL_RELEASE}}])
    err(kms.post("/keys/release", release_body(ccr, rat)), 403, "measurement_not_approved")
    cs.govern(MEMBERS, [{"name": "revoke_ccr_release", "args": {"release_id": VIRTUAL_RELEASE}}])
    err(authorize(cs, contract, d)[1], 403, "measurement_not_approved")


def test_signed_request_replay_and_freshness(kms, cs):
    jws = TDP.sign_request("depa-kms", "dataset.create", {"dataset_id": "bank-a/replay-test"})
    ok(kms.post("/datasets", {"jws": jws}))
    err(kms.post("/datasets", {"jws": jws}), 401, "replay")
    stale = TDP.sign_request("depa-kms", "dataset.create", {"dataset_id": "bank-a/stale"}, iat=int(time.time()) - 600)
    err(kms.post("/datasets", {"jws": stale}), 401, "stale_request")
    wrong_aud = TDP.sign_request("depa-contract-service", "dataset.create", {"dataset_id": "bank-a/aud"})
    err(kms.post("/datasets", {"jws": wrong_aud}), 401, "wrong_audience")
    wrong_op = TDP.sign_request("depa-kms", "dataset.rotate", {"dataset_id": "bank-a/op"})
    err(kms.post("/datasets", {"jws": wrong_op}), 401, "wrong_operation")
    payload = {"aud": "depa-kms", "op": "dataset.create", "iat": int(time.time()), "jti": str(uuid.uuid4()), "body": {"dataset_id": "bank-a/der"}}
    der = jws_es256_der({"kid": "bank-a#k1", "typ": "depa-request+jws"}, payload, TDP.key)
    err(kms.post("/datasets", {"jws": der}), 401, "invalid_signature")


def test_ledger_receipt(cs, world):
    txid = world["txid"]
    for _ in range(30):
        r = cs.get("/receipt", params={"transaction_id": txid})
        if r.status_code == 200:
            body = r.json()
            assert body["transaction_id"] == txid
            assert "signature" in body["receipt"] and "leaf_components" in body["receipt"]
            assert body["receipt"]["leaf_components"].get("claims_digest")
            return
        assert r.status_code == 202, r.text
        time.sleep(1)
    pytest.fail("receipt not available")


def test_snp_evidence_verified_by_ccf(cs, kms):
    """A recorded ACI SEV-SNP attestation (fixture from the DEPA-inferencing KMS)
    passes CCF's verifySnpAttestation (report, VCEK chain, UVM endorsements);
    the services then reject it because REPORT_DATA does not carry our binding."""
    snp = json.loads((Path(__file__).parents[2] / "packages" / "depa-ccf-common" / "test" / "fixtures" / "snp-aci.json").read_text())
    snp.pop("endorsed_tcb")  # fixture encodes it in the pre-CCF-6 byte order
    for svc, path in ((cs, "/contracts/{cid}/runs"), (kms, "/keys/release")):
        ccr = Ccr(str(uuid.uuid4()), "sha256:" + "0" * 64, "sha256:" + "0" * 64, "aci-snp")
        att = {"platform": "aci-snp", **snp}
        body = {"binding": ccr.binding, "attestation": att}
        if svc is kms:
            body.update({"rat": "x.y.z", "dataset_id": DATASET, "wrappingKey": ccr.wrapping_pem})
        r = svc.post(path.format(cid=ccr.binding["contract_id"]), body)
        assert err(r, 401, "attestation_invalid")["error"]["message"] == "SNP REPORT_DATA[0..32] does not match the binding hash"
        # tampered evidence fails CCF verification itself
        raw = bytearray(base64.b64decode(snp["evidence"]))
        raw[0x50] ^= 1
        r = svc.post(path.format(cid=ccr.binding["contract_id"]), {**body, "attestation": {**att, "evidence": base64.b64encode(bytes(raw)).decode()}})
        assert "SNP attestation verification failed" in err(r, 401, "attestation_invalid")["error"]["message"]
