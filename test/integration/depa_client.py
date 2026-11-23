# Copyright (c) iSPIRT Foundation.
# Licensed under the MIT license.
"""Minimal DEPA Training v2 protocol client used by the integration tests.

Implements spec §2 primitives (JCS digest, ES256 JWS with raw r||s, HPKE,
RSA-OAEP) independently of the TypeScript services so that the tests
cross-check both implementations.
"""

from __future__ import annotations

import base64
import hashlib
import json
import ssl
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import requests
import requests.adapters
import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def binding_hash(binding: dict) -> str:
    return hashlib.sha256(rfc8785.dumps(binding)).hexdigest()


def ec_public_jwk(key: ec.EllipticCurvePrivateKey, kid: str | None = None) -> dict:
    nums = key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(nums.x.to_bytes(32, "big")),
        "y": b64url(nums.y.to_bytes(32, "big")),
    }
    if kid is not None:
        jwk["kid"] = kid
    return jwk


def jws_es256(header: dict, payload: Any, key: ec.EllipticCurvePrivateKey) -> str:
    h = b64url(json.dumps({**header, "alg": "ES256"}, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    der = key.sign(f"{h}.{p}".encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return f"{h}.{p}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def jws_es256_der(header: dict, payload: Any, key: ec.EllipticCurvePrivateKey) -> str:
    """A (non-compliant) JWS carrying a DER signature; services must reject it."""
    h = b64url(json.dumps({**header, "alg": "ES256"}, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    der = key.sign(f"{h}.{p}".encode(), ec.ECDSA(hashes.SHA256()))
    return f"{h}.{p}.{b64url(der)}"


def jwk_to_ec_public(jwk: dict) -> ec.EllipticCurvePublicKey:
    x = int.from_bytes(b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def verify_jws(jws: str, jwks: list[dict], typ: str) -> dict:
    """Verifies an ES256 compact JWS against a JWKS; returns the payload."""
    h, p, s = jws.split(".")
    header = json.loads(b64url_decode(h))
    assert header["alg"] == "ES256" and header["typ"] == typ, header
    key = next(k for k in jwks if k["kid"] == header["kid"])
    sig = b64url_decode(s)
    assert len(sig) == 64
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    jwk_to_ec_public(key).verify(der, f"{h}.{p}".encode(), ec.ECDSA(hashes.SHA256()))
    return json.loads(b64url_decode(p))


def jws_payload(jws: str) -> dict:
    return json.loads(b64url_decode(jws.split(".")[1]))


@dataclass
class Signer:
    """A party with an ES256 signing key and an X25519 HPKE key."""

    party_id: str
    roles: list[str]
    name: str = ""
    kid: str = "k1"
    key: ec.EllipticCurvePrivateKey = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))
    hpke_kid: str = "h1"
    hpke_x25519: str = field(default_factory=lambda: b64url(bytes(range(32))))

    def record(self) -> dict:
        return {
            "party_id": self.party_id,
            "name": self.name or self.party_id,
            "roles": self.roles,
            "signing_keys": [ec_public_jwk(self.key, self.kid)],
            "hpke_public_keys": [{"kid": self.hpke_kid, "x25519": self.hpke_x25519}],
            "status": "active",
        }

    def sign_request(self, aud: str, op: str, body: Any, iat: int | None = None, jti: str | None = None) -> str:
        payload = {
            "aud": aud,
            "op": op,
            "iat": int(time.time()) if iat is None else iat,
            "jti": jti or str(uuid.uuid4()),
            "body": body,
        }
        header = {"kid": f"{self.party_id}#{self.kid}", "typ": "depa-request+jws"}
        return jws_es256(header, payload, self.key)


class _CcfTlsAdapter(requests.adapters.HTTPAdapter):
    """Verifies against the CCF service certificate. CCF's self-signed service
    certificate has no keyUsage extension, which Python >= 3.13 rejects under
    VERIFY_X509_STRICT; the chain, hostname and expiry are still verified."""

    def __init__(self, cafile: str, client_cert: tuple[str, str] | None = None):
        self._ctx = ssl.create_default_context(cafile=cafile)
        self._ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        if client_cert:
            self._ctx.load_cert_chain(*client_cert)
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx
        return super().init_poolmanager(*args, **kwargs)


def ccf_session(cafile: str, client_cert: tuple[str, str] | None = None) -> requests.Session:
    s = requests.Session()
    s.mount("https://", _CcfTlsAdapter(cafile, client_cert))
    return s


class Service:
    def __init__(self, name: str, info: dict):
        self.name = name  # "depa-kms" | "depa-contract-service"
        self.info = info
        self.url = info["app_url"]
        self.s = ccf_session(info["service_cert"])

    def get(self, path: str, **kw) -> requests.Response:
        return self.s.get(self.url + path, timeout=30, **kw)

    def post(self, path: str, body: Any = None, **kw) -> requests.Response:
        return self.s.post(self.url + path, json=body, timeout=30, **kw)

    def put(self, path: str, body: Any = None, **kw) -> requests.Response:
        return self.s.put(self.url + path, json=body, timeout=30, **kw)

    def signed(self, method: str, path: str, signer: Signer, op: str, body: Any, **kw) -> requests.Response:
        jws = signer.sign_request(self.name, op, body)
        return self.s.request(method, self.url + path, json={"jws": jws}, timeout=30, **kw)

    def bootstrap(self, members: list[Signer], settings: dict) -> requests.Response:
        operator = ccf_session(self.info["service_cert"], (self.info["user_cert"], self.info["user_key"]))
        return operator.post(
            self.url + "/gov/bootstrap",
            json={"members": [m.record() for m in members], "threshold": {"default": "majority"}, "settings": settings},
            timeout=30,
        )

    def propose(self, member: Signer, actions: list[dict]) -> requests.Response:
        return self.signed("POST", "/gov/proposals", member, "gov.propose", {"actions": actions})

    def vote(self, member: Signer, proposal_id: str, vote: str = "approve") -> requests.Response:
        return self.signed(
            "POST",
            f"/gov/proposals/{proposal_id}/ballots",
            member,
            "gov.vote",
            {"proposal_id": proposal_id, "vote": vote},
        )

    def govern(self, members: list[Signer], actions: list[dict]) -> dict:
        """Proposes and approves with every member until accepted."""
        r = self.propose(members[0], actions)
        assert r.status_code == 200, r.text
        pid = r.json()["proposal_id"]
        for m in members:
            r = self.vote(m, pid)
            assert r.status_code == 200, r.text
            if r.json()["state"] == "accepted":
                return r.json()
        raise AssertionError(f"proposal {pid} not accepted: {r.text}")


def trust_bundle(cs: "Service", kms: "Service") -> dict:
    """The CCR trust bundle (spec §9.1) built from the services' /info and TLS certs."""

    def entry(svc: Service) -> dict:
        with open(svc.info["service_cert"]) as f:
            pem = f.read()
        return {"url": svc.url, "service_cert_pem": pem, "jwks": svc.get("/info").json()["jwks"]}

    return {"v": 1, "cs": entry(cs), "kms": entry(kms)}


class Ccr:
    """Simulated clean room: run material generated "in TEE memory"."""

    # Set by the tests once governance has approved a trust bundle.
    default_trust_bundle_digest = "sha256:" + "e" * 64

    def __init__(self, contract_id: str, contract_digest: str, recipe_digest: str, platform: str, trust_bundle_digest: str | None = None):
        self.run_id = str(uuid.uuid4())
        self.wrapping_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.wrapping_pem = (
            self.wrapping_key.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )
        self.run_key = ec.generate_private_key(ec.SECP256R1())
        self.binding = {
            "v": 1,
            "contract_id": contract_id,
            "contract_digest": contract_digest,
            "run_id": self.run_id,
            "recipe_digest": recipe_digest,
            "platform": platform,
            "wrapping_key_sha256": hashlib.sha256(self.wrapping_pem.encode()).hexdigest(),
            "run_key": ec_public_jwk(self.run_key),
            "trust_bundle_digest": trust_bundle_digest or Ccr.default_trust_bundle_digest,
        }
        self.binding_hash = binding_hash(self.binding)
        self.seq = 0

    def virtual_attestation(self, virtual_id: str = "virtual-dev") -> dict:
        return {"platform": "virtual", "binding_hash": self.binding_hash, "virtual_id": virtual_id}

    def unwrap(self, wrapped_b64: str) -> bytes:
        return self.wrapping_key.decrypt(
            base64.b64decode(wrapped_b64),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

    def event(self, etype: str, data: Any, seq: int | None = None) -> str:
        if seq is None:
            seq = self.seq
            self.seq += 1
        payload = {
            "run_id": self.run_id,
            "seq": seq,
            "type": etype,
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "data": data,
        }
        return jws_es256({"typ": "depa-run-event+jws"}, payload, self.run_key)

    def refresh_request(self, op: str = "run.refresh_rat", iat: int | None = None) -> str:
        """RAT refresh request (spec §9.3a), signed with the run key."""
        payload = {
            "op": op,
            "contract_id": self.binding["contract_id"],
            "run_id": self.run_id,
            "iat": int(time.time()) if iat is None else iat,
            "jti": str(uuid.uuid4()),
        }
        return jws_es256({"typ": "depa-run-event+jws"}, payload, self.run_key)
