# Copyright (c) iSPIRT Foundation.
# Licensed under the MIT license.
"""Session fixtures: two CCF virtual sandboxes (KMS and CS) with fresh state.

Environment:
  DEPA_KMS_REPO / DEPA_CS_REPO  paths to the two repositories
                                (default: siblings of this repository)
  DEPA_KMS_PORT / DEPA_CS_PORT  sandbox ports (default 18010 / 18011)
  DEPA_KEEP_SANDBOX=1           leave the sandboxes running after the tests
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from depa_client import Service, b64url

GCA_ISSUER = "https://confidentialcomputing.googleapis.com"
HERE = Path(__file__).resolve()
REPO = HERE.parents[2]
KMS_REPO = Path(os.environ.get("DEPA_KMS_REPO", REPO.parent / "depa-training-kms-azure"))
CS_REPO = Path(os.environ.get("DEPA_CS_REPO", REPO.parent / "contract-service"))
KMS_PORT = int(os.environ.get("DEPA_KMS_PORT", "18010"))
CS_PORT = int(os.environ.get("DEPA_CS_PORT", "18011"))


class GcaIssuer:
    """Stand-in for Google Cloud Attestation: an RS256 key registered with CCF
    under the real GCA issuer name, so the CCF JWT policy path is exercised."""

    def __init__(self, workdir: Path):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = str(uuid.uuid4())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "confidentialcomputing.googleapis.com")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(self.key, hashes.SHA256())
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        self.issuer_file = workdir / "gca_issuer.json"
        self.issuer_file.write_text(
            json.dumps(
                {
                    "issuer": GCA_ISSUER,
                    "auto_refresh": False,
                    "jwks": {"keys": [{"kty": "RSA", "kid": self.kid, "x5c": [base64.b64encode(der).decode()], "issuer": GCA_ISSUER}]},
                }
            )
        )

    def token(self, audience: str, nonce_hex: str, **overrides) -> str:
        now = int(time.time())
        claims = {
            "iss": GCA_ISSUER,
            "aud": audience,
            "sub": "https://www.googleapis.com/compute/v1/projects/depa-test/zones/asia-south1-a/instances/ccr-1",
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
            "eat_nonce": [nonce_hex],
            "secboot": True,
            "oemid": 11129,
            "hwmodel": "GCP_INTEL_TDX",
            "swname": "CONFIDENTIAL_SPACE",
            "swversion": ["250301"],
            "dbgstat": "disabled-since-boot",
            "submods": {
                "confidential_space": {"support_attributes": ["LATEST", "STABLE", "USABLE"]},
                "container": {
                    "image_reference": "ghcr.io/ispirt/depa-ccr-classic@sha256:" + "ab" * 32,
                    "image_digest": "sha256:" + "ab" * 32,
                },
                "gce": {"project_id": "depa-test", "zone": "asia-south1-a"},
            },
        }
        for k, v in overrides.items():
            if v is None:
                claims.pop(k, None)
            else:
                claims[k] = v
        header = {"alg": "RS256", "kid": self.kid, "typ": "JWT"}
        signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
        sig = self.key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input}.{b64url(sig)}"


def _sandbox_up(repo: Path, port: int, issuer: Path) -> dict:
    out = subprocess.run(
        [str(repo / "scripts" / "sandbox-up.sh"), str(port), "--jwt-issuer", str(issuer), "--recreate"],
        check=True,
        capture_output=True,
        text=True,
        timeout=600,
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="session")
def gca(tmp_path_factory) -> GcaIssuer:
    return GcaIssuer(tmp_path_factory.mktemp("gca"))


@pytest.fixture(scope="session")
def services(gca):
    kms_info = _sandbox_up(KMS_REPO, KMS_PORT, gca.issuer_file)
    cs_info = _sandbox_up(CS_REPO, CS_PORT, gca.issuer_file)
    yield Service("depa-kms", kms_info), Service("depa-contract-service", cs_info)
    if os.environ.get("DEPA_KEEP_SANDBOX") != "1":
        subprocess.run([str(KMS_REPO / "scripts" / "sandbox-down.sh"), str(KMS_PORT)], check=False)
        subprocess.run([str(CS_REPO / "scripts" / "sandbox-down.sh"), str(CS_PORT)], check=False)


@pytest.fixture(scope="session")
def kms(services) -> Service:
    return services[0]


@pytest.fixture(scope="session")
def cs(services) -> Service:
    return services[1]


@pytest.fixture(scope="session")
def world() -> dict:
    """Mutable state shared by the ordered end-to-end tests."""
    return {}
