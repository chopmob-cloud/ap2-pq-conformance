#!/usr/bin/env python
"""build_v1_fixture.py - regenerate ap2-pqc-v1-algovoi-side.json.

Deterministic where it can be: the ES256 and Ed25519 keys are derived from the
seed strings published in the fixture itself, so anyone can re-derive the private
keys and re-sign the same signed input. Falcon-1024 has no seeded key generation
in pqcrypto, so its TEST-ONLY secret key is emitted in the fixture under
`test_key_material`; it must never be used outside this reference fixture.

Run: python build_v1_fixture.py
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

import pqcrypto.sign.falcon_1024 as falcon

import verify_v1

HERE = Path(__file__).resolve().parent
V0 = HERE / "ap2-pqc-v0-algovoi-side.json"
OUT = HERE / "ap2-pqc-v1-algovoi-side.json"

SEED_ES256 = b"ap2pq-test-key/ES256/v1"
SEED_ED25519 = b"ap2pq-test-key/Ed25519/v1"


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def es256_key() -> ec.EllipticCurvePrivateKey:
    scalar = int.from_bytes(hashlib.sha256(SEED_ES256).digest(), "big")
    return ec.derive_private_key(scalar, ec.SECP256R1())


def ed25519_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(SEED_ED25519).digest())


def main() -> int:
    duty = json.loads(V0.read_text(encoding="utf-8"))["mandate_body"]

    # --- keys -------------------------------------------------------------
    ec_priv = es256_key()
    ec_der = ec_priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ed_priv = ed25519_key()
    ed_pub = ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    fal_pub, fal_sk = falcon.generate_keypair()

    # The signed descriptor: sorted by key_id so the ordering is itself canonical.
    signers = sorted(
        [
            {"algorithm": "ES256", "key_id": hashlib.sha256(ec_der).hexdigest()},
            {"algorithm": "Ed25519", "key_id": hashlib.sha256(ed_pub).hexdigest()},
            {"algorithm": "Falcon-1024", "key_id": hashlib.sha256(fal_pub).hexdigest()},
        ],
        key=lambda s: s["key_id"],
    )

    art = {
        "schema_version": "1.0",
        "artefact_id": "ap2-pqc-v1-algovoi-side",
        "published_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "supersedes": "ap2-pqc-v0-algovoi-side",
        "object_type": "PaymentMandate",
        "canonicalizer": "rfc8785@0.1.4",
        "anchored_to": {
            "thread": "https://github.com/google-agentic-commerce/AP2/issues/250",
            "report": "AP2 #250 comment 7127315451 (2026-11-24, @eltociear) on hybrid separation / stripping",
            "reporter": {
                "name": "Ikko Eltociear Ashimine",
                "login": "eltociear",
                "comment": "https://github.com/google-agentic-commerce/AP2/issues/250#issuecomment-7127315451",
                "profile": "https://github.com/eltociear/pqam",
            },
            "schema": "google-agentic-commerce/AP2 PaymentMandate v0.1",
            "rfc": "RFC 8785 (JCS)",
        },
        "signing_construction": (
            "signed_input = 'AP2PQC/1.0/' + object_type + 0x00 "
            "+ jcs(mandate_body) + 0x00 + jcs(signer_set)"
        ),
        "mandate_body": duty,
        "signer_set": {"signers": signers},
        "seed_material": {
            "ES256": SEED_ES256.decode("ascii"),
            "Ed25519": SEED_ED25519.decode("ascii"),
            "derivation": "private_key = sha256(seed), interpreted as the raw private key",
        },
    }

    message = verify_v1.signed_input(art)
    jcs_body = verify_v1.jcs(duty)

    art["expected_jcs_bytes_b64"] = b64e(jcs_body)
    art["expected_jcs_bytes_hex"] = jcs_body.hex()
    art["expected_jcs_bytes_length"] = len(jcs_body)
    art["expected_canonical_sha256"] = "sha256:" + hashlib.sha256(jcs_body).hexdigest()
    art["expected_signed_input_sha256"] = "sha256:" + hashlib.sha256(message).hexdigest()

    art["signatures"] = {
        "ES256": {
            "algorithm": "ES256",
            "curve": "P-256",
            "hash": "SHA-256",
            "publicKeyDer": b64e(ec_der),
            "signature_der": b64e(ec_priv.sign(message, ec.ECDSA(verify_v1.hashes.SHA256()))),
        },
        "Ed25519": {
            "algorithm": "Ed25519",
            "publicKey_b64": b64e(ed_pub),
            "signature_b64": b64e(ed_priv.sign(message)),
        },
        "Falcon-1024": {
            "algorithm": "Falcon-1024",
            "family": "PQC (FIPS 206 / FN-DSA, NIST L5)",
            "publicKey_b64": b64e(fal_pub),
            "signature_b64": b64e(falcon.sign(fal_sk, message)),
        },
    }

    art["test_key_material"] = {
        "note": "TEST KEYS ONLY - reference fixture, never production material",
        "falcon_1024_secret_key_b64": b64e(fal_sk),
    }

    OUT.write_text(json.dumps(art, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {OUT.name}")
    print(f"  mandate JCS bytes: {len(jcs_body)}")
    print(f"  signed input:      {len(message)} bytes")
    print(f"  signers:           {[s['algorithm'] for s in signers]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())