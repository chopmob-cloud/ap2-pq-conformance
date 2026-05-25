#!/usr/bin/env python
"""
verify.py â€” single-file standalone verifier for the AP2 PQC v0 fixture.

For each signature in the artefact, recomputes JCS canonical bytes from the
mandate body, recomputes SHA-256, and verifies the signature against the
published public key.

Usage:
    pip install rfc8785==0.1.4 cryptography pqcrypto
    python verify.py ap2-pqc-v0-algovoi-side.json
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding

import pqcrypto.sign.falcon_1024 as falcon


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: verify.py ap2-pqc-v0-algovoi-side.json", file=sys.stderr)
        return 2
    art = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))

    # Recompute canonical bytes + sha
    canonical = rfc8785.dumps(art["mandate_body"])
    canonical_sha = hashlib.sha256(canonical).hexdigest()
    expected_sha = art["expected_canonical_sha256"].removeprefix("sha256:")
    expected_b64 = art["expected_jcs_bytes_b64"]
    got_b64 = base64.b64encode(canonical).decode("ascii")

    print(f"canonical bytes length:  {len(canonical)}")
    print(f"  recomputed sha256:     {canonical_sha}")
    print(f"  expected sha256:       {expected_sha}")
    sha_ok = canonical_sha == expected_sha
    b64_ok = got_b64 == expected_b64
    print(f"  sha256 match:          {'OK ' if sha_ok else 'FAIL'}")
    print(f"  base64 bytes match:    {'OK ' if b64_ok else 'FAIL'}")
    print()

    sigs = art["signatures"]
    ok = sha_ok and b64_ok

    # ES256
    if "ES256" in sigs:
        s = sigs["ES256"]
        pub = serialization.load_der_public_key(b64d(s["publicKeyDer"]))
        try:
            pub.verify(b64d(s["signature_der"]), canonical, ec.ECDSA(hashes.SHA256()))
            print("  OK   ES256 (P-256 / SHA-256) verifies")
        except Exception as e:
            print(f"  FAIL ES256: {e}")
            ok = False

    # Ed25519
    if "Ed25519" in sigs:
        s = sigs["Ed25519"]
        pub = ed25519.Ed25519PublicKey.from_public_bytes(b64d(s["publicKey_b64"]))
        try:
            pub.verify(b64d(s["signature_b64"]), canonical)
            print("  OK   Ed25519 verifies")
        except Exception as e:
            print(f"  FAIL Ed25519: {e}")
            ok = False

    # Falcon-1024
    if "Falcon-1024" in sigs:
        s = sigs["Falcon-1024"]
        try:
            if falcon.verify(b64d(s["publicKey_b64"]), canonical, b64d(s["signature_b64"])):
                print("  OK   Falcon-1024 (FIPS 206 / FN-DSA, NIST L5) verifies")
            else:
                print("  FAIL Falcon-1024 verification returned False")
                ok = False
        except Exception as e:
            print(f"  FAIL Falcon-1024: {e}")
            ok = False

    print()
    print(f"OVERALL: {'all checks pass' if ok else 'one or more checks FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
