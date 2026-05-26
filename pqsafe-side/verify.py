#!/usr/bin/env python3
"""Standalone verifier — PQSafe ML-DSA-65 (FIPS 204) side of the AP2 #250 joint fixture.

Recomputes the canonical SHA-256 and verifies the ML-DSA-65 signature over the
IDENTICAL canonical byte sequence used by the AlgoVoi-side fixture
(expected_canonical_sha256 = cc8315f7...e0). By construction interoperable with
algovoi-side/ap2-pqc-v0-algovoi-side.json.

    pip install pqcrypto
    python verify.py ap2-pqc-v0-pqsafe-side.json
"""
import sys, json, base64, hashlib
from pqcrypto.sign import ml_dsa_65

ALGOVOI_JCS_HEX = (
    "7b22616d6f756e74223a7b2263757272656e6379223a22555344222c226d696e6f725f756e69"
    "7473223a343939357d2c22636f6e73747261696e7473223a5b7b2274797065223a226d657263"
    "68616e745f69645f616c6c6f776c697374222c2276616c7565223a5b226469643a7765623a6d"
    "65726368616e742e6578616d706c652e636f6d225d7d2c7b2274797065223a22657870697279"
    "5f756e69785f6d73222c2276616c7565223a313738323235393230303030307d5d2c22697373"
    "7565645f6174223a22323032362d30352d32315430303a30303a30305a222c226973737565"
    "645f61745f6d73223a313737393636373230303030302c22697373756572223a226469643a77"
    "65623a77616c6c65742e6578616d706c652e6f7267222c226d65726368616e74223a22646964"
    "3a7765623a6d65726368616e742e6578616d706c652e636f6d222c226e6f6e6365223a223078"
    "37623563653861346631623961346432222c22736368656d61223a22676f6f676c652d616765"
    "6e7469632d636f6d6d657263652f415032205061796d656e744d616e64617465222c22737562"
    "6a656374223a226469643a7765623a6167656e742e6578616d706c652e6f7267236167656e74"
    "2d37222c22766374223a226d616e646174652e7061796d656e742e31222c2276657273696f6e"
    "223a22302e31227d"
)

def main(path):
    art = json.load(open(path))
    jcs = bytes.fromhex(ALGOVOI_JCS_HEX)
    assert len(jcs) == art["expected_jcs_bytes_length"] == 501, "JCS length mismatch"
    digest = "sha256:" + hashlib.sha256(jcs).hexdigest()
    assert digest == art["expected_canonical_sha256"], f"canonical mismatch: {digest}"
    print(f"canonical sha256 OK: {digest}")
    s = art["signatures"]["ML-DSA-65"]
    pk = base64.b64decode(s["publicKey_b64"])
    sig = base64.b64decode(s["signature_b64"])
    ok = ml_dsa_65.verify(pk, jcs, sig)
    print(f"ML-DSA-65 verify: {'OK' if ok else 'FAIL'}  (pk={len(pk)}B sig={len(sig)}B)")
    if not ok:
        sys.exit(1)
    print("PASS — ML-DSA-65 signature verifies over the identical AP2 #250 canonical bytes.")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "ap2-pqc-v0-pqsafe-side.json")
