#!/usr/bin/env python
"""verify_v1.py - standalone verifier for the AP2 PQC v1 fixture.

v1 closes the hybrid-separation weakness reported on AP2 #250 (comment
2026-11-24): in v0 every scheme signed the same JCS bytes with nothing binding
the halves together, so a verifier holding one half accepted it on its own and
the PQ half could be stripped after Q-Day.

v1 binds two things into the signed input:

    signed_input = b"AP2PQC/1.0/" + object_type + 0x00
                   + jcs(mandate_body) + 0x00 + jcs(signer_set)

  * the object type, so a PaymentMandate signature cannot verify as an Approval
  * the required signer set, so the verifier learns which halves are required
    from the signed bytes rather than from local policy

Verification fails closed: every signer listed in the signed descriptor must be
present with a matching key_id, and an unknown algorithm is a failure, not a
skip. Stripping any half therefore fails, in both directions.

Usage:
    pip install rfc8785==0.1.4 cryptography pqcrypto
    python verify_v1.py ap2-pqc-v1-algovoi-side.json
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

import pqcrypto.sign.falcon_1024 as falcon

DOMAIN = b"AP2PQC/1.0/"
SEP = b"\x00"

# Open-enum per the agreed AP2 #250 convention: these are the identifiers this
# verifier can actually check. Anything else is a fail-closed error.
KNOWN_ALGORITHMS = frozenset({"ES256", "Ed25519", "Falcon-1024", "ML-DSA-65"})
KNOWN_OBJECT_TYPES = frozenset({"PaymentMandate", "Approval", "Receipt"})


@dataclass
class Result:
    ok: bool
    errors: list[str] = field(default_factory=list)
    required: list[str] = field(default_factory=list)
    present: list[str] = field(default_factory=list)


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def jcs(obj) -> bytes:
    return rfc8785.dumps(obj)


def signed_input(art: dict) -> bytes:
    """The bytes every signature in a v1 artefact signs."""
    return (
        DOMAIN
        + art["object_type"].encode("utf-8")
        + SEP
        + jcs(art["mandate_body"])
        + SEP
        + jcs(art["signer_set"])
    )


def public_key_bytes(alg: str, entry: dict) -> bytes:
    """The canonical public-key bytes a key_id is derived from."""
    if alg == "ES256":
        return b64d(entry["publicKeyDer"])
    return b64d(entry["publicKey_b64"])


def key_id(alg: str, entry: dict) -> str:
    return hashlib.sha256(public_key_bytes(alg, entry)).hexdigest()


def requires_known_algorithms(signer_set: dict) -> bool:
    if not isinstance(signer_set, dict):
        return False
    signers = signer_set.get("signers") or []
    if not isinstance(signers, list):
        return False
    return bool(signers) and all(s.get("algorithm") in KNOWN_ALGORITHMS for s in signers)


def _verify_one(alg: str, entry: dict, message: bytes) -> str | None:
    """Return None on success, else an error string."""
    try:
        if alg == "ES256":
            pub = serialization.load_der_public_key(b64d(entry["publicKeyDer"]))
            pub.verify(b64d(entry["signature_der"]), message, ec.ECDSA(hashes.SHA256()))
        elif alg == "Ed25519":
            pub = ed25519.Ed25519PublicKey.from_public_bytes(b64d(entry["publicKey_b64"]))
            pub.verify(b64d(entry["signature_b64"]), message)
        elif alg == "Falcon-1024":
            if not falcon.verify(b64d(entry["publicKey_b64"]), message, b64d(entry["signature_b64"])):
                return "Falcon-1024 verification returned False"
        else:
            # ML-DSA-65 is accepted in the descriptor but this single-file
            # verifier cannot check it; it must never be silently skipped.
            return f"algorithm {alg} listed but not verifiable by this verifier"
    except Exception as exc:  # noqa: BLE001 - any failure is a failed verification
        return f"{alg} verification failed: {exc}"
    return None


def verify(art: dict) -> Result:
    errors: list[str] = []

    object_type = art.get("object_type")
    if object_type not in KNOWN_OBJECT_TYPES:
        errors.append(f"unknown_object_type: {object_type!r}")

    signer_set = art.get("signer_set")
    if not isinstance(signer_set, dict):
        errors.append("signer_set is not an object")
        signer_set = {}
    if not requires_known_algorithms(signer_set):
        errors.append("signer_set lists no signers, or an unknown algorithm")

    required = [s.get("algorithm") for s in (signer_set.get("signers") or [])]
    signatures = art.get("signatures")
    if not isinstance(signatures, dict):
        errors.append("signatures is not an object")
        signatures = {}
    present = list(signatures)

    # Fail closed on a stripped half: required comes from the SIGNED descriptor.
    for alg in required:
        if alg is None:
            errors.append("signer_set entry with no algorithm")
        elif alg not in signatures:
            errors.append(f"missing signature for required signer: {alg}")

    # Fail closed on an unlisted extra half, which would otherwise let an
    # attacker add a signature the descriptor never asked for.
    for alg in present:
        if alg not in required:
            errors.append(f"signature present for unlisted signer: {alg}")
        if alg not in KNOWN_ALGORITHMS:
            errors.append(f"unknown algorithm in signatures: {alg}")

    # key_id binds the published key to the signed descriptor.
    for signer in signer_set.get("signers", []):
        alg = signer.get("algorithm")
        entry = signatures.get(alg)
        if entry is None:
            continue
        try:
            if signer.get("key_id") and signer["key_id"] != key_id(alg, entry):
                errors.append(f"key_id mismatch for {alg}")
        except (KeyError, ValueError, TypeError) as exc:
            errors.append(f"malformed signature entry for {alg}: {exc}")

    message = b""
    if object_type in KNOWN_OBJECT_TYPES:
        try:
            message = signed_input(art)
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"malformed artefact: signed_input needs {exc}")

    if message:
        for alg, entry in signatures.items():
            err = _verify_one(alg, entry, message)
            if err:
                errors.append(err)

        expected = art.get("expected_signed_input_sha256", "").removeprefix("sha256:")
        if expected and expected != hashlib.sha256(message).hexdigest():
            errors.append("signed_input digest mismatch against expected_signed_input_sha256")

    return Result(ok=not errors, errors=errors, required=required, present=present)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: verify_v1.py ap2-pqc-v1-algovoi-side.json", file=sys.stderr)
        return 2
    art = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    result = verify(art)
    print(f"object_type:  {art.get('object_type')}")
    print(f"required:     {', '.join(result.required) or '(none)'}")
    print(f"present:      {', '.join(result.present) or '(none)'}")
    if art.get("object_type") in KNOWN_OBJECT_TYPES and art.get("signer_set"):
        message = signed_input(art)
        print(f"signed_input: {len(message)} bytes")
        print(f"  sha256:     {hashlib.sha256(message).hexdigest()}")
    for err in result.errors:
        print(f"  FAIL {err}")
    print()
    print(f"OVERALL: {'all checks pass' if result.ok else 'one or more checks FAILED'}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())