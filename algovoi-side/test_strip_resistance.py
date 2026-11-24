#!/usr/bin/env python
"""Strip-resistance tests for the AP2 PQ conformance fixtures.

`test_v0_is_separable` characterises the weakness reported on AP2 #250 comment
2026-11-24: in the v0 construction every scheme signs the same JCS bytes with
nothing binding the halves together, so a verifier handed only one half accepts
it. The test asserts that weakness is still reproducible on the v0 fixture (it
is history and must not be edited).

`test_v1_*` assert the v1 construction closes it: the signed input carries the
object type and the required signer set, and verification fails closed when a
listed signer is absent, whatever the local policy says.

Run: python -m unittest -v test_strip_resistance
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).resolve().parent
V0 = HERE / "ap2-pqc-v0-algovoi-side.json"
V1 = HERE / "ap2-pqc-v1-algovoi-side.json"

sys.path.insert(0, str(HERE))


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def strip(art: dict, keep: set[str]) -> dict:
    """Return a copy carrying only the named signatures."""
    out = json.loads(json.dumps(art))
    out["signatures"] = {k: v for k, v in art["signatures"].items() if k in keep}
    return out


def resign(art: dict, key_id_override: tuple[str, str] | None = None) -> dict:
    """Re-sign every half with the fixture's published test key material.

    Used to build attacks whose signatures are all valid, so that only the
    guard under test can reject them.
    """
    import base64
    import copy

    import pqcrypto.sign.falcon_1024 as falcon
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed

    import verify_v1 as v1

    out = copy.deepcopy(art)
    if key_id_override:
        alg, kid = key_id_override
        for signer in out["signer_set"]["signers"]:
            if signer["algorithm"] == alg:
                signer["key_id"] = kid

    message = v1.signed_input(out)
    seeds = out["seed_material"]
    ec_priv = ec.derive_private_key(
        int.from_bytes(hashlib.sha256(seeds["ES256"].encode()).digest(), "big"), ec.SECP256R1()
    )
    ed_priv = _ed.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(seeds["Ed25519"].encode()).digest()
    )
    fal_sk = base64.b64decode(out["test_key_material"]["falcon_1024_secret_key_b64"])

    out["signatures"]["ES256"]["signature_der"] = base64.b64encode(
        ec_priv.sign(message, ec.ECDSA(hashes.SHA256()))
    ).decode()
    out["signatures"]["Ed25519"]["signature_b64"] = base64.b64encode(
        ed_priv.sign(message)
    ).decode()
    out["signatures"]["Falcon-1024"]["signature_b64"] = base64.b64encode(
        falcon.sign(fal_sk, message)
    ).decode()
    out["expected_signed_input_sha256"] = "sha256:" + hashlib.sha256(message).hexdigest()
    return out


class TestV0Separable(unittest.TestCase):
    def test_v0_is_separable(self):
        """v0: dropping every half but ES256 still verifies. This is the flaw."""
        art = load(V0)
        canonical = rfc8785.dumps(art["mandate_body"])
        self.assertEqual(
            hashlib.sha256(canonical).hexdigest(),
            art["expected_canonical_sha256"].removeprefix("sha256:"),
            "v0 canonical bytes must still match their published digest",
        )
        only = strip(art, {"ES256"})
        self.assertEqual(list(only["signatures"]), ["ES256"])
        sig = only["signatures"]["ES256"]
        pub = serialization.load_der_public_key(base64.b64decode(sig["publicKeyDer"]))
        # No exception: one half alone is accepted, which is exactly the report.
        pub.verify(base64.b64decode(sig["signature_der"]), canonical, ec.ECDSA(hashes.SHA256()))


class TestV1StripResistant(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not V1.exists():
            raise AssertionError(f"v1 fixture missing: {V1.name}")
        cls.v1 = load(V1)
        import verify_v1
        cls.v = verify_v1

    def test_v1_fixture_verifies_whole(self):
        result = self.v.verify(self.v1)
        self.assertTrue(result.ok, f"whole v1 fixture must verify, got errors {result.errors}")
        self.assertEqual(set(result.present), set(result.required))

    def test_v1_rejects_stripped_pq_half(self):
        """The Q-Day attack: present only the classical signature."""
        stripped = strip(self.v1, {"ES256", "Ed25519"})
        result = self.v.verify(stripped)
        self.assertFalse(result.ok, "a stripped mandate must fail closed")
        self.assertTrue(any("missing" in e for e in result.errors), result.errors)

    def test_v1_rejects_stripped_classical_half(self):
        """The other direction: a PQ-only verifier must not accept on its own."""
        stripped = strip(self.v1, {"Falcon-1024"})
        result = self.v.verify(stripped)
        self.assertFalse(result.ok, "a PQ-only mandate must fail closed")
        self.assertTrue(any("missing" in e for e in result.errors), result.errors)

    def test_v1_rejects_descriptor_substitution(self):
        """Rewriting the signed descriptor to require only the classical half."""
        import copy
        reduced = copy.deepcopy(self.v1)
        keep = [s for s in reduced["signer_set"]["signers"] if s["algorithm"] == "ES256"]
        self.assertEqual(len(keep), 1)
        reduced["signer_set"] = {"signers": keep}
        reduced["signatures"] = {"ES256": reduced["signatures"]["ES256"]}
        reduced["expected_signed_input_sha256"] = "sha256:" + hashlib.sha256(
            self.v.signed_input(reduced)
        ).hexdigest()
        result = self.v.verify(reduced)
        self.assertFalse(result.ok, "a rewritten signer_set must fail: it is inside the signed input")
        self.assertTrue(any("verification failed" in e for e in result.errors), result.errors)

    def test_v1_rejects_wrong_key_id(self):
        """A descriptor naming a key that did not sign, with every signature valid."""
        wrong = resign(self.v1, key_id_override=("ES256", "00" * 32))
        result = self.v.verify(wrong)
        self.assertFalse(result.ok, "key_id mismatch must fail closed")
        self.assertTrue(any("key_id mismatch" in e for e in result.errors), result.errors)

    def test_v1_rejects_unknown_algorithm(self):
        """Fail-closed on an unknown identifier, per the agreed open-enum rule."""
        self.assertFalse(self.v.requires_known_algorithms({"signers": [{"algorithm": "ML-DSA-9999", "key_id": "00"}]}))

    def test_v1_binds_object_type(self):
        """The object type is inside the signed input, so a relabel changes it."""
        self.assertTrue(self.v.signed_input(self.v1).startswith(b"AP2PQC/1.0/PaymentMandate"))
        import copy
        other = copy.deepcopy(self.v1)
        other["object_type"] = "Approval"
        self.assertNotEqual(
            self.v.signed_input(self.v1),
            self.v.signed_input(other),
            "changing the object type must change the signed input",
        )
        # And the artefact signed as a mandate does not verify once relabelled.
        result = self.v.verify(other)
        self.assertFalse(result.ok, "type substitution must fail")

    def test_v1_binds_signer_set(self):
        """The required signer set is inside the signed input."""
        descriptor = self.v.jcs(self.v1["signer_set"])
        self.assertTrue(
            self.v.signed_input(self.v1).endswith(descriptor),
            "the JCS descriptor must be the tail of the signed input",
        )
        import copy
        reduced = copy.deepcopy(self.v1)
        reduced["signer_set"] = {"signers": reduced["signer_set"]["signers"][:1]}
        self.assertNotEqual(
            self.v.signed_input(self.v1),
            self.v.signed_input(reduced),
            "editing the descriptor must change the signed input",
        )

    def test_v1_rejects_extra_unlisted_signature(self):
        """A signature for a signer the descriptor does not list."""
        import copy
        art = copy.deepcopy(self.v1)
        extra = copy.deepcopy(art["signatures"]["ES256"])
        art["signatures"]["ML-DSA-65"] = extra
        result = self.v.verify(art)
        self.assertFalse(result.ok)
        self.assertTrue(any("unlisted signer" in e for e in result.errors), result.errors)

    def test_v1_rejects_digest_mismatch(self):
        """A recorded digest that does not match the recomputed signed input."""
        import copy
        art = copy.deepcopy(self.v1)
        art["expected_signed_input_sha256"] = "sha256:" + "00" * 32
        result = self.v.verify(art)
        self.assertFalse(result.ok)
        self.assertTrue(any("digest mismatch" in e for e in result.errors), result.errors)

    def test_v1_malformed_artefacts_return_a_verdict(self):
        """Missing top-level keys and signer entries must not raise."""
        import copy
        cases = {}
        a = copy.deepcopy(self.v1); del a["signer_set"]; cases["no signer_set"] = a
        b = copy.deepcopy(self.v1); del b["mandate_body"]; cases["no mandate_body"] = b
        c = copy.deepcopy(self.v1)
        c["signer_set"] = {"signers": [{"key_id": "00" * 32}]}
        cases["signer without algorithm"] = c
        d = copy.deepcopy(self.v1); d["signer_set"] = "not-an-object"; cases["signer_set not an object"] = d
        e = copy.deepcopy(self.v1); e["signatures"] = []; cases["signatures not an object"] = e
        f = copy.deepcopy(self.v1); f["mandate_body"] = {"n": float("nan")}; cases["NaN in body"] = f
        for name, art in cases.items():
            with self.subTest(case=name):
                result = self.v.verify(art)  # must not raise
                self.assertFalse(result.ok, f"{name} must fail closed")
                self.assertTrue(result.errors, name)

    def test_v1_signed_input_is_deterministic(self):
        self.assertEqual(self.v.signed_input(self.v1), self.v.signed_input(self.v1))


if __name__ == "__main__":
    unittest.main(verbosity=2)