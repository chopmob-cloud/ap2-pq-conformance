# AP2 PQC conformance fixture v0 â€” AlgoVoi side

Joint cross-implementor fixture for [AP2 #250](https://github.com/google-agentic-commerce/AP2/issues/250) (Post-Quantum Extension to AP2). AlgoVoi-side artefact carrying ECDSA (ES256) + Ed25519 + Falcon-1024 signatures over a single AP2 `PaymentMandate` canonical byte sequence. The `expected_canonical_sha256` is the digest both sides sign â€” @rayc0 supplies ML-DSA-65 (FIPS 204) over the identical canonical bytes plus the 240-vector ML-DSA-65 set, by construction interoperable with this fixture.

## Files

| File | Purpose |
|---|---|
| `ap2-pqc-v0-algovoi-side.json` | The artefact â€” mandate body, canonical bytes (base64 + hex), `expected_canonical_sha256`, three signatures (ES256, Ed25519, Falcon-1024) with their public keys, plus the agreed informative algorithm-identifier table |
| `verify.py` | Single-file standalone verifier â€” reads the artefact, recomputes JCS canonical bytes, recomputes SHA-256, verifies each signature against the published public key |

## How the fixture is built

```
JCS_bytes      = rfc8785(PaymentMandate body)
canonical_sha  = sha256_hex(JCS_bytes)

ES256_sig       = ECDSA(ES256, ecdsa_priv).sign(JCS_bytes)
Ed25519_sig     = Ed25519(ed_priv).sign(JCS_bytes)
Falcon-1024_sig = Falcon-1024(fal_sk).sign(JCS_bytes)
```

The same canonical byte string feeds every signature operation. JCS is the substrate; the signature scheme is a routing choice on top of it.

## Reproduce locally

```bash
pip install rfc8785==0.1.4 cryptography pqcrypto
python verify.py ap2-pqc-v0-algovoi-side.json
```

Expected output: each signature verifies against the published public key over the recomputed canonical bytes; the recomputed SHA-256 matches `expected_canonical_sha256` byte-for-byte.

## Algorithm-identifier table (informative)

The convention agreed with @rayc0 on AP2 #250 on 2026-05-16. Open-enum on `signature_algorithm`; verifiers MUST treat unknown values as opaque and refuse to verify (fail-closed). Recommended-values list is informative, not normative â€” implementors retain latitude as the IETF PQC naming converges.

| Identifier | Family | Source | Notes |
|---|---|---|---|
| `ECDSA` | Classical | Generic ECDSA | Backward-compat alias for AP2 v0.1; new deployments SHOULD use `ES256` / `ES256K` / `ES384` / `ES512`. |
| `ES256` | Classical | RFC 7518 Â§3.4 | ECDSA P-256 SHA-256 |
| `ES256K` | Classical | RFC 8812 | ECDSA secp256k1 SHA-256 |
| `Ed25519` | Classical | RFC 8032 / RFC 8037 | EdDSA Ed25519 |
| `ML-DSA-44` | PQC | FIPS 204 / draft-ietf-cose-dilithium | NIST Level 2 |
| `ML-DSA-65` | PQC | FIPS 204 / draft-ietf-cose-dilithium | NIST Level 3 (@rayc0 default) |
| `ML-DSA-87` | PQC | FIPS 204 / draft-ietf-cose-dilithium | NIST Level 5 |
| `Falcon-512` | PQC | FIPS 206 (FN-DSA) | NIST Level 1 |
| `Falcon-1024` | PQC | FIPS 206 (FN-DSA) | NIST Level 5 (AlgoVoi default) |
| `SLH-DSA-SHA2-128s` | PQC stateless-hash | FIPS 205 | SPHINCS+ small |
| `HMAC-SHA-256` | HMAC | RFC 2104 | Internal-channel only |
| `HMAC-SHA-384` | HMAC | RFC 2104 / FIPS 198-1 | PQC-conservative HMAC |

## v1 signed input

`ap2-pqc-v1-algovoi-side.json` supersedes the v0 artefact for the hybrid-separation
weakness reported on [AP2 #250](https://github.com/google-agentic-commerce/AP2/issues/250)
on 2026-11-24. The canonical substrate is unchanged: the same 501-byte JCS
`PaymentMandate`. What changes is the bytes the signatures cover.

```
signed_input = "AP2PQC/1.0/" + object_type + 0x00 + JCS(mandate_body) + 0x00 + JCS(signer_set)
```

| Element | Why it is there |
|---|---|
| `"AP2PQC/1.0/"` | domain tag, so the preimage cannot collide with another protocol using the same base |
| `object_type` | a `PaymentMandate` signature no longer verifies once the artefact is relabelled `Approval` or `Receipt` |
| `JCS(signer_set)` | the required signer set is inside the signed bytes, so it cannot be downgraded without invalidating every signature |

Verification fails closed: every signer listed in `signer_set` must be present with a
matching `key_id`, a signature for a signer the descriptor does not list is an error,
and an unknown algorithm is a failure rather than a skip.

| File | Purpose |
|---|---|
| `ap2-pqc-v1-algovoi-side.json` | v1 artefact: 501-byte mandate body, 843-byte signed input, three signatures over it |
| `verify_v1.py` | v1 verifier implementing the fail-closed signer set |
| `build_v1_fixture.py` | regenerates the v1 artefact |
| `test_strip_resistance.py` | 10 tests: the v0 separability characterisation plus both stripping directions, descriptor substitution, key_id mismatch and fail-closed unknown algorithm |

```bash
pip install rfc8785==0.1.4 cryptography pqcrypto
python verify_v1.py ap2-pqc-v1-algovoi-side.json    # exit 0, all checks pass
python verify_v1.py ap2-pqc-v0-algovoi-side.json    # exit 1, v0 carries no signed descriptor
python -m unittest -v test_strip_resistance         # 10 tests OK
```

## What this fixture is NOT

- Not a normative AP2 spec contribution by itself; the spec text lives in [#250](https://github.com/google-agentic-commerce/AP2/issues/250) and any follow-up PR.
- Not a complete PQC conformance set on its own. @rayc0's ML-DSA-65 fixture is the second half; merge both and you have the three-signature-scheme cross-implementor convergence the issue thread converged on.
- Keys here are test material only. v1 publishes its seed strings (ES256, Ed25519) and the Falcon-1024 secret under `test_key_material` so the fixture can be re-signed by anyone; v0 publishes public keys only and cannot be re-signed. This is a **public reference fixture**, not a production keypair.

## Cross-references

- [AP2 #250](https://github.com/google-agentic-commerce/AP2/issues/250) â€” the proposal thread + convention agreement
- [AP2 #218](https://github.com/google-agentic-commerce/AP2/pull/218) â€” AlgoVoi Algorand crypto-algo scenario PR (Falcon-1024 path)
- [AP2 #228](https://github.com/google-agentic-commerce/AP2/pull/228) â€” AlgoVoi Solana crypto-solana scenario PR (Ed25519 path)
- [AP2 #265](https://github.com/google-agentic-commerce/AP2/issues/265) â€” open_mandate_hash v0 conformance vectors (same JCS substrate, different digest derivation)
- [PQSafe reference impl](https://github.com/PQSafe/pqsafe) â€” @rayc0's ML-DSA-65 reference implementation

â€” AlgoVoi (chopmob-cloud)
