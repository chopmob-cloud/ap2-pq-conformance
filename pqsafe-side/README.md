# AP2 PQC conformance fixture v0 — PQSafe side

PQSafe-side artefact for [AP2 #250](https://github.com/google-agentic-commerce/AP2/issues/250) (Post-Quantum Extension to AP2). Carries an **ML-DSA-65 (FIPS 204)** signature over the **identical** AP2 `PaymentMandate` canonical byte sequence signed by the AlgoVoi-side fixture (`expected_canonical_sha256 = sha256:cc8315f7…e0`). By construction interoperable with `../algovoi-side/ap2-pqc-v0-algovoi-side.json` — same JCS substrate, different signature scheme.

## Files

| File | Purpose |
|---|---|
| `ap2-pqc-v0-pqsafe-side.json` | The artefact — canonical SHA-256 + ML-DSA-65 public key and signature |
| `verify.py` | Standalone verifier — recomputes JCS canonical bytes, recomputes SHA-256, verifies the ML-DSA-65 signature against the published public key |

## Reproduce locally

```bash
pip install pqcrypto
python verify.py ap2-pqc-v0-pqsafe-side.json
```

Expected output: recomputed SHA-256 matches `expected_canonical_sha256` byte-for-byte; ML-DSA-65 signature verifies against the published public key over the recomputed canonical bytes.

## Cross-implementor convergence

The AlgoVoi side (ES256 + Ed25519 + Falcon-1024) and this PQSafe side (ML-DSA-65) both sign the same 501-byte JCS canonical of one AP2 `PaymentMandate`. This is the four-scheme cross-implementor convergence locked in on AP2 #250 (2026-05-16): the JCS+SHA-256 substrate determinism is independent of the signature scheme.

The 240-vector ML-DSA-65 test set referenced on #250 lives in [`PQSafe/ap2-pq-test-vectors`](https://github.com/PQSafe/ap2-pq-test-vectors) and follows the same canonical-bytes-then-sign pipeline.
