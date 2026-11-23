# ap2-pq-conformance

Joint canonical home for the **AP2 Post-Quantum cross-scheme conformance fixtures**
(AlgoVoi + PQSafe), agreed on [AP2 #250](https://github.com/google-agentic-commerce/AP2/issues/250)
(Post-Quantum Extension to AP2).

One AP2 `PaymentMandate` is canonicalised once with RFC 8785 (JCS) and hashed with
SHA-256. Every signature scheme signs that **identical** canonical byte sequence, so
the JCS + SHA-256 substrate determinism is independent of the signature scheme. This
is the four-scheme cross-implementor convergence locked in on AP2 #250 (2026-05-16).

## The two sides

| Side | Signature schemes | Path |
|---|---|---|
| AlgoVoi | ES256 (ECDSA P-256), Ed25519, Falcon-1024 (FIPS 206) | [`algovoi-side/`](algovoi-side/) |
| PQSafe (@rayc0) | ML-DSA-65 (FIPS 204) | [`pqsafe-side/`](pqsafe-side/) |

Both sides carry the same `expected_canonical_sha256` over the same 501-byte JCS
canonical of one AP2 `PaymentMandate`. Each side ships its fixture JSON plus a
single-file standalone `verify.py` that recomputes the JCS canonical bytes, recomputes
SHA-256, and verifies each signature against the published public key.

## Reproduce

See each side's README for its exact dependencies and command:

- [`algovoi-side/README.md`](algovoi-side/README.md) - ES256 + Ed25519 + Falcon-1024,
  the agreed informative algorithm-identifier table, and the fail-closed open-enum rule.
- [`pqsafe-side/README.md`](pqsafe-side/README.md) - ML-DSA-65 over the identical
  canonical bytes; the 240-vector ML-DSA-65 set lives in
  [`PQSafe/ap2-pq-test-vectors`](https://github.com/PQSafe/ap2-pq-test-vectors).

## Scope

This repository is a public reference fixture, not a normative AP2 spec contribution
by itself; the spec text lives in AP2 #250 and any follow-up PR. Keys are
deterministic-from-seed or freshly generated for re-signing, not production keypairs.

## Licence and attribution

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Builds on RFC 8785 (JSON
Canonicalization Scheme), an IETF standard edited by Anders Rundgren; AlgoVoi does not
claim authorship of RFC 8785 itself.

AlgoVoi (chopmob-cloud) - https://docs.algovoi.co.uk
