# Credits

## Security reports

### Hybrid separation in the v0 fixtures, 2026-11-24

Reported by **Ikko Eltociear Ashimine** ([@eltociear](https://github.com/eltociear)) in
[AP2 #250, comment 7127315451](https://github.com/google-agentic-commerce/AP2/issues/250#issuecomment-7127315451).

The v0 construction had every scheme sign the same JCS canonical bytes with nothing
binding the halves together, so a verifier given only one half accepted it. After
Q-Day that lets an attacker drop the post-quantum signature and present a forged
classical one to any verifier whose policy does not yet require PQ, and it lets a
PQ-only verifier accept the PQ half on its own.

The report also named the remedy (domain separation per object type, plus the signer
set inside the signed message) and cited `draft-uppalapati-wimse-pq-agent-identity`
(PQ-R3) for the underlying weakness, with their own agent-mandate profile at
<https://github.com/eltociear/pqam> offering vectors in both stripping directions.

Fixed in [PR #2](https://github.com/chopmob-cloud/ap2-pq-conformance/pull/2): the v1
fixture binds the object type and the required signer set into the signed input and
fails closed when a listed signer is absent. See
[`algovoi-side/README.md`](algovoi-side/README.md#v1-signed-input).

The v0 fixtures are retained unchanged as history, so their separability stays
reproducible by `algovoi-side/test_strip_resistance.py::test_v0_is_separable` and this
credit stays attached to something a reader can run.

## Canonicalisation

RFC 8785 (JSON Canonicalization Scheme), edited by Anders Rundgren. See
[NOTICE](NOTICE).