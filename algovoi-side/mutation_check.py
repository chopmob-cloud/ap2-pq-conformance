#!/usr/bin/env python
"""mutation_check.py - prove each v1 guard is actually load-bearing.

Disables one guard at a time in `verify_v1.py`, runs the test that should notice,
and requires it to FAIL. A mutation whose test still passes is reported GREEN
(fail-open) and counts as an unproven guard. The file is restored byte-identically
and the restore is asserted, so a crash cannot leave the tree mutated.

Run: python mutation_check.py
Exit: 0 when every guard is proven, 1 otherwise.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = HERE / "verify_v1.py"
T = "test_strip_resistance.TestV1StripResistant."

MUTATIONS = [
    (
        "M1 domain separation: drop object_type from the signed input",
        '        + art["object_type"].encode("utf-8")\n',
        '        + b""\n',
        T + "test_v1_binds_object_type",
    ),
    (
        "M2 descriptor binding: drop signer_set from the signed input",
        '        + SEP\n        + jcs(art["signer_set"])\n',
        '        + SEP\n        + b""\n',
        T + "test_v1_binds_signer_set",
    ),
    (
        "M3 fail-closed on a missing signer",
        '            errors.append(f"missing signature for required signer: {alg}")\n',
        "            pass\n",
        T + "test_v1_rejects_stripped_pq_half",
    ),
    (
        "M4 key_id binding",
        '            errors.append(f"key_id mismatch for {alg}")\n',
        "            pass\n",
        T + "test_v1_rejects_wrong_key_id",
    ),
    (
        "M5 fail-closed on an unknown algorithm",
        '    return bool(signers) and all(s.get("algorithm") in KNOWN_ALGORITHMS for s in signers)\n',
        "    return True\n",
        T + "test_v1_rejects_unknown_algorithm",
    ),
]


def run(test: str) -> int:
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "-v", test],
        cwd=HERE,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return r.returncode


def main() -> int:
    original = TARGET.read_bytes()
    rows, unproven = [], 0
    try:
        for name, old, new, test in MUTATIONS:
            text = original.decode("utf-8")
            hits = text.count(old)
            if hits != 1:
                rows.append((name, "UNAPPLIED", f"anchor matched {hits} times"))
                unproven += 1
                continue
            TARGET.write_text(text.replace(old, new), encoding="utf-8", newline="\n")
            try:
                code = run(test)
            finally:
                TARGET.write_bytes(original)
                if TARGET.read_bytes() != original:
                    raise RuntimeError(f"{name}: RESTORE FAILED - tree left mutated")
            caught = code != 0
            if not caught:
                unproven += 1
            rows.append((name, "CAUGHT" if caught else "GREEN (fail-open)", test.rsplit(".", 1)[-1]))
    finally:
        TARGET.write_bytes(original)

    width = max(len(r[0]) for r in rows)
    for name, verdict, detail in rows:
        print(f"{name:<{width}}  {verdict:<20} {detail}")
    print()
    print("RESULT:", "all guards proven" if unproven == 0 else f"{unproven} guard(s) unproven")
    return 0 if unproven == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())