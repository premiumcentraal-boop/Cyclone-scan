"""Run 19: the committed beta-checklist record matches its candidate and stays NO_GO.

Re-runs the real gate on the committed files, so the record cannot drift from what the
tool computes, and no reviewer can mistake it for a passing candidate.
"""

import hashlib
import json
from pathlib import Path

from tools.assurance.beta_gate import check
from tools.assurance.lab import read_document

V = Path(__file__).resolve().parents[2] / "docs" / "validation"


def test_record_is_bound_to_the_ci_candidate():
    candidate = json.loads((V / "candidate.json").read_text())
    evidence = json.loads((V / "build-evidence.json").read_text())
    review = json.loads((V / "beta-review.json").read_text())
    assert review["revision"] == candidate["tested_revision"] == evidence["tested_revision"]
    assert review["apk_sha256"] == candidate["scanner_apk_sha256"] == evidence["artifacts"]["scanner_apk"]["sha256"]
    assert candidate["signing"]["identity"] == "TEST_DEBUG_KEY"
    digest = hashlib.sha256((V / "build-evidence.json").read_bytes()).hexdigest()
    assert review["approvals"]["candidate_ci"] == {"status": "PASS", "evidence_sha256": digest}
    assert all(a["status"] == "UNVERIFIED" for k, a in review["approvals"].items() if k != "candidate_ci")


def test_gate_result_is_reproduced_and_no_go():
    lab = read_document(V / "lab.json")
    assert lab["observations"] == []          # no device evidence has been recorded
    result = check(lab, json.loads((V / "beta-review.json").read_text()))
    assert result == json.loads((V / "beta-gate-result.json").read_text())
    assert result["decision"] == "NO_GO" and "stable_signing" in result["blockers"]
    assert all(result["gates"][f"lab:{case}"] == "UNVERIFIED" for case in
               ("clean_pixel", "clean_samsung", "emulator", "offline", "biometric"))
