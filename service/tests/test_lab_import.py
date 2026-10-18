"""Run 30: scanner lab record -> lab observation."""

import copy
import json

import pytest

from tools.assurance import lab, lab_import

APK = "ab" * 32
REVISION = "1" * 40


def record(**overrides):
    base = {
        "schema": "cyclone-scan-lab-record",
        "schemaVersion": 1,
        "recordedAt": "2026-10-15T10:00:00.000Z",
        "apkSha256": APK,
        "scannerVersion": "0.9.0-beta.1",
        "os": "Android 16 (API 36)",
        "local": {
            "verdict": "ALLOW", "score": 5, "hardFailures": [], "factors": ["env_vpn"],
            "coverage": {"local": {"detected": 1, "notDetected": 21, "unavailable": 0, "unsupported": 0, "unreported": 0},
                         "native": {"detected": 0, "notDetected": 9, "unavailable": 0, "unsupported": 0, "unreported": 0}},
            "durationMs": 1800, "scannedAt": "2026-10-15T09:58:00.000Z",
        },
        "server": {
            "durationMs": 2400, "finishedAt": "2026-10-15T09:59:00.000Z", "label": "VERIFIED_FRESH",
            "decision": "ALLOW", "decisionId": "dec_x",
            "evidence": {"deviceKeySignature": "VERIFIED", "freshAttestation": "VERIFIED",
                         "playIntegrity": "VERIFIED", "clientSignals": "SIGNED"},
            "historyChanges": ["FRESH_KEY_AUTHORIZED"], "coverage": {"NOT_DETECTED": 22},
            "reasons": [], "riskScore": 5, "riskFactors": ["env_vpn"],
        },
    }
    for key, value in overrides.items():
        base[key] = value
    return base


def build(rec, **kw):
    args = dict(revision=REVISION, apk_sha256=APK, case="clean_pixel", alias="pixel-a", ground_truth="CLEAN",
                origin="PHYSICAL", expectation_met=True, operator_verified=True, crashed=False, mode="auto",
                observation_id=None)
    args.update(kw)
    return lab_import.build_observation(rec, "cd" * 32, **args)


def test_server_result_becomes_a_valid_observation():
    obs = build(record())
    assert obs["verdict"] == "ALLOW" and obs["score"] == 5 and obs["coverage"] == "COMPLETE"
    assert obs["hard_failure"] is False and obs["duration_ms"] == 2400
    assert obs["revision"] == REVISION and obs["apk_sha256"] == APK
    assert obs["source_report_sha256"] == "cd" * 32
    assert {"mode:server", "label:VERIFIED_FRESH", "env_vpn", "FRESH_KEY_AUTHORIZED"} <= set(obs["evidence_codes"])
    assert obs["observed_at"] == "2026-10-15T09:59:00+00:00"
    # Operator declarations come only from the operator.
    assert (obs["case_id"], obs["device_alias"], obs["ground_truth"]) == ("clean_pixel", "pixel-a", "CLEAN")


def test_partial_server_evidence_is_partial():
    rec = record()
    rec["server"]["evidence"]["playIntegrity"] = "NOT_PROVIDED"
    rec["server"]["label"] = "VERIFIED_PARTIAL"
    assert build(rec)["coverage"] == "PARTIAL"


def test_hard_server_failure():
    rec = record()
    rec["server"].update(decision="BLOCK", reasons=["BOOTLOADER_UNLOCKED"], riskScore=None, label="REJECTED")
    obs = build(rec, case="bootloader_unlocked", ground_truth="ALTERED")
    assert obs["verdict"] == "BLOCK" and obs["hard_failure"] is True and obs["score"] == 100


def test_risk_block_is_not_a_hard_failure():
    rec = record()
    rec["server"].update(decision="BLOCK", reasons=["RISK_BLOCK"], riskScore=95, label="REJECTED")
    obs = build(rec, case="rooted_hidden", ground_truth="ALTERED")
    assert obs["hard_failure"] is False and obs["score"] == 95


def test_unavailable_server_is_incomplete():
    rec = record(server={"durationMs": 30, "finishedAt": "2026-10-15T09:59:00.000Z", "label": "UNAVAILABLE",
                         "unavailable": "NETWORK"})
    obs = build(rec, case="offline")
    assert obs["verdict"] == "INCOMPLETE" and obs["coverage"] == "UNAVAILABLE" and obs["score"] is None


def test_local_mode_is_partial_when_any_check_was_not_verified():
    obs = build(record(), mode="local")
    assert obs["verdict"] == "ALLOW" and obs["coverage"] == "COMPLETE" and "mode:local" in obs["evidence_codes"]
    rec = record()
    rec["local"]["coverage"]["native"]["unavailable"] = 3
    assert build(rec, mode="local")["coverage"] == "PARTIAL"


def test_crash_is_recorded_as_error():
    obs = build(record(), case="repeat_scan", crashed=True, expectation_met=False)
    assert obs["verdict"] == "ERROR" and obs["crashed"] is True


@pytest.mark.parametrize("mutate,message", [
    (lambda r: r.update(apkSha256="ef" * 32), "different APK"),
    (lambda r: r["server"].pop("riskScore"), "expose-reasons"),
    (lambda r: r["server"].update(decision="MAYBE"), "unknown server decision"),
])
def test_refusals(mutate, message):
    rec = record()
    mutate(rec)
    with pytest.raises(ValueError, match=message):
        build(rec)


def test_auto_mode_falls_back_to_local_without_a_server_scan():
    assert "mode:local" in build(record(server=None))["evidence_codes"]
    with pytest.raises(ValueError, match="server scan"):
        build(record(server=None), mode="server")


def test_missing_scan_is_reported_as_missing():
    with pytest.raises(ValueError, match="has no local scan"):
        build(record(local=None), mode="local")
    with pytest.raises(ValueError, match="has no server scan"):
        build(record(server=None), mode="server")


def test_file_level_checks_and_cli(tmp_path):
    rec_path = tmp_path / "record.json"
    rec_path.write_text(json.dumps(record()))
    cand = tmp_path / "candidate.json"
    cand.write_text(json.dumps({"tested_revision": REVISION, "scanner_apk_sha256": APK}))
    labfile = tmp_path / "lab.json"
    lab.write_document(labfile, {"schema": 1, "observations": []})
    code = lab_import.main([str(rec_path), "--candidate", str(cand), "--case", "clean_pixel", "--alias", "pixel-a",
                            "--ground-truth", "CLEAN", "--expectation-met", "yes", "--operator-verified",
                            "--lab", str(labfile)])
    assert code == 0
    doc = lab.read_document(labfile)
    assert len(doc["observations"]) == 1
    summary = lab.summary(doc, REVISION, APK)
    assert summary["cases"]["clean_pixel"]["status"] == "PASS"
    # Duplicate keys and wrong schema are refused.
    rec_path.write_text('{"schema":"cyclone-scan-lab-record","schema":"x"}')
    assert lab_import.main([str(rec_path), "--candidate", str(cand), "--case", "clean_pixel", "--alias", "pixel-a",
                            "--ground-truth", "CLEAN", "--expectation-met", "yes"]) == 2
    # The emulator case must be declared as such.
    rec_path.write_text(json.dumps(record()))
    assert lab_import.main([str(rec_path), "--candidate", str(cand), "--case", "emulator", "--alias", "emu-a",
                            "--ground-truth", "ALTERED", "--expectation-met", "yes"]) == 2


def test_record_never_carries_operator_fields():
    """The phone-side schema has no slot for declarations; an injected one is ignored, not trusted."""
    rec = record()
    rec["case_id"] = "clean_pixel"
    rec["ground_truth"] = "CLEAN"
    obs = build(copy.deepcopy(rec), case="vpn_legitimate", ground_truth="UNKNOWN")
    assert obs["case_id"] == "vpn_legitimate" and obs["ground_truth"] == "UNKNOWN"
