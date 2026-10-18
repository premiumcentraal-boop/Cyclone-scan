"""Turn a scanner lab record into a lab observation (Run 30).

The scanner's "Share lab record" button exports only what the app measured
(schema ``cyclone-scan-lab-record`` v1): its own APK digest, the OS, the local
diagnostic and the latest server-verified scan. The operator adds what only a
person can declare -- the case, an anonymous phone alias, the ground truth,
whether the expectation in the runbook was met, and whether they reviewed it --
and this tool builds a ``tools/assurance/lab.py`` observation from both.

    python -m tools.assurance.lab_import record.json \\
        --candidate docs/validation/candidate.json \\
        --case clean_pixel --alias pixel-a --ground-truth CLEAN \\
        --expectation-met yes --operator-verified --lab docs/validation/lab.json

It refuses a record from a different APK than the candidate, and a server
result without the risk score and reasons that a ``--expose-reasons`` lab server
returns. It never invents measured values, and nothing here authenticates the
record: the gate treats origins and reviews as operator declarations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from . import lab
from .evidence_json import loads, read_json

RECORD_MAX_BYTES = 256 * 1024
CANDIDATE_MAX_BYTES = 64 * 1024
SCHEMA = "cyclone-scan-lab-record"
_TOKEN = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# Server reasons that are risk or review outcomes rather than hard verification failures.
_SOFT_REASONS = {"RISK_BLOCK", "RISK_STEP_UP", "CONFIRM_KEY_REQUIRED", "SCAN_DEVICE_EVIDENCE_CHANGED"}
_VERIFIED_DECISIONS = {"ALLOW", "STEP_UP", "BLOCK"}
_EVIDENCE_KEYS = ("deviceKeySignature", "freshAttestation", "playIntegrity", "clientSignals")


def _obj(value, name):
    if value is None:
        # A missing scan is the common operator error; say so instead of "must be an object".
        raise ValueError(f"lab record has no {name}")
    if not isinstance(value, dict):
        raise ValueError(f"lab record: {name} must be an object")
    return value


def _codes(*groups) -> list[str]:
    out: list[str] = []
    for group in groups:
        for value in group or ():
            if isinstance(value, str) and _TOKEN.fullmatch(value) and value not in out:
                out.append(value)
    return out[:64]


def read_record(path: str | Path) -> tuple[dict, str]:
    """Strictly read a lab record; returns it and the SHA-256 of its exact bytes."""
    data = Path(path).read_bytes()
    record = _obj(loads(data, RECORD_MAX_BYTES), "document")
    if record.get("schema") != SCHEMA or record.get("schemaVersion") != 1:
        raise ValueError("not a cyclone-scan-lab-record v1 file")
    apk = record.get("apkSha256")
    if not isinstance(apk, str) or not _HEX64.fullmatch(apk):
        raise ValueError("lab record has no APK digest; it cannot be tied to a candidate")
    return record, hashlib.sha256(data).hexdigest()


def read_candidate(path: str | Path) -> tuple[str, str]:
    doc = _obj(read_json(path, CANDIDATE_MAX_BYTES), "candidate")
    revision, apk = doc.get("tested_revision"), doc.get("scanner_apk_sha256")
    lab.validate_candidate(revision, apk)
    return revision, apk


def _local(record: dict) -> dict:
    local = _obj(record.get("local"), "local scan (run the Scan tab first)")
    coverage = _obj(local.get("coverage"), "local coverage")
    incomplete = 0
    for part in ("local", "native"):
        counts = _obj(coverage.get(part), f"{part} coverage")
        incomplete += sum(int(counts.get(k, 0)) for k in ("unavailable", "unsupported", "unreported"))
    hard = local.get("hardFailures") or []
    return {
        "verdict": local.get("verdict"),
        "score": local.get("score"),
        "hard_failure": bool(hard),
        "coverage": "COMPLETE" if incomplete == 0 else "PARTIAL",
        "duration_ms": local.get("durationMs"),
        "evidence_codes": _codes(["mode:local"], hard, local.get("factors")),
        "observed_at": local.get("scannedAt"),
    }


def _server(record: dict) -> dict:
    server = _obj(record.get("server"), "server scan (run a server-verified scan first)")
    common = {"duration_ms": server.get("durationMs"), "observed_at": server.get("finishedAt")}
    if "unavailable" in server:
        return {**common, "verdict": "INCOMPLETE", "score": None, "hard_failure": False, "coverage": "UNAVAILABLE",
                "evidence_codes": _codes(["mode:server", "label:UNAVAILABLE"], [str(server.get("unavailable"))])}
    decision = server.get("decision")
    if decision not in _VERIFIED_DECISIONS:
        raise ValueError("lab record: unknown server decision")
    if "riskScore" not in server or "reasons" not in server:
        raise ValueError("server result has no risk score or reasons: use a lab server started with --expose-reasons")
    evidence = _obj(server.get("evidence"), "server evidence")
    statuses = [evidence.get(k) for k in _EVIDENCE_KEYS]
    complete = statuses[0] == "VERIFIED" and statuses[1] == "VERIFIED" and statuses[2] == "VERIFIED"
    reasons = [r for r in server.get("reasons") or [] if isinstance(r, str)]
    score = server.get("riskScore")
    hard = any(r not in _SOFT_REASONS for r in reasons)
    if score is None:
        # The server returns no risk score when a hard gate fired before scoring.
        score = 100 if hard else None
    return {
        **common,
        "verdict": decision,
        "score": score,
        "hard_failure": hard,
        "coverage": "COMPLETE" if complete else "PARTIAL",
        "evidence_codes": _codes(["mode:server", f"label:{server.get('label')}"], reasons,
                                 server.get("riskFactors"), server.get("historyChanges")),
    }


def build_observation(record: dict, record_sha256: str, *, revision: str, apk_sha256: str, case: str,
                      alias: str, ground_truth: str, origin: str, expectation_met: bool | None,
                      operator_verified: bool, crashed: bool, mode: str, observation_id: str | None) -> dict:
    if record["apkSha256"] != apk_sha256:
        raise ValueError("lab record is from a different APK than the candidate; it does not count for it")
    if mode == "auto":
        mode = "server" if isinstance(record.get("server"), dict) else "local"
    measured = _server(record) if mode == "server" else _local(record)
    if crashed:
        measured = {**measured, "verdict": "ERROR", "evidence_codes": _codes(measured["evidence_codes"], ["crashed"])}
    observation = {
        "schema": 1,
        "case_id": case,
        "observation_id": observation_id or f"{alias}-{case}-{record_sha256[:12]}",
        "device_alias": alias,
        "os": record.get("os"),
        "revision": revision,
        "apk_sha256": apk_sha256,
        "origin": origin,
        "observed_at": measured.pop("observed_at") or record.get("recordedAt"),
        "ground_truth": ground_truth,
        "crashed": crashed,
        "operator_verified": operator_verified,
        "expectation_met": expectation_met,
        "source_report_sha256": record_sha256,
        **measured,
    }
    return lab.validate(observation)


def _yes_no(value: str) -> bool | None:
    return {"yes": True, "no": False, "unknown": None}[value]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("record")
    parser.add_argument("--candidate", required=True, help="candidate.json with tested_revision and scanner_apk_sha256")
    parser.add_argument("--case", required=True, choices=sorted(lab.CASES))
    parser.add_argument("--alias", required=True, help="stable anonymous phone alias, e.g. pixel-a")
    parser.add_argument("--ground-truth", required=True, choices=["CLEAN", "ALTERED", "UNKNOWN"])
    parser.add_argument("--origin", default="PHYSICAL", choices=["PHYSICAL", "EMULATOR"])
    parser.add_argument("--expectation-met", required=True, choices=["yes", "no", "unknown"],
                        help="compared with the runbook expectation for this case")
    parser.add_argument("--operator-verified", action="store_true", help="set only after reviewing the result")
    parser.add_argument("--crashed", action="store_true", help="the app crashed during this case")
    parser.add_argument("--mode", default="auto", choices=["auto", "server", "local"],
                        help="which result to record (default: server if present)")
    parser.add_argument("--observation-id")
    parser.add_argument("--lab", help="append to this lab.json instead of printing")
    args = parser.parse_args(argv)
    try:
        if args.case == "emulator" and args.origin != "EMULATOR":
            raise ValueError("the emulator case must use --origin EMULATOR")
        record, digest = read_record(args.record)
        revision, apk = read_candidate(args.candidate)
        observation = build_observation(
            record, digest, revision=revision, apk_sha256=apk, case=args.case, alias=args.alias,
            ground_truth=args.ground_truth, origin=args.origin, expectation_met=_yes_no(args.expectation_met),
            operator_verified=args.operator_verified, crashed=args.crashed, mode=args.mode,
            observation_id=args.observation_id)
        if args.lab:
            lab.record(args.lab, observation)
        print(json.dumps(observation, indent=2, sort_keys=True))
        return 0
    except (ValueError, OSError, TypeError, KeyError) as exc:
        print(f"lab_import: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
