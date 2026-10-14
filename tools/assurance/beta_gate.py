"""Offline beta checklist. Declarations are review records, never authenticated release authority."""
import argparse
import json
import math
from .lab import CASES, _hex, _HEX40, _HEX64, read_document, summary
from .calibration import evaluate
from .evidence_json import read_json

APPROVALS = {
    "candidate_ci", "integrated_claude_runs", "attestation_compatibility",
    "device_lifecycle", "live_google_verification", "stable_signing",
    "protocol_review", "privacy_retention", "dependency_licenses",
}
_REQUIRED = {"schema", "revision", "apk_sha256", "approvals", "policy"}
_POLICY = {"reviewed", "allow_below", "block_at", "max_clean_intervention",
           "max_altered_miss", "max_p95_ms"}

def validate_review(raw):
    if not isinstance(raw,dict) or set(raw)!=_REQUIRED or type(raw["schema"]) is not int or raw["schema"]!=1:
        raise ValueError("invalid beta review document")
    if not _hex(raw["revision"],_HEX40) or not _hex(raw["apk_sha256"],_HEX64):
        raise ValueError("concrete candidate revision and APK hash required")
    approvals=raw["approvals"]
    if not isinstance(approvals,dict) or set(approvals)!=APPROVALS:
        raise ValueError("all documented approval categories required")
    for approval in approvals.values():
        if not isinstance(approval,dict) or set(approval)!={"status","evidence_sha256"}:
            raise ValueError("invalid approval record")
        if approval["status"] not in ("PASS","FAIL","UNVERIFIED"):
            raise ValueError("invalid approval status")
        digest=approval["evidence_sha256"]
        if digest is not None and not _hex(digest,_HEX64):
            raise ValueError("invalid approval evidence digest")
        if approval["status"]=="PASS" and digest is None:
            raise ValueError("passing review must reference an evidence document digest")
    policy=raw["policy"]
    if not isinstance(policy,dict) or set(policy)!=_POLICY or type(policy["reviewed"]) is not bool:
        raise ValueError("invalid policy review")
    for key in ("allow_below","block_at"):
        if type(policy[key]) is not int:
            raise ValueError("integer policy thresholds required")
    if not 0<policy["allow_below"]<=policy["block_at"]<=101:
        raise ValueError("invalid score boundaries")
    for key in ("max_clean_intervention","max_altered_miss"):
        value=policy[key]
        if type(value) not in (int,float) or not 0<=value<=1 or not math.isfinite(value):
            raise ValueError("invalid acceptance rate")
    if type(policy["max_p95_ms"]) is not int or not 0<policy["max_p95_ms"]<=3600000:
        raise ValueError("invalid latency budget")
    return raw

def check(document,review):
    review=validate_review(review)
    revision=review["revision"];apk=review["apk_sha256"];policy=review["policy"]
    lab=summary(document,revision,apk)
    calibration=evaluate(document,revision,apk,policy["allow_below"],policy["block_at"])
    # Recompute all measurements from raw observations; do not accept submitted metrics.
    rows=read_rows(document,revision,apk)
    gates={key:record["status"] for key,record in review["approvals"].items()}
    gates["policy_review"]="PASS" if policy["reviewed"] else "UNVERIFIED"
    for case in CASES:
        expected_origin="EMULATOR" if case=="emulator" else "PHYSICAL"
        measured=[r for r in rows if r["case_id"]==case and r["origin"]==expected_origin and r["operator_verified"]]
        if not measured:status="UNVERIFIED"
        elif any(r["crashed"] or r["expectation_met"] is False for r in measured):status="FAIL"
        elif all(r["expectation_met"] is True for r in measured):status="PASS"
        else:status="UNVERIFIED"
        gates["lab:"+case]=status
    gates["pilot_sample"]="PASS" if calibration["data_status"]=="READY_FOR_REVIEW" else "UNVERIFIED"
    for name,metric,limit in (
        ("clean_intervention",calibration["clean_device_intervention"]["rate"],policy["max_clean_intervention"]),
        ("altered_miss",calibration["altered_device_miss"]["rate"],policy["max_altered_miss"]),
        ("latency_p95",calibration["latency_ms"]["p95"],policy["max_p95_ms"]),
    ):
        gates[name]="UNVERIFIED" if metric is None else ("PASS" if metric<=limit else "FAIL")
    gates["no_observed_crashes"]="FAIL" if any(r["crashed"] and r["origin"]!="SYNTHETIC" for r in rows) else ("PASS" if rows else "UNVERIFIED")
    blockers=sorted(key for key,value in gates.items() if value!="PASS")
    return {"schema":1,"revision":revision,"apk_sha256":apk,
            "decision":"NO_GO" if blockers else "READY_FOR_HUMAN_REVIEW",
            "gates":gates,"blockers":blockers,"lab":lab,"calibration":calibration,
            "limitations":[
                "Approval records, origins and ground truth are operator declarations; digests are references, not signatures.",
                "Verify referenced review documents, CI results and APK signer independently before distribution.",
                "Exact revision and APK matching prevents accidental mixing, not malicious evidence fabrication.",
                "All-pass is readiness for human review, not automatic publication or bank-grade certification.",
                "Pilot rates and latency are descriptive and do not establish population-wide accuracy.",
            ]}

def read_rows(document,revision,apk):
    from .lab import validate_document
    return [r for r in validate_document(document)["observations"] if r["revision"]==revision and r["apk_sha256"]==apk]

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("lab");p.add_argument("review")
    args=p.parse_args(argv)
    try:
        result=check(read_document(args.lab),read_json(args.review,65536))
        print(json.dumps(result,indent=2,allow_nan=False))
        return 0 if result["decision"]=="READY_FOR_HUMAN_REVIEW" else 1
    except (OSError,ValueError,TypeError) as exc:p.exit(2,str(exc)+"\n")
if __name__=="__main__":raise SystemExit(main())
