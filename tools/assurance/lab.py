"""Record bounded, revision-specific lab observations. Does not manufacture device evidence."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import tempfile

CASES = {
    "clean_pixel": "Clean reference Pixel", "clean_samsung": "Clean reference Samsung",
    "clean_tee": "Clean TEE-only phone", "bootloader_unlocked": "Designated unlocked lab device",
    "rooted_hidden": "Designated rooted lab configuration",
    "frida_inprocess": "Instrumentation of the SDK test app only",
    "lsposed_inprocess": "Hooking of the SDK test app only",
    "repackaged": "Controlled re-signed scanner build", "emulator": "Declared emulator",
    "custom_rom": "Declared custom OS", "offline": "Unavailable remote verification",
    "no_gms": "Device without Google services", "accessibility_legitimate": "Ordinary accessibility use",
    "vpn_legitimate": "Ordinary VPN use", "remote_support_legitimate": "Owner-authorized remote-support use",
    "repeat_scan": "Repeated/resumed scan without crash", "biometric": "Owner-configured biometric test",
}
_REQUIRED = {"schema", "case_id", "observation_id", "device_alias", "os", "revision", "apk_sha256",
             "origin", "observed_at", "ground_truth", "verdict", "score", "hard_failure",
             "coverage", "crashed", "duration_ms", "evidence_codes", "operator_verified", "expectation_met"}
_OPTIONAL = {"source_report_sha256"}
_TOKEN = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

def _hex(value, pattern):
    return isinstance(value,str) and pattern.fullmatch(value) and set(value)!={"0"}

def validate(raw):
    if not isinstance(raw,dict) or not _REQUIRED <= set(raw) <= _REQUIRED | _OPTIONAL:
        raise ValueError("observation must contain only the documented fields")
    if type(raw["schema"]) is not int or raw["schema"]!=1 or raw["case_id"] not in CASES:
        raise ValueError("unsupported schema or case")
    for key in ("observation_id","device_alias"):
        if not isinstance(raw[key],str) or not _TOKEN.fullmatch(raw[key]):
            raise ValueError("invalid anonymous identifier")
    if not isinstance(raw["os"],str) or not 1<=len(raw["os"])<=96:
        raise ValueError("invalid OS description")
    if not _hex(raw["revision"],_HEX40) or not _hex(raw["apk_sha256"],_HEX64):
        raise ValueError("revision and APK hash must be concrete hexadecimal values")
    if "source_report_sha256" in raw and not _hex(raw["source_report_sha256"],_HEX64):
        raise ValueError("invalid source report hash")
    if raw["origin"] not in {"PHYSICAL","EMULATOR","SYNTHETIC"}:
        raise ValueError("invalid evidence origin")
    if raw["ground_truth"] not in {"CLEAN","ALTERED","UNKNOWN"}:
        raise ValueError("invalid declared ground truth")
    if raw["verdict"] not in {"ALLOW","STEP_UP","BLOCK","INCOMPLETE","ERROR"}:
        raise ValueError("invalid verdict")
    if raw["coverage"] not in {"COMPLETE","PARTIAL","UNAVAILABLE"}:
        raise ValueError("invalid coverage")
    if type(raw["duration_ms"]) is not int or not 0<=raw["duration_ms"]<=3600000:
        raise ValueError("invalid duration")
    for key in ("hard_failure","crashed","operator_verified"):
        if type(raw[key]) is not bool:
            raise ValueError("invalid boolean")
    if raw["expectation_met"] is not None and type(raw["expectation_met"]) is not bool:
        raise ValueError("invalid expectation result")
    score=raw["score"]
    if score is not None and (type(score) is not int or not 0<=score<=100):
        raise ValueError("invalid score")
    if raw["verdict"] in {"ALLOW","STEP_UP","BLOCK"} and score is None:
        raise ValueError("evaluated verdict needs a score")
    if raw["hard_failure"] and raw["verdict"]=="ALLOW":
        raise ValueError("a hard failure cannot allow")
    if raw["crashed"] and raw["verdict"]!="ERROR":
        raise ValueError("crash must have ERROR verdict")
    codes=raw["evidence_codes"]
    if not isinstance(codes,list) or len(codes)>64 or any(not isinstance(v,str) or not _TOKEN.fullmatch(v) for v in codes):
        raise ValueError("invalid bounded evidence codes")
    stamp=dt.datetime.fromisoformat(raw["observed_at"])
    if stamp.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return {**raw,"evidence_codes":sorted(set(codes))}

def validate_document(doc):
    if not isinstance(doc,dict) or set(doc)!={"schema","observations"} or type(doc["schema"]) is not int or doc["schema"]!=1:
        raise ValueError("invalid lab document")
    if not isinstance(doc["observations"],list) or len(doc["observations"])>10000:
        raise ValueError("invalid observation collection")
    rows=[validate(row) for row in doc["observations"]]
    ids=[(row["revision"],row["observation_id"]) for row in rows]
    if len(ids)!=len(set(ids)):
        raise ValueError("duplicate observation ID for a revision")
    return {"schema":1,"observations":rows}

def read_document(path):
    path=Path(path)
    if path.stat().st_size>16*1024*1024:
        raise ValueError("lab document too large")
    return validate_document(json.loads(path.read_text(encoding="utf-8")))

def write_document(path,document):
    path=Path(path);document=validate_document(document)
    path.parent.mkdir(parents=True,exist_ok=True)
    payload=json.dumps(document,indent=2,sort_keys=True,allow_nan=False)+"\n"
    with tempfile.NamedTemporaryFile(mode="w",encoding="utf-8",dir=path.parent,delete=False) as out:
        name=out.name
        try:
            out.write(payload);out.flush();os.fsync(out.fileno())
        except BaseException:
            Path(name).unlink(missing_ok=True);raise
    try: os.replace(name,path)
    finally: Path(name).unlink(missing_ok=True)

def record(path,observation):
    current=read_document(path) if Path(path).exists() else {"schema":1,"observations":[]}
    current["observations"].append(validate(observation))
    write_document(path,current)

def summary(document,revision,apk_sha256):
    doc=validate_document(document)
    selected=[row for row in doc["observations"] if row["revision"]==revision and row["apk_sha256"]==apk_sha256]
    result={}
    for case in CASES:
        rows=[row for row in selected if row["case_id"]==case]
        measured=[row for row in rows if row["origin"]!="SYNTHETIC" and row["operator_verified"]]
        if not measured: status="NOT_RUN"
        elif any(row["crashed"] or row["expectation_met"] is False for row in measured): status="FAIL"
        elif all(row["expectation_met"] is True for row in measured): status="PASS"
        else: status="UNREVIEWED"
        result[case]={"status":status,"measured":len(measured),"synthetic":sum(row["origin"]=="SYNTHETIC" for row in rows)}
    return {"schema":1,"revision":revision,"apk_sha256":apk_sha256,"cases":result,
            "note":"Origins, ground truth and review are operator declarations, not independently attested facts."}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="command",required=True)
    init=sub.add_parser("init");init.add_argument("file")
    add=sub.add_parser("record");add.add_argument("file");add.add_argument("observation")
    report=sub.add_parser("report");report.add_argument("file");report.add_argument("--revision",required=True);report.add_argument("--apk-sha256",required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=="init":
            if Path(args.file).exists(): raise ValueError("refusing to replace an existing lab document")
            write_document(args.file,{"schema":1,"observations":[]})
        elif args.command=="record":
            observation=json.loads(Path(args.observation).read_text(encoding="utf-8"))
            record(args.file,observation)
        else:
            print(json.dumps(summary(read_document(args.file),args.revision,args.apk_sha256),indent=2))
        return 0
    except (ValueError,OSError,TypeError) as exc:
        parser.exit(2,str(exc)+"\n")
if __name__=="__main__":
    raise SystemExit(main())
