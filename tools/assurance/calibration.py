"""Descriptive score-policy evaluation. Never rewrites production weights or thresholds."""
import argparse
import datetime as dt
import json
import math
from .lab import read_document, validate_document, validate_candidate

def _rate(errors,total):
    if not total:return {"errors":0,"devices":0,"rate":None,"wilson95":None}
    p=errors/total;z=1.959963984540054
    denominator=1+z*z/total
    center=(p+z*z/(2*total))/denominator
    radius=z*math.sqrt(p*(1-p)/total+z*z/(4*total*total))/denominator
    return {"errors":errors,"devices":total,"rate":p,
            "wilson95":[max(0,center-radius),min(1,center+radius)]}

def _percentile(values,p):
    if not values:return None
    values=sorted(values);position=(len(values)-1)*p
    low=math.floor(position);high=math.ceil(position)
    return values[low]+(values[high]-values[low])*(position-low)

def score_band(row,allow_below,block_at):
    if row["hard_failure"]:return "BLOCK"
    if row["score"]>=block_at:return "BLOCK"
    if row["score"]>=allow_below:return "STEP_UP"
    return "ALLOW"

def evaluate(document,revision,apk_sha256,allow_below=50,block_at=80,min_clean_devices=5,min_altered_devices=3):
    validate_candidate(revision,apk_sha256)
    if not all(type(v) is int for v in (allow_below,block_at,min_clean_devices,min_altered_devices)):
        raise ValueError("integer evaluation settings required")
    if not 0<allow_below<=block_at<=101 or min_clean_devices<1 or min_altered_devices<1:
        raise ValueError("invalid evaluation settings")
    rows=validate_document(document)["observations"]
    selected=[r for r in rows if r["revision"]==revision and r["apk_sha256"]==apk_sha256]
    measured=[r for r in selected if r["origin"]!="SYNTHETIC" and r["operator_verified"]]
    # Repeated scans do not create additional independent accuracy samples.
    latest={}
    for row in sorted(measured,key=lambda r:(dt.datetime.fromisoformat(r["observed_at"]),r["observation_id"])):
        latest[(row["device_alias"],row["case_id"])]=row
    measurements=list(latest.values())
    eligible=[r for r in measurements if r["coverage"]=="COMPLETE" and not r["crashed"] and
              r["verdict"] in {"ALLOW","STEP_UP","BLOCK"} and r["ground_truth"] in {"CLEAN","ALTERED"}]
    clean={r["device_alias"] for r in eligible if r["ground_truth"]=="CLEAN"}
    altered={r["device_alias"] for r in eligible if r["ground_truth"]=="ALTERED"}
    false_positive={r["device_alias"] for r in eligible if r["ground_truth"]=="CLEAN" and score_band(r,allow_below,block_at)!="ALLOW"}
    missed={r["device_alias"] for r in eligible if r["ground_truth"]=="ALTERED" and score_band(r,allow_below,block_at)=="ALLOW"}
    durations=[r["duration_ms"] for r in measurements if not r["crashed"]]
    sufficient=len(clean)>=min_clean_devices and len(altered)>=min_altered_devices
    return {
        "schema":1,"revision":revision,"apk_sha256":apk_sha256,
        "data_status":"READY_FOR_REVIEW" if sufficient else "INSUFFICIENT_DATA",
        "policy":{"allow_below":allow_below,"block_at":block_at,"weights_changed":False},
        "minimums":{"clean_devices":min_clean_devices,"altered_devices":min_altered_devices},
        "counts":{"submitted":len(selected),"reviewed_latest_scenarios":len(measurements),
                  "eligible_scenarios":len(eligible),"excluded_from_accuracy":len(measurements)-len(eligible),
                  "synthetic":sum(r["origin"]=="SYNTHETIC" for r in selected),
                  "unreviewed":sum(not r["operator_verified"] and r["origin"]!="SYNTHETIC" for r in selected),
                  "crashes":sum(r["crashed"] for r in measurements)},
        "clean_device_intervention":_rate(len(false_positive),len(clean)),
        "altered_device_miss":_rate(len(missed),len(altered)),
        "latency_ms":{"p50":_percentile(durations,0.5),"p95":_percentile(durations,0.95),"samples":len(durations)},
        "limitations":[
            "Score-policy proxy, not a measurement of every deployed backend policy.",
            "Ground truth and physical origins are operator declarations.",
            "Intervals are descriptive and assume independent stable device aliases; scenario correlation remains.",
            "ALTERED means the declared lab condition, not necessarily malicious activity.",
            "Pilot sample minimums are review prerequisites, not proof of production accuracy.",
            "No production policy is modified; no causal or population-wide effectiveness claim.",
        ],
    }

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("file");p.add_argument("--revision",required=True);p.add_argument("--apk-sha256",required=True)
    p.add_argument("--allow-below",type=int,default=50);p.add_argument("--block-at",type=int,default=80)
    args=p.parse_args(argv)
    try:
        print(json.dumps(evaluate(read_document(args.file),args.revision,args.apk_sha256,
                                  args.allow_below,args.block_at),indent=2,allow_nan=False))
        return 0
    except (OSError,ValueError,TypeError) as exc:p.exit(2,str(exc)+"\n")
if __name__=="__main__":raise SystemExit(main())
