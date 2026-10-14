import hashlib
import tempfile
import unittest
from pathlib import Path
from test_assurance_lab import observation
from tools.assurance.lab import CASES
from tools.assurance.beta_gate import APPROVALS,check
from tools.assurance.artifact_manifest import manifest

def review():
    return {"schema":1,"revision":"a"*40,"apk_sha256":"b"*64,
            "approvals":{key:{"status":"PASS","evidence_sha256":"c"*64} for key in APPROVALS},
            "policy":{"reviewed":True,"allow_below":50,"block_at":80,
                      "max_clean_intervention":0.1,"max_altered_miss":0.1,"max_p95_ms":3000}}

def candidate():
    rows=[]
    for i,case in enumerate(CASES):
        rows.append(observation(case_id=case,observation_id=str(i),device_alias="clean"+str(i),
                    origin="EMULATOR" if case=="emulator" else "PHYSICAL",
                    operator_verified=True,expectation_met=True,ground_truth="CLEAN",score=0,verdict="ALLOW"))
    for i in range(3):
        rows.append(observation(case_id="rooted_hidden",observation_id="alt"+str(i),device_alias="alt"+str(i),
                    origin="PHYSICAL",operator_verified=True,expectation_met=True,
                    ground_truth="ALTERED",score=90,verdict="BLOCK"))
    return {"schema":1,"observations":rows}

class BetaGateTests(unittest.TestCase):
    def test_no_data_never_ready(self):
        result=check({"schema":1,"observations":[]},review())
        self.assertEqual(result["decision"],"NO_GO")
        self.assertIn("pilot_sample",result["blockers"])

    def test_review_ready_is_not_publication(self):
        self.assertEqual(check(candidate(),review())["decision"],"READY_FOR_HUMAN_REVIEW")

    def test_every_approval_is_required(self):
        for key in APPROVALS:
            r=review();r["approvals"][key]={"status":"UNVERIFIED","evidence_sha256":None}
            self.assertEqual(check(candidate(),r)["decision"],"NO_GO",key)

    def test_every_lab_case_is_required(self):
        for case in CASES:
            doc=candidate();doc["observations"]=[r for r in doc["observations"] if r["case_id"]!=case]
            self.assertIn("lab:"+case,check(doc,review())["blockers"])

    def test_synthetic_and_wrong_revision_cannot_pass(self):
        for field,value in (("origin","SYNTHETIC"),("revision","d"*40),("apk_sha256","e"*64)):
            doc=candidate()
            for row in doc["observations"]:row[field]=value
            self.assertEqual(check(doc,review())["decision"],"NO_GO")

    def test_emulator_cannot_satisfy_physical_case(self):
        doc=candidate()
        for row in doc["observations"]:
            if row["case_id"]=="clean_pixel":row["origin"]="EMULATOR"
        self.assertIn("lab:clean_pixel",check(doc,review())["blockers"])

    def test_crash_remains_a_blocker(self):
        doc=candidate();doc["observations"][0].update(crashed=True,verdict="ERROR",operator_verified=False)
        self.assertIn("no_observed_crashes",check(doc,review())["blockers"])

    def test_false_positive_and_miss_fail(self):
        doc=candidate()
        for row in doc["observations"]:row["score"]=90 if row["ground_truth"]=="CLEAN" else 0
        result=check(doc,review())
        self.assertEqual(result["gates"]["clean_intervention"],"FAIL")
        self.assertEqual(result["gates"]["altered_miss"],"FAIL")

    def test_latency_and_unreviewed_policy_fail(self):
        doc=candidate()
        for row in doc["observations"]:row["duration_ms"]=4000
        r=review();r["policy"]["reviewed"]=False
        result=check(doc,r)
        self.assertEqual(result["gates"]["latency_p95"],"FAIL")
        self.assertEqual(result["gates"]["policy_review"],"UNVERIFIED")

    def test_approval_without_reference_and_nonfinite_limit_rejected(self):
        r=review();r["approvals"]["stable_signing"]["evidence_sha256"]=None
        with self.assertRaises(ValueError):check(candidate(),r)
        r=review();r["policy"]["max_altered_miss"]=float("nan")
        with self.assertRaises(ValueError):check(candidate(),r)

    def test_artifact_digest_and_signer_honesty(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"test.apk";path.write_bytes(b"fixture only")
            result=manifest(path,"a"*40)
            self.assertEqual(result["apk_sha256"],hashlib.sha256(b"fixture only").hexdigest())
            self.assertEqual(result["signer_verification"],"UNVERIFIED")
            path.write_bytes(b"")
            with self.assertRaises(ValueError):manifest(path,"a"*40)
