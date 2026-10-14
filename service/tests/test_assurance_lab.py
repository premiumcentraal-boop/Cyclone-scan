import tempfile
import unittest
from pathlib import Path
from tools.assurance.lab import validate, record, read_document, summary

def observation(**changes):
    return {"schema":1,"case_id":"clean_pixel","observation_id":"scan-1","device_alias":"pixel-a",
            "os":"Android 16","revision":"a"*40,"apk_sha256":"b"*64,"origin":"SYNTHETIC",
            "observed_at":"2026-10-15T00:00:00+02:00","ground_truth":"CLEAN","verdict":"ALLOW",
            "score":0,"hard_failure":False,"coverage":"COMPLETE","crashed":False,"duration_ms":120,
            "evidence_codes":[],"operator_verified":False,"expectation_met":None,**changes}

class LabTest(unittest.TestCase):
    def test_synthetic_never_counts_as_device_pass(self):
        doc={"schema":1,"observations":[observation(operator_verified=True,expectation_met=True)]}
        self.assertEqual("NOT_RUN",summary(doc,"a"*40,"b"*64)["cases"]["clean_pixel"]["status"])
    def test_reports_are_bound_to_revision_and_apk(self):
        doc={"schema":1,"observations":[observation(origin="PHYSICAL",operator_verified=True,expectation_met=True)]}
        self.assertEqual("PASS",summary(doc,"a"*40,"b"*64)["cases"]["clean_pixel"]["status"])
        self.assertEqual("NOT_RUN",summary(doc,"c"*40,"b"*64)["cases"]["clean_pixel"]["status"])
    def test_crash_and_partial_review_are_visible(self):
        doc={"schema":1,"observations":[observation(origin="PHYSICAL",operator_verified=True,crashed=True,verdict="ERROR",score=None)]}
        self.assertEqual("FAIL",summary(doc,"a"*40,"b"*64)["cases"]["clean_pixel"]["status"])
    def test_sensitive_unexpected_fields_and_ambiguous_types_rejected(self):
        for changes in ({"imei":"secret"},{"serial":"secret"},{"duration_ms":True},{"score":float("nan")},
                        {"revision":"0"*40},{"hard_failure":True},{"observed_at":"2026-10-15"}):
            with self.assertRaises(ValueError):validate(observation(**changes))
    def test_atomic_record_and_duplicate_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"lab.json";record(path,observation())
            self.assertEqual(1,len(read_document(path)["observations"]))
            with self.assertRaises(ValueError):record(path,observation())
            self.assertEqual(1,len(read_document(path)["observations"]))
    def test_absent_cases_remain_not_run(self):
        report=summary({"schema":1,"observations":[]},"a"*40,"b"*64)
        self.assertTrue(all(case["status"]=="NOT_RUN" for case in report["cases"].values()))
if __name__=="__main__":unittest.main()
