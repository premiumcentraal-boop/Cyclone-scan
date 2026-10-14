import unittest
from tools.assurance.calibration import evaluate, score_band
from test_assurance_lab import observation

class CalibrationTest(unittest.TestCase):
    def evaluate(self,rows,**settings):
        return evaluate({"schema":1,"observations":rows},"a"*40,"b"*64,**settings)
    def test_empty_data_is_unknown_not_zero_error(self):
        out=self.evaluate([])
        self.assertEqual("INSUFFICIENT_DATA",out["data_status"])
        self.assertIsNone(out["clean_device_intervention"]["rate"])
        self.assertIsNone(out["latency_ms"]["p95"])
    def test_partial_and_synthetic_evidence_do_not_count(self):
        rows=[observation(operator_verified=True),
              observation(observation_id="other",origin="PHYSICAL",operator_verified=True,coverage="PARTIAL")]
        out=self.evaluate(rows)
        self.assertEqual(0,out["counts"]["eligible_scenarios"])
        self.assertEqual(1,out["counts"]["synthetic"])
        self.assertEqual(1,out["counts"]["excluded_from_accuracy"])
    def test_repeated_scans_do_not_inflate_devices(self):
        rows=[observation(observation_id="scan-"+str(i),origin="PHYSICAL",operator_verified=True) for i in range(20)]
        out=self.evaluate(rows)
        self.assertEqual(1,out["clean_device_intervention"]["devices"])
        self.assertEqual("INSUFFICIENT_DATA",out["data_status"])
    def test_false_positive_and_miss_are_separate(self):
        rows=[observation(origin="PHYSICAL",operator_verified=True,score=60,verdict="STEP_UP"),
              observation(observation_id="altered",device_alias="device-b",origin="PHYSICAL",
                          operator_verified=True,ground_truth="ALTERED",score=10)]
        out=self.evaluate(rows,min_clean_devices=1,min_altered_devices=1)
        self.assertEqual(1,out["clean_device_intervention"]["rate"])
        self.assertEqual(1,out["altered_device_miss"]["rate"])
        self.assertEqual("READY_FOR_REVIEW",out["data_status"])
        self.assertFalse(out["policy"]["weights_changed"])
    def test_hard_failure_cannot_be_rescued_by_threshold(self):
        row=observation(hard_failure=True,score=0,verdict="BLOCK")
        self.assertEqual("BLOCK",score_band(row,100,101))
    def test_revision_and_apk_are_not_mixed(self):
        out=self.evaluate([observation(revision="c"*40,origin="PHYSICAL",operator_verified=True)])
        self.assertEqual(0,out["counts"]["submitted"])
    def test_latency_and_uncertainty_are_reported(self):
        rows=[observation(origin="PHYSICAL",operator_verified=True,duration_ms=100),
              observation(observation_id="b",device_alias="b",origin="PHYSICAL",operator_verified=True,duration_ms=300)]
        out=self.evaluate(rows)
        self.assertEqual(200,out["latency_ms"]["p50"])
        self.assertEqual(290,out["latency_ms"]["p95"])
        self.assertGreater(out["clean_device_intervention"]["wilson95"][1],0)
if __name__=="__main__":unittest.main()
