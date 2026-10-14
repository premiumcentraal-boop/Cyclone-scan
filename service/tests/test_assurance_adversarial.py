"""Deterministic malformed evidence corpus; all valid samples here are test fixtures."""
import copy
import io
import json
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_assurance_lab import observation
from test_assurance_beta_gate import review
from tools.assurance import evidence_json as bounded
from tools.assurance.lab import validate,summary
from tools.assurance.calibration import evaluate
from tools.assurance.beta_gate import validate_review

ROOT=Path(__file__).resolve().parents[2]

class EvidenceJsonTests(unittest.TestCase):
    def test_duplicate_fields_rejected_at_every_level(self):
        for data in (
            b'{"schema":999,"schema":1,"observations":[]}',
            b'{"observation":{"operator_verified":false,"operator_verified":true}}',
            b'{"policy":{"reviewed":false,"reviewed":true}}',
            b'{"approvals":{"stable_signing":{"status":"FAIL","status":"PASS"}}}',
            b'{"a":1,"\\u0061":2}',
        ):
            with self.assertRaises(ValueError):bounded.loads(data,65536)

    def test_nonfinite_and_huge_numbers_rejected(self):
        for value in (b"NaN",b"Infinity",b"-Infinity",b"1e9999",b"-1e9999",b"1"*129):
            with self.assertRaises(ValueError):bounded.loads(b'{"value":'+value+b'}',65536)
        self.assertEqual(bounded.loads(b'{"value":1.5}',65536),{"value":1.5})

    def test_unicode_and_syntax_errors_are_controlled(self):
        for data in (b"\xff",b'{"os":"\\ud800"}',b'{"\\udfff":1}',b'{"x":',b"\xef\xbb\xbf{}"):
            with self.assertRaises(ValueError):bounded.loads(data,65536)
        self.assertEqual(bounded.loads('{"os":"日本語"}'.encode(),65536),{"os":"日本語"})

    def test_size_depth_and_node_budgets(self):
        self.assertEqual(bounded.loads(b"{}",2),{})
        for data,limit in ((b"{}",1),(b"",1)):
            with self.assertRaises(ValueError):bounded.loads(data,limit)
        with self.assertRaises(ValueError):
            bounded.loads(b"["*(bounded.MAX_DEPTH+1)+b"0"+b"]"*(bounded.MAX_DEPTH+1),65536)
        with self.assertRaises(ValueError):
            bounded.loads(b"["*2000+b"0"+b"]"*2000,65536)
        with patch.object(bounded,"MAX_NODES",3):
            with self.assertRaises(ValueError):bounded.loads(b"[1,2,3]",65536)

    def test_file_reader_requests_only_limit_plus_one_bytes(self):
        class Reader(io.BytesIO):
            requested=None
            def read(self,size=-1):
                self.requested=size
                return super().read(size)
        reader=Reader(b" "*10000)
        with patch.object(Path,"open",return_value=reader):
            with self.assertRaises(ValueError):bounded.read_json("unused",64)
        self.assertEqual(reader.requested,65)

class EvidenceSchemaTests(unittest.TestCase):
    def test_all_missing_observation_fields_rejected(self):
        fixture=observation()
        for key in fixture:
            row=fixture.copy();del row[key]
            with self.assertRaises(ValueError,msg=key):validate(row)

    def test_unhashable_enums_and_bad_timestamps_are_value_errors(self):
        for key in ("case_id","origin","ground_truth","verdict","coverage","observed_at"):
            for value in ([],{},None,True,42):
                with self.assertRaises(ValueError,msg=key):validate(observation(**{key:value}))
        for value in ("2026-10-15","not a date","0001-01-01T00:00:00+23:00","x"*100):
            with self.assertRaises(ValueError):validate(observation(observed_at=value))

    def test_os_text_and_timestamp_normalization(self):
        for value in ("bad"+chr(0xd800),"bad\ntext","bad\x00text"):
            with self.assertRaises(ValueError):validate(observation(os=value))
        row=validate(observation(observed_at="2026-10-15T00:00:00+02:00"))
        self.assertEqual(row["observed_at"],"2026-10-14T22:00:00+00:00")
        # Datetime comparison avoids Windows' platform-dependent negative epoch conversion.
        doc={"schema":1,"observations":[observation(observed_at="0001-01-01T00:00:00Z",
             origin="PHYSICAL",operator_verified=True)]}
        self.assertEqual(evaluate(doc,"a"*40,"b"*64)["counts"]["submitted"],1)

    def test_invalid_candidate_is_rejected_instead_of_empty_report(self):
        for function in (summary,evaluate):
            for revision,apk in (([],"b"*64),("a"*40,None),("0"*40,"b"*64),("A"*40,"b"*64)):
                with self.assertRaises(ValueError):function({"schema":1,"observations":[]},revision,apk)

    def test_huge_integer_rate_is_a_controlled_validation_error(self):
        for key in ("max_clean_intervention","max_altered_miss"):
            r=review();r["policy"][key]=10**400
            with self.assertRaises(ValueError):validate_review(r)

    def test_seeded_wrong_type_corpus_never_escapes_validation_contract(self):
        rng=random.Random(2601)
        values=[None,True,False,0,-1,10**400,0.5,float("nan"),float("inf"),
                "",[],{},["PHYSICAL"],{"status":"PASS"},"bad"+chr(0xd800)]
        keys=list(observation())
        for _ in range(1200):
            row=observation();row[rng.choice(keys)]=copy.deepcopy(rng.choice(values))
            try:validated=validate(row)
            except ValueError:continue
            # Accepted values must also serialize safely for subsequent tools.
            json.dumps(validated,allow_nan=False,ensure_ascii=False).encode("utf-8")

class EvidenceCliTests(unittest.TestCase):
    def run_cli(self,module,*args):
        return subprocess.run([sys.executable,"-m",module,*map(str,args)],
                              capture_output=True,text=True,cwd=ROOT,timeout=10)

    def test_duplicate_lab_and_review_fail_with_exit_two_no_traceback(self):
        with tempfile.TemporaryDirectory() as temp:
            lab=Path(temp)/"lab.json";approval=Path(temp)/"review.json"
            lab.write_text('{"schema":9,"schema":1,"observations":[]}',encoding="utf-8")
            approval.write_text(json.dumps(review()),encoding="utf-8")
            result=self.run_cli("tools.assurance.beta_gate",lab,approval)
            self.assertEqual(result.returncode,2,result.stderr)
            self.assertNotIn("Traceback",result.stderr)
            lab.write_text('{"schema":1,"observations":[]}',encoding="utf-8")
            approval.write_text(json.dumps(review()).replace('"reviewed": true','"reviewed": false, "reviewed": true'),encoding="utf-8")
            result=self.run_cli("tools.assurance.beta_gate",lab,approval)
            self.assertEqual(result.returncode,2,result.stderr)
            self.assertNotIn("Traceback",result.stderr)

    def test_oversized_observation_never_changes_existing_lab(self):
        with tempfile.TemporaryDirectory() as temp:
            lab=Path(temp)/"lab.json";row=Path(temp)/"row.json"
            original=b'{"schema":1,"observations":[]}'
            lab.write_bytes(original);row.write_bytes(json.dumps(observation()).encode()+b" "*65537)
            result=self.run_cli("tools.assurance.lab","record",lab,row)
            self.assertEqual(result.returncode,2,result.stderr)
            self.assertEqual(lab.read_bytes(),original)

    def test_duplicate_observation_flags_never_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            lab=Path(temp)/"lab.json";row=Path(temp)/"row.json"
            original=b'{"schema":1,"observations":[]}'
            lab.write_bytes(original)
            payload=json.dumps(observation()).replace('"operator_verified": false',
                       '"operator_verified": false, "operator_verified": true')
            row.write_text(payload,encoding="utf-8")
            result=self.run_cli("tools.assurance.lab","record",lab,row)
            self.assertEqual(result.returncode,2,result.stderr)
            self.assertEqual(lab.read_bytes(),original)

if __name__=="__main__":unittest.main()
