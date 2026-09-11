import json, tempfile, unittest
from pathlib import Path
from src.assessor import load_records, assess, metrics
from src.models import DelegationRecord, finding_id
from src.reporting import render
from src.remediation import validate_closure

class DelegationTests(unittest.TestCase):
    def rec(self,**kw):
        base=dict(principal="svc-x",delegation_type="unconstrained",enabled=True,privileged=False,protocol_transition=False,interactive_logon=False,managed_identity=True,target_count=1,rbcd_writer_count=0,criticality="medium",owner="Team",review_age_days=20); base.update(kw); return DelegationRecord(**base)
    def test_unconstrained_detected(self): self.assertTrue(any("Unconstrained" in f.title for f in assess([self.rec()])))
    def test_privilege_increases_risk(self): self.assertGreater(assess([self.rec(privileged=True)])[0].score,assess([self.rec()])[0].score)
    def test_disabled_reduces_risk(self): self.assertLess(assess([self.rec(enabled=False)])[0].score,assess([self.rec()])[0].score)
    def test_score_bounded(self): self.assertLessEqual(assess([self.rec(privileged=True,interactive_logon=True,managed_identity=False,target_count=99,criticality="critical",review_age_days=999)])[0].score,100)
    def test_deterministic_id(self): self.assertEqual(finding_id("a","b"),finding_id("a","b"))
    def test_protocol_transition(self): self.assertTrue(any("Protocol transition" in f.title for f in assess([self.rec(delegation_type="constrained",protocol_transition=True)])))
    def test_rbcd_writer_scope(self): self.assertTrue(any("RBCD" in f.title for f in assess([self.rec(delegation_type="rbcd",rbcd_writer_count=4)])))
    def test_metrics(self): self.assertEqual(metrics(assess([self.rec()]))["total"],1)
    def test_report_contains_attack(self): self.assertIn("T1558",render(assess([self.rec()])))
    def test_valid_closure(self): self.assertEqual(validate_closure({"change_reference":"CHG-1","owner":"Identity","delegation_corrected":True,"privilege_reviewed":True,"post_change_export":True,"authentication_validated":True})[0],"validated")
    def test_incomplete_closure(self): self.assertEqual(validate_closure({})[0],"needs_evidence")
    def test_duplicate_rejected(self):
        item={"principal":"x","delegation_type":"none","enabled":True,"privileged":False,"protocol_transition":False,"interactive_logon":False,"managed_identity":True,"target_count":0,"rbcd_writer_count":0,"criticality":"low","owner":"T","review_age_days":1}
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"x.json"; p.write_text(json.dumps([item,item]))
            with self.assertRaises(ValueError): load_records(str(p))
    def test_invalid_boolean_rejected(self):
        item={"principal":"x","delegation_type":"none","enabled":"yes","privileged":False,"protocol_transition":False,"interactive_logon":False,"managed_identity":True,"target_count":0,"rbcd_writer_count":0,"criticality":"low","owner":"T","review_age_days":1}
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"x.json"; p.write_text(json.dumps([item]))
            with self.assertRaises(ValueError): load_records(str(p))

if __name__ == "__main__": unittest.main()
