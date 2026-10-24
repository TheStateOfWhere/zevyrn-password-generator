"""Dynamic final-completeness checks with disposable completion envelopes only.

The existing historical root is read-only. A genuine authenticated context and
refresh proof are reused as fixture INPUTS; no output is qualification evidence.
The real completion checker and refreshed_security validator are not stubbed.
"""
import copy,hashlib,json,pathlib,runpy,tempfile,unittest
D=pathlib.Path(__file__).parent
ROOT=D.parent/'zevyrn-v1.2.1-final-runtime-scope-preparation-20261021-01'/'isolated-controller'/'qualification-dk02-20261019-02-attempt-20261020-01'
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class FinalBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseC=runpy.run_path(str(D/'continuation.PROPOSED.py'))['main'].__globals__
        cls.originalLink=cls.baseC['settlement_link']()
        cls.genuineContext=cls.originalLink['context'](cls.baseC,ROOT)
        cls.genuineProof=cls.baseC['refreshed_security'](ROOT)['proof']
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='zevyrn-final-completeness-fixture-')
        self.out=pathlib.Path(self.tmp.name)
        self.C=runpy.run_path(str(D/'continuation.PROPOSED.py'))['main'].__globals__
        self.ctx=copy.deepcopy(self.genuineContext);self.ctx['output']=self.out
        self.ctx['policy']['settlementExecutionID']='fixture-only-final-binding'
        self.ctx['proof']['settlementExecutionID']='fixture-only-final-binding'
        link={**self.originalLink,'context':lambda C,root:self.ctx}
        self.C['settlement_link']=lambda:link
        save(self.out/'browser-evidence-integration.json',self.ctx['proof'])
        save(self.out/'security-evidence-integration.json',self.genuineProof)
        save(self.out/'settled.json',{'executionID':ROOT.name,'qualificationRunID':self.C['RUN'],
          'workloads':read(ROOT/'execution-workloads-before.json'),'resources':read(ROOT/'execution-resources-before.json')})
        identity={'executionID':ROOT.name,'settlementExecutionID':'fixture-only-final-binding',
          'qualificationRunID':self.C['RUN'],'sourceManifestSHA256':self.C['SOURCE'],'images':self.C['IMAGES'],
          'policySHA256':self.C['SETTLEMENT_POLICY_SHA256'],'startedUTC':'2026-10-23T00:00:00+00:00'}
        save(self.out/'settlement-attempt.json',identity)
        self.receipt={**identity,'finishedUTC':'2026-10-23T00:00:01+00:00',
          'artifacts':{n:sha(self.out/n) for n in self.C['artifacts']('settlement')}}
        save(self.out/'settlement-completed.json',self.receipt)
    def tearDown(self):self.tmp.cleanup()
    def test_actual_complete_contract_accepts_fixture_binding(self):
        result=self.C['complete_contract'](ROOT)
        self.assertIn('security-evidence-integration.json',result['supplemental'])
    def test_missing_refresh_proof_fails_final(self):
        (self.out/'security-evidence-integration.json').unlink()
        with self.assertRaises(FileNotFoundError):self.C['complete_contract'](ROOT)
    def test_altered_refresh_proof_fails_final(self):
        save(self.out/'security-evidence-integration.json',{})
        with self.assertRaisesRegex(ValueError,'Settlement artifact changed: security-evidence-integration'):self.C['complete_contract'](ROOT)
    def test_contradictory_resealed_refresh_proof_fails_final(self):
        wrong=copy.deepcopy(self.genuineProof);wrong['databaseSHA256']='0'*64
        save(self.out/'security-evidence-integration.json',wrong)
        self.receipt['artifacts']['security-evidence-integration.json']=sha(self.out/'security-evidence-integration.json')
        save(self.out/'settlement-completed.json',self.receipt)
        with self.assertRaisesRegex(ValueError,'Security refresh completion changed'):self.C['complete_contract'](ROOT)
if __name__=='__main__':unittest.main(verbosity=2)
