"""Actual controller loading functions with ordinary isolated JSON/filesystem fixtures.

Only fixture-local path/digest anchors are rebound. No successful host, scan,
schema, archive or controller verdict is mocked in the genuine positive run.
"""
import copy,datetime,hashlib,json,pathlib,runpy,shutil,tempfile,types,unittest
from unittest.mock import patch
D=pathlib.Path(__file__).parent
ROOT=D.parent/'zevyrn-v1.2.1-final-runtime-scope-preparation-20261021-01'/'isolated-controller'/'qualification-dk02-20261019-02-attempt-20261020-01'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')

class RefreshPath(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='zevyrn-refresh-defensive-')
        cls.base=pathlib.Path(cls.tmp.name);cls.view=cls.base/'view'
        shutil.copytree(D/'security-view',cls.view)
        cls.module=(D/'security_refresh.py').read_text()
        cls.entry=(D/'continuation.PROPOSED.py').read_text()
        cls.original_authority=read(D/'security-refresh-authority.PROPOSED.json')
        cls.original_manifest=read(D/'security-view-inventory.json')
        cls.original_fresh=read(pathlib.Path(cls.original_authority['freshManifest']['path']))
        cls.originals={}
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def setUp(self):
        self.a=copy.deepcopy(self.original_authority)
        self.m=copy.deepcopy(self.original_manifest);self.m['root']=str(self.view)
        self.fresh=copy.deepcopy(self.original_fresh)
        self.backups={}
    def tearDown(self):
        for p,value in self.backups.items():
            if value is None:p.unlink(missing_ok=True)
            else:p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(value)
    def change(self,name,mutate=None,raw=None,missing=False):
        p=self.view/name
        self.backups.setdefault(p,p.read_bytes() if p.exists() else None)
        if missing:p.unlink();return
        if raw is not None:p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
        else:
            value=read(p);mutate(value);save(p,value)
    def reseal(self,*names):
        """Authentic-but-contradictory JSON fixtures, not production authorizations."""
        for name in names:
            p=self.view/name
            for table in (self.m['files'],self.fresh['files']):
                for row in table:
                    if row['path']==name:row.update(sha256=sha(p),bytes=p.stat().st_size)
    def controller(self):
        manifest=self.base/'fixture-view-inventory.json';save(manifest,self.m)
        fresh=self.base/'fixture-fresh-manifest.json';save(fresh,self.fresh)
        self.a['viewRoot']=str(self.view)
        self.a['viewManifest']={'path':str(manifest),'sha256':sha(manifest)}
        self.a['freshManifest']={'path':str(fresh),'sha256':sha(fresh)}
        policy=self.base/'security-refresh-authority.PROPOSED.json';save(policy,self.a)
        old_pin=self.original_authority
        original_hash=sha(D/'security-refresh-authority.PROPOSED.json')
        module=self.base/'security_refresh.py'
        text=self.module.replace(original_hash,sha(policy))
        self.assertEqual(self.module.count(original_hash),1)
        module.write_text(text,encoding='utf-8')
        entry=self.base/'continuation-fixture.py'
        text=self.entry.replace(repr(str(D/'security_refresh.py')),repr(str(module))).replace(sha(D/'security_refresh.py'),sha(module))
        self.assertEqual(self.entry.count(repr(str(D/'security_refresh.py'))),1)
        self.assertEqual(self.entry.count(sha(D/'security_refresh.py')),1)
        entry.write_text(text,encoding='utf-8')
        return runpy.run_path(str(entry))['main'].__globals__
    def rejects(self,message,guard=False,now=None):
        C=self.controller()
        with self.assertRaisesRegex((ValueError,FileNotFoundError),message):
            if guard:C['guard'](ROOT,'settlement',docker=False)
            else:C['fresh_security'](ROOT,now=now,settlement=True)
        self.assertFalse((D/'authorized-settlement-output').exists())
    def test_missing_scan_receipt(self):
        self.change('builder-scan-receipt.json',missing=True);self.rejects('No such file|cannot find|cannot find the file')
    def test_altered_scan_receipt(self):
        self.change('builder-scan-receipt.json',raw=b'{}');self.rejects('Refresh inventory changed: builder-scan-receipt')
    def test_missing_sbom(self):
        self.change('runtime-sbom.cdx.json',missing=True);self.rejects('No such file|cannot find|cannot find the file')
    def test_missing_source_report(self):
        self.change('source-secrets.json',missing=True);self.rejects('No such file|cannot find|cannot find the file')
    def test_changed_database(self):
        # Same-size ordinary byte replacement, never a substitute database engine.
        self.change('trivy-cache/db/metadata.json',raw=b'{}');self.rejects('Refresh inventory changed: trivy-cache/db/metadata')
    def test_unexpected_importable(self):
        self.change('unapproved.py',raw=b'# ordinary inert defensive fixture\n');self.rejects('Unexpected/missing refresh inventory')
    def test_unapproved_cache(self):
        self.change('bad.pyc',raw=b'ordinary inert fixture');self.rejects('Unapproved refresh bytecode')
    def test_missing_historical_receipt(self):
        self.a['historicalReceipts']['not-present-completion.json']='0'*64;self.rejects('No such file|cannot find|cannot find the file')
    def test_altered_historical_receipt_pin(self):
        self.a['historicalReceipts']['scan-completed.json']='0'*64;self.rejects('Historical refresh predecessor changed: scan-completed')
    def test_wrong_parent_execution(self):
        self.a['parentExecutionID']='wrong';self.rejects('Refresh parent identity')
    def test_wrong_approved_image(self):
        self.a['images']['runtime']='sha256:'+'0'*64;self.rejects('Refresh approved identity')
    def test_wrong_approved_source(self):
        self.a['sourceManifestSHA256']='0'*64;self.rejects('Refresh approved identity')
    def test_wrong_scope(self):
        self.a['scope']='all-qualification';self.rejects('Refresh scope')
    def test_wrong_receipt_execution(self):
        self.change('builder-scan-receipt.json',lambda r:r.update(attemptID='unrelated'))
        self.reseal('builder-scan-receipt.json');self.rejects('Refresh receipt execution')
    def test_wrong_receipt_image_through_guard(self):
        self.change('builder-scan-receipt.json',lambda r:r.update(imageID='sha256:'+'0'*64))
        self.reseal('builder-scan-receipt.json');self.rejects('Evidence image/archive mismatch: imageID',guard=True)
    def test_receipt_process_failure(self):
        self.change('runtime-scan.log.exit.json',lambda r:r.update(exitCode=1))
        self.reseal('runtime-scan.log.exit.json');self.rejects('Refresh scanner process failed: runtime-scan.log')
    def test_stale_receipts_through_controller_loader(self):
        self.rejects('Stale vulnerability database',now=datetime.datetime(2026,10,24,tzinfo=datetime.timezone.utc))
    def test_actual_guard_rejects_stale_supplemental_evidence_first(self):
        C=self.controller()
        class Future(datetime.datetime):
            @classmethod
            def now(cls,tz=None):return cls(2026,10,24,tzinfo=datetime.timezone.utc)
        with patch.object(C['datetime'],'datetime',Future):
            # The browser retest has its own earlier freshness deadline. Preserve
            # that first authoritative rejection; the DB loader is tested below.
            with self.assertRaisesRegex(ValueError,'STALE_RETEST'):C['guard'](ROOT,'settlement',docker=False)
        self.assertFalse((D/'authorized-settlement-output').exists())
    def test_actual_guard_rejects_stale_database_at_selector(self):
        C=self.controller();original=C['fresh_security']
        future=datetime.datetime(2026,10,24,tzinfo=datetime.timezone.utc)
        def database_clock(root,now=None,**options):
            return original(root,now=future,**options)
        # Change only the DB validator's explicit clock input. The actual
        # verify/progress/browser authority functions and evidence stay intact.
        C['fresh_security']=database_clock
        with self.assertRaisesRegex(ValueError,'Stale vulnerability database'):C['guard'](ROOT,'settlement',docker=False)
        self.assertFalse((D/'authorized-settlement-output').exists())
    def finding_fixture(self,secret=False):
        report=read(self.view/'builder-raw-scan.json')
        if secret:
            report['Results'][0]['Secrets']=[{'RuleID':'inert-defensive-control'}]
        else:
            rows=[v for item in report['Results'] for v in item.get('Vulnerabilities',[])]
            self.assertTrue(rows);rows[0]['Severity']='HIGH'
        self.change('builder-raw-scan.json',raw=(json.dumps(report)+'\n').encode())
        self.change('builder-scan-receipt.json',lambda r:r.update(reportSHA256=sha(self.view/'builder-raw-scan.json')))
        self.reseal('builder-raw-scan.json','builder-scan-receipt.json')
    def test_high_findings_still_rejected(self):
        self.finding_fixture();self.rejects('Critical/high vulnerability or secret gate failed')
    def test_secret_findings_still_rejected(self):
        self.finding_fixture(secret=True);self.rejects('Critical/high vulnerability or secret gate failed')
    def test_nonsettlement_keeps_original_freshness(self):
        C=self.controller()
        with self.assertRaisesRegex(ValueError,'Stale vulnerability database'):C['fresh_security'](ROOT)
    def test_unrelated_failed_phase_not_superseded(self):
        C=self.controller()
        with self.assertRaisesRegex(ValueError,'Continuation blocked by failed phase'):C['guard'](ROOT,'audit',docker=False)
    def test_final_requires_refresh_proof_in_inventory(self):
        C=self.controller();self.assertIn('security-evidence-integration.json',C['artifacts']('settlement'))
        self.assertIn("'Security refresh completion changed'",self.entry)
        self.assertIn("'securityEvidenceRefresh':refreshed_security(root,w)['proof']",self.entry)

class Capacity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.C=runpy.run_path(str(D/'continuation.PROPOSED.py'))['main'].__globals__
    def test_actual_output_budget_matches_record(self):
        actual=self.C['settlement_output_capacity'](ROOT)
        self.assertEqual(actual['requiredBytes'],read(D/'genuine-controller-readiness.json')['capacity']['requiredBytes'])
        self.assertGreater(actual['availableBytes'],actual['requiredBytes'])
    def test_output_one_byte_short_rejected(self):
        required=self.C['settlement_output_capacity'](ROOT)['requiredBytes']
        with patch.object(self.C['shutil'],'disk_usage',return_value=types.SimpleNamespace(free=required-1)):
            with self.assertRaisesRegex(ValueError,'Insufficient settlement output capacity'):self.C['settlement_output_capacity'](ROOT)
    def test_output_exact_bound_accepted_fixture(self):
        required=self.C['settlement_output_capacity'](ROOT)['requiredBytes']
        with patch.object(self.C['shutil'],'disk_usage',return_value=types.SimpleNamespace(free=required)):
            self.assertEqual(self.C['settlement_output_capacity'](ROOT)['requiredBytes'],required)
    def test_original_eight_gib_gate_unchanged(self):
        w=self.C['workflow']()
        proc=types.SimpleNamespace(read_text=lambda:'MemAvailable: 4194304 kB\n')
        with patch.object(w,'execute',return_value='unused-read-only-fixture'),patch.object(w,'Path',return_value=proc),\
             patch.object(w.shutil,'disk_usage',return_value=types.SimpleNamespace(free=8*1024**3-1)),patch.object(w.os,'cpu_count',return_value=8):
            with self.assertRaisesRegex(ValueError,'Insufficient qualification headroom'):w.capacity(ROOT)

if __name__=='__main__':unittest.main(verbosity=2)
