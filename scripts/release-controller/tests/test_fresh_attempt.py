"""Offline guards and real disposable subprocesses only. No scans or Docker."""
import ast,copy,datetime,hashlib,importlib.util,json,pathlib,subprocess,sys,tempfile,types,unittest
from unittest.mock import Mock,patch
from restored_support import P as HERE, load_controller, fixture, bind_unit_context, OLD
c=load_controller(__name__)
EXEC=c.RUN+'-attempt-20261020-01';REAL=fixture(c)

def function(path,name):
    return next(n for n in ast.parse(path.read_text()).body if isinstance(n,ast.FunctionDef) and n.name==name)

def body_without_auth(node):
    if node.body and isinstance(node.body[0],ast.Expr) and isinstance(node.body[0].value,ast.Call) and isinstance(node.body[0].value.func,ast.Name) and node.body[0].value.func.id=='authenticate_helpers':node.body.pop(0)
    return ast.dump(node)

class FreshTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name)/EXEC;self.root.mkdir();self.binding=bind_unit_context(c,self.root);self.binding.__enter__()
    def tearDown(self):self.binding.__exit__(None,None,None);self.tmp.cleanup()
    def seed(self,name):
        for n in c.artifacts(name):
            p=self.root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'fixture')
        identity={'executionID':EXEC,'qualificationRunID':c.RUN,'sourceManifestSHA256':c.SOURCE,'images':c.IMAGES,'startedUTC':'2026-10-20T00:00:00+00:00'}
        c.save(self.root/(name+'-attempt.json'),identity)
        c.save(self.root/(name+'-completed.json'),{**identity,'finishedUTC':'2026-10-20T00:00:01+00:00','artifacts':{n:c.sha(self.root/n) for n in c.artifacts(name)}})
    def test_exact_execution_identity(self):self.assertEqual(c.execution_id(EXEC),EXEC)
    def test_old_or_arbitrary_identity_rejected(self):
        for n in (c.RUN,c.RUN+'-continuation-01',EXEC+'/x',EXEC+'x','../'+EXEC):
            with self.subTest(n=n),self.assertRaisesRegex(ValueError,'Invalid continuation'):c.execution_id(n)
    def test_every_predecessor_mandatory(self):
        for name in c.ORDER[1:]:
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'Required predecessor'):c.progress(self.root,name)
    def test_failure_sticky(self):
        c.save(self.root/'scan-failed.json',{})
        for name in c.ORDER:
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'blocked by failed phase'):c.progress(self.root,name)
    def test_interrupted_attempt_blocks(self):
        c.save(self.root/'scan-attempt.json',{})
        with self.assertRaisesRegex(ValueError,'Required predecessor incomplete'):c.progress(self.root,'preflight')
    def test_wrong_predecessor_source(self):
        self.seed('preflight');p=self.root/'preflight-completed.json';r=c.read(p);r['sourceManifestSHA256']='0'*64;p.write_text(json.dumps(r))
        with self.assertRaisesRegex(ValueError,'Wrong predecessor identity'):c.progress(self.root,'scan')
    def test_wrong_predecessor_image(self):
        self.seed('preflight');p=self.root/'preflight-completed.json';r=c.read(p);r['images']['runtime']='sha256:'+'0'*64;p.write_text(json.dumps(r))
        with self.assertRaisesRegex(ValueError,'Wrong predecessor identity'):c.progress(self.root,'scan')
    def test_missing_predecessor_artifact(self):
        self.seed('preflight');(self.root/'live-preflight.json').unlink()
        with self.assertRaisesRegex(ValueError,'Partial predecessor evidence'):c.progress(self.root,'scan')
    def test_altered_predecessor_artifact(self):
        self.seed('preflight');(self.root/'live-preflight.json').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'Predecessor evidence changed'):c.progress(self.root,'scan')
    def test_incomplete_artifact_set(self):
        self.seed('preflight');p=self.root/'preflight-completed.json';r=c.read(p);r['artifacts'].pop('live-preflight.json');p.write_text(json.dumps(r))
        with self.assertRaisesRegex(ValueError,'Incomplete predecessor evidence'):c.progress(self.root,'scan')
    def test_valid_preflight_permits_scan_boundary(self):self.seed('preflight');c.progress(self.root,'scan')
    def test_preparation_contains_no_scan_evidence(self):
        rows=c.read(REAL/'fresh-inputs.json');self.assertEqual(len([n for n in rows if n.startswith('source/')]),97)
        self.assertNotIn('evidence-context.json',rows);self.assertNotIn('runtime-raw-scan.json',rows);self.assertNotIn('accepted.json',rows)
        self.assertFalse((REAL/'data/trivy-cache').exists());self.assertFalse(list(REAL.glob('*-attempt.json')))
    def test_real_preparation_verify(self):
        with bind_unit_context(c,REAL):c.verify(REAL)
    def test_reused_directory_rejected(self):
        with self.assertRaisesRegex(ValueError,'Reused or unexpected'):c.prepare(HERE,self.root)
    def test_unsafe_paths(self):
        for name in ('../x','/x','a\\b','C:/x','a/./b'):
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'Unsafe evidence'):c.safe(self.root,name)
    def test_all_runtime_collector_functions_unchanged(self):
        for name in ('installed_apk_records','runtime_package_expectation','runtime_package_script','validate_runtime_package_output','collect_runtime_packages','collect_runtime','container_contract','remove_owned','create','browser_contract','bound_acceptance'):
            with self.subTest(name=name):self.assertEqual(body_without_auth(function(HERE/'continuation.py',name)),body_without_auth(function(OLD/'continuation.py',name)))
    def test_reviewed_workflow_unchanged(self):self.assertEqual(c.sha(HERE/'workflow.py'),c.COLLECTOR)
    def test_scanner_archive_functions_unchanged(self):
        old=REAL/'history/remote-evidence/scan-images.py'
        before={n.name:ast.dump(n) for n in ast.parse(old.read_text()).body if isinstance(n,ast.FunctionDef) and n.name!='run'}
        after={n.name:ast.dump(n) for n in ast.parse((HERE/'scan-images.py').read_text()).body if isinstance(n,ast.FunctionDef) and n.name!='run'}
        self.assertEqual(before,after)
    def test_security_validator_catalog_unchanged(self):
        old=c.read(REAL/'history/remote-evidence/helpers.json');new=c.read(REAL/'data/helpers.json')
        self.assertEqual(set(old),set(new));self.assertEqual({n for n in old if old[n]!=new[n]},{'scan-images.py'})
        for n in old:
            if n!='scan-images.py':self.assertEqual(c.sha(REAL/'data'/n),old[n])
    def test_original_qualification_metadata_only_adds_attempt(self):
        old=c.read(REAL/'history/remote-evidence/qualification.json');new=c.read(REAL/'data/qualification.json')
        self.assertEqual(new.pop('attemptID'),EXEC);self.assertEqual(old,new)
    def test_every_scan_process_has_stdout_stderr_status(self):
        names=c.scan_files()
        for n in c.SCAN_LOGS:
            self.assertTrue(all(n+s in names for s in ('','.stderr','.exit.json')))
    def test_old_scan_attempt_rejected_before_policy(self):
        (self.root/'data').mkdir();c.save(self.root/'data/evidence-context.json',{'attemptID':c.RUN+'-continuation-01'})
        # Canonical helper discovery: never add execution data to sys.path.
        with patch.object(c,'authenticate_helpers'),self.assertRaisesRegex(ValueError,'Scan attempt substitution'):c.fresh_security(self.root)
    def test_old_scan_timestamp_rejected_before_policy(self):
        (self.root/'data').mkdir();c.save(self.root/'data/evidence-context.json',{'attemptID':EXEC,'startedUTC':'2026-10-19T00:00:00+00:00'})
        c.save(self.root/'scan-attempt.json',{'startedUTC':'2026-10-20T00:00:00+00:00'});# Canonical helper discovery: never add execution data to sys.path.
        with patch.object(c,'authenticate_helpers'),self.assertRaisesRegex(ValueError,'Historical scan replay'):c.fresh_security(self.root)
    def test_phase_failure_records_original_failure(self):
        def fail():raise RuntimeError('deliberate-validator-rejection')
        with self.assertRaisesRegex(RuntimeError,'deliberate-validator-rejection'):c.phase(self.root,'preflight',fail)
        self.assertFalse((self.root/'preflight-completed.json').exists());self.assertEqual(c.read(self.root/'preflight-failed.json')['exception'],'RuntimeError')
    def test_diagnostic_write_failure_never_passes(self):
        def fail():raise RuntimeError('validator-failed')
        with patch.object(c,'save',side_effect=OSError('disk-full')),self.assertRaisesRegex(OSError,'disk-full'):c.phase(self.root,'preflight',fail)
        self.assertFalse((self.root/'preflight-completed.json').exists())
    def test_runtime_cannot_start_without_fresh_security(self):
        with patch.object(c,'verify',return_value=Mock()),patch.object(c,'live') as live,self.assertRaisesRegex(ValueError,'Required predecessor'):c.guard(self.root,'runtime-creation',docker=True)
        live.assert_not_called()
    def test_browser_cannot_start_without_runtime(self):
        with patch.object(c,'verify',return_value=Mock()),patch.object(c,'live') as live,self.assertRaisesRegex(ValueError,'Required predecessor'):c.guard(self.root,'browser-creation',docker=True)
        live.assert_not_called()
    def test_no_qualification_without_cli_authorization(self):
        with patch.object(sys,'argv',['continuation.py','scan',str(self.root)]),self.assertRaisesRegex(ValueError,'separate authorization'):c.main()
    def test_scanner_flags_preserve_policy(self):
        source=(HERE/'scan-images.py').read_text()
        for text in ("'vuln,secret'","'--image-config-scanners','secret'","'--list-all-pkgs'","'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL'","'--skip-db-update'","'--download-db-only'","validate_scan("):
            self.assertIn(text,source)
        self.assertNotIn('--include-dev-deps',source)
    def test_browser_inherits_all_security_predecessors(self):
        text=(HERE/'browser-acceptance.mjs').read_text()
        self.assertIn("['preflight','scan','scan-acceptance','reuse','audit','acceptance'",text)
        self.assertNotIn('continuation-\\d{2}',text)
    def test_three_images_bound_to_original_builds(self):
        builds=c.read(REAL/'data/builds.json')
        self.assertEqual({k:v['image']['id'] for k,v in builds.items()},c.IMAGES)
    def test_real_reviewed_compose_interface_accepts_prepared_inputs(self):
        (self.root/'data').mkdir();import shutil
        shutil.copytree(REAL/'data/source',self.root/'data/source')
        shutil.copyfile(REAL/'data/source-manifest.json',self.root/'data/source-manifest.json')
        target=c.compose_inputs(self.root)
        spec=importlib.util.spec_from_file_location('real_compose_helper',REAL/'data/compose_prebuild.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        calls=[]
        def execute(command,**kwargs):
            calls.append((command,kwargs));return types.SimpleNamespace(returncode=0,stdout='5.6.0\n',stderr='')
        runner=m.Runner(target,['/reviewed/docker-compose'],{'runID':c.RUN,'sourceManifestSHA256':c.SOURCE},{'PATH':'/usr/bin:/bin'},execute)
        self.assertEqual(len(calls),1);self.assertEqual(calls[0][0],['/reviewed/docker-compose','version','--short'])
        self.assertEqual(runner.env['DOCKER_HOST'],'tcp://127.0.0.1:1');self.assertEqual(len(list((target/'source').rglob('*.yaml'))),len(list((REAL/'data/source').rglob('*.yaml'))))
    def test_scan_status_failure_blocks_even_with_json(self):
        (self.root/'data').mkdir();c.save(self.root/'scan-driver-exit.json',{'exitCode':0,'error':None,'executionID':EXEC})
        c.save(self.root/'data/evidence-context.json',{})
        c.save(self.root/'data/scanner-db-download.log.exit.json',{'attemptID':EXEC,'runID':c.RUN,'sourceManifestSHA256':c.SOURCE,'exitCode':13,'error':None})
        # Canonical helper discovery: never add execution data to sys.path.
        with patch.object(c,'authenticate_helpers'),patch.object(c,'fresh_security'),self.assertRaisesRegex(ValueError,'Scanner process failed: scanner-db-download.log'):c.strict_scans(self.root)
    def test_driver_failure_blocks_before_output_interpretation(self):
        (self.root/'data').mkdir();c.save(self.root/'scan-driver-exit.json',{'exitCode':2,'error':None,'executionID':EXEC})
        c.save(self.root/'data/evidence-context.json',{})
        # Canonical helper discovery: never add execution data to sys.path.
        with patch.object(c,'authenticate_helpers'),patch.object(c,'fresh_security'),self.assertRaisesRegex(ValueError,'Scanner driver status mismatch'):c.strict_scans(self.root)
    def test_scanner_diagnostic_tampering_rejected(self):
        (self.root/'data').mkdir();c.save(self.root/'scan-driver-exit.json',{'exitCode':0,'error':None,'executionID':EXEC})
        c.save(self.root/'data/evidence-context.json',{})
        n='scanner-db-download.log';(self.root/'data'/n).write_bytes(b'original');(self.root/'data'/(n+'.stderr')).write_bytes(b'notice')
        c.save(self.root/'data'/(n+'.exit.json'),{'attemptID':EXEC,'runID':c.RUN,'sourceManifestSHA256':c.SOURCE,'exitCode':0,'error':None,'stdoutSHA256':'0'*64,'stderrSHA256':c.sha(self.root/'data'/(n+'.stderr'))})
        # Canonical helper discovery: never add execution data to sys.path.
        with patch.object(c,'authenticate_helpers'),patch.object(c,'fresh_security'),self.assertRaisesRegex(ValueError,'Scanner diagnostic evidence changed'):c.strict_scans(self.root)

class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);(self.root/'scanner-policy').mkdir()
        source=(HERE/'scan-images.py').read_text();nodes=ast.parse(source).body
        module=ast.Module(body=[n for n in nodes if isinstance(n,ast.FunctionDef) and n.name in ('utc','write','digest','run')],type_ignores=[])
        import time,os
        self.ns={'R':self.root,'Q':{'attemptID':EXEC,'runID':c.RUN,'sourceManifestSHA256':c.SOURCE},'datetime':datetime,'time':time,'Path':pathlib.Path,'hashlib':hashlib,'json':json,'subprocess':subprocess,'isolated_scanner_environment':lambda r:os.environ.copy()}
        exec(compile(module,'reviewed-scanner-run','exec'),self.ns)
    def tearDown(self):self.tmp.cleanup()
    def test_real_stdout_stderr_separation(self):
        self.ns['run']([sys.executable,'-I','-B','-c',"import sys;print('{}');print('notice',file=sys.stderr)"],'audit.log')
        self.assertEqual(json.loads((self.root/'audit.log').read_text()),{})
        self.assertEqual((self.root/'audit.log.stderr').read_text().strip(),'notice')
        self.assertEqual(c.read(self.root/'audit.log.exit.json')['exitCode'],0)
    def test_real_nonzero_status_retained(self):
        with self.assertRaisesRegex(AssertionError,'Scanner/tool failure'):self.ns['run']([sys.executable,'-I','-B','-c','raise SystemExit(17)'],'bad.log')
        self.assertEqual(c.read(self.root/'bad.log.exit.json')['exitCode'],17)
    def test_real_missing_executable_status_retained(self):
        with self.assertRaises(FileNotFoundError):self.ns['run']([str(self.root/'missing-executable')],'missing.log')
        status=c.read(self.root/'missing.log.exit.json');self.assertIsNone(status['exitCode']);self.assertEqual(status['error']['exception'],'FileNotFoundError')
    def test_no_overwrite_of_scanner_output(self):
        (self.root/'exists.log').write_bytes(b'previous')
        with self.assertRaises(FileExistsError):self.ns['run']([sys.executable,'-V'],'exists.log')
        self.assertEqual((self.root/'exists.log').read_bytes(),b'previous')

if __name__=='__main__':unittest.main(verbosity=2)
