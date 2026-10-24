"""Actual subprocess controller decision-boundary tests; capture-only transport."""
from pathlib import Path
import copy,hashlib,json,os,shutil,subprocess,sys,tempfile,unittest,py_compile
from controller_fixture import make
HERE=Path(__file__).resolve().parent
H=lambda b:hashlib.sha256(b).hexdigest()

def dump(p,v):p.write_text(json.dumps(v,sort_keys=True)+'\n')

class ControllerTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.template=Path(tempfile.mkdtemp(dir=HERE,prefix='synthetic-template-'))/'bundle';cls.anchors=make(cls.template)
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir=HERE,prefix='boundary-')
  self.r=Path(self.temp.name);self.env=self.r/'environment';self.e=self.r/'evidence'
  shutil.copytree(HERE/'environment',self.env);shutil.copytree(self.template,self.e)
  self.man=json.loads((HERE/'controller-environment-manifest.PROPOSED.json').read_bytes());self.man['environmentRoot']=str(self.env)
  self.a=copy.deepcopy(self.anchors);self.flags=['-I','-B'];self.extra='';self.diag=self.r/'diagnostic.json'
 def tearDown(self):self.temp.cleanup()
 def reseal_env(self):self.man['files']={p.relative_to(self.env).as_posix():H(p.read_bytes()) for p in self.env.rglob('*') if p.is_file()}
 def edit(self,name,fn):
  p=self.e/name;v=json.loads(p.read_bytes());fn(v);dump(p,v)
 def sbom(self,fn):
  self.edit('runtime-sbom.cdx.json',fn)
  self.edit('runtime-sbom-receipt.json',lambda r:r.update(sbomSHA256=H((self.e/'runtime-sbom.cdx.json').read_bytes())))
 def report(self,kind,fn):
  self.edit(kind+'-raw-scan.json',fn)
  self.edit(kind+'-scan-receipt.json',lambda r:r.update(reportSHA256=H((self.e/(kind+'-raw-scan.json')).read_bytes())))
 def call(self,passed=False,stage=None):
  manifest=self.r/'manifest.json';dump(manifest,self.man)
  args={'evidence':str(self.e),'manifest':str(manifest),'digest':H(manifest.read_bytes()),'anchors':self.a,'diag':str(self.diag)}
  # Trusted fixture launcher verifies the initial controller bytes itself, then
  # compiles those bytes; it never relies on importing the controller from cache.
  code="""from pathlib import Path
import sys,json,hashlib,types
v=json.loads(sys.argv[1]);manifest=Path(v['manifest']).read_bytes()
assert hashlib.sha256(manifest).hexdigest()==v['digest']
m=json.loads(manifest);root=Path(m['environmentRoot']);b=(root/'control.py').read_bytes()
assert hashlib.sha256(b).hexdigest()==m['files']['control.py']
ns={'__file__':str(root/'control.py'),'__name__':'reviewed_controller'}
exec(compile(b,str(root/'control.py'),'exec'),ns)
"""+self.extra+"""
sent=[];constructed=[]
original_constructor=ns['_authorization_payload']
def observe_construction(*args):
 constructed.append(True)
 return original_constructor(*args)
ns['_authorization_payload']=observe_construction
try:
 payload=ns['gate'](v['evidence'],v['manifest'],v['digest'],v['anchors'],v['diag'],lambda p:sent.append(p))
 print(json.dumps({'accepted':True,'sentCount':len(sent),'constructedCount':len(constructed),'keys':sorted(payload)}))
except BaseException as error:
 print(json.dumps({'accepted':False,'sentCount':len(sent),'constructedCount':len(constructed),'error':str(error)}))
"""
  r=subprocess.run([sys.executable,*self.flags,'-c',code,json.dumps(args)],capture_output=True,text=True)
  self.assertEqual(r.returncode,0,r.stderr)
  v=json.loads(r.stdout);self.assertIs(v['accepted'],passed,v)
  self.assertEqual(v['sentCount'],1 if passed else 0,v)
  self.assertEqual(v['constructedCount'],1 if passed else 0,v)
  if stage:self.assertTrue(v['error'].startswith(stage+':'),v)
  if self.diag.is_file() and self.diag.read_text().startswith('{'):
   d=json.loads(self.diag.read_bytes());self.assertEqual(set(d)-{'status','phase','utc','errorType'},set())
   self.assertNotIn('FAKE-CREDENTIAL',self.diag.read_text())
  return v
 def test_complete_valid_bundle(self):self.call(True)
 def test_wrong_interpreter_path(self):self.man['interpreter']['path']='C:/wrong/python.exe';self.call(stage='environment')
 def test_wrong_interpreter_hash(self):self.man['interpreter']['sha256']='0'*64;self.call(stage='environment')
 def test_wrong_architecture(self):self.man['interpreter']['bits']=32;self.call(stage='environment')
 def test_wrong_python_version(self):self.man['interpreter']['version']='0.0.0';self.call(stage='environment')
 def test_optimization_flag(self):self.flags=['-I','-B','-O'];self.call(stage='environment')
 def test_double_optimization_flag(self):self.flags=['-I','-B','-OO'];self.call(stage='environment')
 def test_missing_isolation(self):self.flags=['-B'];self.call(stage='environment')
 def test_missing_no_bytecode_flag(self):self.flags=['-I'];self.call(stage='environment')
 def test_modified_helper(self):
  p=self.env/'acceptance_gate.py';p.write_bytes(p.read_bytes()+b'\n# changed');self.call(stage='environment')
 def test_modified_dependency(self):
  p=self.env/'schema-validator/rfc3987.py';p.write_bytes(p.read_bytes()+b'\n# changed');self.call(stage='environment')
 def test_modified_native_extension(self):
  p=next((self.env/'schema-validator/rpds').glob('*.pyd'));p.write_bytes(p.read_bytes()+b'changed');self.call(stage='environment')
 def test_modified_schema(self):
  p=self.env/'schemas/1.6/bom-1.6.schema.json';p.write_bytes(p.read_bytes()+b' ');self.call(stage='environment')
 def test_unexpected_cache(self):
  p=self.env/'schema-validator/jsonschema/__pycache__';p.mkdir();(p/'malicious.pyc').write_bytes(b'fake');self.call(stage='environment')
 def test_executable_cached_helper_never_runs(self):
  path=self.env/'image_metadata.py';original=path.read_bytes();stamp=path.stat()
  malicious=b"raise RuntimeError('MALICIOUS_CACHE_EXECUTED')\n"
  path.write_bytes(malicious+b'#'*(len(original)-len(malicious)));os.utime(path,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
  py_compile.compile(str(path),doraise=True,invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
  path.write_bytes(original);os.utime(path,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
  self.call(stage='environment')
 def test_diagnostic_failure_on_environment_failure(self):
  self.man['interpreter']['bits']=32;self.diag=self.r/'missing/diagnostic.json';self.call(stage='diagnostic')
 def test_unexpected_dependency_origin(self):
  self.extra="x=types.ModuleType('rfc3987');x.__file__='C:/unexpected/rfc3987.py';sys.modules['rfc3987']=x\n"
  self.call(stage='environment')
 def test_missing_format_checker(self):
  (self.env/'schema-validator/rfc3987.py').unlink();self.reseal_env();self.call(stage='environment')
 def test_wrong_manifest_anchor(self):
  self.extra="v['digest']='0'*64\n";self.call(stage='environment')
 def test_optimization_environment(self):
  self.extra="__import__('os').environ['PYTHONOPTIMIZE']='1'\n";self.call(stage='environment')
 def test_valid_relative_iri_full_sbom(self):
  self.sbom(lambda b:b['externalReferences'][0].update(url='/\u4f8b/\u8def\u5f84'));self.call(True)
 def test_invalid_uri_percent_escape(self):
  self.sbom(lambda b:b['signature'].update(algorithm='https://example.org/%ZZ'));self.call(stage='acceptance')
 def test_invalid_iri_percent_escape(self):
  self.sbom(lambda b:b['externalReferences'][0].update(url='https://example.org/%ZZ'));self.call(stage='acceptance')
 def test_missing_datetime_checker(self):
  (self.env/'schema-validator/rfc3339_validator.py').unlink();self.reseal_env();self.call(stage='environment')
 def test_valid_uri_iri_datetime_full_acceptance(self):self.call(True)
 def test_invalid_uri_full_sbom(self):self.sbom(lambda b:b['signature'].update(algorithm='bad uri with spaces'));self.call(stage='acceptance')
 def test_invalid_iri_full_sbom(self):self.sbom(lambda b:b['externalReferences'][0].update(url='bad iri with spaces'));self.call(stage='acceptance')
 def test_invalid_datetime_full_sbom(self):self.sbom(lambda b:b['metadata'].update(timestamp='not a timestamp'));self.call(stage='acceptance')
 def test_valid_full_sbom_17(self):self.sbom(lambda b:b.update(specVersion='1.7'));self.call(True)
 def test_invalid_uri_full_sbom_17(self):
  self.sbom(lambda b:(b.update(specVersion='1.7'),b['signature'].update(algorithm='bad uri with spaces')));self.call(stage='acceptance')
 def test_invalid_iri_full_sbom_17(self):
  self.sbom(lambda b:(b.update(specVersion='1.7'),b['externalReferences'][0].update(url='bad iri with spaces')));self.call(stage='acceptance')
 def test_invalid_datetime_full_sbom_17(self):
  self.sbom(lambda b:(b.update(specVersion='1.7'),b['metadata'].update(timestamp='not a timestamp')));self.call(stage='acceptance')
 def test_valid_format_but_stale_sbom_timestamp(self):self.sbom(lambda b:b['metadata'].update(timestamp='2020-01-01T00:00:00Z'));self.call(stage='acceptance')
 def test_stale_database(self):self.edit('scanner-db-end.json',lambda x:x['metadata'].update(UpdatedAt='2020-01-01T00:00:00Z'));self.call(stage='acceptance')
 def test_substituted_evidence(self):
  p=self.e/'runtime-raw-scan.json';p.write_bytes(p.read_bytes()+b' ');self.call(stage='acceptance')
 def test_high_finding(self):self.report('builder',lambda r:r['Results'][0].update(Vulnerabilities=[{'VulnerabilityID':'synthetic','Severity':'HIGH'}]));self.call(stage='acceptance')
 def test_critical_finding(self):self.report('runtime',lambda r:r['Results'][0].update(Vulnerabilities=[{'VulnerabilityID':'synthetic','Severity':'CRITICAL'}]));self.call(stage='acceptance')
 def test_secret_finding_redacted(self):self.report('builder',lambda r:r['Results'][0].update(Secrets=[{'RuleID':'synthetic','Match':'FAKE-CREDENTIAL'}]));self.call(stage='acceptance')
 def test_incorrect_package_reconciliation(self):self.report('runtime',lambda r:r['Results'][0]['Packages'].pop());self.call(stage='acceptance')
 def test_missing_alias_coverage(self):self.report('builder',lambda r:r['Results'][1]['Packages'].pop(1));self.call(stage='acceptance')
 def test_wrong_compiler_version(self):self.report('builder',lambda r:r['Results'][1]['Packages'][1].update(Version='7.0.2'));self.call(stage='acceptance')
 def test_missing_diagnostic(self):self.diag=self.r/'missing-parent/diagnostic.json';self.call(stage='diagnostic')
 def test_conflicting_diagnostic(self):self.diag.write_text('existing');self.call(stage='diagnostic')
 def test_other_session(self):self.a['runID']='another-session';self.call(stage='evidence_identity')
 def test_wrong_image_anchor(self):self.a['buildsSHA256']='0'*64;self.call(stage='evidence_identity')
 def test_wrong_source_anchor(self):self.a['sourceManifestSHA256']='0'*64;self.call(stage='evidence_identity')
 def test_wrong_daemon(self):self.a['expectedDaemonID']='wrong';self.call(stage='evidence_identity')
 def test_empty_results(self):self.report('builder',lambda r:r.update(Results=[]));self.call(stage='acceptance')
 def test_missing_report(self):(self.e/'builder-raw-scan.json').unlink();self.call(stage='acceptance')
 def test_missing_checker_dependency_identity(self):self.man['distributions']['rfc3987']='0.0.0';self.call(stage='environment')
 def test_missing_evidence_diagnostic(self):(self.e/'filesystem-equivalence.json').unlink();self.call(stage='acceptance')
 def test_prior_acceptance_file_not_authority(self):
  dump(self.e/'scan-and-sbom-acceptance.json',{'passed':True});(self.e/'builder-raw-scan.json').unlink();self.call(stage='acceptance')

if __name__=='__main__':unittest.main(verbosity=2)
