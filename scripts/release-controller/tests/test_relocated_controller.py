"""Synthetic EXTERNAL trust fixtures, never approval of a real qualification.
No host calls, Docker commands, browser launch, network or native clipboard write.
"""
from pathlib import Path
import ast,hashlib,json,os,platform,shutil,subprocess,sys,tempfile,types,unittest

P=Path(__file__).absolute().parents[1];REPO=P.parents[1];E=REPO.parent
H=lambda b:hashlib.sha256(b).hexdigest()
J=lambda x:json.dumps(x,sort_keys=True).encode()
DEV=E.parent
ENV=DEV/'zevyrn-v1.2.1-atomic-worker-containment-20261019-01/environment'
MANIFEST=DEV/'zevyrn-v1.2.1-final-runtime-scope-preparation-20261021-01/controller-environment-manifest.python-3.12.14-bundle-26.1020.11348.PROPOSED.json'

class RelocationTests(unittest.TestCase):
 def setUp(self):
  base=E.with_name(E.name+'-completion')/'validation';base.mkdir(exist_ok=True)
  self.root=Path(tempfile.mkdtemp(prefix='relocation-',dir=base));self.repo=self.root/'repository'
  # Only source trees, no original Git index/environment or historical evidence.
  shutil.copytree(REPO,self.repo,ignore=shutil.ignore_patterns('node_modules','dist'))
  self.p=self.repo/'scripts/release-controller';self.out=self.root/'run';self.out.mkdir()
  self.profile={'schemaVersion':1,'status':'EXTERNALLY_APPROVED','authorizedPhases':['verify'],
                'executionRoot':str(self.out),'bindings':{},'records':{}}
  self.profile_path=self.root/'profile.json';self.profile_path.write_bytes(J(self.profile))
  self.catalog=self.root/'catalog.json';self.catalog.write_bytes((P/'source-catalog.json').read_bytes())
  self.doc={'schemaVersion':1,'status':'EXTERNALLY_APPROVED','repositoryRoot':str(self.repo),
   'sourceCommit':'e81942b932c53d83eeaa2605467fd04ae9b26b2c',
   'sourceCatalog':{'path':str(self.catalog),'sha256':H(self.catalog.read_bytes())},
   'interpreter':{'path':str(Path(sys.executable).absolute()),'sha256':H(Path(sys.executable).read_bytes()),'version':platform.python_version(),'architecture':platform.machine()},
   'dependencyEnvironment':{'root':str(ENV),'manifest':{'path':str(MANIFEST),'sha256':H(MANIFEST.read_bytes())}},
   'profile':{'path':str(self.profile_path),'sha256':H(self.profile_path.read_bytes())}}
  self.context=self.root/'context.json';self.bootstrap=self.root/'fixture-bootstrap.py';self.cwd=self.root/'other-cwd';self.cwd.mkdir()
  self.seal()
 def seal(self):
  self.context.write_bytes(J(self.doc))
  source=(E/'operator-bootstrap.TEMPLATE.py').read_text().replace('APPROVED_CONTEXT_SHA256=frozenset()',"APPROVED_CONTEXT_SHA256=frozenset(['"+H(self.context.read_bytes())+"'])")
  self.bootstrap.write_text(source)
 def run_boot(self,phase='verify',preload='',env=None):
  if preload:
   code=preload+"\nimport runpy,sys;sys.argv="+repr([str(self.bootstrap),str(self.context),phase])+";runpy.run_path("+repr(str(self.bootstrap))+",run_name='__main__')"
   command=[sys.executable,'-I','-B','-c',code]
  else:command=[sys.executable,'-I','-B',str(self.bootstrap),str(self.context),phase]
  result=subprocess.run(command,cwd=self.cwd,capture_output=True,text=True,timeout=60,env=env)
  record={'command':command,'exitCode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
  (self.root/'last-execution.json').write_bytes(J(record));return result
 def rejected(self,**kwargs):self.assertNotEqual(self.run_boot(**kwargs).returncode,0)
 def test_valid_external_fixture_from_alternate_cwd(self):
  r=self.run_boot();self.assertEqual(r.returncode,0,r.stderr+r.stdout);self.assertIn('"qualificationExecuted": false',r.stdout)
 def test_actual_template_empty_pins_reject_context(self):
  self.bootstrap.write_bytes((E/'operator-bootstrap.TEMPLATE.py').read_bytes());self.rejected()
 def test_direct_selfhashed_api_cannot_issue_context(self):
  code="import types;from pathlib import Path;m=types.ModuleType('control');m.__file__="+repr(str(self.p/'control.py'))+";exec(compile(Path(m.__file__).read_bytes(),m.__file__,'exec'),m.__dict__);m.authenticate_context("+repr(str(self.context))+","+repr(H(self.context.read_bytes()))+")"
  r=subprocess.run([sys.executable,'-I','-B','-c',code],capture_output=True,text=True)
  self.assertNotEqual(r.returncode,0);self.assertIn('external_bootstrap_capability_required',r.stderr)
 def test_helper_tamper(self):
  f=self.p/'builder_security.py';f.write_bytes(f.read_bytes()+b'\n# modified fixture\n');self.rejected()
 def test_missing_helper(self):
  (self.p/'builder_security.py').rename(self.root/'preserved-helper.py');self.rejected()
 def test_schema_tamper(self):
  (self.p/'schemas/1.6/bom-1.6.schema.json').write_bytes(b'{}');self.rejected()
 def test_missing_schema(self):
  (self.p/'schemas/1.7/spdx.schema.json').rename(self.root/'preserved-schema.json');self.rejected()
 def test_catalog_tamper(self):self.catalog.write_bytes(b'{}');self.rejected()
 def test_profile_tamper(self):self.profile_path.write_bytes(b'{}');self.rejected()
 def test_unapproved_context_change(self):self.context.write_bytes(b'{}');self.rejected()
 def test_extra_importable_module(self):(self.p/'unexpected.py').write_bytes(b'# ordinary unexpected file');self.rejected()
 def test_nested_source_catalog_not_excluded(self):(self.p/'tests/source-catalog.json').write_bytes(b'{}');self.rejected()
 def test_preloaded_helper_even_matching_filename(self):
  code="import types,sys;m=types.ModuleType('compiler_inventory');m.__file__="+repr(str(self.p/'compiler_inventory.py'))+";sys.modules['compiler_inventory']=m"
  self.rejected(preload=code)
 def test_preloaded_dependency_even_matching_filename(self):
  code="import types,sys;m=types.ModuleType('jsonschema');m.__file__="+repr(str(ENV/'schema-validator/jsonschema/__init__.py'))+";sys.modules['jsonschema']=m"
  self.rejected(preload=code)
 def test_pythonpath_and_cwd_cannot_shadow(self):
  (self.cwd/'control.py').write_bytes(b'# decoy; never imported')
  env=dict(os.environ,PYTHONPATH=str(self.cwd));r=self.run_boot(env=env);self.assertEqual(r.returncode,0,r.stdout+r.stderr)
 def test_fake_control_module_rejected(self):
  code="import sys,types,runpy;m=types.ModuleType('control');m.__file__="+repr(str(self.p/'control.py'))+";m.active=lambda:True;sys.modules['control']=m;s=runpy.run_path("+repr(str(self.p/'runtime_context.py'))+");s['active']()"
  r=subprocess.run([sys.executable,'-I','-B','-c',code],capture_output=True,text=True)
  self.assertNotEqual(r.returncode,0);self.assertIn('CONTROL_MODULE_SHADOWED',r.stderr)
 def test_boolean_profile_version_rejected(self):
  self.profile['schemaVersion']=True;self.profile_path.write_bytes(J(self.profile));self.doc['profile']['sha256']=H(self.profile_path.read_bytes());self.seal();self.rejected()
 def test_unknown_phase_rejected(self):
  self.profile['authorizedPhases']=['publish'];self.profile_path.write_bytes(J(self.profile));self.doc['profile']['sha256']=H(self.profile_path.read_bytes());self.seal();self.rejected()
 def test_repository_context_cannot_approve_itself(self):
  self.context=self.repo/'self-context.json';self.seal();self.rejected()
 def test_bad_interpreter(self):self.doc['interpreter']['sha256']='0'*64;self.seal();self.rejected()
 def test_bad_dependency_manifest(self):self.doc['dependencyEnvironment']['manifest']['sha256']='0'*64;self.seal();self.rejected()
 def test_readiness_cannot_dispatch(self):
  self.profile['authorizedPhases']=['readiness'];self.profile_path.write_bytes(J(self.profile));self.doc['profile']['sha256']=H(self.profile_path.read_bytes());self.seal();self.rejected(phase='readiness')
 def test_settlement_cannot_dispatch(self):
  self.profile['authorizedPhases']=['settlement'];self.profile_path.write_bytes(J(self.profile));self.doc['profile']['sha256']=H(self.profile_path.read_bytes());self.seal();self.rejected(phase='settlement')
 def test_compiler_catalog_is_single_existing_file(self):
  self.assertFalse((self.p/'compiler-integrity.json').exists())
  self.assertEqual(H((self.repo/'scripts/compiler-integrity.json').read_bytes()),'ca9993e94e4f109d59130f29e140434817214eb9549eb44b8beedd65dcd99acd')
 def test_empty_applicability_authority(self):
  self.assertEqual(json.loads((self.p/'builder-security-authority.json').read_bytes())['approvedReceipts'],[])
 def after_auth(self,code):
  body="import sys,runpy;sys.argv="+repr([str(self.bootstrap),str(self.context),'verify'])+";runpy.run_path("+repr(str(self.bootstrap))+",run_name='__main__');"+code
  return subprocess.run([sys.executable,'-I','-B','-c',body],capture_output=True,text=True,cwd=self.cwd,timeout=60)
 def test_real_offline_schema_validator(self):
  r=self.after_auth("import qualification_evidence as q,socket;socket.create_connection=lambda *a,**k:(_ for _ in ()).throw(AssertionError('network'));q.validate_schema({'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':[]});print('OFFLINE_SCHEMA_PASS')")
  self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertIn('OFFLINE_SCHEMA_PASS',r.stdout)
 def test_invalid_schema_document_rejected(self):
  r=self.after_auth("import qualification_evidence as q;q.validate_schema({'bomFormat':'CycloneDX','specVersion':'1.6','version':'wrong'})")
  self.assertNotEqual(r.returncode,0);self.assertIn('Invalid CycloneDX schema',r.stderr)
 def test_actual_compiler_catalog_locator(self):
  r=self.after_auth("import compiler_inventory as c,hashlib;exec(\"def stop(raw):\\n print('CATALOG:'+hashlib.sha256(raw).hexdigest());raise RuntimeError('AFTER_CATALOG')\");c.manifest=stop;c.authenticate_compiler(b'ordinary', 'unused',hashlib.sha256(b'ordinary').hexdigest(),'unused')")
  self.assertNotEqual(r.returncode,0);self.assertIn('CATALOG:ca9993e94e4f109d59130f29e140434817214eb9549eb44b8beedd65dcd99acd',r.stdout);self.assertIn('AFTER_CATALOG',r.stderr)
 def test_context_object_mutation_cannot_select_authority(self):
  r=self.after_auth("import control;ctx=control.active();ctx.document['sourceCommit']='b'*40;control.active()")
  self.assertNotEqual(r.returncode,0);self.assertIn('activation_object_changed',r.stderr)
 def test_ordinary_nonisolated_start_rejected(self):
  r=subprocess.run([sys.executable,'-B',str(self.bootstrap),str(self.context),'verify'],capture_output=True,text=True,cwd=self.cwd)
  self.assertNotEqual(r.returncode,0)
 def test_optimized_start_rejected(self):
  r=subprocess.run([sys.executable,'-I','-B','-O',str(self.bootstrap),str(self.context),'verify'],capture_output=True,text=True,cwd=self.cwd)
  self.assertNotEqual(r.returncode,0)
 def test_actual_dependency_copy_tamper_before_import(self):
  env=self.root/'dependency-copy';shutil.copytree(ENV,env)
  f=env/'schema-validator/jsonschema/__init__.py';f.write_bytes(f.read_bytes()+b'\n# changed synthetic copy\n')
  self.doc['dependencyEnvironment']['root']=str(env);self.seal();self.rejected()
 def test_missing_external_authority(self):
  self.profile['records']['transport']={'path':str(self.root/'absent-authority.json'),'sha256':'a'*64}
  self.profile_path.write_bytes(J(self.profile));self.doc['profile']['sha256']=H(self.profile_path.read_bytes());self.seal();self.rejected()
 def test_duplicate_bootstrap_context_keys(self):
  raw=J(self.doc);raw=raw[:-1]+b',"schemaVersion":1}';self.context.write_bytes(raw)
  self.bootstrap.write_text((E/'operator-bootstrap.TEMPLATE.py').read_text().replace('APPROVED_CONTEXT_SHA256=frozenset()',"APPROVED_CONTEXT_SHA256=frozenset(['"+H(raw)+"'])"))
  self.rejected()
 def test_duplicate_bootstrap_catalog_keys(self):
  raw=self.catalog.read_bytes().rstrip();raw=raw[:-1]+b',"schemaVersion":1}';self.catalog.write_bytes(raw)
  self.doc['sourceCatalog']['sha256']=H(raw);self.seal();self.rejected()
 def test_readiness_requires_complete_execution_bindings(self):
  self.profile['authorizedPhases']=['readiness'];self.profile_path.write_bytes(J(self.profile));self.doc['profile']['sha256']=H(self.profile_path.read_bytes());self.seal();self.rejected(phase='readiness')

class ProfileShapeTests(unittest.TestCase):
 def setUp(self):
  import types
  self.control=types.ModuleType('shape_only_control');self.control.__file__=str(P/'control.py')
  exec(compile((P/'control.py').read_bytes(),str(P/'control.py'),'exec'),self.control.__dict__)
  b={'runID':'synthetic','sourceCommit':'a'*40,'sourceManifestSHA256':'b'*64,'parentManifestSHA256':'c'*64,
     'images':{n:'sha256:'+c*64 for n,c in [('builder','a'),('runtime','b'),('rootfs','c')]},
     'runtimePackages':{'nginx':'1.30.6-r1'},'hostname':'synthetic-host','machineID':'d'*32,
     'daemonID':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','account':'user','uid':1000,'endpoint':'unix:///var/run/docker.sock'}
  roles=('baseline','executionBoundary','transport','settlement','securityRefresh','supersession')
  self.profile={'schemaVersion':1,'status':'EXTERNALLY_APPROVED','authorizedPhases':['readiness','settlement'],
     'executionRoot':str(E/'validation/synthetic-shape-only'),'bindings':b,
     'records':{r:{'path':str(E/'validation'/r),'sha256':'a'*64} for r in roles}}
 def test_full_readiness_settlement_shape(self):self.control.validate_profile(self.profile)
 def test_each_missing_binding_rejected(self):
  import copy
  for key in self.profile['bindings']:
   p=copy.deepcopy(self.profile);p['bindings'].pop(key)
   with self.subTest(key=key),self.assertRaises(ValueError):self.control.validate_profile(p)
 def test_each_missing_settlement_authority_rejected(self):
  import copy
  for key in self.profile['records']:
   p=copy.deepcopy(self.profile);p['records'].pop(key)
   with self.subTest(key=key),self.assertRaises(ValueError):self.control.validate_profile(p)
 def test_wrong_image_digest_rejected(self):
  self.profile['bindings']['images']['builder']='latest'
  with self.assertRaises(ValueError):self.control.validate_profile(self.profile)
 def test_wrong_endpoint_rejected(self):
  self.profile['bindings']['endpoint']='tcp://unapproved:2375'
  with self.assertRaises(ValueError):self.control.validate_profile(self.profile)

if __name__=='__main__':unittest.main(verbosity=2)
