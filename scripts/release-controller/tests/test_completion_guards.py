"""Focused new guards; synthetic files and ordinary local Node only, no host/registry."""
from pathlib import Path
import copy,hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
from unittest.mock import patch
P=Path(__file__).absolute().parents[1]
def module(name):
 spec=importlib.util.spec_from_file_location('guard_unit_'+name,P/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
H=lambda b:hashlib.sha256(b).hexdigest()
class CompletionGuardTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.v=module('clipboard_supersession')
  self.authority='a'*64;self.anchors=[];self.doc={'scope':'historical-browser-tool-copies-v1','authoritySHA256':self.authority,'files':[]}
  for n in ('node.exe','msedge.exe'):
   b=('SYNTHETIC '+n).encode();p=self.root/n;p.write_bytes(b);original=self.root/'original'/n
   self.doc['files'].append({'originalPath':str(original),'path':str(p),'sha256':H(b)});self.anchors.append({'path':str(original),'sha256':H(b)})
 def tearDown(self):self.temp.cleanup()
 def evaluate(self):return self.v.historical_browser_tools(self.doc,self.authority,self.anchors)
 def test_two_exact_copies_accepted_without_executing(self):self.assertEqual(len(self.evaluate()),2)
 def test_changed_authority_rejected(self):
  self.doc['authoritySHA256']='b'*64
  with self.assertRaisesRegex(ValueError,'COPY_AUTHORITY'):self.evaluate()
 def test_wrong_scope_rejected(self):
  self.doc['scope']='any-artifact'
  with self.assertRaisesRegex(ValueError,'COPY_SCOPE'):self.evaluate()
 def test_partial_or_extra_mapping_rejected(self):
  for rows in (self.doc['files'][:1],self.doc['files']+self.doc['files'][:1]):
   with self.subTest(count=len(rows)),self.assertRaisesRegex(ValueError,'COPY_COVERAGE'):
    d=copy.deepcopy(self.doc);d['files']=rows;self.v.historical_browser_tools(d,self.authority,self.anchors)
 def test_duplicate_mapping_rejected(self):
  self.doc['files'][1]=self.doc['files'][0]
  with self.assertRaisesRegex(ValueError,'COPY_IDENTITY'):self.evaluate()
 def test_different_expected_hash_not_authorized(self):
  self.doc['files'][0]['sha256']='0'*64
  with self.assertRaisesRegex(ValueError,'ORIGINAL_BINDING'):self.evaluate()
 def test_unrelated_source_helper_mapping_rejected(self):
  self.doc['files'][0]['originalPath']=str(self.root/'control.py')
  with self.assertRaisesRegex(ValueError,'COPY_IDENTITY'):self.evaluate()
 def test_wrong_original_path_rejected(self):
  self.doc['files'][0]['originalPath']=str(self.root/'another/node.exe')
  with self.assertRaisesRegex(ValueError,'ORIGINAL_BINDING'):self.evaluate()
 def test_tampered_retained_copy_rejected(self):
  Path(self.doc['files'][0]['path']).write_bytes(b'TAMPERED')
  with self.assertRaisesRegex(ValueError,'COPY_HASH'):self.evaluate()
 def test_missing_retained_copy_rejected(self):
  self.doc['files'][0]['path']=str(self.root/'missing')
  with self.assertRaises(FileNotFoundError):self.evaluate()
 def test_reparse_or_symlink_copy_rejected(self):
  target=Path(self.doc['files'][0]['path'])
  with patch.object(Path,'lstat',side_effect=PermissionError('unavailable link visibility')),self.assertRaises(PermissionError):self.evaluate()
 def test_alias_does_not_accept_different_requested_digest(self):
  self.v._HISTORICAL_BROWSER_TOOLS=self.evaluate()
  with self.assertRaises(FileNotFoundError):self.v.authenticated_bytes(self.doc['files'][0]['originalPath'],'0'*64)
 def test_proposed_approvals_still_empty(self):
  self.assertEqual(json.loads((P/'builder-security-authority.json').read_text())['approvedReceipts'],[])
 def test_browser_environment_removes_all_loader_injection(self):
  c=module('continuation');env=c.browser_environment({'PATH':'fixture','SYSTEMROOT':'fixture','NODE_OPTIONS':'bad','node_path':'bad','NODE_REPL_EXTERNAL_MODULE':'bad','KEYSMITH_BROWSER_PATH':'bad','PYTHONPATH':'bad','HTTP_PROXY':'bad'})
  self.assertEqual(env,{'PATH':'fixture','SYSTEMROOT':'fixture'})
 def test_actual_node_preload_cannot_execute_after_sanitization(self):
  c=module('continuation');node=P.parents[3]/'zevyrn-v1.2.1-builder-staging-remediation-20261023-01/portable-runtime/node-v24.22.1-win-x64/node.exe'
  # The portable tool is authenticated independently from production browser authority.
  self.assertEqual(H(node.read_bytes()),'d702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5')
  inherited={**os.environ,'NODE_OPTIONS':'--zevyrn-unapproved-option','NODE_PATH':str(self.root)}
  denied=subprocess.run([str(node),'-e',"console.log('UNEXPECTED')"],env=inherited,capture_output=True,text=True,timeout=30)
  self.assertNotEqual(denied.returncode,0);self.assertNotIn('UNEXPECTED',denied.stdout)
  r=subprocess.run([str(node),'-e',"console.log('SAFE')"],env=c.browser_environment(inherited),capture_output=True,text=True,timeout=30)
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.strip(),'SAFE')
 def test_worker_import_has_no_native_side_effects(self):
  with patch.object(subprocess,'run',side_effect=AssertionError('unexpected host operation')):module('dk02_readonly_probe')
 def ssh_fixture(self):
  profile={'account':'user','sshHost':'fixture.example'};a={'config':{'path':str(self.root/'config')},'knownHosts':{'path':str(self.root/'known_hosts')}}
  a['arguments']=['-T','-F',a['config']['path'],'-i',str(self.root/'identity'),'-l','user']
  for opt in ('BatchMode=yes','StrictHostKeyChecking=yes','IdentitiesOnly=yes','PreferredAuthentications=publickey','HostKeyAlgorithms=ssh-ed25519','UpdateHostKeys=no','UserKnownHostsFile='+a['knownHosts']['path'],'ForwardAgent=no','ClearAllForwardings=yes','ConnectTimeout=12'):a['arguments']+=['-o',opt]
  a['arguments']+=['fixture.example'];return a,profile
 def test_exact_strict_ssh_argument_structure(self):
  a,b=self.ssh_fixture();self.assertEqual(module('dk02_transport').validate_arguments(a,b),a['arguments'])
 def test_preposed_hostkey_override_rejected(self):
  a,b=self.ssh_fixture();a['arguments']=['-o','StrictHostKeyChecking=no']+a['arguments']
  with self.assertRaises(ValueError):module('dk02_transport').validate_arguments(a,b)
 def test_concatenated_hostkey_override_rejected(self):
  a,b=self.ssh_fixture();a['arguments'].insert(-1,'-oStrictHostKeyChecking=no')
  with self.assertRaisesRegex(ValueError,'strict argument'):module('dk02_transport').validate_arguments(a,b)
 def test_proxy_or_remote_command_injection_rejected(self):
  for extra in ('-oProxyCommand=unapproved','hostname'):
   a,b=self.ssh_fixture();a['arguments'].insert(-1,extra)
   with self.subTest(extra=extra),self.assertRaisesRegex(ValueError,'strict argument'):module('dk02_transport').validate_arguments(a,b)
 def test_mismatched_pinned_ssh_config_rejected(self):
  a,b=self.ssh_fixture();a['config']['path']=str(self.root/'other')
  with self.assertRaisesRegex(ValueError,'strict argument'):module('dk02_transport').validate_arguments(a,b)
 def test_mismatched_approved_ssh_host_rejected(self):
  a,b=self.ssh_fixture();b['sshHost']='other.example'
  with self.assertRaisesRegex(ValueError,'strict argument'):module('dk02_transport').validate_arguments(a,b)
 def test_ssh_host_cannot_be_an_option(self):
  a,b=self.ssh_fixture();b['sshHost']='-v';a['arguments'][-1]='-v'
  with self.assertRaisesRegex(ValueError,'host binding'):module('dk02_transport').validate_arguments(a,b)
 def test_scanner_platform_gate_before_data_or_network(self):
  import runtime_context,io,types
  profile={'executionRoot':str(self.root),'bindings':{'nativeDataLayout':'data'}}
  ctx=types.SimpleNamespace(require_phase=lambda phase:None,profile=lambda:profile)
  with patch.object(runtime_context,'active',lambda:ctx),patch.object(runtime_context.sys,'platform','win32'),patch.object(subprocess,'run',side_effect=AssertionError('tool must not execute')):
   with self.assertRaisesRegex(ValueError,'Linux scanner'):runtime_context.run_scanner(self.root/'data',io.StringIO(),io.StringIO())
 def test_scanner_rejects_missing_native_authority(self):
  import runtime_context,io,types
  def reject(phase):raise ValueError('phase_not_authorized')
  ctx=types.SimpleNamespace(require_phase=reject)
  with patch.object(runtime_context,'active',lambda:ctx),self.assertRaisesRegex(ValueError,'phase_not_authorized'):runtime_context.run_scanner(self.root/'data',io.StringIO(),io.StringIO())
 def test_scanner_linked_data_rejected_before_helper_or_process(self):
  import runtime_context,io,types,stat
  data=self.root/'data';data.mkdir();profile={'executionRoot':str(self.root),'bindings':{'nativeDataLayout':'data'}}
  ctx=types.SimpleNamespace(require_phase=lambda phase:None,profile=lambda:profile)
  original=Path.lstat
  def state(path,*a,**kw):
   if path==data:return types.SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_file_attributes=0x400)
   return original(path,*a,**kw)
  with patch.object(runtime_context,'active',lambda:ctx),patch.object(runtime_context.sys,'platform','linux'),patch.object(runtime_context.os,'getuid',lambda:1000,create=True),patch.object(Path,'lstat',state),patch.object(runtime_context,'helper',side_effect=AssertionError('helper must not import')):
   with self.assertRaisesRegex(ValueError,'Linked scanner execution data'):runtime_context.run_scanner(data,io.StringIO(),io.StringIO())
 def test_actual_completion_bootstrap_has_no_approval(self):
  C=P.parents[2].with_name(P.parents[2].name+'-completion');context=self.root/'unapproved.json';context.write_text('{}')
  r=subprocess.run([sys.executable,'-I','-B',str(C/'operator-bootstrap.TEMPLATE.py'),str(context),'readiness'],capture_output=True,text=True,timeout=30)
  self.assertNotEqual(r.returncode,0);self.assertIn('NO_EXTERNAL_APPROVAL',r.stderr)
 def test_stdlib_layout_uses_interpreter_paths_not_environment(self):
  import types
  c=module('control');base=self.root/'python';library=base/'lib/python3.12'
  with patch.object(c,'os',types.SimpleNamespace(name='posix',__file__=str(library/'os.py'))),patch.object(c.sys,'base_prefix',str(base)):
   self.assertEqual(c.standard_library_paths(),[str(library.parent/'python312.zip'),str(library/'lib-dynload'),str(library)])
 def test_stdlib_outside_interpreter_rejected(self):
  import types
  c=module('control')
  with patch.object(c,'os',types.SimpleNamespace(name='nt',__file__=str(self.root/'outside/os.py'))),patch.object(c.sys,'base_prefix',str(self.root/'python')),self.assertRaisesRegex(ValueError,'stdlib_outside_interpreter'):c.standard_library_paths()
if __name__=='__main__':unittest.main(verbosity=2)
