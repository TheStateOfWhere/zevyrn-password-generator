"""Explicit unit-boundary fixtures. These do not issue production control capabilities.
The real external-bootstrap/loader boundary is covered separately by relocation
and complete-path tests. No historical finalizer or payload generator is executed.
"""
from pathlib import Path
from contextlib import ExitStack,contextmanager
import ast,hashlib,importlib.util,json,shutil,sys,tempfile,types
from unittest.mock import patch
P=Path(__file__).absolute().parents[1]
E=P.parents[2];C=E.with_name(E.name+'-completion')
OLD=C/'prior-canonical-source'
H=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def write(p,v):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(v if isinstance(v,bytes) else json.dumps(v,sort_keys=True).encode())
def load_controller(name):
 s=importlib.util.spec_from_file_location(name+'_canonical',P/'continuation.py');c=importlib.util.module_from_spec(s);s.loader.exec_module(c)
 c.RUN='qualification-dk02-20261019-02';c.SOURCE='a'*64;c.PARENT='b'*64;c.IMAGES={k:'sha256:'+str(i)*64 for i,k in enumerate(('builder','runtime','rootfs'),1)}
 c.COLLECTOR=read(P/'source-catalog.json')['files']['scripts/release-controller/workflow.py'];return c

class UnitContext:
 def __init__(self,c,root,controller):
  self.c=c;self.root=Path(root);self.controller=Path(controller)
  self.document={'repositoryRoot':str(self.controller.parents[1])}
  self.catalog=read(P/'source-catalog.json')
  self.expected={p.name:H(p) for p in self.controller.iterdir() if p.is_file()}
  self.seal=H(self.root/'preparation-seal.json') if (self.root/'preparation-seal.json').exists() else None
 def profile(self):
  return {'executionRoot':str(self.root),'authorizedPhases':['verify','readiness','settlement','native-linux-execution','read-only-host-check'],
          'bindings':{'runID':self.c.RUN,'sourceManifestSHA256':self.c.SOURCE,'parentManifestSHA256':self.c.PARENT,
                      'images':self.c.IMAGES,'runtimePackages':{'fixture':'1.0'},'sourceCommit':'a'*40,
                      'machineID':'f5cf9b91ec464c73afb914149cd2ee17','daemonID':'a69a1524-fcf8-41b9-8371-9a17d84affdc','hostname':'fnxa-dk02'},'records':{}}
 def revalidate(self):
  if self.controller==P:
   for n,h in self.catalog['files'].items():
    if H(P.parents[1]/n)!=h:raise ValueError('Approved controller helper missing or changed: '+n)
   return
  for n,h in self.expected.items():
   if H(self.controller/n)!=h:raise ValueError('Approved controller helper missing or changed: '+n)
  for p in self.controller.iterdir():
   if p.is_dir() and p!=self.root:raise ValueError('Unexpected controller directory: '+p.name)
   if p.is_file() and p.name not in self.expected:raise ValueError('Unexpected controller executable/importable: '+p.name)
 def require_execution(self,root):
  if Path(root).absolute()!=self.root.absolute():raise ValueError('Execution identity')
 def require_phase(self,name):
  if name not in self.profile()['authorizedPhases']:raise ValueError('phase_not_authorized')
 def code_hash(self,name):return H(self.controller/name)
 def authority(self,name):
  if name=='executionBoundary':return {'path':str(self.root/'preparation-seal.json'),'sha256':self.seal}
  if name=='transport':return {'path':str(C/'unit-transport.json'),'sha256':H(C/'unit-transport.json')}
  raise ValueError('missing_authority:'+name)

@contextmanager
def bind_unit_context(c,root,controller=None):
 import runtime_context
 controller=controller or P;ctx=UnitContext(c,root,controller)
 write(C/'unit-transport.json',{'schemaVersion':1,'testOnly':True})
 # No callback is used for the real bootstrap tests; this is an explicit unit boundary.
 def unit_helper(name):
  ctx.revalidate();path=controller/(name+'.py')
  spec=importlib.util.spec_from_file_location('restored_unit_'+name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  return m
 with ExitStack() as stack:
  stack.enter_context(patch.object(c,'active',lambda:ctx));stack.enter_context(patch.object(c,'helper',unit_helper))
  stack.enter_context(patch.object(runtime_context,'active',lambda:ctx))
  yield ctx

def fixture(c):
 """Synthetic 805-record history, real frozen97 source files, no real completion claims."""
 root=C/'restored-fixtures'/H(P/'source-catalog.json')[:12]/(c.RUN+'-attempt-20261020-01')
 marker=root/'synthetic-fixture.json'
 if marker.exists():
  info=read(marker);c.SOURCE=info['source'];c.PARENT=info['parent'];return root
 root.mkdir(parents=True)
 source=E.parent/'zevyrn-v1.2.1-cli-linked-root-correction-20261020-01'/(c.RUN+'-attempt-20261020-01')/'data'
 manifest=read(source/'source-manifest.json')
 for row in manifest:
  p=source/'source'/row['path'];assert H(p)==row['sha256'];write(root/'data/source'/row['path'],p.read_bytes())
 write(root/'data/source-manifest.json',(source/'source-manifest.json').read_bytes());c.SOURCE=H(root/'data/source-manifest.json')
 spec=importlib.util.spec_from_file_location('fixture_only_workflow',P/'workflow.py');w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
 helpers={}
 for name in w.HELPERS:
  p=w.helper_path(name);write(root/'data'/name,p.read_bytes());helpers[name]=H(p)
 write(root/'data/helpers.json',helpers)
 q={'runID':c.RUN,'attemptID':root.name,'sourceManifestSHA256':c.SOURCE,'expectedDaemonID':'a69a1524-fcf8-41b9-8371-9a17d84affdc'}
 write(root/'data/qualification.json',q)
 recipe=(root/'data/source/Dockerfile').read_text()
 write(root/'data/Dockerfile.runtime',w.runtime_dockerfile(recipe,'zevyrn-builder:1.2.1-'+c.RUN).encode())
 write(root/'data/Dockerfile.final',w.final_dockerfile(recipe,'zevyrn:1.2.1-'+c.RUN+'-rootfs').encode())
 write(root/'data/builds.json',{k:{'image':{'id':v}} for k,v in c.IMAGES.items()})
 write(root/'data/execution-inputs.json',{n:H(root/'data'/n) for n in ('qualification.json','source-manifest.json','helpers.json','Dockerfile.runtime','Dockerfile.final')})
 oldhelpers={**helpers,'scan-images.py':H(source.parent/'history/remote-evidence/scan-images.py')}
 write(root/'history/remote-evidence/helpers.json',oldhelpers)
 write(root/'history/remote-evidence/qualification.json',{k:v for k,v in q.items() if k!='attemptID'})
 historical_scanner=source.parent/'history/remote-evidence/scan-images.py'
 write(root/'history/remote-evidence/scan-images.py',historical_scanner.read_bytes())
 # Fill fixed original inventory cardinality with inert evidence, not fabricated success records.
 for i in range(802):write(root/f'history/synthetic-record-{i:04}.txt',b'SYNTHETIC UNIT FIXTURE ONLY\n')
 rows=[{'path':p.relative_to(root/'history').as_posix(),'sha256':H(p),'bytes':p.stat().st_size} for p in (root/'history').rglob('*') if p.is_file()]
 assert len(rows)==805;write(root/'parent-evidence-manifest.json',{'files':rows});c.PARENT=H(root/'parent-evidence-manifest.json')
 write(root/'history-manifest.json',{r['path']:r['sha256'] for r in rows})
 write(root/'fresh-inputs.json',{p.relative_to(root/'data').as_posix():H(p) for p in (root/'data').rglob('*') if p.is_file()})
 write(root/'continuation.json',{'executionID':root.name,'qualificationRunID':c.RUN,'sourceManifestSHA256':c.SOURCE,'images':c.IMAGES,'collectorSHA256':c.COLLECTOR,'parentManifestSHA256':c.PARENT})
 write(root/'controller-identities.json',{n:H(P/n) for n in c.CONTROLLER})
 write(root/'python-execution-boundary.json',{'controllerFiles':{n:H(P/n) for n in c.CONTROLLER},'controllerDirectories':['schemas','tests']})
 for n in ('imported-evidence.json','production-assets.json','attempt-plan.json'):write(root/n,{'testOnly':True})
 write(root/'preparation-seal.json',{n:H(root/n) for n in c.SEALS})
 write(marker,{'source':c.SOURCE,'parent':c.PARENT,'testOnly':True});return root
