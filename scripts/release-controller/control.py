"""Trusted controller acceptance preflight. No network transport or manifest generation.

An approved caller supplies an independently reviewed manifest digest and evidence
anchors. This working copy exposes the existing gate as a callback boundary; it
cannot contact SSH by itself. Tests use capture-only callbacks, never live release.
CPython, system libraries, Windows and the same-account operator remain trusted.
"""
from pathlib import Path, PurePosixPath
import datetime as dt
import hashlib, importlib, importlib.metadata, json, os, platform, re, stat, sys

ROOT = Path(__file__).resolve().parent
PACKAGES = {'attrs':'26.1.0','jsonschema':'4.26.0','jsonschema-specifications':'2025.9.1',
            'referencing':'0.37.0','rpds-py':'2026.9.1','typing_extensions':'4.16.0',
            'rfc3987':'1.3.8','rfc3339-validator':'0.1.4','six':'1.17.0'}
PREFIXES = ('attr','attrs','jsonschema','jsonschema_specifications','referencing','rpds',
            'typing_extensions','rfc3987','rfc3339_validator','six')
FORMATS = {'uri':('https://example.org/a','bad uri with spaces'),
           'iri-reference':('/\u4f8b/\u8def\u5f84','bad iri with spaces'),
           'date-time':('2026-10-18T12:00:00Z','not a timestamp')}

class ControllerBlocked(ValueError): pass

def require(ok, reason):
    if not ok: raise ControllerBlocked(reason)

def sha(data): return hashlib.sha256(data).hexdigest()

def load(data):
    def pairs(rows):
        result={}
        for key,value in rows:
            require(key not in result,'duplicate_json_key');result[key]=value
        return result
    return json.loads(data,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(ControllerBlocked('nonfinite_json')))

def read(path):
    path=Path(path)
    require(path.is_absolute() and path.resolve()==path,'noncanonical_path')
    for part in [*reversed(path.parents),path]:
        state=part.lstat()
        require(not stat.S_ISLNK(state.st_mode) and not getattr(state,'st_file_attributes',0)&0x400,'linked_path')
    before=path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'nonregular_file')
    with path.open('rb') as stream:
        opened=os.fstat(stream.fileno());data=stream.read()
    after=path.stat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
    require(identity(before)==identity(opened)==identity(after),'file_changed_during_read')
    return data

def inside(root,name):
    require(type(name) is str and name and '\\' not in name and not PurePosixPath(name).is_absolute()
            and all(p not in ('','.','..') and ':' not in p for p in name.split('/')),'unsafe_relative_path')
    result=root/name;require(result.resolve().is_relative_to(root),'path_escape');return result

# Portable extension of reviewed stdlib file/path checks. No network or commands.
CODE=Path(__file__).absolute().parent
REPOSITORY=CODE.parents[1]
_ACTIVE=None
_BOOTSTRAP_CAPABILITY=None
_ISSUED=None

def external(path):
 require(Path(path).is_absolute(),'absolute_external_path_required')
 p=Path(path).absolute()
 require(not p.is_relative_to(REPOSITORY),'authority_inside_repository');return p

def keys(value,names):require(type(value) is dict and set(value)==set(names),'record_shape')

def validate_profile(profile):
 keys(profile,('schemaVersion','status','authorizedPhases','executionRoot','bindings','records'))
 phases={'verify','readiness','settlement','native-linux-execution','read-only-host-check'}
 require(type(profile['schemaVersion']) is int and profile['schemaVersion']==1 and profile['status']=='EXTERNALLY_APPROVED'
         and type(profile['authorizedPhases']) is list and all(type(p) is str and p in phases for p in profile['authorizedPhases'])
         and len(set(profile['authorizedPhases']))==len(profile['authorizedPhases'])
         and type(profile['bindings']) is dict and type(profile['records']) is dict,'profile_identity')
 external(profile['executionRoot'])
 if set(profile['authorizedPhases'])-{'verify'}:
  b=profile['bindings'];required={'runID','sourceCommit','sourceManifestSHA256','parentManifestSHA256','images','runtimePackages',
            'hostname','machineID','daemonID','account','uid','endpoint'}
  require(required<=set(b),'missing_execution_bindings')
  require(type(b['runID']) is str and re.fullmatch('[a-zA-Z0-9-]+',b['runID']) and
          re.fullmatch('[0-9a-f]{40}',b['sourceCommit']) and
          all(re.fullmatch('[0-9a-f]{64}',b[k]) for k in ('sourceManifestSHA256','parentManifestSHA256')),'execution_source_identity')
  require(type(b['images']) is dict and set(b['images'])=={'builder','runtime','rootfs'} and
          all(type(v) is str and re.fullmatch('sha256:[0-9a-f]{64}',v) for v in b['images'].values()),'execution_images')
  require(type(b['runtimePackages']) is dict and bool(b['runtimePackages']) and all(type(k) is str and type(v) is str and v for k,v in b['runtimePackages'].items()),'runtime_package_identity')
  require(type(b['hostname']) is str and re.fullmatch('[a-z0-9.-]+',b['hostname']) and
          re.fullmatch('[0-9a-f]{32}',b['machineID']) and re.fullmatch('[0-9a-f-]{36}',b['daemonID']) and
          type(b['uid']) is int and b['uid']==1000 and b['account']=='user' and b['endpoint']=='unix:///var/run/docker.sock','host_identity')
  roles={'baseline','executionBoundary','transport'}
  if 'settlement' in profile['authorizedPhases']:roles|={'settlement','securityRefresh','supersession'}
  require(roles<=set(profile['records']),'missing_execution_authority')
  if 'native-linux-execution' in profile['authorizedPhases']:
   require(b.get('nativeDataLayout') in ('.','data'),'native_data_layout')

def record(item):
 keys(item,('path','sha256'));p=Path(item['path'])
 require(p.is_absolute() and re.fullmatch('[0-9a-f]{64}',item['sha256'] or ''),'record_identity')
 data=read(p);require(sha(data)==item['sha256'],'record_changed');return data

def verify_code(catalog):
 keys(catalog,('schemaVersion','sourceCommit','files'))
 require(type(catalog['schemaVersion']) is int and catalog['schemaVersion']==1 and
         re.fullmatch('[0-9a-f]{40}',catalog['sourceCommit']),'source_commit')
 require(type(catalog['files']) is dict and bool(catalog['files']),'code_inventory')
 for name,h in catalog['files'].items():
  require(re.fullmatch('[0-9a-f]{64}',h or '') and sha(read(inside(REPOSITORY,name)))==h,'code_changed:'+name)
 actual=set()
 for p in CODE.rglob('*'):
  s=p.lstat();require(not p.is_symlink() and not getattr(s,'st_file_attributes',0)&0x400,'linked_code')
  require('__pycache__' not in p.parts and p.suffix.lower() not in ('.pyc','.pyo'),'unexpected_bytecode')
  if p.is_file() and p!=CODE/'source-catalog.json':actual.add(p.relative_to(REPOSITORY).as_posix())
 require(actual=={n for n in catalog['files'] if n.startswith('scripts/release-controller/')},'extra_or_missing_code')

def dependencies(item):
 keys(item,('root','manifest'));root=external(item['root']);external(item['manifest']['path'])
 doc=load(record(item['manifest']))
 require(doc['distributions']==PACKAGES and type(doc['files']) is dict and len(doc['files'])==190,'dependency_manifest')
 names=set()
 for p in root.rglob('*'):
  s=p.lstat();require(not p.is_symlink() and not getattr(s,'st_file_attributes',0)&0x400,'linked_dependency')
  require('__pycache__' not in p.parts and p.suffix.lower() not in ('.pyc','.pyo'),'dependency_bytecode')
  if p.is_file():names.add(p.relative_to(root).as_posix())
 require(names==set(doc['files']),'dependency_inventory')
 for name,h in doc['files'].items():require(sha(read(inside(root,name)))==h,'dependency_changed')
 return root

def origins(ctx,initial=False):
 helpers={}
 for n in ctx.catalog['files']:
  if n.endswith('.py') and n.startswith('scripts/release-controller/'):
   name=Path(n).stem;require(name not in helpers,'ambiguous_helper_stem');helpers[name]=inside(REPOSITORY,n)
 for name,module in list(sys.modules.items()):
  p=getattr(module,'__file__',None)
  if name.split('.')[0] in PREFIXES:
   require(not initial,'dependency_preloaded_before_authentication')
   require(p is not None and Path(p).absolute().is_relative_to(ctx.environment/'schema-validator'),'shadowed_dependency')
  elif name in helpers:
   if initial:
    require(name=='control' and module.__dict__ is globals(),'helper_preloaded_before_authentication')
   require(p is not None and Path(p).absolute()==helpers[name],'shadowed_helper')

def standard_library_paths():
 """Trusted interpreter layout, never environment-provided search roots."""
 base=Path(sys.base_prefix).absolute();library=Path(os.__file__).absolute().parent
 require(library.is_relative_to(base),'stdlib_outside_interpreter')
 if os.name=='nt':return [str(base/'python312.zip'),str(base/'DLLs'),str(library)]
 return [str(library.parent/'python312.zip'),str(library/'lib-dynload'),str(library)]

class Activation:
 def __init__(self,path,digest,document,catalog,environment):
  self.path=path;self.digest=digest;self.document=document;self.catalog=catalog;self.environment=environment
 def revalidate(self):
  require(sha(read(self.path))==self.digest,'activation_changed')
  require(load(read(self.path))==self.document,'activation_object_changed')
  require(load(record(self.document['sourceCatalog']))==self.catalog,'catalog_changed')
  verify_code(self.catalog);require(dependencies(self.document['dependencyEnvironment'])==self.environment,'environment_object_changed')
  require(self.document['interpreter']['path']==str(Path(sys.executable).absolute()) and self.document['interpreter']['sha256']==sha(read(Path(sys.executable).absolute())),'interpreter_changed')
  record(self.document['profile']);origins(self)
 def profile(self):
  self.revalidate();return load(record(self.document['profile']))
 def require_phase(self,phase):require(phase in self.profile()['authorizedPhases'],'phase_not_authorized')
 def require_execution(self,root):require(Path(root).absolute()==external(self.profile()['executionRoot']),'execution_identity')
 def code_hash(self,name):return self.catalog['files']['scripts/release-controller/'+name]
 def authority(self,name):
  p=self.profile();require(name in p['records'],'missing_authority:'+name)
  doc=p['records'][name];external(doc['path']);return doc

def authenticate_context(path,approved_digest,capability=None):
 """Trusted external-bootstrap API, never a CLI/environment-derived approval.
 The actual external bootstrap template has an EMPTY approved-digest set.
 """
 global _ACTIVE,_BOOTSTRAP_CAPABILITY,_ISSUED
 _ACTIVE=None;_ISSUED=None
 require(capability is not None and capability is _BOOTSTRAP_CAPABILITY,'external_bootstrap_capability_required')
 _BOOTSTRAP_CAPABILITY=None
 require(sys.flags.isolated and sys.flags.dont_write_bytecode and not sys.flags.optimize,'python_flags')
 p=external(path);raw=read(p)
 require(re.fullmatch('[0-9a-f]{64}',approved_digest or '') and sha(raw)==approved_digest,'external_context_identity')
 doc=load(raw)
 keys(doc,('schemaVersion','status','repositoryRoot','sourceCommit','sourceCatalog','interpreter','dependencyEnvironment','profile'))
 require(type(doc['schemaVersion']) is int and doc['schemaVersion']==1 and doc['status']=='EXTERNALLY_APPROVED'
         and Path(doc['repositoryRoot']).absolute()==REPOSITORY,'external_context_scope')
 expected={'path':str(Path(sys.executable).absolute()),'sha256':sha(read(Path(sys.executable).absolute())),
           'version':platform.python_version(),'architecture':platform.machine()}
 require(doc['interpreter']==expected,'interpreter_identity')
 external(doc['sourceCatalog']['path']);catalog=load(record(doc['sourceCatalog']))
 require(catalog['sourceCommit']==doc['sourceCommit'],'source_commit');verify_code(catalog)
 env=dependencies(doc['dependencyEnvironment']);external(doc['profile']['path'])
 profile=load(record(doc['profile']))
 keys(profile,('schemaVersion','status','authorizedPhases','executionRoot','bindings','records'))
 phases={'verify','readiness','settlement','native-linux-execution','read-only-host-check'}
 require(type(profile['schemaVersion']) is int and profile['schemaVersion']==1 and profile['status']=='EXTERNALLY_APPROVED'
         and type(profile['authorizedPhases']) is list and all(type(p) is str and p in phases for p in profile['authorizedPhases'])
         and len(set(profile['authorizedPhases']))==len(profile['authorizedPhases'])
         and type(profile['bindings']) is dict and type(profile['records']) is dict,'profile_identity')
 validate_profile(profile)
 external(profile['executionRoot'])
 for item in profile['records'].values():external(item['path']);record(item)
 ctx=Activation(p,approved_digest,doc,catalog,env);origins(ctx,initial=True)
 sys.path[:]=[str(CODE),str(env/'schema-validator'),*standard_library_paths()]
 from jsonschema import Draft7Validator,FormatChecker
 installed={d.metadata['Name'].lower().replace('_','-'):d.version for d in importlib.metadata.distributions(path=[str(env/'schema-validator')])}
 require(installed=={k.lower().replace('_','-'):v for k,v in PACKAGES.items()},'distribution_identity')
 checker=FormatChecker()
 for fmt,(good,bad) in FORMATS.items():
  require(fmt in checker.checkers,'format_checker_missing')
  v=Draft7Validator({'type':'string','format':fmt},format_checker=checker)
  require(not list(v.iter_errors(good)) and bool(list(v.iter_errors(bad))),'format_checker_inactive')
 origins(ctx);_ACTIVE=ctx;_ISSUED=ctx;return ctx

def active():
 require(_ACTIVE is not None and _ACTIVE is _ISSUED and type(_ACTIVE) is Activation,'external_bootstrap_required');_ACTIVE.revalidate();return _ACTIVE

def authenticate(*args,**kwargs):raise ControllerBlocked('external_bootstrap_required')
def gate(*args,**kwargs):raise ControllerBlocked('PHASE1_NO_RUNTIME_AUTHORIZATION')
if __name__=='__main__':raise SystemExit('BLOCKED: external operator bootstrap required')
