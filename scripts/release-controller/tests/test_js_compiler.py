"""Current JS-candidate controls; historical tests are run separately unchanged."""
from pathlib import Path
import copy,datetime,hashlib,io,json,tarfile,unittest
from compiler_inventory import authenticate_compiler
from qualification_evidence import validate_scan,SCANNER_POLICY_SHA256,EvidenceError
from test_whiteouts import tar_bytes,entry
from cli_fixtures import archive
E=Path(__file__).resolve().parent;P=E.parents[2]
H=lambda data:hashlib.sha256(data).hexdigest()
J=lambda obj:json.dumps(obj,sort_keys=True).encode()

class CompilerTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.files={'app/package.json':(P/'package.json').read_bytes(),'app/package-lock.json':(P/'package-lock.json').read_bytes()}
  for package in ('old','typescript6'):
   for p in (P/'node_modules/@typescript'/package).rglob('*'):
    if p.is_file():cls.files['app/node_modules/@typescript/'+package+'/'+p.relative_to(P/'node_modules/@typescript'/package).as_posix()]=p.read_bytes()
  for package in ('playwright','playwright-core'):
   cls.files['app/node_modules/'+package+'/package.json']=(P/'node_modules'/package/'package.json').read_bytes()
  dirs=set()
  for p in cls.files:
   for i in range(1,len(p.split('/'))):dirs.add('/'.join(p.split('/')[:i]))
  cls.base=tar_bytes([entry(d,b'',tarfile.DIRTYPE) for d in sorted(dirs)]+[entry(p,data) for p,data in sorted(cls.files.items())])
 @classmethod
 def fixture(cls,changes=None):
  layers=[cls.base]+([tar_bytes(changes)] if changes else [])
  cfg=J({'os':'linux','architecture':'amd64','config':{'Labels':{'io.zevyrn.source-manifest-sha256':'a'*64}},'rootfs':{'type':'layers','diff_ids':['sha256:'+H(x) for x in layers]}})
  identity='sha256:'+H(cfg);data=archive([('config.json',cfg),('manifest.json',J([{'Config':'config.json','Layers':['layer'+str(i)+'.tar' for i in range(len(layers))]}]))]+[('layer'+str(i)+'.tar',x) for i,x in enumerate(layers)])
  return data,identity,H(data)
 def auth(self,changes=None):
  data,i,h=self.fixture(changes);return authenticate_compiler(data,i,h,'a'*64)
 def test_exact_real_artifact_files_and_alias_accepted(self):
  proof=self.auth();self.assertEqual(len(proof),4);self.assertEqual(proof['app/node_modules/@typescript/old/package.json'],{'name':'typescript','version':'6.0.3'})
 def test_tampered_manifest_code_and_lock_rejected(self):
  for p in ('app/package.json','app/package-lock.json','app/node_modules/@typescript/old/package.json','app/node_modules/@typescript/old/lib/_tsc.js','app/node_modules/@typescript/typescript6/package.json','app/node_modules/@typescript/typescript6/lib/tsc.js'):
   with self.subTest(path=p),self.assertRaises(ValueError):self.auth([entry(p,self.files[p]+b' ')])
 def test_missing_and_whiteout_manifests_or_code_rejected(self):
  for p in ('app/node_modules/@typescript/old/.wh.package.json','app/node_modules/@typescript/.wh.old','app/node_modules/@typescript/old/.wh..wh..opq','app/node_modules/@typescript/old/lib/.wh._tsc.js','app/.wh.package-lock.json'):
   with self.subTest(path=p),self.assertRaises(ValueError):self.auth([entry(p)])
 def test_exact_whiteout_recreation_accepted(self):
  p='app/node_modules/@typescript/old/package.json';self.assertEqual(len(self.auth([entry('app/node_modules/@typescript/old/.wh.package.json'),entry(p,self.files[p])])),4)
 def test_symlink_and_hardlink_redirection_rejected(self):
  for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.auth([entry('app/node_modules/@typescript/old/package.json',b'',kind,'/outside')])
 def test_parent_symlink_and_canonical_collision_rejected(self):
  for changes in ([entry('app/node_modules/@typescript/old',b'',tarfile.SYMTYPE,'/outside')],[entry('app/package.json',self.files['app/package.json']),entry('./app/package.json',self.files['app/package.json'])],[entry('../app/package.json',b'{}')]):
   with self.assertRaises(ValueError):self.auth(changes)
 def test_unexpected_native_package_extra_file_and_dependency_rejected(self):
  for p,body in [('app/node_modules/@typescript/old/native-tsc',b'ELF'),('app/node_modules/@typescript/typescript-linux-x64/package.json',b'{"name":"@typescript/typescript-linux-x64","version":"7.0.2"}'),('app/node_modules/other/package.json',b'{"name":"other","version":"1.0.0"}')]:
   with self.subTest(path=p),self.assertRaises(ValueError):self.auth([entry(p,body)])
 def test_archive_identity_and_source_substitution_rejected(self):
  data,i,h=self.fixture()
  with self.assertRaisesRegex(ValueError,'archive hash'):
   authenticate_compiler(data,i,'0'*64,'a'*64)
  with self.assertRaisesRegex(AssertionError,'^Unexpected image configuration identity$'):
   authenticate_compiler(data,'sha256:'+'0'*64,h,'a'*64)
  with self.assertRaisesRegex(ValueError,'source binding'):
   authenticate_compiler(data,i,h,'b'*64)

class ScanTests(CompilerTests):
 def setUp(self):
  self.data,self.identity,self.digest=self.fixture();self.now=datetime.datetime(2026,10,18,4,tzinfo=datetime.timezone.utc);t=lambda n:(self.now+datetime.timedelta(minutes=n)).isoformat();self.t=t;self.db=b'unit-db'
  self.context={'runID':'js-unit','sourceManifestSHA256':'a'*64,'startedUTC':t(-10),'scannerVersion':'0.76.0','scannerBinarySHA256':'b'*64,'dbSHA256':H(self.db),'scannerPolicySHA256':SCANNER_POLICY_SHA256,'images':{'builder':{'imageID':self.identity,'archiveSHA256':self.digest}}}
  self.database={'Version':2,'UpdatedAt':t(-60),'DownloadedAt':t(-9),'NextUpdate':t(60)}
  rows=[{'Name':name,'Version':v,'FilePath':'app/node_modules/'+path+'/package.json'} for name,v,path in [('@typescript/typescript6','6.0.2','@typescript/typescript6'),('typescript','6.0.3','@typescript/old'),('playwright','1.62.1','playwright'),('playwright-core','1.62.1','playwright-core')]]
  self.report={'SchemaVersion':2,'ArtifactType':'container_image','CreatedAt':t(-3),'Metadata':{'ImageID':self.identity},'Results':[{'Target':'builder (alpine)','Class':'os-pkgs','Type':'alpine','Packages':[{'Name':'zlib','Version':'1.3.2-r1'}]},{'Target':'Node.js','Class':'lang-pkgs','Type':'node-pkg','Packages':rows}]}
 def scan(self,report=None,context=None,metadata=None,receipt=None):
  r=self.report if report is None else report;data=J(r);c=self.context if context is None else context
  rec={**{k:c[k] for k in ('runID','sourceManifestSHA256','scannerVersion','scannerBinarySHA256','dbSHA256','scannerPolicySHA256')},**c['images']['builder'],'reportSHA256':H(data),'startedUTC':self.t(-4),'finishedUTC':self.t(-2)}
  if receipt:rec.update(receipt)
  return validate_scan(data,rec,c,'builder',{'zlib':'1.3.2-r1'},metadata or self.database,self.db,self.data,self.now)
 def test_valid_complete_scanner_coverage(self):self.assertTrue(self.scan()['passed'])
 def test_each_dependency_omission_rejected(self):
  for i in range(4):
   r=copy.deepcopy(self.report);r['Results'][1]['Packages'].pop(i)
   with self.subTest(index=i),self.assertRaises(EvidenceError):self.scan(r)
 def test_alias_identity_path_version_ecosystem_and_duplicate_rejected(self):
  for change in ({'Name':'@typescript/old'},{'Name':'substitute'},{'Version':'7.0.2'},{'FilePath':'app/node_modules/typescript/package.json'},{'FilePath':'app/../node_modules/@typescript/old/package.json'},{'FilePath':None}):
   r=copy.deepcopy(self.report);r['Results'][1]['Packages'][1].update(change)
   with self.subTest(change=change),self.assertRaises(EvidenceError):self.scan(r)
  for change in ({'Type':'npm'},{'Type':'pip'},{'Class':'os-pkgs'}):
   r=copy.deepcopy(self.report);r['Results'][1].update(change)
   with self.assertRaises(EvidenceError):self.scan(r)
  r=copy.deepcopy(self.report);r['Results'][1]['Packages'].append(copy.deepcopy(r['Results'][1]['Packages'][1]))
  with self.assertRaises(EvidenceError):self.scan(r)
 def test_severity_secret_empty_malformed_and_go_results_rejected(self):
  for finding in ({'Vulnerabilities':[{'VulnerabilityID':'control','Severity':'HIGH'}]},{'Vulnerabilities':[{'VulnerabilityID':'control','Severity':'CRITICAL'}]},{'Secrets':[{'RuleID':'control'}]}):
   r=copy.deepcopy(self.report);r['Results'][1].update(finding)
   with self.assertRaisesRegex(EvidenceError,'Critical/high'):self.scan(r)
  for results in ([],None,{},[{'Target':'empty'}]):
   r=copy.deepcopy(self.report);r['Results']=results
   with self.assertRaises(EvidenceError):self.scan(r)
  r=copy.deepcopy(self.report);r['Results'].append({'Target':'compiler','Type':'gobinary','Class':'lang-pkgs','Packages':[{'Name':'stdlib','Version':'v1.26.4'}]})
  with self.assertRaisesRegex(EvidenceError,'native compiler'):self.scan(r)
 def test_os_report_binding_policy_and_freshness_rejected(self):
  for key,value in (('scannerPolicySHA256','0'*64),('sourceManifestSHA256','b'*64),('dbSHA256','0'*64)):
   c=copy.deepcopy(self.context);c[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.scan(context=c)
  r=copy.deepcopy(self.report);r['Results'][0]['Packages']=[]
  with self.assertRaises(EvidenceError):self.scan(r)
  r=copy.deepcopy(self.report);r['Metadata']['ImageID']='sha256:'+'0'*64
  with self.assertRaises(EvidenceError):self.scan(r)
  with self.assertRaises(EvidenceError):self.scan(metadata={**self.database,'UpdatedAt':self.t(-1500)})
  with self.assertRaises(EvidenceError):self.scan(receipt={'reportSHA256':'0'*64})

if __name__=='__main__':unittest.main()
