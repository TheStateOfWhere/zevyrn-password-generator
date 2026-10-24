"""Unprivileged archive qualification; never connects to a Docker daemon."""
from pathlib import Path
import os,json,hashlib,tarfile,gzip,io,subprocess,datetime,urllib.request,sys,time
from runtime_context import active
active().require_phase('native-linux-execution')
assert sys.platform=='linux' and os.getuid()==1000,'Approved unprivileged Linux scanner required'
from qualification_evidence import validate_scan, report_identity, isolated_scanner_environment, SCANNER_POLICY_SHA256
_profile=active().profile();_layout=_profile['bindings'].get('nativeDataLayout')
assert _layout in ('.','data'),'Explicit native data layout required'
R=Path(_profile['executionRoot'])/_layout;Q=json.loads((R/'qualification.json').read_text())
os.umask(0o077)
def utc():return datetime.datetime.now(datetime.timezone.utc)
def write(name,data):
 with (R/name).open('x') as f:json.dump(data,f,indent=2);f.write('\n')
def digest(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def status(phase):
 (R/'scan-status.json').write_text(json.dumps({'phase':phase,'utc':utc().isoformat(),'uid':os.getuid()})+'\n')
def packages(text):
 import re
 result=[];seen=set()
 for stanza in text.split('\n\n'):
  if not stanza.strip():continue
  data={}
  for line in stanza.splitlines():
   if len(line)<2 or line[1]!=':' or not line[0].isalpha():raise ValueError('Malformed APK record field')
   key,value=line[0],line[2:]
   # File/dependency metadata can repeat; identity metadata cannot.
   if key in 'PVAo' and key in data:raise ValueError('Duplicate APK identity field')
   data.setdefault(key,value)
  name=data.get('P');version=data.get('V')
  if not name or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]*',name):raise ValueError('Invalid APK package name')
  if not version or not re.fullmatch(r'[0-9][A-Za-z0-9+_.~:-]*',version):raise ValueError('Missing or malformed APK package version')
  if name in seen:raise ValueError('Duplicate or conflicting APK package identity')
  seen.add(name)
  result.append({'name':name,'version':version,'origin':data.get('o'),'architecture':data.get('A')})
 return result
def archive_name(name,root_directory=False):
 # Never extract members to the host. Reject ambiguous names before applying
 # layer semantics; use POSIX separators consistently on Linux and Windows.
 if not isinstance(name,str) or not name or '\\' in name or '\x00' in name or name.startswith('/'):
  raise ValueError('Unsafe archive member name')
 while name.startswith('./'):name=name[2:]
 if name in ('','.') and root_directory:return ''
 if root_directory:name=name.rstrip('/')
 if any(part in ('','.','..') or ':' in part for part in name.split('/')):
  raise ValueError('Unsafe archive member name')
 return name

def archive_inventory(kind,build):
 from export_identity import resolve_export
 path=R/build['archive'];assert digest(path)==build['archiveSHA256']
 apk=None;names=set();checks=[]
 database='lib/apk/db/installed';ancestors={'lib','lib/apk','lib/apk/db'}
 with tarfile.open(path,'r:') as archive:
  # Validate outer members and referenced names too: tarfile may otherwise
  # resolve archive-internal links or duplicate names implicitly.
  outer={}
  for item in archive.getmembers():
   name=archive_name(item.name,item.isdir())
   if not name:continue
   if not (item.isfile() or item.isdir()) or name in outer:
    raise ValueError('Unsupported or duplicate outer archive member')
   outer[name]=item
  def outer_file(name):
   name=archive_name(name)
   if name not in outer or not outer[name].isfile():raise ValueError('Missing regular archive member')
   return archive.extractfile(outer[name])
  resolved=resolve_export(outer_file,outer,build['image']['id'])
  config=resolved['config'];m={'Layers':resolved['layerReferences']}
  assert len(m['Layers'])==len(config['rootfs']['diff_ids'])
  for member,expected in zip(m['Layers'],config['rootfs']['diff_ids']):
   raw=outer_file(member);magic=raw.read(2);raw.seek(0)
   stream=gzip.GzipFile(fileobj=raw) if magic==b'\x1f\x8b' else raw
   h=hashlib.sha256()
   for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
   assert 'sha256:'+h.hexdigest()==expected
   checks.append(expected);raw=outer_file(member)
   additions=[];deletions=[];db=None;seen=set()
   with tarfile.open(fileobj=raw,mode='r:*') as layer:
    for item in layer:
     name=archive_name(item.name,item.isdir())
     if not name:continue
     if name in seen:raise ValueError('Duplicate layer member')
     seen.add(name)
     parts=name.split('/');base=parts[-1];parent='/'.join(parts[:-1])
     if any(part.startswith('.wh.') for part in parts[:-1]):raise ValueError('Malformed whiteout path')
     if base.startswith('.wh.'):
      target=base[4:]
      if not item.isfile() or item.size!=0 or target in ('','.','..') or (target.startswith('.wh.') and base!='.wh..wh..opq'):
       raise ValueError('Malformed whiteout entry')
      deletions.append((parent,base))
     else:
      # Resolving links at/above the database would require a full filesystem
      # interpreter. Refuse incomplete evidence instead of reading stale data.
      if name in ancestors and not item.isdir():
       raise ValueError('Incomplete package inventory: unsupported database ancestor replacement')
      if name==database and not item.isfile():
       raise ValueError('Incomplete package inventory: database is not a regular file')
      additions.append(name)
      if name==database:db=layer.extractfile(item).read().decode()
   # Whiteouts hide LOWER layers only, independent of tar entry order. Apply
   # all removals before same-layer additions/database replacement.
   for parent,base in deletions:
    prefix=parent+'/' if parent else ''
    target=prefix+base.removeprefix('.wh.')
    if base=='.wh..wh..opq':
     names={n for n in names if not n.startswith(prefix)}
     if database.startswith(prefix):apk=None
    else:
     names={n for n in names if n!=target and not n.startswith(target+'/')}
     if database==target or database.startswith(target+'/'):apk=None
   names.update(additions)
   if db is not None:apk=db
 if apk is None or database not in names:
  raise ValueError('Incomplete package inventory: effective APK database missing')
 inventory=packages(apk)
 if not inventory:raise ValueError('Incomplete package inventory: effective APK database empty')
 versions={p['name']:p['version'] for p in inventory}
 required={'nginx':'1.30.6-r1','libexpat':'2.9.0-r0','zlib':'1.3.2-r1','pcre2':'10.49-r0','tiff':'4.7.2-r0','libpng':'1.6.59-r0','nghttp2-libs':'1.70.0-r0'}
 if kind=='runtime':
  for package,version in required.items():assert versions.get(package)==version,'Runtime package mismatch: '+package
  forbidden=['usr/local/bin/node','usr/local/bin/npm','usr/local/lib/node_modules','app/node_modules']
  assert not any(n==p or n.startswith(p+'/') for n in names for p in forbidden),'Unexpected runtime build tooling'
 else:forbidden=[]
 result={'imageID':build['image']['id'],'archiveSHA256':build['archiveSHA256'],'identityChain':resolved['chain'],'platform':'linux/amd64','allLayerDiffIDsVerified':checks,'packages':inventory,'requiredPackages':{p:{'installed':versions.get(p),'requiredRuntimeVersion':v,'scope':'required in runtime; builder absence separately reported'} for p,v in required.items()},'unexpectedRuntimeBuildTools':False if kind=='runtime' else None}
 write(kind+'-installed-packages.json',result);return versions
def run(command,log):
 start=utc().isoformat();before=time.monotonic();code=None;error=None
 try:
  with (R/log).open('xb') as out,(R/(log+'.stderr')).open('xb') as err:
   result=subprocess.run(command,stdout=out,stderr=err,env=isolated_scanner_environment(R),cwd=R/'scanner-policy')
   code=result.returncode
 except BaseException as failure:
  error={'exception':type(failure).__name__,'message':str(failure)};raise
 finally:
  write(log+'.exit.json',{'attemptID':Q['attemptID'],'runID':Q['runID'],'sourceManifestSHA256':Q['sourceManifestSHA256'],
   'command':command,'exitCode':code,'error':error,'startedUTC':start,'finishedUTC':utc().isoformat(),
   'stdoutSHA256':digest(R/log) if (R/log).is_file() else None,'stderrSHA256':digest(R/(log+'.stderr')) if (R/(log+'.stderr')).is_file() else None})
 assert type(code) is int and code==0,'Scanner/tool failure: '+log
 return time.monotonic()-before

try:
 started=utc().isoformat()
 (R/'scanner-policy').mkdir(mode=0o700,exist_ok=False)
 (R/'scanner-policy/empty-ignore').write_text('')
 (R/'scanner-policy/empty-config.yaml').write_text('{}\n')
 builds=json.loads((R/'builds.json').read_text());inventory={}
 for kind in ['builder','runtime']:
  status('verifying-'+kind+'-archive');inventory[kind]=archive_inventory(kind,builds[kind])
 tools=R/'tools';tools.mkdir(mode=0o700,exist_ok=True);status('downloading-verified-scanner')
 url='https://github.com/aquasecurity/trivy/releases/download/v0.76.0/trivy_0.76.0_Linux-64bit.tar.gz'
 data=urllib.request.urlopen(url,timeout=120).read();checksum=hashlib.sha256(data).hexdigest();assert checksum=='e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7'
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as t:
  binary=t.extractfile('trivy').read()
 trivy=tools/'trivy';trivy.write_bytes(binary);trivy.chmod(0o700)
 write('scanner-provenance.json',{'version':'0.76.0','url':url,'releaseArchiveSHA256':checksum,'binarySHA256':hashlib.sha256(binary).hexdigest(),'executedUID':os.getuid()})
 status('downloading-fresh-db');dbStarted=utc();run([str(trivy),'image','--download-db-only'],'scanner-db-download.log')
 metadata=R/'trivy-cache/db/metadata.json';db=json.loads(metadata.read_text())
 def parse(text):return datetime.datetime.fromisoformat(text.replace('Z','+00:00'))
 assert parse(db['DownloadedAt'])>=dbStarted-datetime.timedelta(seconds=5)
 assert -300<=(utc()-parse(db['UpdatedAt'])).total_seconds()<=24*3600
 write('scanner-db-start.json',{'metadata':db,'databaseSHA256':digest(R/'trivy-cache/db/trivy.db'),'checkedUTC':utc().isoformat(),'freshWithin24Hours':True})
 run([str(trivy),'version','--format','json'],'scanner-version.json')
 context={'attemptID':Q['attemptID'],'runID':Q['runID'],'sourceManifestSHA256':Q['sourceManifestSHA256'],'startedUTC':started,'scannerVersion':'0.76.0','scannerBinarySHA256':digest(trivy),'dbSHA256':digest(R/'trivy-cache/db/trivy.db'),'scannerPolicySHA256':SCANNER_POLICY_SHA256,'images':{k:{'imageID':builds[k]['image']['id'],'archiveSHA256':builds[k]['archiveSHA256']} for k in ('builder','runtime')}}
 context['exportIdentities']={k:json.loads((R/(k+'-installed-packages.json')).read_text())['identityChain'] for k in ('builder','runtime')}
 write('evidence-context.json',context)
 reports={}
 for kind in ['builder','runtime']:
  status('scanning-'+kind)
  scanStarted=utc().isoformat()
  seconds=run([str(trivy),'image','--config',str(R/'scanner-policy/empty-config.yaml'),'--ignorefile',str(R/'scanner-policy/empty-ignore'),'--skip-db-update','--input',str(R/builds[kind]['archive']),'--list-all-pkgs','--severity','UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL','--scanners','vuln,secret','--image-config-scanners','secret','--format','json','--output',str(R/(kind+'-raw-scan.json'))],kind+'-scan.log')
  receipt={**context['images'][kind],'attemptID':Q['attemptID'],'runID':Q['runID'],'sourceManifestSHA256':Q['sourceManifestSHA256'],'reportSHA256':digest(R/(kind+'-raw-scan.json')),'startedUTC':scanStarted,'finishedUTC':utc().isoformat(),'scannerVersion':'0.76.0','scannerBinarySHA256':digest(trivy),'dbSHA256':digest(R/'trivy-cache/db/trivy.db'),'scannerPolicySHA256':SCANNER_POLICY_SHA256}
  write(kind+'-scan-receipt.json',receipt)
  validated = validate_scan((R/(kind+'-raw-scan.json')).read_bytes(),receipt,context,kind,inventory[kind],db,(R/'trivy-cache/db/trivy.db').read_bytes(),(R/builds[kind]['archive']).read_bytes(),utc(),evidence_root=R)
  raw=json.loads((R/(kind+'-raw-scan.json')).read_text());assert raw['SchemaVersion']>=2 and raw['ArtifactType']=='container_image'
  # Use the existing verified export-chain policy, including OCI config IDs.
  # validate_scan above already enforces this policy on the actual report.
  identity_role=report_identity(context,kind,raw['Metadata']['ImageID'])
  results=raw['Results'];assert any(x.get('Class')=='os-pkgs' and x.get('Type')=='alpine' and x.get('Packages') for x in results),'Missing Alpine package coverage'
  found={p['Name']:p['Version'] for x in results for p in x.get('Packages',[])}
  for p,v in inventory[kind].items():assert found.get(p)==v,'Missing or mismatched OS package coverage: '+p
  if kind=='builder':
   for name,version in [('@typescript/typescript6','6.0.2'),('typescript','6.0.3'),('playwright','1.62.1'),('playwright-core','1.62.1')]:assert any(p.get('Name')==name and p.get('Version')==version for x in results for p in x.get('Packages',[])),'Missing development dependency coverage: '+name
  counts={x:0 for x in ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']};secrets=0
  for target in results:
   for v in target.get('Vulnerabilities',[]):counts[v['Severity']]+=1
   secrets+=len(target.get('Secrets',[]))
  reports[kind]={'imageID':builds[kind]['image']['id'],'archiveSHA256':builds[kind]['archiveSHA256'],'reportSHA256':digest(R/(kind+'-raw-scan.json')),'seconds':seconds,'counts':counts,'secrets':secrets,'osPackageCoverageVerified':True,'npmDevelopmentCoverageVerified':kind=='builder','builderApplicability':validated['builderApplicability']}
 write('scan-binding-and-counts.json',reports)
 # Report both stages completely before enforcing the strict vulnerability gate.
 assert all(r['builderApplicability']['status'] in ('PASS','PASS_WITH_APPROVED_BUILDER_HIGH') for r in reports.values()),'Vulnerability applicability gate failed'
 status('generating-runtime-sbom')
 sbomStarted=utc().isoformat()
 run([str(trivy),'convert','--format','cyclonedx','--output',str(R/'runtime-sbom.cdx.json'),str(R/'runtime-raw-scan.json')],'sbom-generation.log')
 write('runtime-sbom-receipt.json',{**context['images']['runtime'],'attemptID':Q['attemptID'],'runID':Q['runID'],'sourceManifestSHA256':Q['sourceManifestSHA256'],'sbomSHA256':digest(R/'runtime-sbom.cdx.json'),'sourceReportSHA256':digest(R/'runtime-raw-scan.json'),'startedUTC':sbomStarted,'finishedUTC':utc().isoformat(),'scannerVersion':'0.76.0','scannerBinarySHA256':digest(trivy),'dbSHA256':digest(R/'trivy-cache/db/trivy.db'),'scannerPolicySHA256':SCANNER_POLICY_SHA256})
 write('sbom-binding.json',{'runtimeImageID':builds['runtime']['image']['id'],'runtimeArchiveSHA256':builds['runtime']['archiveSHA256'],'sourceManifestSHA256':Q['sourceManifestSHA256'],'sbomSHA256':digest(R/'runtime-sbom.cdx.json'),'schemaValidation':'PENDING_LOCAL_OFFICIAL_SCHEMA_VALIDATION'})
 dbEnd=json.loads(metadata.read_text());assert -300<=(utc()-parse(dbEnd['UpdatedAt'])).total_seconds()<=86400
 write('scanner-db-end.json',{'metadata':dbEnd,'databaseSHA256':digest(R/'trivy-cache/db/trivy.db'),'checkedUTC':utc().isoformat()})
 status('READY_FOR_LOCAL_SCHEMA_VALIDATION')
except BaseException as error:
 write('scan-stopped.json',{'status':'BLOCKED','reason':type(error).__name__+': '+str(error),'utc':utc().isoformat()});status('BLOCKED');sys.exit(1)
