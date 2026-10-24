"""Tiny deterministic saved-archive fixture; no Docker build or execution."""
import hashlib,io,json,tarfile
from pathlib import Path

def archive(entries):
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w',format=tarfile.PAX_FORMAT) as tar:
  for path,data in entries:
   item=tarfile.TarInfo(path);item.size=len(data);item.mode=0o644;item.mtime=0
   tar.addfile(item,io.BytesIO(data))
 return out.getvalue()

def installed_dependencies_fixture(path, *, omit_dev=False, secret=False):
 project={'name':'zevyrn-cli-fixture','version':'1.0.0','dependencies':{'fixture-prod':'1.0.0'},'devDependencies':{'fixture-dev':'2.0.0'}}
 rows=[('etc/alpine-release',b'3.24.0\n'),('etc/os-release',b'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.24.0\n'),('lib/apk/db/installed',b'P:fixture-os\nV:1.0-r0\nA:x86_64\no:fixture-os\nL:MIT\n\n'),('app/package.json',json.dumps(project).encode())]
 expected={'fixture-prod':'1.0.0','fixture-dev':'2.0.0','fixture-transitive':'3.0.0'}
 for name,version in expected.items():
  if omit_dev and name=='fixture-dev':continue
  package={'name':name,'version':version,'license':'MIT'}
  if name=='fixture-dev':package['dependencies']={'fixture-transitive':'3.0.0'}
  rows.append(('app/node_modules/'+name+'/package.json',json.dumps(package).encode()))
 if secret:
  # Deterministic token-shaped string, never issued or used as a credential.
  token='ghp_'+'A9b8C7d6E5f4G3h2J1k0L9m8N7p6Q5r4S3t2'
  assert len(token)==40
  rows.append(('app/offline-secret-negative-control.txt',('# Synthetic unissued negative control\n'+token+'\n').encode()))
 layer=archive(rows)
 config=json.dumps({'architecture':'amd64','os':'linux','config':{},'rootfs':{'type':'layers','diff_ids':['sha256:'+hashlib.sha256(layer).hexdigest()]},'history':[{'created_by':'synthetic offline CLI coverage fixture'}]},sort_keys=True).encode()
 identity=hashlib.sha256(config).hexdigest()
 manifest=json.dumps([{'Config':identity+'.json','RepoTags':['synthetic-cli-fixture:offline'],'Layers':['layer.tar']}]).encode()
 data=archive([(identity+'.json',config),('manifest.json',manifest),('layer.tar',layer)])
 Path(path).write_bytes(data)
 return {'configurationDigest':'sha256:'+identity,'archiveSHA256':hashlib.sha256(data).hexdigest(),'expectedInstalledDependencies':expected,'fixturePurpose':'Offline dependency-discovery check only, not a security qualification report'}
