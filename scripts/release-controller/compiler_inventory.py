"""Authenticate the exact JS compiler closure from an image-bound effective tree."""
from pathlib import Path
import gzip,hashlib,io,json,tarfile
from export_identity import resolve_export
from filesystem_equivalence import name,apply_layer,digest_stream
from vendored_inventory import manifest
CATALOG_SHA256='ca9993e94e4f109d59130f29e140434817214eb9549eb44b8beedd65dcd99acd'

def require(condition,message):
 if not condition:raise ValueError('Unauthenticated JavaScript compiler: '+message)

def authenticate_compiler(data,identity,archive_sha,source_sha):
 require(hashlib.sha256(data).hexdigest()==archive_sha,'archive hash')
 root=Path(__file__).absolute().parent
 catalog_path=root.parent/'compiler-integrity.json' if root.name=='release-controller' and root.parent.name=='scripts' else root/'compiler-integrity.json'
 raw=catalog_path.read_bytes();require(hashlib.sha256(raw).hexdigest()==CATALOG_SHA256,'catalog integrity')
 catalog=manifest(raw);tree={};selected={}
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as outer:
  members={}
  for item in outer:
   key=name(item.name,item.isdir())
   if not key:continue
   require(key not in members and (item.isfile() or item.isdir()),'outer archive member')
   members[key]=item
  def read(key):
   require(key in members and members[key].isfile(),'missing regular export object');return outer.extractfile(members[key])
  resolved=resolve_export(read,members,identity);cfg=resolved['config']
  require(cfg.get('os')=='linux' and cfg.get('architecture')=='amd64','platform')
  require(cfg.get('config',{}).get('Labels',{}).get('io.zevyrn.source-manifest-sha256')==source_sha,'source binding')
  refs=resolved['layerReferences'];diffs=cfg.get('rootfs',{}).get('diff_ids',[]);require(len(refs)==len(diffs),'layer count')
  for ref,diff in zip(refs,diffs,strict=True):
   stream=read(ref);magic=stream.read(2);stream.seek(0);stream=gzip.GzipFile(fileobj=stream) if magic==b'\x1f\x8b' else stream
   require('sha256:'+digest_stream(stream)==diff,'layer hash')
   with tarfile.open(fileobj=read(ref),mode='r:*') as layer:
    apply_layer(tree,layer)
    for item in layer.getmembers():
     key=name(item.name,item.isdir())
     if key in ('app/package.json','app/package-lock.json') or key.startswith('app/node_modules/') and key.endswith('/package.json'):
      require(item.isfile() and item.size<=2*1024**2,'regular manifest; links rejected')
      selected[key]=layer.extractfile(item).read()
 def effective(path,expected=None):
  item=tree.get(path,{});require(item.get('type')=='file','missing effective regular file: '+path)
  if expected:require(item['sha256']==expected,'artifact bytes: '+path)
  for i in range(1,len(path.split('/'))):require(tree.get('/'.join(path.split('/')[:i]),{}).get('type')=='directory','symlink/non-directory ancestor')
  return item
 for path,key in (('app/package.json','packageSHA256'),('app/package-lock.json','lockSHA256')):
  effective(path,catalog[key]);require(path in selected and hashlib.sha256(selected[path]).hexdigest()==tree[path]['sha256'],'effective project metadata')
 project=manifest(selected['app/package.json']);lock=manifest(selected['app/package-lock.json']);require(lock.get('lockfileVersion')==3,'lock version')
 require(project.get('devDependencies')=={'@typescript/typescript6':'6.0.2','playwright':'1.62.1'},'project dependencies')
 expected={}
 for artifact in catalog['artifacts']:
  root='app/'+artifact['installPath'];entry=lock.get('packages',{}).get(artifact['installPath'],{})
  require(entry.get('version')==artifact['version'] and entry.get('integrity')==artifact['integrity'] and entry.get('resolved')==artifact['tarball'],'locked compiler artifact')
  wanted={root+'/'+p:sha for p,sha in artifact['files'].items()}
  actual={p for p,v in tree.items() if p.startswith(root+'/') and v.get('type')!='directory'};require(actual==set(wanted),'compiler file inventory')
  for path,digest in wanted.items():effective(path,digest)
  m=manifest(selected[root+'/package.json']);require(m.get('name')==artifact['name'] and m.get('version')==artifact['version'],'compiler identity')
  if artifact['name']=='@typescript/typescript6':require(m.get('dependencies')=={'@typescript/old':'npm:typescript@^6'},'wrapper alias relationship')
  else:require(not m.get('dependencies'),'unexpected compiler dependencies')
 for path in tree:
  if path.startswith('app/node_modules/') and path.endswith('/package.json'):
   effective(path);require(path in selected and hashlib.sha256(selected[path]).hexdigest()==tree[path]['sha256'],'effective installed manifest')
   m=manifest(selected[path]);require(m.get('name') not in ('typescript',) or path=='app/node_modules/@typescript/old/package.json','unexpected native compiler identity')
   require(not str(m.get('name','')).startswith('@typescript/typescript-'),'native platform package')
   expected[path]={'name':m.get('name'),'version':m.get('version')}
 required={'app/node_modules/@typescript/typescript6/package.json':('@typescript/typescript6','6.0.2'),'app/node_modules/@typescript/old/package.json':('typescript','6.0.3'),'app/node_modules/playwright/package.json':('playwright','1.62.1'),'app/node_modules/playwright-core/package.json':('playwright-core','1.62.1')}
 require(set(expected)==set(required),'complete dependency inventory')
 for path,(package,version) in required.items():require(expected[path]=={'name':package,'version':version},'installed dependency identity')
 for p,entry in lock['packages'].items():require(not p.startswith('node_modules/@typescript/typescript-') and p!='node_modules/typescript','native compiler in lock')
 require(lock['packages']['node_modules/@typescript/typescript6'].get('dependencies')=={'@typescript/old':'npm:typescript@^6'},'locked alias relationship')
 require(lock['packages']['node_modules/@typescript/old'].get('name')=='typescript','locked alias identity')
 return expected
