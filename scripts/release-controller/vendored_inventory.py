"""Authenticate one installed TypeScript vendor relationship from a bound export.

No extraction, network or subprocesses. Reuse the reviewed OCI resolver and
whiteout-aware effective-filesystem implementation; never trust a report path.
"""
import gzip,hashlib,io,json,tarfile
from export_identity import resolve_export
from filesystem_equivalence import name,apply_layer,digest_stream

PARENT='app/node_modules/typescript/package.json'
VENDOR='app/node_modules/typescript/vendor/vscode-jsonrpc/package.json'
ENTRY='app/node_modules/typescript/vendor/vscode-jsonrpc/lib/node/main.js'

def require(value,message):
 if not value:raise ValueError('Unverified TypeScript vendor relationship: '+message)

def manifest(data):
 def unique(pairs):
  result={}
  for key,value in pairs:
   require(key not in result,'duplicate manifest key')
   result[key]=value
  return result
 value=json.loads(data,object_pairs_hook=unique)
 require(isinstance(value,dict),'manifest object')
 return value

def authenticate_typescript_vendor(data,identity,archive_sha,source_sha):
 require(hashlib.sha256(data).hexdigest()==archive_sha,'archive hash')
 tree={};selected={}
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as outer:
  members={}
  for member in outer:
   key=name(member.name,member.isdir())
   if not key:continue
   require(key not in members and (member.isfile() or member.isdir()),'unsafe/duplicate outer member')
   members[key]=member
  def read(key):
   require(key in members and members[key].isfile(),'missing regular export object')
   return outer.extractfile(members[key])
  resolved=resolve_export(read,members,identity)
  cfg=resolved['config']
  require(cfg.get('os')=='linux' and cfg.get('architecture')=='amd64','platform')
  require(cfg.get('config',{}).get('Labels',{}).get('io.zevyrn.source-manifest-sha256')==source_sha,'source binding')
  refs=resolved['layerReferences'];diffs=cfg.get('rootfs',{}).get('diff_ids',[])
  require(len(refs)==len(diffs),'layer count')
  for ref,diff in zip(refs,diffs,strict=True):
   raw=read(ref);magic=raw.read(2);raw.seek(0)
   stream=gzip.GzipFile(fileobj=raw) if magic==b'\x1f\x8b' else raw
   require('sha256:'+digest_stream(stream)==diff,'layer identity')
   with tarfile.open(fileobj=read(ref),mode='r:*') as layer:
    apply_layer(tree,layer)
    for member in layer.getmembers():
     key=name(member.name,member.isdir())
     if key in (PARENT,VENDOR,ENTRY):
      # A later link cannot authenticate a manifest, even if bytes match.
      require(member.isfile(),'manifest/entry must be regular; links rejected')
      require(member.size<=2*1024**2,'oversized manifest/entry')
      selected[key]=layer.extractfile(member).read()
 for path in (PARENT,VENDOR,ENTRY):
  require(path in selected and tree.get(path,{}).get('type')=='file','missing effective manifest/entry')
  require(tree[path]['sha256']==hashlib.sha256(selected[path]).hexdigest(),'effective file mismatch')
  parts=path.split('/')[:-1]
  for i in range(1,len(parts)+1):
   require(tree.get('/'.join(parts[:i]),{}).get('type')=='directory','non-directory/symlink ancestor')
 parent=manifest(selected[PARENT]);vendor=manifest(selected[VENDOR])
 require(parent.get('name')=='typescript' and parent.get('version')=='7.0.2','parent identity')
 imports=parent.get('imports')
 require(isinstance(imports,dict) and imports.get('#vscode-jsonrpc/node')=='./vendor/vscode-jsonrpc/lib/node/main.js','explicit import relationship')
 require(vendor.get('name')=='vscode-jsonrpc' and vendor.get('version')=='9.0.0','vendor identity')
 return {VENDOR:{'name':vendor['name'],'version':vendor['version'],'parentName':parent['name'],'parentVersion':parent['version'],
  'parentManifestSHA256':tree[PARENT]['sha256'],'manifestSHA256':tree[VENDOR]['sha256'],'entrySHA256':tree[ENTRY]['sha256'],
  'imageID':identity,'archiveSHA256':archive_sha,'sourceManifestSHA256':source_sha}}
