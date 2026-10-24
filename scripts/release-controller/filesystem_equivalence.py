"""Compare image filesystem records without extracting or executing image contents.

Uses the reviewed export resolver and Python tarfile, applies layer whiteouts,
and fails closed on unsupported/ambiguous paths. No host filesystem extraction.
Timestamps are excluded: this gate compares contents, ownership, modes, links,
device identities and xattrs, rather than layer packaging/history timestamps.
"""
from pathlib import Path
import gzip,hashlib,json,posixpath,tarfile
from export_identity import resolve_export

def digest_stream(stream):
 h=hashlib.sha256()
 for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
 return h.hexdigest()

def name(value,directory=False):
 if not isinstance(value,str) or not value or value.startswith('/') or '\\' in value or '\0' in value:raise ValueError('Unsafe filesystem archive path')
 while value.startswith('./'):value=value[2:]
 if directory:value=value.rstrip('/')
 if value in ('','.') and directory:return ''
 if any(p in ('','.','..') or ':' in p for p in value.split('/')):raise ValueError('Unsafe filesystem archive path')
 return value

def apply_layer(tree,layer):
 entries={};whiteouts=[]
 for item in layer:
  path=name(item.name,item.isdir())
  if path in entries:raise ValueError('Duplicate layer path')
  base=posixpath.basename(path);parent=posixpath.dirname(path)
  if any(p.startswith('.wh.') for p in path.split('/')[:-1]):raise ValueError('Malformed whiteout path')
  if base.startswith('.wh.'):
   target=base[4:]
   if not item.isfile() or item.size or target in ('','.','..') or (target.startswith('.wh.') and base!='.wh..wh..opq'):raise ValueError('Malformed whiteout entry')
   whiteouts.append((path,parent,base));entries[path]=None;continue
  record={'uid':item.uid,'gid':item.gid,'mode':item.mode,'xattrs':{k:v for k,v in item.pax_headers.items() if k.startswith(('SCHILY.xattr.','LIBARCHIVE.xattr.'))}}
  if item.isfile():record.update(type='file',size=item.size,sha256=digest_stream(layer.extractfile(item)))
  elif item.isdir():record.update(type='directory')
  elif item.issym():
   if not item.linkname or '\0' in item.linkname:raise ValueError('Malformed symlink')
   record.update(type='symlink',target=item.linkname)
  elif item.islnk():record.update(type='hardlink',target=name(item.linkname))
  elif item.ischr() or item.isblk():record.update(type='character' if item.ischr() else 'block',major=item.devmajor,minor=item.devminor)
  elif item.isfifo():record.update(type='fifo')
  else:raise ValueError('Unsupported filesystem entry type')
  entries[path]=record
 # Whiteouts affect lower layers only, including when tar entries are reordered.
 for path,parent,base in whiteouts:
  prefix=parent+'/' if parent else ''
  target=prefix+base[4:]
  for lower in list(tree):
   hidden=lower.startswith(prefix) and lower!=parent if base=='.wh..wh..opq' else lower==target or lower.startswith(target+'/')
   if hidden:del tree[lower]
  del entries[path]
 # Parent replacement removes lower descendants. Directory updates retain them.
 for path,record in entries.items():
  if record['type']!='directory':
   for lower in list(tree):
    if lower.startswith(path+'/'):del tree[lower]
 def inode(path,seen):
  if path in seen:raise ValueError('Hardlink cycle')
  value=entries.get(path,tree.get(path))
  if value is None:raise ValueError('Missing hardlink target')
  if value['type']=='hardlink':return inode(value['target'],seen|{path})
  if value['type']!='file':raise ValueError('Non-file hardlink target')
  return dict(value)
 for path,record in entries.items():
  # Image layers writing beneath symlinks require filesystem resolution, which
  # this bounded comparator deliberately does not guess at.
  for parent in (posixpath.dirname(path),):
   while parent:
    ancestor=entries.get(parent,tree.get(parent))
    if ancestor and ancestor['type']!='directory':raise ValueError('Unsupported non-directory path ancestor')
    parent=posixpath.dirname(parent)
  if record['type']=='hardlink':record=inode(path,set())
  tree[path]=record
 return tree

def filesystem(path,identity,expected_archive_sha):
 path=Path(path)
 with path.open('rb') as stream:
  if digest_stream(stream)!=expected_archive_sha:raise ValueError('Filesystem export SHA-256 mismatch')
 tree={};layers=[]
 with tarfile.open(path,'r:') as outer:
  members={}
  for item in outer:
   key=name(item.name,item.isdir())
   if not key:continue
   if key in members or not (item.isfile() or item.isdir()):raise ValueError('Unsafe or duplicate export member')
   members[key]=item
  def read(key):
   key=name(key)
   if key not in members or not members[key].isfile():raise ValueError('Missing export object')
   return outer.extractfile(members[key])
  resolved=resolve_export(read,members,identity)
  for ref,diffid in zip(resolved['layerReferences'],resolved['config']['rootfs']['diff_ids'],strict=True):
   raw=read(ref);magic=raw.read(2);raw.seek(0)
   stream=gzip.GzipFile(fileobj=raw) if magic==b'\x1f\x8b' else raw
   if 'sha256:'+digest_stream(stream)!=diffid:raise ValueError('Filesystem layer diffID mismatch')
   with tarfile.open(fileobj=read(ref),mode='r:*') as layer:apply_layer(tree,layer)
   layers.append(diffid)
 # A missing root directory entry expresses no image-layer override; compare
 # explicit root records only when both exports provide them. Runtime root
 # ownership/mode is separately verified through a constrained in-container stat.
 root=tree.pop('',None)
 return {'files':tree,'explicitRootRecord':root,'identityChain':resolved['chain'],'allLayerDiffIDsVerified':layers,'config':resolved['config']}

def compare(rootfs,runtime):
 a,b=rootfs['files'],runtime['files'];mismatches=[]
 for path in sorted(set(a)|set(b)):
  if a.get(path)!=b.get(path):mismatches.append({'path':path,'source':a.get(path),'runtime':b.get(path)})
 if rootfs['explicitRootRecord'] is not None and runtime['explicitRootRecord'] is not None and rootfs['explicitRootRecord']!=runtime['explicitRootRecord']:
  mismatches.append({'path':'/','source':rootfs['explicitRootRecord'],'runtime':runtime['explicitRootRecord']})
 return {'passed':not mismatches,'filesCompared':len(set(a)|set(b)),'mismatches':mismatches,'sourceIdentityChain':rootfs['identityChain'],'runtimeIdentityChain':runtime['identityChain'],'sourceRootRecord':rootfs['explicitRootRecord'],'runtimeRootRecord':runtime['explicitRootRecord'],'timestampPolicy':'packaging timestamps excluded; all recorded contents, UID/GID, mode, symlinks, device identities and xattrs compared','rootPolicy':'implicit root records are not guessed; explicit records compared if both present, runtime stat required'}

def main(root):
 root=Path(root);q=json.loads((root/'qualification.json').read_text());builds=json.loads((root/'builds.json').read_text())
 values={}
 for kind in ('rootfs','runtime'):
  b=builds[kind];values[kind]=filesystem(root/b['archive'],b['image']['id'],b['archiveSHA256'])
 result=compare(values['rootfs'],values['runtime'])
 result.update(runID=q['runID'],sourceManifestSHA256=q['sourceManifestSHA256'],exports={k:{'imageID':builds[k]['image']['id'],'archiveSHA256':builds[k]['archiveSHA256']} for k in values})
 with (root/'filesystem-equivalence.json').open('x') as out:json.dump(result,out,indent=2);out.write('\n')
 if not result['passed']:raise ValueError('Scratch filesystem equivalence failed: '+str(len(result['mismatches']))+' unexplained differences')
 return result

if __name__=='__main__':main(Path(__file__).resolve().parent)
