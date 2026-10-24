"""Candidate-source staging only; archive permissions never override approved modes."""
import base64,hashlib,io,json,os,pathlib,shutil,stat,sys,tarfile

def digest(data):return hashlib.sha256(data).hexdigest()

def apply_mode(path,mode):
    # Windows cannot establish POSIX mode preservation. Native execution fails closed.
    if os.name!='posix':raise RuntimeError('Native POSIX mode enforcement is required')
    os.chmod(path,mode)
    if stat.S_IMODE(path.stat().st_mode)!=mode:raise ValueError('Staged mode mismatch')

def stage_source(root,data,manifest,policy):
    root=pathlib.Path(root)
    if not root.is_absolute() or root.exists() or root.is_symlink():raise ValueError('Workspace must be new and absolute')
    if any(p.is_symlink() for p in root.parents):raise ValueError('Linked workspace ancestor')
    if policy.get('schemaVersion')!=1 or policy.get('attemptRootMode')!=0o700 or policy.get('directoryMode')!=0o755:raise ValueError('Mode policy')
    rows=manifest.get('source');modes=policy.get('files')
    if not isinstance(rows,list) or not isinstance(modes,dict):raise ValueError('Missing source/mode inventory')
    expected={}
    for row in rows:
        name=row['path']
        if not isinstance(name,str) or not name or name.startswith('/') or '\\' in name or ':' in name or any(p in ('','.','..') for p in name.split('/')):raise ValueError('Unsafe source path')
        if name in expected:raise ValueError('Duplicate source record')
        if type(row.get('mode')) is not int or row['mode'] not in (0o644,0o755) or modes.get(name)!=row['mode']:raise ValueError('Unapproved source mode')
        expected[name]=row
    if not expected or set(expected)!=set(modes):raise ValueError('Incomplete mode inventory')
    verified=[]
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
        members=archive.getmembers()
        if len(members)!=len(expected) or {m.name for m in members}!=set(expected):raise ValueError('Archive inventory')
        for member in members:
            if not member.isfile() or member.pax_headers:raise ValueError('Only plain regular source members')
            row=expected[member.name];content=archive.extractfile(member).read()
            if len(content)!=row['bytes'] or digest(content)!=row['sha256']:raise ValueError('Source bytes mismatch')
            verified.append((member.name,content,row['mode']))
    # Validate every member before creating anything. Explicit modes defeat umask drift.
    root.mkdir(mode=0o700);apply_mode(root,0o700)
    source=root/'source';source.mkdir(mode=0o755);apply_mode(source,0o755)
    written=[]
    for name,content,mode in verified:
        target=source/name
        for directory in reversed(target.parent.parents):
            if directory==source or directory.is_relative_to(source):
                if not directory.exists():directory.mkdir(mode=0o755)
                apply_mode(directory,0o755)
        if not target.parent.exists():target.parent.mkdir(mode=0o755)
        apply_mode(target.parent,0o755)
        with target.open('xb') as stream:stream.write(content)
        apply_mode(target,mode)
        if digest(target.read_bytes())!=expected[name]['sha256']:raise ValueError('Post-stage source bytes')
        written.append({'path':name,'sha256':digest(content),'bytes':len(content),'mode':mode})
    with (root/'candidate-source-manifest.json').open('x') as stream:json.dump(manifest,stream,indent=2);stream.write('\n')
    apply_mode(root/'candidate-source-manifest.json',0o600)
    return {'status':'STAGED_WITH_APPROVED_MODES','workspace':str(root),'attemptRootMode':0o700,'directoryMode':0o755,'files':written}

def main(request,workspace,policy_sha,manifest_sha,archive_sha):
    if sys.platform!='linux' or os.getuid()!=1000:raise ValueError('Approved Linux UID1000 required')
    if set(request)!={'policyJSON','manifestJSON','archiveBase64'}:raise ValueError('Unexpected staging inputs')
    policy_bytes=request['policyJSON'].encode();manifest_bytes=request['manifestJSON'].encode()
    if digest(policy_bytes)!=policy_sha or digest(manifest_bytes)!=manifest_sha:raise ValueError('Staging authority identity')
    data=base64.b64decode(request['archiveBase64'],validate=True)
    if digest(data)!=archive_sha:raise ValueError('Transfer identity')
    root=pathlib.Path(workspace)
    if shutil.disk_usage(root.parent).free<8*1024**3:raise ValueError('Insufficient unchanged 8 GiB build capacity')
    return stage_source(root,data,json.loads(manifest_bytes),json.loads(policy_bytes))
