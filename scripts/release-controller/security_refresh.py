"""One authenticated scan refresh for the existing settlement path only."""
import datetime,hashlib,json,pathlib,stat,sys
from runtime_context import active
AUTHORITY_SHA256=None

def require(ok,message):
    if not ok:raise ValueError(message)
def plain(path):
    p=pathlib.Path(path).absolute()
    for part in [*reversed(p.parents),p]:
        s=part.lstat()
        require(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400,'Linked refresh evidence')
    return p
def sha(p):
    with plain(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def pairs(rows):
    out={}
    for k,v in rows:
        require(k not in out,'Duplicate refresh JSON key');out[k]=v
    return out
def read(p):return json.loads(plain(p).read_text(encoding='utf-8-sig'),object_pairs_hook=pairs,
    parse_constant=lambda _:require(False,'Nonfinite refresh JSON'))
def authenticated(path,digest):
    require(sha(path)==digest,'Refresh evidence identity: '+str(path))
    return read(path)
def safe(root,name):
    require(type(name) is str and name and '\\' not in name and ':' not in name and not name.startswith('/') and
        all(p not in ('','.','..') for p in name.split('/')),'Unsafe refresh path')
    return plain(root/name)

def validate(C,root,w,now=None):
    """No output, transport or qualification dispatch. Reuse all strict validators."""
    descriptor=active().authority('securityRefresh')
    global AUTHORITY_SHA256
    AUTHORITY_SHA256=descriptor['sha256']
    a=authenticated(pathlib.Path(descriptor['path']),descriptor['sha256'])
    require(a['schemaVersion']==1 and a['scope']=='settlement-security-freshness-only','Refresh scope')
    require(str(plain(root))==a['originalRoot'] and root.name==a['parentExecutionID'],'Refresh parent identity')
    require(a['runID']==C['RUN'] and a['sourceManifestSHA256']==C['SOURCE'] and a['images']==C['IMAGES'],'Refresh approved identity')
    C['authenticate_helpers'](root)
    for name,digest in a['historicalReceipts'].items():
        require(sha(safe(root,name))==digest,'Historical refresh predecessor changed: '+name)
    # Original execution/completion records still must be genuine and complete.
    for name in ('scan','scan-acceptance','audit','acceptance'):C['completed'](root,name)
    fresh_manifest=authenticated(a['freshManifest']['path'],a['freshManifest']['sha256'])
    require(fresh_manifest['executionID']==a['refreshExecutionID'] and fresh_manifest['exitCode']==0,'Refresh execution failed')
    view=plain(a['viewRoot']);m=authenticated(a['viewManifest']['path'],a['viewManifest']['sha256'])
    require(m['root']==str(view),'Refresh view substitution')
    expected={}
    for row in m['files']:
        name=row['path'];require(name.casefold() not in {n.casefold() for n in expected},'Duplicate refresh inventory')
        p=safe(view,name);require(p.is_file() and sha(p)==row['sha256'] and p.stat().st_size==row['bytes'],'Refresh inventory changed: '+name)
        expected[name]=row['sha256']
    files=set()
    for p in view.rglob('*'):
        plain(p)
        require('__pycache__' not in p.parts and p.suffix.lower() not in ('.pyc','.pyo'),'Unapproved refresh bytecode')
        if p.is_file():files.add(p.relative_to(view).as_posix())
    require(files==set(expected),'Unexpected/missing refresh inventory')
    for row in fresh_manifest['files']:require(expected.get(row['path'])==row['sha256'],'Fresh scanner record substituted')
    require(sha(view/'accepted.json')==a['acceptedSHA256'],'Fresh acceptance substituted')
    q=w.inputs(view);original_q=C['read'](root/'data/qualification.json')
    expected_q={**original_q,'attemptID':a['refreshExecutionID'],'parentExecutionID':root.name}
    require(q==expected_q,'Refresh qualification lineage')
    context=read(view/'evidence-context.json')
    require(context['attemptID']==a['refreshExecutionID'] and context['runID']==C['RUN'] and
        context['sourceManifestSHA256']==C['SOURCE'],'Refresh scanner identity')
    require(read(view/'refresh-driver-exit.json')['exitCode']==0 and
        read(view/'scan-status.json')['phase']=='READY_FOR_LOCAL_SCHEMA_VALIDATION','Incomplete refresh execution')
    imported=read(view/'refresh-import-receipt.json')
    require(imported['parentExecutionID']==root.name and imported['executionID']==a['refreshExecutionID'] and
        imported['sourceManifestSHA256']==C['SOURCE'] and imported['originalEvidenceModified'] is False,'Refresh import lineage')
    original_inputs=C['read'](root/'fresh-inputs.json')
    require(imported['importedUnchangedFiles']=={n:h for n,h in original_inputs.items() if n not in ('source-secret-binding.json','source-secrets.json')},'Refresh imported inputs changed')
    require(all(expected[n]==h for n,h in original_inputs.items() if n not in
        ('qualification.json','execution-inputs.json','source-secret-binding.json','source-secrets.json')),'Refresh frozen input changed')
    # All helper bytes and origins have been authenticated before dependency imports.
    w.schema_environment()
    import qualification_evidence as qe
    require(sha(qe.__file__)==active().code_hash('qualification_evidence.py') and pathlib.Path(qe.__file__).parent == pathlib.Path(__file__).absolute().parent,'Refresh validator origin')
    now=now or datetime.datetime.now(datetime.timezone.utc)
    database=(view/'trivy-cache/db/trivy.db').read_bytes()
    for point in ('start','end'):qe.database_valid(read(view/('scanner-db-'+point+'.json'))['metadata'],database,context,now)
    for kind in ('builder','runtime'):
        require(context['images'][kind]['imageID']==C['IMAGES'][kind],'Refresh image substitution')
        r=read(view/(kind+'-scan-receipt.json'))
        require(r['attemptID']==a['refreshExecutionID'],'Refresh receipt execution')
        qe.bind_receipt((view/(kind+'-raw-scan.json')).read_bytes(),r,context,kind,'reportSHA256',now)
    r=read(view/'runtime-sbom-receipt.json')
    require(r['attemptID']==a['refreshExecutionID'],'Refresh SBOM execution')
    qe.bind_receipt((view/'runtime-sbom.cdx.json').read_bytes(),r,context,'runtime','sbomSHA256',now)
    for name in C['SCAN_LOGS']:
        r=read(view/(name+'.exit.json'))
        require(r.get('attemptID')==a['refreshExecutionID'] and r.get('runID')==C['RUN'] and
            r.get('sourceManifestSHA256')==C['SOURCE'] and type(r.get('exitCode')) is int and r['exitCode']==0 and
            r.get('error') is None,'Refresh scanner process failed: '+name)
        require(r['stdoutSHA256']==expected[name] and r['stderrSHA256']==expected[name+'.stderr'],'Refresh diagnostics changed')
    # Fresh role-specific applicability decision, never a cached passed flag.
    dispositions = {kind: qe.builder_applicability((view/(kind+'-raw-scan.json')).read_bytes(), context, kind, view, now)
                    for kind in ('builder','runtime')}
    # Existing full schema/archive/package/SBOM/filesystem/source-secret/npm gates.
    accepted=w.verify_acceptance(view)
    proof={'scope':a['scope'],'originalExecutionID':root.name,'refreshExecutionID':a['refreshExecutionID'],
        'qualificationRunID':C['RUN'],'sourceManifestSHA256':C['SOURCE'],'images':C['IMAGES'],
        'authoritySHA256':AUTHORITY_SHA256,'viewManifest':a['viewManifest'],'acceptedSHA256':a['acceptedSHA256'],
        'databaseSHA256':accepted['databaseSHA256'],'historicalReceipts':a['historicalReceipts'],
        'historicalFailuresPreserved':True,'historicalCompletionRecordsRewritten':False,'builderApplicability':dispositions['builder']}
    return {'accepted':accepted,'proof':proof}
