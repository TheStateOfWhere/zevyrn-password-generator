"""Fresh retained-image adapter; original build qualification identity is preserved.

prepare/verify are local and read-only for all parent inputs. All execution phases
require separate operator authorization; no build, pull or deployment API.
"""
from pathlib import Path
import argparse,datetime,hashlib,importlib.util,json,os,re,shutil,socket,subprocess,sys,time

from runtime_context import active,helper,authority_document,run_scanner
HERE=Path(__file__).absolute().parent
SETTLEMENT_POLICY=None
SETTLEMENT_POLICY_SHA256=None
SETTLEMENT_LINK=HERE/'settlement_link.py'
SETTLEMENT_LINK_SHA256=None

def configure():
    global RUN,SOURCE,PARENT,COLLECTOR,IMAGES,RUNTIME_PACKAGES,SETTLEMENT_POLICY,SETTLEMENT_POLICY_SHA256,SETTLEMENT_LINK_SHA256
    ctx=active();profile=ctx.profile();b=profile['bindings']
    RUN=b['runID'];SOURCE=b['sourceManifestSHA256'];PARENT=b['parentManifestSHA256']
    IMAGES=b['images'];RUNTIME_PACKAGES=b['runtimePackages'];COLLECTOR=ctx.code_hash('workflow.py')
    if 'settlement' in profile['records']:
        item=ctx.authority('settlement');SETTLEMENT_POLICY=Path(item['path']);SETTLEMENT_POLICY_SHA256=item['sha256']
    SETTLEMENT_LINK_SHA256=ctx.code_hash('settlement_link.py')

def settlement_link():
    import stat
    for p in [*reversed(SETTLEMENT_LINK.absolute().parents),SETTLEMENT_LINK.absolute()]:
        info=p.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'Linked settlement module')
    data=SETTLEMENT_LINK.read_bytes()
    require(hashlib.sha256(data).hexdigest()==SETTLEMENT_LINK_SHA256,'Settlement module identity')
    scope={'__file__':str(SETTLEMENT_LINK),'__name__':'authenticated_settlement_link'}
    exec(compile(data,str(SETTLEMENT_LINK),'exec'),scope)
    return scope

RUN=None
SOURCE=None
PARENT=None
COLLECTOR=None
IMAGES=None
HISTORY=('remote-evidence/npm-audit-summary.json','extra-security-client-exit.json','extra-security-ssh.log')
CONTROLLER=('continuation.py','workflow.py','browser-acceptance.mjs','scan-images.py')
SEALS=('continuation.json','parent-evidence-manifest.json','imported-evidence.json','controller-identities.json','production-assets.json','fresh-inputs.json','history-manifest.json','attempt-plan.json','python-execution-boundary.json')
NEW_DATA={'npm-audit-capture.json','npm-audit.stderr.log','npm-audit-exit.json','npm-audit.json','npm-audit-summary.json','npm-audit-binding.json','accepted.json'}
ORDER=('preflight','scan','scan-acceptance','reuse','audit','acceptance','runtime-creation','runtime-collection','runtime-removal','browser-creation','browser-collection','browser-testing','browser-removal','settlement','final')
PREDECESSORS={name:ORDER[:i] for i,name in enumerate(ORDER)}
RUNTIME_PACKAGES=None

def artifacts(name):
    if name=='preflight':return ['live-preflight.json','execution-workloads-before.json','execution-resources-before.json']
    if name=='scan':return ['scan-driver.stdout.log','scan-driver.stderr.log','scan-driver-exit.json']+['data/'+n for n in scan_files()]
    if name=='scan-acceptance':return ['scan-acceptance.json']
    if name=='reuse':return ['reuse-acceptance.json','compose-executable.json','compose-evidence.json']
    if name=='audit':return ['data/'+n for n in ('npm-audit-capture.json','npm-audit.stderr.log','npm-audit-exit.json','npm-audit.json','npm-audit-summary.json','npm-audit-binding.json')]+['execution-workloads-before.json','execution-resources-before.json','audit-workloads-after.json','audit-resources-after.json']
    if name=='acceptance':return ['data/accepted.json']
    if name.endswith('-creation'):
        kind=name.split('-')[0];return [kind+'-created'+x for x in ('.cid','.stdout.log','.stderr.log','-exit.json')]
    if name.endswith('-collection'):
        kind=name.split('-')[0];return [kind+'-'+n for n in ('inspect.json','checks.json','health-stdout.log','health-stderr.log','packages-stdout.log','packages-stderr.log','packages-exit.json','container-stdout.log','container-stderr.log')]
    if name.endswith('-removal'):return [name.split('-')[0]+'-created.cid']
    return {'browser-testing':['browser-results.json','browser-launcher.stdout.log','browser-launcher.stderr.log','browser-launcher-exit.json'],'settlement':['settled.json','browser-evidence-integration.json','security-evidence-integration.json'],'final':['consolidated-qualification.json']}[name]

def completed(root,name):
    require((root/(name+'-completed.json')).is_file(),'Required predecessor incomplete: '+name)
    try:
        a=read(root/(name+'-attempt.json'));r=read(root/(name+'-completed.json'))
        require(all(v.get('executionID')==root.name and v.get('qualificationRunID')==RUN and v.get('sourceManifestSHA256')==SOURCE and v.get('images')==IMAGES for v in (a,r)),'Wrong predecessor identity: '+name)
        require(a['startedUTC']==r['startedUTC'] and datetime.datetime.fromisoformat(r['finishedUTC'])>=datetime.datetime.fromisoformat(a['startedUTC']),'Invalid predecessor interval: '+name)
        require(set(r['artifacts'])==set(artifacts(name)),'Incomplete predecessor evidence: '+name)
        for n,h in r['artifacts'].items():require(sha(safe(root,n))==h,'Predecessor evidence changed: '+name+'/'+n)
    except (KeyError,TypeError,json.JSONDecodeError,FileNotFoundError) as error:raise ValueError('Partial predecessor evidence: '+name) from error
    return r

def progress(root,name,cleanup=False):
    if name in ('settlement','final') and not cleanup:
        # Reject unrelated failures and missing ordinary predecessors before any
        # supplemental contract load. Only its exact browser gate may differ.
        failures={p.name for p in root.glob('*-failed.json')}
        require(not failures-{'browser-testing-failed.json'},'Continuation blocked by failed phase')
        for predecessor in PREDECESSORS[name]:
            if predecessor not in ('browser-testing','settlement'):completed(root,predecessor)
        return settlement_link()['progress'](globals(),root,name)
    require(name in ORDER,'Unknown continuation phase')
    if cleanup:return # Ownership/integrity checks still apply; no freshness gate on removal.
    failures=list(root.glob('*-failed.json'));require(not failures,'Continuation blocked by failed phase: '+(failures[0].stem if failures else ''))
    for p in root.glob('*-attempt.json'):
        phase_name=p.name[:-len('-attempt.json')]
        require(phase_name in ORDER,'Unexpected phase attempt')
        completed(root,phase_name) # An interrupted or partial attempt blocks all new work.
    for predecessor in PREDECESSORS[name]:completed(root,predecessor)


def refreshed_security(root,w=None,now=None):
    p=HERE/'security_refresh.py'
    for part in [p,*p.parents]:plain_entry(part)
    data=p.read_bytes();require(hashlib.sha256(data).hexdigest()==active().code_hash('security_refresh.py'),'Reviewed security refresh identity')
    scope={'__file__':str(p),'__name__':'authenticated_settlement_security_refresh'}
    exec(compile(data,str(p),'exec'),scope)
    return scope['validate'](globals(),root,w or workflow(),now)

def fresh_security(root,now=None,*,settlement=False):
    if settlement:return refreshed_security(root,now=now)
    authenticate_helpers(root)
    data=root/'data';import qualification_evidence as qe
    context=read(data/'evidence-context.json')
    require(context.get('attemptID')==root.name,'Scan attempt substitution')
    start=datetime.datetime.fromisoformat(read(root/'scan-attempt.json')['startedUTC'])
    require(datetime.datetime.fromisoformat(context['startedUTC'])>=start,'Historical scan replay')
    database=(data/'trivy-cache/db/trivy.db').read_bytes();now=now or datetime.datetime.now(datetime.timezone.utc)
    for point in ('start','end'):qe.database_valid(read(data/('scanner-db-'+point+'.json'))['metadata'],database,context,now)
    for kind in ('builder','runtime'):
        receipt=read(data/(kind+'-scan-receipt.json'));require(receipt.get('attemptID')==root.name,'Scan receipt attempt substitution')
        qe.bind_receipt((data/(kind+'-raw-scan.json')).read_bytes(),receipt,context,kind,'reportSHA256',now)
    receipt=read(data/'runtime-sbom-receipt.json');require(receipt.get('attemptID')==root.name,'SBOM attempt substitution')
    qe.bind_receipt((data/'runtime-sbom.cdx.json').read_bytes(),receipt,context,'runtime','sbomSHA256',now)

def guard(root,name,docker=False):
    ctx=active();ctx.require_execution(root)
    ctx.require_phase('settlement' if name in ('settlement','final') else 'readiness' if name=='preflight' else 'native-linux-execution')
    w=verify(root);progress(root,name)
    if name in ('settlement','final'):settlement_output_capacity(root)
    if docker and sys.platform=='win32':require(name in ('settlement','final'),'Read-only settlement transport profile required')
    if name not in ('preflight','scan'):
        fresh_security(root,settlement=name in ('settlement','final'))
        if name!='scan-acceptance':completed(root,'scan-acceptance');strict_scans(root,settlement=name in ('settlement','final'))
    if name in ORDER[ORDER.index('acceptance'):]:
        completed(root,'audit');w.audit_evidence(root/'data')
        if name!='acceptance':bound_acceptance(root,w,settlement=name in ('settlement','final'))
    if docker:live(w)
    return w

def settlement_output_capacity(root):
    # Only local JSON output remains. Archives are read in place, never extracted.
    ctx=settlement_link()['context'](globals(),root)
    bound={p.relative_to(root).as_posix():'f'*64 for p in root.rglob('*') if p.is_file()}
    encoded=lambda value:len(json.dumps(value,indent=2,ensure_ascii=True).encode('utf-8'))
    # Two inventory encodings, four proof envelopes and 64 KiB for the fixed
    # receipt fields/hash maps of nine JSON files; write errors still fail closed.
    required=2*encoded(bound)+4*encoded(ctx['proof'])+65536
    available=shutil.disk_usage(ctx['output'].parent).free
    require(available>=required,'Insufficient settlement output capacity')
    return {'filesystemPath':str(ctx['output'].parent),'requiredBytes':required,'availableBytes':available,
            'remoteScratchRequiredBytes':0,'archiveExtraction':False}

def require(ok,message):
    if not ok:raise ValueError(message)
def sha(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def save(p,data):
    with Path(p).open('x',encoding='utf-8',newline='\n') as f:json.dump(data,f,indent=2,allow_nan=False);f.write('\n')
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def safe(root,name):
    require(isinstance(name,str) and name and '\\' not in name and ':' not in name and not name.startswith('/') and all(x not in ('','.','..') for x in name.split('/')),'Unsafe evidence path')
    p=root/name
    require(p.resolve().is_relative_to(root.resolve()) and all(not q.is_symlink() for q in [p,*p.parents] if q!=root.parent),'Linked/escaping evidence path')
    return p
def execution_id(value):
    require(isinstance(value,str) and value==Path(active().profile()['executionRoot']).name and re.fullmatch(r'[A-Za-z0-9-]+',value),'Invalid continuation execution identity')
    return value
def excluded(name):
    return name=='npm-audit-summary.json' or name in ('workloads-before.json','resources-before.json') or name.startswith(('workloads-after-','resources-after-'))
def parent_rows(manifest):
    require(sha(manifest)==PARENT,'Parent evidence manifest identity mismatch')
    rows=read(manifest)['files'];result={}
    for row in rows:
        name=row['path'];require(name not in result,'Duplicate parent evidence path');safe(manifest.parent,name);result[name]=row
    require(len(result)==805,'Incomplete parent evidence inventory')
    return result
def workflow():
    authenticate_controller()
    w=helper('workflow');w.configure()
    if sys.platform=='win32':
        boundary=[]
        def transport():
            if not boundary:boundary.append(helper('dk02_transport').Transport())
            return boundary[0]
        w.host=lambda:transport().host()
        w.execute=lambda *a,**kw:transport().execute_readonly(*a,**kw)
        w.readonly_capacity=lambda:transport().probe()['capacity']
    return w

def historical_contract(data,w):
    q=w.inputs(data)
    require(q.get('runID')==RUN and q.get('sourceManifestSHA256')==SOURCE,'Original qualification/source identity mismatch')
    require(q.get('expectedDaemonID')==w.DAEMON,'Original daemon identity mismatch')
    builds=read(data/'builds.json');context=read(data/'evidence-context.json')
    require(context.get('runID')==RUN and context.get('sourceManifestSHA256')==SOURCE,'Historical scan context mismatch')
    for kind,identity in IMAGES.items():
        require(builds[kind]['image']['id']==identity,'Retained image identity mismatch: '+kind)
        require(sha(safe(data,builds[kind]['archive']))==builds[kind]['archiveSHA256'],'Historical export changed: '+kind)
        if kind=='rootfs':continue
        require(context['images'][kind]=={'imageID':identity,'archiveSHA256':builds[kind]['archiveSHA256']},'Historical image/source binding mismatch')
        receipt=read(data/(kind+'-scan-receipt.json'))
        require(receipt['runID']==RUN and receipt['sourceManifestSHA256']==SOURCE and receipt['imageID']==identity
                and receipt['archiveSHA256']==builds[kind]['archiveSHA256'] and receipt['reportSHA256']==sha(data/(kind+'-raw-scan.json')),'Historical scan receipt mismatch')
    summary=read(data/'compose-validation-v2/summary.json');checks=list((data/'compose-validation-v2').glob('*/check-*.json'))
    cases=list((data/'compose-validation-v2').glob('*/result.json'))
    require(summary.get('passed') is True and summary.get('runID')==RUN and summary.get('sourceManifestSHA256')==SOURCE
            and summary.get('caseCount')==len(cases)==53 and len(checks)==271,'Missing mandatory Compose evidence')
    require(all(read(p).get('passed') is True for p in checks) and all(read(p).get('status')=='PASS' for p in cases),'Historical Compose failure')
    counts=read(data/'scan-binding-and-counts.json')
    require(all(counts[k]['counts']['HIGH']==counts[k]['counts']['CRITICAL']==counts[k]['secrets']==0 for k in ('builder','runtime')),'Historical security gate did not pass')
    require(read(data/'filesystem-equivalence.json').get('passed') is True,'Missing filesystem relationship evidence')
    source=read(data/'source-secret-binding.json')
    require(source['sourceManifestSHA256']==SOURCE and source['reportSHA256']==sha(data/'source-secrets.json') and source['scannerExitCode']==0,'Historical source-secret binding mismatch')
    w.validate_source_report(read(data/'source-secrets.json'),source['sourceArtifactName'])
    receipt=read(data/'runtime-sbom-receipt.json')
    require(receipt['runID']==RUN and receipt['sourceManifestSHA256']==SOURCE and receipt['imageID']==IMAGES['runtime']
            and receipt['sbomSHA256']==sha(data/'runtime-sbom.cdx.json') and receipt['sourceReportSHA256']==sha(data/'runtime-raw-scan.json'),'Historical SBOM generation binding mismatch')
    # Generation is authenticated here; schema/package acceptance remains pending.
    return q

def prepare(parent,root):
    parent=parent.resolve();root=root.resolve();execution_id(root.name)
    require(root.parent==Path(active().profile()['executionRoot']).parent and not root.exists(),'Reused or unexpected attempt output path')
    rows=parent_rows(parent/'final-evidence-inventory.json')
    for name,row in rows.items():require(sha(safe(parent,name))==row['sha256'],'Altered historical evidence: '+name)
    w=workflow();historical_contract(parent/'remote-evidence',w)
    require(read(parent/'build-client-exit.json')['exitCode']==read(parent/'scan-client-exit.json')['exitCode']==0,'Earlier successful receipt missing')
    root.mkdir(mode=0o700);(root/'data').mkdir();(root/'history').mkdir()
    history={}
    for name,row in rows.items():
        dest=safe(root/'history',name);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(parent/name,dest);history[name]=row['sha256']
    shutil.copyfile(parent/'final-evidence-inventory.json',root/'parent-evidence-manifest.json')
    failed=Path(active().authority('failedContinuation')['path']).parent
    require(sha(failed/'final-evidence-inventory.json')==active().authority('failedContinuation')['sha256'],'Failed continuation manifest changed')
    for name in ('final-evidence-inventory.json','qualification-dk02-20261019-02-continuation-01/runtime-collection-failed.json'):
        dest=root/'history'/'failed-continuation'/Path(name).name;dest.parent.mkdir(exist_ok=True);shutil.copyfile(failed/name,dest)
        history[dest.relative_to(root/'history').as_posix()]=sha(dest)
    save(root/'history-manifest.json',history)
    original=root/'history/remote-evidence'
    keep={'source-manifest.json','qualification.json','helpers.json','execution-inputs.json','Dockerfile.runtime','Dockerfile.final','builds.json',
      'builder.tar','rootfs.tar','runtime.tar','filesystem-equivalence.json','source-secrets.json','source-secret-binding.json'}|set(read(original/'helpers.json'))
    for p in original.rglob('*'):
        if p.is_file() and (p.relative_to(original).as_posix() in keep or p.relative_to(original).as_posix().startswith('source/')):
            dest=root/'data'/p.relative_to(original);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
    for name in w.HELPERS:shutil.copyfile(w.helper_path(name),root/'data'/name)
    q=read(root/'data/qualification.json');q['attemptID']=root.name
    (root/'data/qualification.json').write_text(json.dumps(q,indent=2)+'\n')
    helpers={n:sha(w.helper_path(n)) for n in w.HELPERS}
    (root/'data/helpers.json').write_text(json.dumps(helpers,indent=2)+'\n')
    inputs=read(root/'data/execution-inputs.json')
    for name in ('qualification.json','helpers.json'):inputs[name]=sha(root/'data'/name)
    (root/'data/execution-inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
    save(root/'fresh-inputs.json',{p.relative_to(root/'data').as_posix():sha(p) for p in (root/'data').rglob('*') if p.is_file()})
    save(root/'imported-evidence.json',{'originalManifestSHA256':PARENT,'historicalFiles':len(rows),'activeInputsOnly':True})
    save(root/'continuation.json',{'executionID':root.name,'qualificationRunID':RUN,'sourceManifestSHA256':SOURCE,'images':IMAGES,
      'parentManifestSHA256':PARENT,'collectorSHA256':COLLECTOR,'preparedUTC':utc(),'historicalFailuresRemainFailed':True})
    save(root/'controller-identities.json',{n:sha(HERE/n) for n in CONTROLLER})
    from filesystem_equivalence import filesystem
    build=read(root/'data/builds.json')['builder'];view=filesystem(root/'data'/build['archive'],IMAGES['builder'],build['archiveSHA256'])
    assets={n[len('app/dist/'):]:v['sha256'] for n,v in view['files'].items() if n.startswith('app/dist/') and v['type']=='file'}
    require(len(assets)==16,'Incomplete authenticated production assets');save(root/'production-assets.json',assets)
    save(root/'attempt-plan.json',{'executionID':root.name,'sequence':ORDER,'noBuild':True,'authorization':'PREPARATION ONLY',
      'reuse':{'application':'authenticated successful builder log, 169 pass/1 Docker CLI skip','assets':'recompute archive relationship and 16 hashes',
      'compose':'rerender 53/271; old executable binary digest unavailable','npm':'fresh audit; old zero-advisory evidence remains historical',
      'SBOM':'fresh report-bound generation plus full schema acceptance','packages':'fresh scanner reconciliation plus approved live APK collector'},
      'oldDatabase':'EXPIRED: never imported into active scan paths','automaticRetry':False})
    save(root/'preparation-seal.json',{n:sha(root/n) for n in SEALS});verify(root)
    return {'prepared':root.name,'qualificationRunID':RUN,'qualificationExecuted':False,'activeInputFiles':len(read(root/'fresh-inputs.json'))}

def checked_execution_path(root):
    for p in (root.absolute(),*root.absolute().parents):plain_entry(p)
    require(root.is_dir(),'Execution path must be an existing directory')
    return root.resolve()

def verify(root):
    root=checked_execution_path(root);active().require_execution(root);execution_id(root.name)
    anchor=active().authority('executionBoundary')
    require(Path(anchor['path'])==root/'preparation-seal.json' and sha(root/'preparation-seal.json')==anchor['sha256'],'External preparation seal identity')
    seal=read(root/'preparation-seal.json');require(set(seal)==set(SEALS),'Incomplete preparation seal')
    for n,h in seal.items():require(sha(safe(root,n))==h,'Preparation input changed: '+n)
    plan=read(root/'continuation.json')
    require(plan['executionID']==root.name and plan['qualificationRunID']==RUN and plan['sourceManifestSHA256']==SOURCE and plan['images']==IMAGES,'Attempt identity substitution')
    collector=COLLECTOR
    if 'historicalController' in active().profile()['records']:
        item=active().authority('historicalController');require(sha(item['path'])==item['sha256'],'Historical controller authority')
        collector=read(item['path'])['files']['workflow.py']['sha256']
    require(plan['collectorSHA256']==collector and plan['parentManifestSHA256']==PARENT,'Attempt authority changed')
    identities=read(root/'controller-identities.json')
    if 'historicalController' in active().profile()['records']:
        # These bytes authenticate original records; they never become current imports.
        item=active().authority('historicalController');require(sha(item['path'])==item['sha256'],'Historical controller authority')
        history_code=read(item['path'])
        require(identities=={n:r['sha256'] for n,r in history_code['files'].items()},'Incomplete historical controller identities')
        for n,h in identities.items():require(sha(history_code['files'][n]['path'])==h,'Historical controller changed: '+n)
    else:
        require(set(identities)==set(CONTROLLER),'Incomplete controller identities')
        for n,h in identities.items():require(sha(HERE/n)==h,'Controller changed: '+n)
    rows=parent_rows(root/'parent-evidence-manifest.json');history=read(root/'history-manifest.json')
    require(set(rows)<=set(history),'Incomplete historical evidence')
    for n,row in rows.items():require(history[n]==row['sha256'],'Unbound historical evidence')
    for n,h in history.items():require(sha(safe(root/'history',n))==h,'Historical evidence changed: '+n)
    inputs=read(root/'fresh-inputs.json')
    for n,h in inputs.items():require(sha(safe(root/'data',n))==h,'Fresh input changed: '+n)
    require(not {'runtime-raw-scan.json','evidence-context.json','runtime-sbom.cdx.json','accepted.json','npm-audit.json'}&set(inputs),'Historical output imported as new evidence')
    authenticate_helpers(root)
    w=workflow();q=w.inputs(root/'data')
    require(q.get('runID')==RUN and q.get('attemptID')==root.name and q.get('sourceManifestSHA256')==SOURCE,'Fresh source/attempt binding mismatch')
    original=root/'history/remote-evidence';old=read(original/'helpers.json');new=read(root/'data/helpers.json')
    require(set(old)==set(new),'Security validator substitution')
    if 'historicalController' not in active().profile()['records']:
        for n,h in new.items():
            path=w.helper_path(n);key=path.relative_to(HERE.parents[1]).as_posix()
            require(h==active().catalog['files'][key],'Security validator substitution')
        require(new['scan-images.py']==sha(HERE/'scan-images.py'),'Scanner entrypoint changed')
    # Historical helper bytes remain sealed evidence. All execution imports use
    # the current authenticated canonical source catalog, never root/data.
    builds=read(root/'data/builds.json')
    for k,i in IMAGES.items():require(builds[k]['image']['id']==i,'Retained image substitution')
    if (root/'compose-evidence.json').exists():
        for n,h in read(root/'compose-evidence.json').items():require(sha(safe(root,n))==h,'Compose evidence changed: '+n)
    return w

def retained_images(w,lookup):
    for kind,identity in IMAGES.items():
        if kind=='rootfs':continue
        values=lookup(identity)
        require(isinstance(values,list) and len(values)==1 and values[0]['Id']==identity,'Missing or mismatched retained image: '+kind)
        labels=values[0]['Config'].get('Labels') or {}
        require(labels.get('io.zevyrn.source-manifest-sha256')==SOURCE,'Live image source mismatch')
        if kind=='runtime':require(labels.get('io.zevyrn.builder-image-id')==IMAGES['builder'],'Live runtime builder mismatch')

def live(w):
    w.host();retained_images(w,lambda i:json.loads(w.execute(w.DOCKER+['image','inspect',i])))

def phase(root,name,action,cleanup=False):
    ctx=active();ctx.require_execution(root)
    ctx.require_phase('settlement' if name in ('settlement','final') else 'readiness' if name=='preflight' else 'native-linux-execution')
    if name in ('settlement','final') and not cleanup:
        return settlement_link()['phase'](globals(),root,name,action)
    # No retry: preserve an attempt even if a validator or diagnostic write fails.
    progress(root,name,cleanup=cleanup)
    start=utc();identity={'executionID':root.name,'qualificationRunID':RUN,'sourceManifestSHA256':SOURCE,'images':IMAGES,'startedUTC':start}
    save(root/(name+'-attempt.json'),{**identity,'ownerPID':os.getpid()})
    try:result=action()
    except BaseException as error:
        save(root/(name+'-failed.json'),{'executionID':root.name,'exception':type(error).__name__,'message':str(error),'utc':utc()});raise
    save(root/(name+'-completed.json'),{**identity,'finishedUTC':utc(),'result':result,'artifacts':{n:sha(safe(root,n)) for n in artifacts(name)}})
    return result

def audit(root):
    w=guard(root,'audit',docker=True);data=root/'data'
    before=w.snapshot();resources=resource_snapshot(w);w.capacity(root)
    w.application_ready(before)
    require(before==read(root/'execution-workloads-before.json') and resources==read(root/'execution-resources-before.json'),'Workloads changed since preflight')
    def run():
        try:return w.audit_builder(data)
        finally:
            after=w.snapshot();after_resources=resource_snapshot(w)
            save(root/'audit-workloads-after.json',after);save(root/'audit-resources-after.json',after_resources)
            require(before==after and resources==after_resources,'Workload preservation failure')
    return phase(root,'audit',run)

def accept(root):
    w=guard(root,'acceptance')
    def run():
        result=w.accept(root/'data');w.verify_acceptance(root/'data')
        return {**result,'acceptedFileSHA256':sha(root/'data/accepted.json')}
    return phase(root,'acceptance',run)

def bound_acceptance(root,w,*,settlement=False):
    authenticate_helpers(root)
    # Linux runtime collection consumes the trusted Windows acceptance decision;
    # all source/report/export/DB bytes and npm evidence are checked again.
    require((root/'acceptance-completed.json').is_file(),'Schema/image acceptance gate incomplete')
    completed=read(root/'acceptance-completed.json')
    require(completed.get('executionID')==root.name and completed.get('qualificationRunID')==RUN
            and completed.get('result',{}).get('acceptedFileSHA256')==sha(root/'data/accepted.json'),'Schema acceptance receipt changed')
    a=read(root/'data/accepted.json');require(a['passed'] is True and a['runID']==RUN and a['sourceManifestSHA256']==SOURCE and a['runtimeImageID']==IMAGES['runtime'],'Accepted identity mismatch')
    for name,digest in a['boundFiles'].items():require(sha(safe(root/'data',name))==digest,'Accepted evidence changed: '+name)
    w.extra_security(root/'data',a)
    if settlement:return refreshed_security(root,w)['accepted']
    import qualification_evidence as qe
    context=read(root/'data/evidence-context.json');db=root/'data/trivy-cache/db/trivy.db'
    qe.database_valid(read(root/'data/scanner-db-end.json')['metadata'],db.read_bytes(),context,datetime.datetime.now(datetime.timezone.utc))
    return a

def container_contract(info,execution,kind):
    expected='zevyrn-'+execution+'-'+kind
    require(info['Image']==IMAGES['runtime'] and info['Name']=='/'+expected and info['Config']['Labels'].get('org.zevyrn.qualification')==execution,'Unowned runtime container')
    c=info['Config'];h=info['HostConfig'];require(c['User']=='10001:10001' and h['ReadonlyRootfs'] and not h['Privileged'] and h['CapDrop']==['ALL'] and not h.get('CapAdd'),'Runtime privilege mismatch')
    require('no-new-privileges:true' in h['SecurityOpt'] and h['Memory']==134217728 and h['NanoCpus']==1000000000 and h['PidsLimit']==128,'Runtime hardening mismatch')
    require(c['Labels'].get('traefik.enable')==c['Labels'].get('com.centurylinklabs.watchtower.enable')=='false','Runtime discovery enabled')
    require(set(c['ExposedPorts'])=={'8080/tcp'} and set(h.get('Tmpfs') or {})=={'/tmp'} and not (h.get('Binds') or h.get('Mounts')),'Runtime mount/port mismatch')
    options=h['Tmpfs']['/tmp'].split(',');require(all(v in options for v in ('rw','noexec','nosuid','size=16m','mode=1777')),'Runtime tmpfs hardening mismatch')
    require(info['State']['Running'] and info['State']['Health']['Status']=='healthy','Runtime not healthy')
    if kind=='runtime':require(h['NetworkMode']=='none' and not h.get('PortBindings'),'Runtime isolation mismatch')
    else:
        bindings=h.get('PortBindings') or {};require(h['NetworkMode']=='bridge' and set(bindings)=={'8080/tcp'} and len(bindings['8080/tcp'])==1 and bindings['8080/tcp'][0]['HostIp']=='127.0.0.1','Browser port is not loopback-only')

def installed_apk_records(raw):
    # Same P/V and identity-field rules as the reviewed archive inventory.
    # File metadata fields may repeat; identity fields and package names may not.
    require(type(raw) is bytes and bool(raw),'Empty installed APK database')
    require(raw.endswith(b'\n\n'),'Truncated installed APK database')
    require(not any(x<32 and x not in (9,10) or x==127 for x in raw),'Malformed APK database control character')
    text=raw.decode('utf-8',errors='strict');result={}
    for stanza in text[:-2].split('\n\n'):
        require(bool(stanza),'Empty APK database record');fields={}
        for line in stanza.split('\n'):
            require(re.match(r'^[A-Za-z]:',line) is not None,'Malformed APK record field')
            key,value=line[0],line[2:]
            require(not (key in 'PVAo' and key in fields),'Duplicate APK identity field')
            fields.setdefault(key,value)
        name,version=fields.get('P'),fields.get('V')
        require(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]*',name) is not None,'Invalid APK package name')
        require(isinstance(version,str) and re.fullmatch(r'[0-9][A-Za-z0-9+_.~:-]*',version) is not None,'Missing or malformed APK package version')
        require(bool(fields.get('A')) and bool(fields.get('o')),'Incomplete APK identity metadata')
        require(name not in result,'Duplicate or conflicting APK package identity')
        result[name]={'version':version,'origin':fields['o'],'architecture':fields['A']}
    return result

def runtime_package_expectation(root):
    authenticate_helpers(root)
    # Reuse the authenticated export/whiteout/filesystem resolver. Do not create
    # another archive parser or derive installed versions from repository indexes.
    data=root/'data';build=read(data/'builds.json')['runtime'];inventory=read(data/'runtime-installed-packages.json');accepted=read(data/'accepted.json')
    require(build['image']['id']==inventory['imageID']==accepted['runtimeImageID']==accepted['images']['runtime']['imageID']==IMAGES['runtime'],'Runtime package image identity mismatch')
    require(accepted.get('passed') is True and accepted['results']['runtime'].get('passed') is True,'Runtime package acceptance prerequisite failed')
    require(accepted['sourceManifestSHA256']==SOURCE,'Runtime package source identity mismatch')
    require(build['archiveSHA256']==inventory['archiveSHA256']==accepted['images']['runtime']['archiveSHA256'],'Runtime package archive binding mismatch')
    from filesystem_equivalence import filesystem
    view=filesystem(safe(data,build['archive']),IMAGES['runtime'],build['archiveSHA256'])
    require(view['identityChain']==inventory['identityChain'],'Runtime package export identity changed')
    for parent in ('lib','lib/apk','lib/apk/db'):require(view['files'].get(parent,{}).get('type')=='directory','Unsafe APK database ancestor')
    db=view['files'].get('lib/apk/db/installed',{})
    require(db.get('type')=='file' and type(db.get('size')) is int and db['size']>0 and re.fullmatch('[0-9a-f]{64}',db.get('sha256','')) is not None,'Missing or invalid installed APK database')
    packages={}
    require(type(inventory.get('packages')) is list and bool(inventory['packages']),'Missing installed package inventory')
    for row in inventory['packages']:
        require(type(row) is dict and isinstance(row.get('name'),str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]*',row['name']) is not None and isinstance(row.get('version'),str) and re.fullmatch(r'[0-9][A-Za-z0-9+_.~:-]*',row['version']) is not None,'Malformed installed package inventory')
        require(row['name'] not in packages,'Duplicate installed package inventory');packages[row['name']]=row['version']
    require(packages==accepted['results']['runtime']['packages'],'Incomplete installed package reconciliation')
    for name,version in RUNTIME_PACKAGES.items():require(packages.get(name)==version,'Required runtime package mismatch: '+name)
    return {'imageID':IMAGES['runtime'],'sourceManifestSHA256':SOURCE,'archiveSHA256':build['archiveSHA256'],'databaseSHA256':db['sha256'],'databaseSize':db['size'],'packages':packages}

def runtime_package_script():
    return 'test "$(id -u):$(id -g)" = 10001:10001; for p in /lib /lib/apk /lib/apk/db /lib/apk/db/installed; do test ! -L "$p"; done; test -f /lib/apk/db/installed; test -r /lib/apk/db/installed; if command -v node || command -v npm || test -d /app/node_modules; then exit 43; fi; exec /bin/cat /lib/apk/db/installed'

def validate_runtime_package_output(stdout,stderr,exit_code,expected,image_id):
    require(image_id==expected['imageID']==IMAGES['runtime'] and expected['sourceManifestSHA256']==SOURCE,'Runtime package image/source identity mismatch')
    require(type(exit_code) is int and exit_code==0,'Runtime package command failed: '+str(exit_code))
    require(type(stderr) is bytes and stderr==b'','Unexpected runtime package diagnostics')
    records=installed_apk_records(stdout);packages={n:r['version'] for n,r in records.items()}
    for name,version in RUNTIME_PACKAGES.items():require(packages.get(name)==version,'Runtime package identity mismatch: '+name)
    require(records['libexpat']['origin']=='expat','Runtime Expat origin mismatch')
    require(packages==expected['packages'],'Incomplete runtime installed-package evidence')
    require(len(stdout)==expected['databaseSize'] and hashlib.sha256(stdout).hexdigest()==expected['databaseSHA256'],'Runtime installed database differs from authenticated image')
    return packages

def collect_runtime_packages(root,kind,w,cid,info):
    require(info['Image']==IMAGES['runtime'] and info['Id']==cid,'Runtime package container identity mismatch')
    expected=runtime_package_expectation(root);script=runtime_package_script()
    command=w.DOCKER+['exec',cid,'/bin/sh','-ec',script]
    stdout=stderr=b'';status=None;error=None
    try:
        result=subprocess.run(command,capture_output=True,timeout=30)
        stdout,stderr,status=result.stdout,result.stderr,result.returncode
    except BaseException as failure:
        error={'exception':type(failure).__name__,'message':str(failure)}
        if isinstance(failure,subprocess.TimeoutExpired):stdout,stderr=failure.stdout or b'',failure.stderr or b''
        raise
    finally:
        for channel,raw in [('stdout',stdout),('stderr',stderr)]:
            with (root/(kind+'-packages-'+channel+'.log')).open('xb') as f:f.write(raw)
        save(root/(kind+'-packages-exit.json'),{'exitCode':status,'error':error,'containerID':cid,'imageID':info['Image'],'sourceManifestSHA256':SOURCE,'archiveSHA256':expected['archiveSHA256'],'expectedDatabaseSHA256':expected['databaseSHA256'],'stdoutSHA256':hashlib.sha256(stdout).hexdigest(),'stderrSHA256':hashlib.sha256(stderr).hexdigest(),'scriptSHA256':hashlib.sha256(script.encode()).hexdigest()})
    packages=validate_runtime_package_output(stdout,stderr,status,expected,info['Image'])
    return {'installedPackages':packages,'packageDatabaseSHA256':expected['databaseSHA256'],'runtimeArchiveSHA256':expected['archiveSHA256'],'packageCommandExitCode':status}

def collect_runtime(root,cid,kind):
    w=guard(root,kind+'-collection',docker=True)
    require(re.fullmatch('[0-9a-f]{64}',cid) is not None,'Full container identity required')
    require((root/(kind+'-created.cid')).read_text().strip()==cid,'Collection container identity substitution')
    def run():
        deadline=time.monotonic()+120
        while True:
            inspected=subprocess.run(w.DOCKER+['inspect',cid],capture_output=True,timeout=10)
            require(inspected.returncode==0,'Container inspection failed')
            info=json.loads(inspected.stdout)[0]
            if info['State'].get('Health',{}).get('Status')=='healthy':break
            require(info['State']['Running'] and info['State'].get('Health',{}).get('Status')!='unhealthy','Runtime startup failed')
            if time.monotonic()>=deadline:raise TimeoutError('Runtime health deadline expired')
            time.sleep(1)
        container_contract(info,root.name,kind)
        require(info['Id']==cid,'Inspected container identity substitution')
        health=subprocess.run(w.DOCKER+['exec',cid,'wget','-S','-O','-','http://127.0.0.1:8080/healthz'],capture_output=True)
        for name,value in [('health-stdout',health.stdout),('health-stderr',health.stderr)]:
            with (root/(kind+'-'+name+'.log')).open('xb') as f:f.write(value)
        require(health.returncode==0 and b'HTTP/1.1 200 OK' in health.stderr,'Runtime HTTP health failed')
        packages=collect_runtime_packages(root,kind,w,cid,info)
        save(root/(kind+'-inspect.json'),info);save(root/(kind+'-checks.json'),{'containerID':cid,'imageID':IMAGES['runtime'],'executionID':root.name,'healthExitCode':health.returncode,**packages})
        logs=subprocess.run(w.DOCKER+['logs',cid],capture_output=True)
        for channel,value in [('stdout',logs.stdout),('stderr',logs.stderr)]:
            with (root/(kind+'-container-'+channel+'.log')).open('xb') as f:f.write(value)
        require(logs.returncode==0 and not re.search(rb'\[(emerg|alert|crit|error)\]',logs.stdout+logs.stderr),'Unexpected runtime errors')
        return {'containerID':cid,'imageID':IMAGES['runtime'],'kind':kind}
    return phase(root,kind+'-collection',run)

def settled(root):
    w=guard(root,'settlement',docker=True)
    def run():
        before=read(root/'execution-workloads-before.json');resources=read(root/'execution-resources-before.json')
        after=w.snapshot();actual=resource_snapshot(w)
        require(before==after and actual==resources,'Unsettled containers or changed workloads/resources')
        ctx=settlement_link()['context'](globals(),root)
        save(ctx['output']/'browser-evidence-integration.json',ctx['proof'])
        save(ctx['output']/'security-evidence-integration.json',refreshed_security(root,w)['proof'])
        save(ctx['output']/'settled.json',{'executionID':root.name,'qualificationRunID':RUN,'utc':utc(),'workloads':after,'resources':actual})
        return {'settled':True}
    return phase(root,'settlement',run)

def remove_owned(root,kind):
    w=verify(root);w.host()
    cid=(root/(kind+'-created.cid')).read_text().strip();require(re.fullmatch('[0-9a-f]{64}',cid) is not None,'Full created-container identity required')
    def run():
        info=json.loads(w.execute(w.DOCKER+['inspect',cid]))[0]
        require(info['Id']==cid and info['Image']==IMAGES['runtime'] and info['Name']=='/zevyrn-'+root.name+'-'+kind
                and info['Config']['Labels'].get('org.zevyrn.qualification')==root.name,'Cleanup ownership mismatch')
        w.execute(w.DOCKER+['rm','-f',cid])
        require(cid not in w.execute(w.DOCKER+['ps','-aq','--no-trunc']).split(),'Owned container remains')
        return {'removedContainerID':cid,'runtimeImageID':IMAGES['runtime']}
    return phase(root,kind+'-removal',run,cleanup=True)

def create(root,kind):
    w=guard(root,kind+'-creation',docker=True)
    name='zevyrn-'+root.name+'-'+kind
    command=w.runtime_command(IMAGES['runtime'],name,None if kind=='runtime' else 18489)
    require(command.count('org.zevyrn.qualification='+name)==1,'Unexpected runtime ownership command')
    command[command.index('org.zevyrn.qualification='+name)]='org.zevyrn.qualification='+root.name
    def run():
        if kind=='browser':
            with socket.socket() as probe:probe.bind(('127.0.0.1',18489))
        # Docker's own bind is authoritative if the port becomes occupied later.
        with (root/(kind+'-created.stdout.log')).open('xb') as stdout,(root/(kind+'-created.stderr.log')).open('xb') as stderr:
            try:r=subprocess.run(command,stdout=stdout,stderr=stderr,timeout=60)
            except BaseException as error:
                save(root/(kind+'-created-exit.json'),{'exitCode':None,'exception':type(error).__name__,'message':str(error)});raise
        save(root/(kind+'-created-exit.json'),{'exitCode':r.returncode})
        require(r.returncode==0,'Disposable container creation failed')
        cid=(root/(kind+'-created.stdout.log')).read_text().strip();require(re.fullmatch('[0-9a-f]{64}',cid) is not None,'Missing created container identity')
        with (root/(kind+'-created.cid')).open('x') as f:f.write(cid+'\n')
        return {'containerID':cid,'imageID':IMAGES['runtime']}
    return phase(root,kind+'-creation',run)

def browser_environment(inherited=None):
    # Loader options can execute before any JS verification. Do not inherit them.
    inherited=os.environ if inherited is None else inherited
    allowed={'PATH','SYSTEMROOT','WINDIR','USERPROFILE','TEMP','TMP','APPDATA','LOCALAPPDATA','SYSTEMDRIVE','COMSPEC','USERNAME','USERDOMAIN'}
    return {k:v for k,v in inherited.items() if k.upper() in allowed}

def browser_command(root,tool):
    """Exact externally approved browser record; no PATH/environment authority."""
    ctx=active();ctx.require_execution(root);ctx.require_phase('native-linux-execution')
    require(tool in ('browser-acceptance.mjs','collect-browser-console-evidence.mjs','verify-native-cleanup.mjs'),'Browser tool scope')
    descriptor=ctx.authority('browserExecution');spec=authority_document('browserExecution')
    require(spec['scope']=='canonical-browser-execution-v1' and spec['executionRoot']==str(root)
            and spec['executionID']==root.name and spec['sourceManifestSHA256']==SOURCE and spec['images']==IMAGES,'Browser execution identity')
    from control import record,load
    tools=load(record(spec['authority']));node=Path(tools['node']['path'])
    require(node.is_absolute() and sha(node)==tools['node']['sha256'],'Browser Node identity')
    require(sha(HERE/tool)==ctx.code_hash(tool),'Browser producer identity')
    return [str(node),str(HERE/tool),'--guarded-child',str(root),descriptor['path'],descriptor['sha256'],str(os.getpid())]

def browser(root):
    w=guard(root,'browser-testing')
    # Full schema/coverage revalidation precedes the browser subprocess as well.
    w.verify_acceptance(root/'data')
    def run():
        with (root/'browser-launcher.stdout.log').open('xb') as stdout,(root/'browser-launcher.stderr.log').open('xb') as stderr:
            r=subprocess.run(browser_command(root,'browser-acceptance.mjs'),stdout=stdout,stderr=stderr,env=browser_environment())
        save(root/'browser-launcher-exit.json',{'exitCode':r.returncode})
        require(r.returncode==0,'Browser acceptance process failed')
        browser_contract(root)
        return {'browserAccepted':True}
    return phase(root,'browser-testing',run)

def supplemental_browser_producer(root,tool):
    """Bounded standalone evidence producer; never a qualification verdict."""
    require(tool in ('collect-browser-console-evidence.mjs','verify-native-cleanup.mjs'),'Supplemental browser scope')
    prefix='browser-console' if tool.startswith('collect-') else 'clipboard-cleanup'
    with (root/(prefix+'-launcher.stdout.log')).open('xb') as out,(root/(prefix+'-launcher.stderr.log')).open('xb') as err:
        result=subprocess.run(browser_command(root,tool),stdout=out,stderr=err,env=browser_environment(),timeout=180)
    save(root/(prefix+'-launcher-exit.json'),{'exitCode':result.returncode})
    require(result.returncode==0,'Supplemental browser producer failed')
    return {'producer':tool,'exitCode':result.returncode,'qualificationSettled':False}

def browser_contract(root):
    if (root/'browser-testing-failed.json').is_file():
        return settlement_link()['context'](globals(),root)['proof']
    b=read(root/'browser-results.json')
    require(b.get('executionID')==root.name and b.get('qualificationRunID')==RUN and b.get('runtimeImageID')==IMAGES['runtime']
            and b.get('browserContainerID')==read(root/'browser-inspect.json')['Id'],'Browser evidence identity mismatch')
    expected={'selection','keysmith','profiles','themes','contrast-regression','ui-corrections','focus-copy','direction-b','regeneration'}
    require(len(b.get('suites',[]))==9 and {x['suite'] for x in b['suites']}==expected and all(type(x.get('exitCode')) is int and x['exitCode']==0 for x in b['suites'])
            and b.get('realClipboardPasteBack') is True and b.get('actualAssetHashesVerified')==16 and b.get('consoleErrors')==0,'Browser acceptance incomplete')
    for row in b.get('artifacts',[]):require(sha(safe(root,row['path']))==row['sha256'],'Browser artifact changed')
    require(bool(b.get('artifacts')),'Missing browser artifacts')

def complete_contract(root):
    strict_scans(root,settlement=True)  # Re-evaluate expiry/approval at final completeness.
    ctx=settlement_link()['context'](globals(),root)
    settlement_link()['completed'](globals(),ctx,'settlement')
    required=['audit-completed.json','acceptance-completed.json','runtime-collection-completed.json','browser-collection-completed.json',
              'runtime-inspect.json','runtime-checks.json','browser-inspect.json','browser-checks.json']
    required += [kind+'-'+name+'.log' for kind in ('runtime','browser') for name in ('health-stdout','health-stderr','packages-stdout','packages-stderr','container-stdout','container-stderr')]
    require(all((root/n).is_file() for n in required),'Incomplete final evidence binding')
    for n in ('audit','acceptance','runtime-collection','browser-collection'):
        r=read(root/(n+'-completed.json'));require(r.get('executionID')==root.name and r.get('qualificationRunID')==RUN,'Wrong resumed phase identity')
        require(not (root/(n+'-failed.json')).exists(),'Failed resumed phase cannot be accepted')
    for kind in ('runtime','browser'):
        info=read(root/(kind+'-inspect.json'));container_contract(info,root.name,kind)
        r=read(root/(kind+'-checks.json'));require(r['executionID']==root.name and r['containerID']==info['Id'] and r['imageID']==IMAGES['runtime'] and r['healthExitCode']==0,'Runtime evidence binding mismatch')
    browser_contract(root)
    require(read(ctx['output']/'browser-evidence-integration.json')==ctx['proof'],'Supplemental completion proof changed')
    s=read(ctx['output']/'settled.json');require(s['executionID']==root.name and s['qualificationRunID']==RUN and s['workloads']==read(root/'execution-workloads-before.json') and s['resources']==read(root/'execution-resources-before.json'),'Cleanup/workload binding mismatch')
    require(read(ctx['output']/'security-evidence-integration.json')==refreshed_security(root)['proof'],'Security refresh completion changed')
    supplemental=['browser-evidence-integration.json','security-evidence-integration.json','settled.json','settlement-attempt.json','settlement-completed.json']
    return {'original':required,'supplemental':{n:sha(safe(ctx['output'],n)) for n in supplemental}}

def final(root):
    w=guard(root,'final')
    def run():
        required=complete_contract(root)
        refreshed_security(root,w) # Fresh full existing schema/archive/package/SBOM acceptance.
        files={p.relative_to(root).as_posix():sha(safe(root,p.relative_to(root).as_posix())) for p in root.rglob('*') if p.is_file()}
        ctx=settlement_link()['context'](globals(),root)
        authority=active()
        canonical={'contextSHA256':authority.digest,'sourceCatalogSHA256':authority.document['sourceCatalog']['sha256'],
                   'profileSHA256':authority.document['profile']['sha256'],'entrySHA256':authority.code_hash('continuation.py')}
        save(ctx['output']/'consolidated-qualification.json',{'executionID':root.name,'qualificationRunID':RUN,'sourceManifestSHA256':SOURCE,'images':IMAGES,
             'canonicalExecutionAuthority':canonical,
             'settlementExecutionID':ctx['policy']['settlementExecutionID'],'settlementPolicySHA256':SETTLEMENT_POLICY_SHA256,
             'supplementalBrowserCompletion':ctx['proof'],'securityEvidenceRefresh':refreshed_security(root,w)['proof'],'parentManifestSHA256':PARENT,'historicalAuditStatus':'FAILED; superseded by fresh bound audit, not rewritten',
             'requiredEvidence':required,'boundFiles':files,'result':'GO FOR INDEPENDENT QUALIFICATION REVIEW','utc':utc()})
        return {'consolidated':True}
    return phase(root,'final',run)

def readiness(root):
    """Existing frozen-input and strict scan gates, then bounded read-only host checks."""
    ctx=active();ctx.require_phase('readiness');ctx.require_execution(root)
    w=verify(root)
    # Readiness re-evaluates the same approval/freshness path used at settlement.
    security=refreshed_security(root,w) if 'securityRefresh' in ctx.profile()['records'] else strict_scans(root)
    live(w);w.application_ready(w.snapshot())
    capacity=w.readonly_capacity() if sys.platform=='win32' else w.capacity(root)
    return {'ready':True,'sourceManifestSHA256':SOURCE,'images':IMAGES,'capacity':capacity,
            'security':security,'qualificationExecuted':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('phase',choices=['verify','readiness','preflight','scan','scan-acceptance','reuse','audit','accept','runtime-create','browser-create','runtime-collect','browser-collect','browser-test','browser-console','clipboard-cleanup','remove-runtime','remove-browser','settled','final'])
    p.add_argument('execution',type=Path);p.add_argument('--container');p.add_argument('--compose-executable',type=Path);p.add_argument('--compose-sha256');p.add_argument('--execute-approved',action='store_true');a=p.parse_args();root=checked_execution_path(a.execution)
    if a.phase!='verify':require(a.execute_approved,'Execution requires independent review and separate authorization')
    configure();ctx=active();ctx.require_execution(root)
    ctx.require_phase('verify' if a.phase=='verify' else 'settlement' if a.phase in ('settled','final') else 'readiness' if a.phase in ('readiness','preflight') else 'native-linux-execution')
    if a.phase=='verify':verify(root);result={'verified':True,'qualificationExecuted':False}
    else:
        require(a.execute_approved,'Execution requires independent review and separate authorization')
        if a.phase=='readiness':result=readiness(root)
        elif a.phase=='preflight':result=preflight(root)
        elif a.phase=='scan':result=scan(root)
        elif a.phase=='scan-acceptance':result=scan_accept(root)
        elif a.phase=='reuse':result=reuse(root,a.compose_executable,a.compose_sha256)
        elif a.phase=='audit':result=audit(root)
        elif a.phase=='accept':result=accept(root)
        elif a.phase in ('runtime-create','browser-create'):result=create(root,'runtime' if a.phase=='runtime-create' else 'browser')
        elif a.phase in ('runtime-collect','browser-collect'):result=collect_runtime(root,a.container,'runtime' if a.phase=='runtime-collect' else 'browser')
        elif a.phase=='browser-test':result=browser(root)
        elif a.phase in ('browser-console','clipboard-cleanup'):result=supplemental_browser_producer(root,'collect-browser-console-evidence.mjs' if a.phase=='browser-console' else 'verify-native-cleanup.mjs')
        elif a.phase in ('remove-runtime','remove-browser'):result=remove_owned(root,'runtime' if a.phase=='remove-runtime' else 'browser')
        elif a.phase=='settled':result=settled(root)
        else:result=final(root)
    print(json.dumps(result))
def resource_snapshot(w):
    values=json.loads(w.execute(w.DOCKER+['image','inspect',IMAGES['builder'],IMAGES['runtime']]))
    require(len(values)==2 and {row['Id'] for row in values}=={IMAGES['builder'],IMAGES['runtime']},'Qualification image dependency missing')
    return {**w.resources(),'images':sorted(row['Id'] for row in values)}

SCAN_LOGS=('scanner-db-download.log','scanner-version.json','builder-scan.log','runtime-scan.log','sbom-generation.log')
def scan_files():
    names=['scanner-provenance.json','scanner-db-start.json','scanner-db-end.json','evidence-context.json','scan-binding-and-counts.json',
      'builder-installed-packages.json','runtime-installed-packages.json','builder-raw-scan.json','runtime-raw-scan.json',
      'builder-scan-receipt.json','runtime-scan-receipt.json','runtime-sbom.cdx.json','runtime-sbom-receipt.json','sbom-binding.json',
      'scan-status.json','tools/trivy','trivy-cache/db/trivy.db','trivy-cache/db/metadata.json','scanner-policy/empty-config.yaml','scanner-policy/empty-ignore']
    return names+[n+s for n in SCAN_LOGS for s in ('','.stderr','.exit.json')]

def preflight(root):
    w=guard(root,'preflight',docker=True)
    def run():
        require(sys.platform=='linux' and os.getuid()==1000,'Approved unprivileged Linux account required')
        before=w.snapshot();resources=resource_snapshot(w);capacity=w.capacity(root)
        w.application_ready(before)
        require(any(c['name']=='/keysmith-keysmith-1' and c['health']=='healthy' for c in before.values()),'Existing KeySmith application unhealthy or missing')
        save(root/'execution-workloads-before.json',before);save(root/'execution-resources-before.json',resources)
        save(root/'live-preflight.json',{'executionID':root.name,'qualificationRunID':RUN,'sourceManifestSHA256':SOURCE,'images':IMAGES,
          'hostname':active().profile()['bindings']['hostname'],'machineID':w.MACHINE,'daemonID':w.DAEMON,'endpoint':'unix:///var/run/docker.sock','capacity':capacity,'utc':utc()})
        return {'passed':True}
    return phase(root,'preflight',run)

def scan(root):
    w=guard(root,'scan',docker=True);data=root/'data'
    require(not any((data/n).exists() for n in scan_files()),'Fresh scan paths already used')
    def run():
        code=None;failure=None
        try:
            with (root/'scan-driver.stdout.log').open('x',encoding='utf-8') as out,(root/'scan-driver.stderr.log').open('x',encoding='utf-8') as err:
                code=run_scanner(data,out,err)
        except BaseException as e:failure={'exception':type(e).__name__,'message':str(e)};raise
        finally:save(root/'scan-driver-exit.json',{'exitCode':code,'error':failure,'executionID':root.name})
        require(type(code) is int and code==0,'Scanner driver failed')
        strict_scans(root)
        return {'passed':True}
    return phase(root,'scan',run)

def strict_scans(root,*,settlement=False):
    if settlement:return refreshed_security(root)['accepted']['results']
    authenticate_helpers(root)
    data=root/'data';fresh_security(root);import qualification_evidence as qe
    context=read(data/'evidence-context.json');now=datetime.datetime.now(datetime.timezone.utc)
    require(read(root/'scan-driver-exit.json')=={'exitCode':0,'error':None,'executionID':root.name},'Scanner driver status mismatch')
    for n in SCAN_LOGS:
        r=read(data/(n+'.exit.json'))
        require(r.get('attemptID')==root.name and r.get('runID')==RUN and r.get('sourceManifestSHA256')==SOURCE and type(r.get('exitCode')) is int and r['exitCode']==0 and r.get('error') is None,'Scanner process failed: '+n)
        require(r['stdoutSHA256']==sha(data/n) and r['stderrSHA256']==sha(data/(n+'.stderr')),'Scanner diagnostic evidence changed: '+n)
    require(read(data/'scan-status.json')['phase']=='READY_FOR_LOCAL_SCHEMA_VALIDATION','Incomplete scanner execution')
    builds=read(data/'builds.json');results={}
    for k in ('builder','runtime'):
        require(context['images'][k]=={'imageID':IMAGES[k],'archiveSHA256':builds[k]['archiveSHA256']},'Scan image binding mismatch')
        results[k]=qe.validate_scan((data/(k+'-raw-scan.json')).read_bytes(),read(data/(k+'-scan-receipt.json')),context,k,
          {r['name']:r['version'] for r in read(data/(k+'-installed-packages.json'))['packages']},read(data/'scanner-db-end.json')['metadata'],(data/'trivy-cache/db/trivy.db').read_bytes(),(data/builds[k]['archive']).read_bytes(),now,evidence_root=data)
    return results

def scan_accept(root):
    guard(root,'scan-acceptance')
    def run():
        result=strict_scans(root)
        save(root/'scan-acceptance.json',{'executionID':root.name,'qualificationRunID':RUN,'sourceManifestSHA256':SOURCE,'images':IMAGES,
          'databaseSHA256':sha(root/'data/trivy-cache/db/trivy.db'),'results':result,'zeroUnresolvedHighCritical':True,'zeroSecrets':True})
        return {'passed':True}
    return phase(root,'scan-acceptance',run)

def reuse(root,executable,digest):
    w=guard(root,'reuse',docker=True)
    def run():
        require(executable is not None and executable.is_absolute() and re.fullmatch('[0-9a-f]{64}',digest or '') is not None,'Reviewed Compose executable and digest required')
        require(executable.name=='docker-compose' and executable.is_file() and not executable.is_symlink() and sha(executable)==digest,'Compose executable substitution')
        require(executable.stat().st_uid==0 and executable.stat().st_mode&0o022==0,'Compose executable not administrator-owned and immutable to ordinary accounts')
        original=root/'history/remote-evidence';historical_contract(original,w)
        require(read(root/'history/build-client-exit.json')['exitCode']==0,'Build receipt failed')
        log=(original/'builder-build.log').read_text()
        require('tests 170' in log and 'pass 169' in log and 'fail 0' in log,'Builder application test evidence incomplete')
        require(w.filesystem_gate(root/'data',read(root/'data/builds.json'),persist=False)==read(root/'data/filesystem-equivalence.json'),'Filesystem reuse mismatch')
        authenticate_helpers(root)
        from compose_prebuild import validate
        target=compose_inputs(root)
        # The unchanged reviewed helper accepts exactly these two anchors.
        # Attempt/executable identity is bound by the outer phase receipt.
        identity={'runID':RUN,'sourceManifestSHA256':SOURCE}
        result=validate(target,[str(executable)],{'PATH':'/usr/bin:/bin','HOME':str(target)},identity)
        require(sha(executable)==digest,'Compose executable changed during use')
        summary=target/'compose-validation-v2/summary.json';s=read(summary)
        checks=list(summary.parent.glob('*/check-*.json'));cases=list(summary.parent.glob('*/result.json'))
        require(result.get('passed') is True and s.get('passed') is True and s.get('caseCount')==len(cases)==53 and len(checks)==271 and s.get('runID')==RUN and s.get('sourceManifestSHA256')==SOURCE and s.get('helperSHA256')==sha(root/'data/compose_prebuild.py'),'Compose matrix incomplete')
        require(all(read(p).get('passed') is True for p in checks) and all(read(p).get('status')=='PASS' for p in cases),'Compose matrix failed')
        save(root/'compose-executable.json',{'path':str(executable),'sha256':digest,'version':s['composeVersion']})
        save(root/'compose-evidence.json',{p.relative_to(root).as_posix():sha(p) for p in summary.parent.rglob('*') if p.is_file()})
        save(root/'reuse-acceptance.json',{'executionID':root.name,'historicalManifestSHA256':PARENT,'applicationPass':169,'applicationSkip':1,
          'composeFreshCases':53,'composeFreshChecks':271,'filesystemSHA256':sha(root/'data/filesystem-equivalence.json'),'assets':read(root/'production-assets.json')})
        return {'passed':True}
    return phase(root,'reuse',run)

def compose_inputs(root):
    target=root/'compose-workspace';target.mkdir()
    shutil.copytree(root/'data/source',target/'source')
    shutil.copyfile(root/'data/source-manifest.json',target/'source-manifest.json')
    return target

def plain_entry(path):
    # Junctions/reparse points also redirect Windows file access.
    require(not path.is_symlink() and not getattr(path,'is_junction',lambda:False)()
        and not getattr(path.lstat(),'st_file_attributes',0)&0x400,'Linked helper boundary entry: '+str(path))

def boundary_spec(root):
    anchor=active().authority('executionBoundary')
    require(Path(anchor['path'])==root/'preparation-seal.json' and sha(root/'preparation-seal.json')==anchor['sha256'],'External preparation seal identity')
    path=safe(root,'python-execution-boundary.json')
    require(sha(path)==read(root/'preparation-seal.json').get('python-execution-boundary.json'),'Python boundary identity mismatch')
    spec=read(path)
    require(set(spec)=={'controllerFiles','controllerDirectories'} and type(spec['controllerFiles']) is dict
        and type(spec['controllerDirectories']) is list,'Malformed Python execution boundary')
    return spec

def authenticate_controller():
    ctx=active();ctx.revalidate()
    require(HERE==Path(ctx.document['repositoryRoot'])/'scripts/release-controller','Controller source root substitution')

def authenticate_helpers(root):
    # Only stdlib and the externally reviewed entrypoint have executed so far.
    # The boundary manifest and input catalog are sealed before helpers load.
    authenticate_controller();boundary_spec(root)
    require(sha(root/'fresh-inputs.json')==read(root/'preparation-seal.json').get('fresh-inputs.json'),'Helper input catalog changed')
    inputs=read(root/'fresh-inputs.json');data=root/'data';plain_entry(data)
    allowed=set(inputs)|set(scan_files())|NEW_DATA|{'scan-stopped.json','trivy-cache/fanal/fanal.db'}
    directories={part for n in allowed for part in ('/'.join(n.split('/')[:i]) for i in range(1,len(n.split('/'))))}
    for p in data.rglob('*'):
        plain_entry(p);n=p.relative_to(data).as_posix()
        require('__pycache__' not in p.relative_to(data).parts and p.suffix.lower() not in {'.pyc','.pyo'},'Unexpected Python bytecode/cache: '+n)
        require((p.is_dir() and n in directories) or (p.is_file() and n in allowed),'Unexpected active helper payload: '+n)
    for n,h in inputs.items():
        p=safe(data,n);plain_entry(p);require(p.is_file() and sha(p)==h,'Approved helper input missing or changed: '+n)

if __name__=='__main__':main()
