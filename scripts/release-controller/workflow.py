"""Operator-run qualification. No SSH, sudo, publication, or automatic deployment.

Only `prepare` is local-only. build/scan/runtime require separate authorization.
Reviewed validators are copied byte-for-byte; this module supplies orchestration.
"""
from pathlib import Path
from runtime_context import active,helper,run_scanner
import argparse, datetime, hashlib, importlib, json, os, re, shutil, subprocess, sys

HERE = Path(__file__).resolve().parent
BASELINE = None
MACHINE = None
DAEMON = None
HELPERS = ('scan-images.py', 'qualification_evidence.py', 'acceptance_gate.py',
           'image_metadata.py', 'export_identity.py', 'filesystem_equivalence.py',
           'compiler_inventory.py', 'compiler-integrity.json', 'vendored_inventory.py',
           'compose_prebuild.py','builder_security.py','builder-security-policy.json','builder-security-authority.json')
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']

def configure():
    global BASELINE,MACHINE,DAEMON
    b=active().profile()['bindings'];BASELINE=b['sourceCommit'];MACHINE=b['machineID'];DAEMON=b['daemonID']

def require(ok, message):
    if not ok: raise ValueError(message)

def sha(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()

def read(path): return json.loads(Path(path).read_text(encoding='utf-8-sig'))

def save(path, data):
    with Path(path).open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(data, stream, indent=2, allow_nan=False); stream.write('\n')

def execute(args, cwd=None, log=None, env=None):
    if log:
        with Path(log).open('xb') as stream:
            result = subprocess.run(args, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
        require(result.returncode == 0, 'Command failed; see ' + str(log)); return ''
    return subprocess.check_output(args, cwd=cwd, env=env, text=True, stderr=subprocess.PIPE).strip()

def build_driver(text):
    matches=re.findall(r'^Driver:\s+(\S+)\s*$',text,re.MULTILINE)
    require(matches==['docker'],'Expected exactly one local Docker Buildx driver')
    return matches[0]

def verify_files(root, rows, exact=False):
    root = Path(root).resolve(); seen = set()
    for row in rows:
        name = row['path']; parts = name.split('/')
        require(name and not name.startswith('/') and '\\' not in name and ':' not in name
                and all(p not in ('', '.', '..') for p in parts) and name not in seen, 'Unsafe/duplicate path')
        seen.add(name); p = root/name
        require(all(not parent.is_symlink() for parent in [p, *p.parents] if parent != root.parent), 'Linked source')
        require(p.is_file() and p.resolve().is_relative_to(root) and sha(p) == row['sha256'], 'File mismatch: ' + name)
    if exact:
        require({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()} == seen, 'Unexpected source files')

def runtime_dockerfile(original, builder):
    require(re.fullmatch(r'zevyrn-builder:1\.2\.1-[a-z0-9-]+', builder), 'Unapproved builder tag')
    marker = 'FROM nginx:'
    require(original.count(marker) == 1 and ' AS runtime-rootfs\n' in original, 'Unrecognized Dockerfile stages')
    tail = original[original.index(marker):]
    require('COPY --from=build --chown=10001:10001 /app/dist /usr/share/nginx/html' in tail
            and 'FROM scratch AS runtime' in tail, 'Unrecognized runtime copy')
    return 'FROM ' + builder + ' AS build\n' + tail

def final_dockerfile(original, rootfs):
    require(re.fullmatch(r'zevyrn:1\.2\.1-[a-z0-9-]+-rootfs',rootfs), 'Unapproved rootfs tag')
    require(original.count('FROM scratch AS runtime\n')==1,'Unrecognized final stage')
    return 'FROM '+rootfs+' AS runtime-rootfs\n'+original[original.index('FROM scratch AS runtime\n'):]

def helper_path(name):
    return HERE.parent/'compiler-integrity.json' if name=='compiler-integrity.json' else HERE/name

def prepare(root):
    active().require_phase('readiness');active().require_execution(root)
    item=active().authority('baseline'); baseline=read(Path(item['path'])); repo=Path(baseline['repository'])
    git = ['git', '--no-optional-locks', '-C', str(repo)]
    require(execute(git+['rev-parse', 'HEAD']) == BASELINE, 'HEAD mismatch')
    require(execute(git+['branch', '--show-current']) == 'main', 'Branch mismatch')
    require(execute(git+['remote','get-url','origin'])==baseline['origin']=='https://github.com/TheStateOfWhere/zevyrn-password-generator.git','Origin mismatch')
    require(not execute(git+['diff', '--cached', '--name-only']), 'Staging not empty')
    # Preserve porcelain leading whitespace, which is part of its format.
    status = subprocess.check_output(git+['status', '--short', '--untracked-files=all'], text=True)
    require({line[3:] for line in status.splitlines()} == {r['path'] for r in baseline['changes']}, 'Pending inventory mismatch')
    for key in ('changes', 'protected', 'source'): verify_files(repo, baseline[key])
    require(re.fullmatch(r'[a-z0-9-]+', root.name) is not None, 'Run directory name must be lowercase identifier')
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    (root/'source').mkdir()
    for row in baseline['source']:
        p = root/'source'/row['path']; p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes((repo/row['path']).read_bytes())
    save(root/'source-manifest.json', baseline['source'])
    verify_files(root/'source', baseline['source'], exact=True)
    locks = {}
    for name in HELPERS:
        source=helper_path(name);relative=source.relative_to(HERE.parents[1]).as_posix()
        require(sha(source)==active().catalog['files'][relative], 'Reviewed helper changed')
        shutil.copyfile(source, root/name); locks[name] = sha(root/name)
    save(root/'helpers.json', locks)
    save(root/'qualification.json', {'runID':root.name, 'sourceManifestSHA256':sha(root/'source-manifest.json'),
         'expectedDaemonID':DAEMON, 'baselineHEAD':BASELINE, 'candidate':'frozen uncommitted 97-file candidate; not HEAD alone'})
    tag = 'zevyrn-builder:1.2.1-' + root.name
    (root/'Dockerfile.runtime').write_text(runtime_dockerfile((root/'source/Dockerfile').read_text(),tag), newline='\n')
    (root/'Dockerfile.final').write_text(final_dockerfile((root/'source/Dockerfile').read_text(),'zevyrn:1.2.1-'+root.name+'-rootfs'),newline='\n')
    save(root/'execution-inputs.json', {n:sha(root/n) for n in ('qualification.json','source-manifest.json','helpers.json','Dockerfile.runtime','Dockerfile.final')})
    return {'prepared':str(root), 'sourceFiles':len(baseline['source']), 'dockerOperations':0}

def inputs(root):
    for name, digest in read(root/'execution-inputs.json').items(): require(sha(root/name)==digest, 'Run input changed: '+name)
    for name, digest in read(root/'helpers.json').items(): require(sha(root/name)==digest, 'Helper changed: '+name)
    q=read(root/'qualification.json')
    require(q['sourceManifestSHA256']==sha(root/'source-manifest.json'), 'Manifest binding')
    b=active().profile()['bindings']
    require(q['runID']==b['runID'] and q['sourceManifestSHA256']==b['sourceManifestSHA256'],'External source/run binding')
    verify_files(root/'source', read(root/'source-manifest.json'), exact=True)
    expected=runtime_dockerfile((root/'source/Dockerfile').read_text(), 'zevyrn-builder:1.2.1-'+q['runID'])
    require((root/'Dockerfile.runtime').read_text()==expected, 'Runtime recipe changed')
    require((root/'Dockerfile.final').read_text()==final_dockerfile((root/'source/Dockerfile').read_text(),'zevyrn:1.2.1-'+q['runID']+'-rootfs'), 'Final recipe changed')
    return q

def host():
    require(sys.platform=='linux', 'DK02 Linux execution required')
    require(execute(['hostname'])==active().profile()['bindings']['hostname'] and Path('/etc/machine-id').read_text().strip()==MACHINE, 'Host mismatch')
    require(execute(DOCKER+['info','--format','{{.ID}}'])==DAEMON, 'Docker daemon mismatch')
    require(not any(v for k,v in os.environ.items() if k.startswith(('DOCKER_','BUILDX_','BUILDKIT_')) and k!='DOCKER_HOST'), 'Unexpected Docker/build endpoint selection')
    require(os.environ.get('DOCKER_HOST', 'unix:///var/run/docker.sock')=='unix:///var/run/docker.sock', 'Unexpected endpoint')
    require(execute(DOCKER+['context','inspect','default','--format','{{.Endpoints.docker.Host}}'])=='unix:///var/run/docker.sock','Default builder context endpoint mismatch')

def application_workloads(values):
    # Only the existing Zevyrn/KeySmith service is an eligibility dependency.
    selected={identity:row for identity,row in values.items() if row['name']=='/keysmith-keysmith-1'}
    require(len(selected)==1,'Existing KeySmith application missing or ambiguous')
    return selected

def application_ready(values):
    selected=application_workloads(values)
    require(all(row['status']=='running' and row['health']=='healthy' for row in selected.values()),'Existing KeySmith application unhealthy')

def snapshot():
    ids=execute(DOCKER+['ps','-aq','--no-trunc','--filter','name=^/keysmith-keysmith-1$']).split()
    values=json.loads(execute(DOCKER+['inspect',*ids])) if ids else []
    rows={c['Id']:{'name':c['Name'], 'image':c['Image'], 'started':c['State']['StartedAt'],
                  'status':c['State']['Status'], 'health':c['State'].get('Health',{}).get('Status'),
                  'networks':sorted(c['NetworkSettings']['Networks'])} for c in values}
    return application_workloads(rows)

def resources():
    # No qualification phase creates/removes networks or volumes. These are the
    # exact networks used by Compose/isolated containers, not a host inventory.
    values=json.loads(execute(DOCKER+['network','inspect','proxy','bridge','none']))
    require(len(values)==3 and {row['Name'] for row in values}=={'proxy','bridge','none'},'Qualification dependency network missing')
    return {'network':sorted(row['Id']+' '+row['Name'] for row in values),'volume':[]}

def capacity(root):
    docker_root=execute(DOCKER+['info','--format','{{.DockerRootDir}}'])
    memory=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
    available=int(memory['MemAvailable'].split()[0])*1024
    result={'workFree':shutil.disk_usage(root).free,'dockerFree':shutil.disk_usage(docker_root).free,
            'availableMemory':available,'cpus':os.cpu_count()}
    require(min(result['workFree'],result['dockerFree'])>=8*1024**3 and available>=2*1024**3 and result['cpus']>=2,'Insufficient qualification headroom')
    return result

def image(root, tag, kind):
    from image_metadata import normalize_image
    payload=json.loads(execute(DOCKER+['image','inspect',tag]))[0]
    normalized=normalize_image(payload,'runtime' if kind=='runtime' else 'builder')
    archive=kind+'.tar'
    execute(DOCKER+['image','save','--output',str(root/archive),payload['Id']])
    return {'image':{'id':payload['Id'], 'metadata':normalized}, 'archive':archive, 'archiveSHA256':sha(root/archive)}

def stage_build(root):
    active().require_phase('native-linux-execution');active().require_execution(root)
    q=inputs(root); host()
    build_driver(execute(DOCKER+['buildx','inspect']))
    save(root/'capacity.json',capacity(root))
    require(not (root/'build-attempt.json').exists(), 'No automatic build retry; use a separately approved run')
    save(root/'build-attempt.json', {'startedUTC':datetime.datetime.now(datetime.timezone.utc).isoformat()})
    before=snapshot(); save(root/'workloads-before.json', before)
    application_ready(before)
    save(root/'resources-before.json',resources())
    import compose_prebuild
    compose_prebuild.validate(root, ['docker','compose'], os.environ.copy(), {'runID':q['runID'],'sourceManifestSHA256':q['sourceManifestSHA256']})
    builder='zevyrn-builder:1.2.1-'+q['runID']; runtime='zevyrn:1.2.1-'+q['runID']; rootfs=runtime+'-rootfs'
    for tag in (builder,runtime,rootfs):
        found=subprocess.run(DOCKER+['image','inspect',tag],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        require(found.returncode!=0, 'Candidate tag already exists')
    label=['--label','io.zevyrn.source-manifest-sha256='+q['sourceManifestSHA256']]
    execute(DOCKER+['build','--platform','linux/amd64','--pull','--no-cache','--target','build',*label,'-t',builder,'.'],root/'source',root/'builder-build.log')
    builds={'builder':image(root,builder,'builder')}
    # Use Docker's standard local image store, not a separate remote BuildKit daemon.
    expected=builds['builder']['image']['id']
    require(execute(DOCKER+['image','inspect',builder,'--format','{{.Id}}'])==expected,'Builder changed before runtime')
    for target,tag,kind in [('runtime-rootfs',rootfs,'rootfs'),('runtime',runtime,'runtime')]:
        recipe=root/('Dockerfile.final' if kind=='runtime' else 'Dockerfile.runtime')
        if kind=='runtime': require(execute(DOCKER+['image','inspect',rootfs,'--format','{{.Id}}'])==builds['rootfs']['image']['id'],'Rootfs changed before final build')
        execute(DOCKER+['build','--platform','linux/amd64','--pull=false','--no-cache','--target',target,
                 '-f',str(recipe),*label,'--label','io.zevyrn.builder-image-id='+expected,'-t',tag,'.'],root/'source',root/(kind+'-build.log'))
        require(execute(DOCKER+['image','inspect',builder,'--format','{{.Id}}'])==expected,'Builder changed during runtime')
        if kind=='runtime': require(execute(DOCKER+['image','inspect',rootfs,'--format','{{.Id}}'])==builds['rootfs']['image']['id'],'Rootfs changed during final build')
        builds[kind]=image(root,tag,kind)
    save(root/'builds.json',builds)
    filesystem_gate(root,builds)
    after=snapshot(); save(root/'workloads-after-build.json',after)
    require(before==after,'Existing workload changed')
    return {'built':True,'images':{k:v['image']['id'] for k,v in builds.items()}}

def filesystem_gate(root,builds,persist=True):
    from filesystem_equivalence import filesystem, compare
    views={k:filesystem(root/v['archive'],v['image']['id'],v['archiveSHA256']) for k,v in builds.items()}
    result=compare(views['rootfs'],views['runtime'])
    require(result['passed'],'Runtime scratch filesystem mismatch')
    b=views['builder']['files']; r=views['runtime']['files']
    dist={p[len('app/dist/'):]:v for p,v in b.items() if p.startswith('app/dist/') and v['type']=='file'}
    require(dist,'Missing builder application output')
    final={p[len('usr/share/nginx/html/'):]:v for p,v in r.items() if p.startswith('usr/share/nginx/html/') and v['type']=='file'}
    require(set(dist).issubset(final),'Runtime missing application files from scanned builder')
    # The pinned nginx rootfs may retain its 50x.html. Full rootfs equivalence
    # above authenticates inherited files; they are not compiler output.
    for p,v in dist.items():
        require(v['sha256']==final[p]['sha256'] and v['size']==final[p]['size'], 'Runtime application differs from scanned builder: '+p)
        require(final[p]['uid']==final[p]['gid']==10001,'Runtime application ownership mismatch')
    q=read(root/'qualification.json'); bid=builds['builder']['image']['id']
    require(views['runtime']['config']['config']['Labels'].get('io.zevyrn.builder-image-id')==bid,'Runtime builder association mismatch')
    result.update(runID=q['runID'],sourceManifestSHA256=q['sourceManifestSHA256'],builderImageID=bid,
                  applicationFiles=len(dist),inheritedHtmlFiles=sorted(set(final)-set(dist)),
                  exports={k:{'imageID':v['image']['id'],'archiveSHA256':v['archiveSHA256']} for k,v in builds.items()})
    if persist: save(root/'filesystem-equivalence.json',result)
    return result

def scan(root):
    inputs(root)
    require(sys.platform=='linux' and os.getuid()==1000,'Reviewed unprivileged scanner requires Linux UID 1000')
    require((root/'filesystem-equivalence.json').is_file(),'Build/relationship gate missing')
    # Unchanged reviewed script owns scanner download, clean policy, database,
    # full package/alias reconciliation, secret gates, and SBOM generation.
    with (root/'scan-driver.log').open('x') as log:
        require(run_scanner(root,log,log)==0,'Scanner driver failed')
    return {'scanned':True,'schemaAcceptance':'PENDING'}

def schema_environment():
    ctx=active();ctx.revalidate();return HERE


def source_scan(root):
    active().require_phase('native-linux-execution');active().require_execution(root)
    q=inputs(root)
    from qualification_evidence import isolated_scanner_environment
    context=read(root/'evidence-context.json');tool=root/'tools/trivy'
    require(sha(tool)==context['scannerBinarySHA256'],'Scanner binary changed')
    execute([str(tool),'fs','--config',str(root/'scanner-policy/empty-config.yaml'),
             '--ignorefile',str(root/'scanner-policy/empty-ignore'),'--scanners','secret','--exit-code','1',
             '--format','json','--output',str(root/'source-secrets.json'),str(root/'source')],
             root/'scanner-policy',root/'source-secrets.log',isolated_scanner_environment(root))
    report=read(root/'source-secrets.json')
    validate_source_report(report,str(root/'source'))
    save(root/'source-secret-binding.json',{'sourceManifestSHA256':q['sourceManifestSHA256'],
         'scannerBinarySHA256':sha(tool),'reportSHA256':sha(root/'source-secrets.json'),
         'sourceArtifactName':str(root/'source'),'scannerExitCode':0,'scanners':['secret']})
    return {'sourceSecretsPassed':True}

def validate_source_report(report,target):
    # Trivy v0.76.0 Report.Results has json omitempty: a successful secret-only
    # scan can legitimately omit it. This NEVER applies to image/package scans.
    require(report.get('SchemaVersion')==2 and report.get('ArtifactType')=='filesystem'
            and report.get('ArtifactName')==target and report.get('Trivy',{}).get('Version')=='0.76.0'
            and isinstance(report.get('Results',[]),list),'Malformed source secret report')
    require(not any(k in report for k in ('Error','Errors','error')),'Scanner error')
    for item in report.get('Results',[]):
        require(isinstance(item,dict) and item.get('Class')=='secret' and isinstance(item.get('Target'),str)
                and isinstance(item.get('Secrets',[]),list) and not item.get('Secrets')
                and not item.get('ExperimentalModifiedFindings'),'Source secret finding or unexpected result')

def audit_script(directory='/tmp'):
    # No shell pipeline: retain npm's own status and streams before reduction.
    return """const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const directory=REPLACE_DIRECTORY, audit=path.join(directory,'audit.json'), summary=path.join(directory,'summary.json');
const options={encoding:'utf8',maxBuffer:64*1024*1024};
const npm=spawnSync('npm',['audit','--json','--cache',path.join(directory,'npm')],options);
if(npm.stderr)process.stderr.write(npm.stderr);
const record={npmExitCode:npm.status,npmSignal:npm.signal,npmError:npm.error?String(npm.error):null,auditStdout:npm.stdout||'',
 validatorExitCode:null,validatorSignal:null,validatorError:null,summaryStdout:''};
try {
 fs.writeFileSync(audit,record.auditStdout,{flag:'wx'});
 const validation=spawnSync(process.execPath,['scripts/ci-security.mjs','npm',audit,summary],options);
 if(validation.stderr)process.stderr.write(validation.stderr);
 if(validation.stdout)process.stderr.write(validation.stdout);
 Object.assign(record,{validatorExitCode:validation.status,validatorSignal:validation.signal,
  validatorError:validation.error?String(validation.error):null,summaryStdout:fs.existsSync(summary)?fs.readFileSync(summary,'utf8'):''});
} catch(error) { record.validatorError=String(error);process.stderr.write(String(error)+'\\n'); }
process.stdout.write(JSON.stringify(record)+'\\n');
if(npm.error||npm.signal||![0,1].includes(npm.status)||record.validatorError||record.validatorSignal||record.validatorExitCode!==0)process.exitCode=1;
""".replace('REPLACE_DIRECTORY',json.dumps(directory))

def capture_audit(command, root):
    # Exclusive files and separate descriptors: diagnostics can never enter JSON.
    with (root/'npm-audit-capture.json').open('xb') as stdout, (root/'npm-audit.stderr.log').open('xb') as stderr:
        try:
            result=subprocess.run(command,stdout=stdout,stderr=stderr)
        except OSError as error:
            save(root/'npm-audit-exit.json',{'containerExitCode':None,'launchError':str(error)})
            raise
    save(root/'npm-audit-exit.json',{'containerExitCode':result.returncode,
         'captureSHA256':sha(root/'npm-audit-capture.json'),'stderrSHA256':sha(root/'npm-audit.stderr.log')})

def audit_json(text):
    def pairs(rows):
        result={}
        for key,value in rows:
            require(key not in result,'Duplicate npm evidence key');result[key]=value
        return result
    def constant(value): raise ValueError('Non-JSON npm evidence constant: '+value)
    result=json.loads(text,object_pairs_hook=pairs,parse_constant=constant)
    require(type(result) is dict,'Expected npm evidence object')
    return result

def audit_evidence(root, persist=False):
    status=read(root/'npm-audit-exit.json')
    require(type(status.get('containerExitCode')) is int and status['containerExitCode']==0,'Audit container process failed')
    require(status.get('captureSHA256')==sha(root/'npm-audit-capture.json')
            and status.get('stderrSHA256')==sha(root/'npm-audit.stderr.log'),'Audit streams changed')
    record=audit_json((root/'npm-audit-capture.json').read_text(encoding='utf-8'))
    require(set(record)=={'npmExitCode','npmSignal','npmError','auditStdout','validatorExitCode','validatorSignal','validatorError','summaryStdout'},'Incomplete npm process evidence')
    require(type(record['npmExitCode']) is int and record['npmExitCode'] in (0,1)
            and record['npmSignal'] is None and record['npmError'] is None,'npm process failed')
    require(type(record['validatorExitCode']) is int and record['validatorExitCode']==0
            and record['validatorSignal'] is None and record['validatorError'] is None,'npm policy validator failed')
    require(type(record['auditStdout']) is str and type(record['summaryStdout']) is str,'Malformed npm stdout')
    report=audit_json(record['auditStdout']); summary=audit_json(record['summaryStdout'])
    require(report.get('auditReportVersion')==2 and not report.get('error')
            and type(report.get('vulnerabilities')) is dict and type(report.get('metadata')) is dict,'Invalid npm audit report')
    counts=report['metadata'].get('vulnerabilities')
    require(type(counts) is dict and all(type(counts.get(k)) is int and counts[k]>=0 for k in ('info','low','moderate','high','critical','total')),'Incomplete npm advisory counts')
    require(sum(counts[k] for k in ('info','low','moderate','high','critical'))==counts['total']==len(report['vulnerabilities']),'Contradictory npm advisory counts')
    # Existing policy permits npm exit 1 for advisory findings below HIGH only.
    # A zero-advisory report with exit 1 is an unexplained process failure.
    require((record['npmExitCode']==0)==(counts['total']==0),'npm exit status contradicts advisory evidence')
    require(summary.get('counts')==counts and summary.get('blocked') is False
            and counts['high']==counts['critical']==0,'npm security gate failed')
    require(type(summary.get('packages')) is list and len(summary['packages'])==len(report['vulnerabilities']),'Incomplete npm summary')
    observed={key:0 for key in ('info','low','moderate','high','critical')}
    for key,package in report['vulnerabilities'].items():
        require(type(package) is dict and package.get('name')==key
                and package.get('severity') in ('info','low','moderate','high','critical'),'Invalid npm package advisory')
        expected={k:package.get(k) for k in ('name','severity','isDirect','range','fixAvailable')}
        require(summary['packages'].count(expected)==1,'npm advisory summary mismatch')
        observed[package['severity']]+=1
    require(all(observed[k]==counts[k] for k in observed),'npm package severities contradict counts')
    if persist:
        # Only validated, single-document JSON streams receive acceptance names.
        for name,value in [('npm-audit.json',record['auditStdout']),('npm-audit-summary.json',record['summaryStdout'])]:
            with (root/name).open('x',encoding='utf-8',newline='') as stream: stream.write(value)
    else:
        require((root/'npm-audit.json').read_bytes()==record['auditStdout'].encode('utf-8')
                and (root/'npm-audit-summary.json').read_bytes()==record['summaryStdout'].encode('utf-8'),'Validated audit evidence changed')
    return record

def audit_builder(root):
    active().require_phase('native-linux-execution');active().require_execution(root)
    q=inputs(root);host();builds=read(root/'builds.json');identity=builds['builder']['image']['id']
    name='zevyrn-qualification-'+q['runID']+'-npm-audit'
    # Only this build-tool container needs registry egress; no host mounts/socket.
    command=DOCKER+['run','--rm','--name',name,'--pull','never','--network','bridge','--user','10001:10001',
        '--label','org.zevyrn.qualification='+name,'--label','traefik.enable=false',
        '--label','com.centurylinklabs.watchtower.enable=false',
        '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--memory','256m','--cpus','1','--pids-limit','128','--tmpfs','/tmp:rw,noexec,nosuid,size=64m,mode=1777',
        '--env','HOME=/tmp',identity,'node','-e',audit_script()]
    capture_audit(command,root)
    record=audit_evidence(root,persist=True)
    save(root/'npm-audit-binding.json',{'builderImageID':identity,'sourceManifestSHA256':q['sourceManifestSHA256'],
         'summarySHA256':sha(root/'npm-audit-summary.json'),'reportSHA256':sha(root/'npm-audit.json'),
         'captureSHA256':sha(root/'npm-audit-capture.json'),'stderrSHA256':sha(root/'npm-audit.stderr.log'),
         'exitSHA256':sha(root/'npm-audit-exit.json'),'npmExitCode':record['npmExitCode']})
    return {'npmAuditPassed':True}

def accept(root):
    active().require_phase('native-linux-execution');active().require_execution(root)
    inputs(root); env=schema_environment()
    import qualification_evidence as qe
    # Only the official schema/dependency resource location changes, not logic.
    qe.HERE=env
    from acceptance_gate import validate_bundle
    result=validate_bundle(root)
    builds=read(root/'builds.json')
    # Recompute copy/identity evidence; do not trust a previously passed flag.
    old=root/'filesystem-equivalence.json'; expected=read(old)
    require(filesystem_gate(root,builds,persist=False)==expected,'Filesystem evidence changed')
    result['filesystemSHA256']=sha(old)
    result['scope']='image vulnerability/secret/package/SBOM acceptance; application/browser and deployment approval remain separate'
    save(root/'accepted.json',result)
    return {'accepted':True,'runtimeImageID':result['runtimeImageID']}

def verify_acceptance(root):
    """Fresh read-only decision immediately before any disposable run."""
    inputs(root); env=schema_environment()
    import qualification_evidence as qe
    qe.HERE=env
    from acceptance_gate import validate_bundle
    actual=validate_bundle(root); saved=read(root/'accepted.json')
    for key in ('runtimeImageID','images','sourceManifestSHA256','boundFiles','databaseSHA256'):
        require(saved[key]==actual[key],'Acceptance input changed: '+key)
    require(saved['filesystemSHA256']==sha(root/'filesystem-equivalence.json'),'Filesystem record changed')
    require(filesystem_gate(root,read(root/'builds.json'),persist=False)==read(root/'filesystem-equivalence.json'),'Filesystem/builder relationship changed')
    extra_security(root,actual)
    return actual

def extra_security(root,accepted):
    source=read(root/'source-secret-binding.json'); audit=read(root/'npm-audit-binding.json')
    require(source['sourceManifestSHA256']==audit['sourceManifestSHA256']==accepted['sourceManifestSHA256'],'Additional security source mismatch')
    require(source['reportSHA256']==sha(root/'source-secrets.json'),'Source secret report changed')
    require(source['scannerBinarySHA256']==read(root/'evidence-context.json')['scannerBinarySHA256'],'Source scanner changed')
    require(source['scannerExitCode']==0 and source['scanners']==['secret'],'Source scanner execution mismatch')
    report=read(root/'source-secrets.json')
    validate_source_report(report,source['sourceArtifactName'])
    require(audit['builderImageID']==accepted['images']['builder']['imageID'],'Audit builder mismatch')
    require(audit['summarySHA256']==sha(root/'npm-audit-summary.json'),'npm audit changed')
    record=audit_evidence(root)
    require(audit.get('npmExitCode')==record['npmExitCode'] and all(audit.get(key)==sha(root/name) for key,name in
            [('reportSHA256','npm-audit.json'),('captureSHA256','npm-audit-capture.json'),
             ('stderrSHA256','npm-audit.stderr.log'),('exitSHA256','npm-audit-exit.json')]),'npm audit binding changed')
    summary=read(root/'npm-audit-summary.json');counts=summary.get('counts',{})
    require(summary.get('blocked') is False and all(type(counts.get(k)) is int and counts[k]>=0 for k in ('low','moderate','high','critical'))
            and counts['high']==counts['critical']==0,'npm security gate failed')

def runtime_command(identity,name,port=None):
    require(re.fullmatch(r'sha256:[0-9a-f]{64}',identity) and re.fullmatch('zevyrn-qualification-[a-z0-9-]+',name),'Unsafe runtime identity/name')
    command=DOCKER+['run','-d','--name',name,'--pull','never','--label','org.zevyrn.qualification='+name,
                   '--label','traefik.enable=false','--label','com.centurylinklabs.watchtower.enable=false',
                   '--user','10001:10001','--read-only','--cap-drop','ALL',
                   '--security-opt','no-new-privileges:true','--pids-limit','128','--memory','128m','--cpus','1',
                   '--tmpfs','/tmp:rw,noexec,nosuid,size=16m,mode=1777']
    if port is None: command+=['--network','none']
    else:
        require(type(port) is int and 1024<=port<=65535,'Invalid loopback test port')
        command+=['--network','bridge','-p','127.0.0.1:'+str(port)+':8080']
    return command+[identity]

def image_only(before,after,image):
    expected=json.loads(json.dumps(before))
    require(set(before['services'])=={'keysmith'},'Unexpected deployment service ownership')
    expected['services']['keysmith']['image']=image
    require(after==expected,'Deployment changes more than application image')
    return True

def override(root,base,rendered):
    accepted=verify_acceptance(root); identity=accepted['runtimeImageID']
    require(re.fullmatch('sha256:[0-9a-f]{64}',identity) is not None,'Invalid qualified image ID')
    image_only(read(base),read(rendered),identity)
    return {'verified':True,'image':identity,'note':'Use immutable ID in services.keysmith.image; no build or pull'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('phase',choices=['prepare','build','scan','source-scan','npm-audit','accept','verify-acceptance','verify-override'])
    p.add_argument('run',type=Path);p.add_argument('--base',type=Path);p.add_argument('--rendered',type=Path)
    a=p.parse_args();root=a.run.resolve();ctx=active();ctx.require_execution(root);configure()
    ctx.require_phase('readiness' if a.phase in ('prepare','verify-acceptance','verify-override') else 'native-linux-execution')
    if a.phase in ('build','npm-audit'): host()  # Never run final inventory against an unverified host.
    try:
        if a.phase=='prepare': result=prepare(root)
        elif a.phase=='build': result=stage_build(root)
        elif a.phase=='scan': result=scan(root)
        elif a.phase=='source-scan':result=source_scan(root)
        elif a.phase=='npm-audit':result=audit_builder(root)
        elif a.phase=='accept': result=accept(root)
        elif a.phase=='verify-acceptance': result=verify_acceptance(root)
        else: result=override(root,a.base,a.rendered)
    finally:
        if a.phase in ('build','npm-audit') and (root/'workloads-before.json').exists():
            after=snapshot();save(root/('workloads-after-'+a.phase+'-finally.json'),after)
            require(after==read(root/'workloads-before.json'),'Existing workload changed, including failed attempt')
            after_resources=resources();save(root/('resources-after-'+a.phase+'.json'),after_resources)
            require(after_resources==read(root/'resources-before.json'),'Existing networks/volumes changed')
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
