import {test} from 'node:test';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import assert from 'node:assert/strict';
import {hash,inspectGraph,diagnosticCode,inspectionDiagnostic,sanitizedToolIdentity,qualificationIdentity,validatePacketPurpose,validateConfig,validateRun,validateEvidence,validateTags,validateReleaseRef,validateQuality,verifyLoaded,verifyContainer,repository,repositoryId,suites} from '../scripts/release-integrity.mjs';
const source='a'.repeat(40),tree='b'.repeat(40),now=Date.UTC(2026,10,16,5),sha='sha256:'+'c'.repeat(64);
const clone=structuredClone;
const mt='application/vnd.oci.image.manifest.v1+json',it='application/vnd.oci.image.index.v1+json',ct='application/vnd.oci.image.config.v1+json';
function config(){return {os:'linux',architecture:'amd64',rootfs:{type:'layers',diff_ids:[sha]},config:{User:'10001:10001',WorkingDir:'/',StopSignal:'SIGQUIT',Entrypoint:['nginx'],Cmd:['-g','daemon off;'],ExposedPorts:{'8080/tcp':{}},Healthcheck:{Test:['CMD-SHELL','wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1'],Interval:30000000000,Timeout:3000000000,StartPeriod:10000000000,Retries:3},Env:['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','NGINX_VERSION=1.30.6','PKG_RELEASE=1','DYNPKG_RELEASE=1','NJS_VERSION=1.0.2','NJS_RELEASE=1','ACME_VERSION=0.4.1'],Labels:{'org.opencontainers.image.version':'1.2.2','org.opencontainers.image.revision':source,'org.opencontainers.image.source':'https://github.com/'+repository}}};}
function graph(change=()=>{},attest=true){
  const members=new Map(),store=(value,mediaType)=>{const bytes=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value));const digest='sha256:'+hash(bytes);members.set('blobs/sha256/'+digest.slice(7),bytes);return {mediaType,digest,size:bytes.length};};
  const c=config(),s={_type:'https://in-toto.io/Statement/v1',predicateType:'https://slsa.dev/provenance/v1',subject:[],predicate:{}};
  const model={config:c,statement:s,extra:null,duplicate:false,corrupt:false,orphan:false,duplicateMember:false,artifact:false,attestationConfig:null,attestationConfigType:null,artifactType:null,manifestSubject:null,badSize:false};change(model);
  const runtime={...store({schemaVersion:2,mediaType:mt,config:store(c,ct),layers:[store(Buffer.from('synthetic compressed layer'),'application/vnd.oci.image.layer.v1.tar+gzip')]},mt),platform:{os:'linux',architecture:'amd64'}};
  if(model.badSize)runtime.size++;
  const descriptors=[runtime];if(model.duplicate)descriptors.push(clone(runtime));
  if(attest){if(!s.subject.length)s.subject=[{name:'runtime',digest:{sha256:runtime.digest.slice(7)}}];const layer={...store(s,'application/vnd.in-toto+json'),annotations:{'in-toto.io/predicate-type':s.predicateType}};const legacy={architecture:'unknown',os:'unknown',config:{},rootfs:{type:'layers',diff_ids:[layer.digest]}};const manifest={schemaVersion:2,mediaType:mt,config:store(model.attestationConfig??(model.artifact?{}:legacy),model.attestationConfigType??(model.artifact?'application/vnd.oci.empty.v1+json':ct)),layers:[layer]};if(model.artifact){manifest.artifactType=model.artifactType??'application/vnd.docker.attestation.manifest.v1+json';manifest.subject=model.manifestSubject??{mediaType:runtime.mediaType,digest:runtime.digest,size:runtime.size};}descriptors.push({...store(manifest,mt),platform:{os:'unknown',architecture:'unknown'},annotations:{'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':runtime.digest}});}
  if(model.extra)descriptors.push({...clone(runtime),platform:model.extra});
  const index={schemaVersion:2,mediaType:it,manifests:descriptors};members.set('index.json',Buffer.from(JSON.stringify({schemaVersion:2,mediaType:it,manifests:[store(index,it)]})));members.set('oci-layout',Buffer.from('{"imageLayoutVersion":"1.0.0"}'));
  if(model.corrupt)members.set('blobs/sha256/'+runtime.digest.slice(7),Buffer.from('{}'));
  if(model.orphan)store({unexpected:'unreferenced manifest'},mt);
  const names=[...members.keys()];if(model.duplicateMember)names.push('index.json');
  return ()=>inspectGraph(name=>{assert(members.has(name));return members.get(name);},names,source);
}
test('OCI graph accepts only one runtime and recognized subject-bound provenance, including no-attestation case',()=>{assert.equal(graph()().version,'1.2.2');assert.equal(graph(()=>{},false)().version,'1.2.2');});
test('OCI graph separately accepts documented legacy image and OCI artifact attestation configurations',()=>{
  assert.equal(graph()().version,'1.2.2');assert.equal(graph(m=>m.artifact=true)().version,'1.2.2');
});
const rejectsCode=(operation,code)=>assert.throws(operation,error=>diagnosticCode(error)===code);
test('attestation config rejects wrong media types, hybrid formats, bad content and artifact types',()=>{
  for(const change of [m=>m.attestationConfig={},m=>m.attestationConfigType='unknown',m=>m.attestationConfigType='application/vnd.oci.empty.v1+json',
    m=>{m.artifact=true;m.attestationConfigType=ct;},m=>{m.artifact=true;m.attestationConfig={unexpected:'content'};},
    m=>{m.artifact=true;m.artifactType='unknown';},m=>m.attestationConfig={architecture:'amd64',os:'linux',config:{},rootfs:{type:'layers',diff_ids:[]}},
    m=>m.attestationConfig={architecture:'unknown',os:'unknown',config:{},rootfs:{type:'layers',diff_ids:[sha]}}]){
    rejectsCode(graph(change),'OCI_ATTESTATION_CONFIG_INVALID');
  }
});
test('OCI artifact manifest subject must match runtime digest, media type and size',()=>{
  for(const subject of [{mediaType:mt,digest:sha,size:1},{mediaType:'unknown',digest:sha,size:1},{}])
    rejectsCode(graph(m=>{m.artifact=true;m.manifestSubject=subject;}),'OCI_PROVENANCE_SUBJECT_INVALID');
});
test('digest and size corruption, duplicate runtime and changed runtime protections retain specific blocking codes',()=>{
  for(const change of [m=>m.badSize=true,m=>m.corrupt=true])rejectsCode(graph(change),'OCI_BLOB_DIGEST_MISMATCH');
  rejectsCode(graph(m=>m.duplicate=true),'OCI_RUNTIME_DESCRIPTOR_INVALID');
  for(const change of [c=>c.config.User='0',c=>c.config.Labels['org.opencontainers.image.revision']=tree,c=>c.config.Healthcheck.Retries=1])
    rejectsCode(graph(m=>change(m.config)),'OCI_RUNTIME_CONFIG_INVALID');
  rejectsCode(graph(m=>m.statement.subject=[{digest:{sha256:'d'.repeat(64)}}]),'OCI_PROVENANCE_SUBJECT_INVALID');
});
test('diagnostic codes cannot be spoofed by secret-like messages or exception properties',()=>{
  const secret='TOKEN=fixture-secret-do-not-print';const error=Object.assign(new Error(secret),{code:'OCI_LAYOUT_INVALID',stage:secret});
  assert.equal(diagnosticCode(error),'RELEASE_INTEGRITY_UNEXPECTED');
  assert.equal(JSON.stringify(inspectionDiagnostic(diagnosticCode(error))).includes(secret),false);
  assert.throws(()=>inspectionDiagnostic(secret));
  assert.equal(inspectionDiagnostic('OCI_LAYOUT_INVALID').promotionEligible,false);
});
test('tool diagnostics accept only recognized version and immutable image identity fields',()=>{
  const image='sha256:'+'e'.repeat(64);
  assert.deepEqual(sanitizedToolIdentity('github.com/docker/buildx v0.30.1 abc','Nodes:\nBuildKit version: v0.26.2\n',image+'\n'),{buildxVersion:'v0.30.1',buildkitVersion:'v0.26.2',buildkitImageID:image});
  assert.equal(sanitizedToolIdentity('','BuildKit:       v0.26.2','').buildkitVersion,'v0.26.2');
  assert.deepEqual(sanitizedToolIdentity('TOKEN=fixture-secret v1.2.3','TOKEN=fixture-secret v1.2.3','TOKEN=fixture-secret'),{buildxVersion:null,buildkitVersion:null,buildkitImageID:null});
});
test('CLI inspection failures emit one safe code, retain sanitized results and exit 1',()=>{
  const directory=mkdtempSync(join(tmpdir(),'zevyrn-inspection-diagnostics-')),output=join(directory,'inspection.json');
  const env={...process.env,GITHUB_SHA:source};delete env.QUALIFICATION_KIND;
  const git=spawnSync('git',['rev-parse','HEAD'],{encoding:'utf8'});
  const result=spawnSync(process.execPath,['scripts/release-integrity.mjs','inspect',join(directory,'TOKEN=fixture-secret.oci.tar'),join(directory,'identity.json'),output],{env,encoding:'utf8'});
  const code=git.status===0?'OCI_ARCHIVE_READ_INVALID':'SOURCE_IDENTITY_INVALID';
  assert.equal(result.status,1);assert.equal(result.stdout,'');assert.equal(result.stderr.trim(),code);
  assert.deepEqual(JSON.parse(readFileSync(output)),inspectionDiagnostic(code));
  const fallback=spawnSync(process.execPath,['scripts/release-integrity.mjs','TOKEN=fixture-secret'],{encoding:'utf8'});
  assert.equal(fallback.status,1);assert.equal(fallback.stdout,'');assert.equal(fallback.stderr.trim(),'RELEASE_INTEGRITY_UNEXPECTED');
});
test('CLI diagnostic evidence contains only archive hash, validated index digest and sanitized tool identities',()=>{
  const directory=mkdtempSync(join(tmpdir(),'zevyrn-failed-evidence-')),archive=join(directory,'archive'),metadata=join(directory,'metadata'),output=join(directory,'diagnostics.json');
  writeFileSync(archive,'synthetic archive fixture');writeFileSync(metadata,JSON.stringify({'containerimage.digest':sha,secret:'TOKEN=fixture-secret'}));
  for(const name of ['release-buildx.txt','release-buildkit.txt','release-buildkit-image.txt'])writeFileSync(join(directory,name),'TOKEN=fixture-secret');
  const result=spawnSync(process.execPath,['scripts/release-integrity.mjs','diagnostics',archive,metadata,output],{env:{...process.env,RUNNER_TEMP:directory},encoding:'utf8'});
  assert.equal(result.status,0);assert.equal(result.stdout,'');assert.equal(result.stderr,'');
  assert.deepEqual(JSON.parse(readFileSync(output)),{schemaVersion:1,promotionEligible:false,archiveSHA256:hash(Buffer.from('synthetic archive fixture')),indexDigest:sha,indexDigestVerified:false,buildxVersion:null,buildkitVersion:null,buildkitImageID:null});
  writeFileSync(metadata,JSON.stringify({'containerimage.digest':'TOKEN=fixture-secret'}));
  const malformed=spawnSync(process.execPath,['scripts/release-integrity.mjs','diagnostics',join(directory,'missing'),metadata,output],{env:{...process.env,RUNNER_TEMP:directory},encoding:'utf8'});
  assert.equal(malformed.status,0);const sanitized=JSON.parse(readFileSync(output));assert.equal(sanitized.archiveSHA256,null);assert.equal(sanitized.indexDigest,null);
});
test('OCI graph rejects additional platforms, duplicate runtimes, orphan blobs, corrupt blobs and duplicate members',()=>{for(const change of [m=>m.extra={os:'linux',architecture:'arm64'},m=>m.extra={os:'windows',architecture:'amd64'},m=>m.duplicate=true,m=>m.orphan=true,m=>m.corrupt=true,m=>m.duplicateMember=true])assert.throws(graph(change));});
test('OCI graph rejects unknown provenance and incorrect or multiple attestation subjects',()=>{for(const change of [m=>m.statement.predicateType='https://unrecognized',m=>m.statement._type='unknown',m=>m.statement.subject=[{digest:{sha256:'d'.repeat(64)}}],m=>m.statement.subject=[{digest:{sha256:'d'.repeat(64)}},{digest:{sha256:'e'.repeat(64)}}]])assert.throws(graph(change));});
test('archive config rejects historical version, false source labels and changed runtime protections',()=>{for(const change of [c=>c.config.Labels['org.opencontainers.image.version']='1.2.1',c=>c.config.Labels['org.opencontainers.image.revision']='f'.repeat(40),c=>c.config.User='0',c=>c.config.Entrypoint=['sh'],c=>c.config.Env.push('EXTRA=1'),c=>c.config.ExposedPorts['80/tcp']={},c=>c.config.Healthcheck.Retries=1]){const c=config();change(c);assert.throws(()=>validateConfig(c,source));}});
function runFixture(){const start=new Date(now-600000).toISOString();return {run:{id:42,run_attempt:2,repository:{id:repositoryId,full_name:repository},head_repository:{id:repositoryId},path:'.github/workflows/qualify-maintenance-image.yml',event:'workflow_dispatch',head_branch:'main',head_sha:source,status:'completed',conclusion:'success',created_at:start,run_started_at:start},jobs:{total_count:3,jobs:['runtime','browser','seal'].map((name,id)=>({id,name,run_id:42,run_attempt:2,status:'completed',conclusion:'success'}))},artifacts:{total_count:1,artifacts:[{id:9,name:'zevyrn-v1.2.2-qualified-42-2',size_in_bytes:100,digest:sha,expired:false,created_at:new Date(now).toISOString(),workflow_run:{id:42,head_sha:source,head_branch:'main',repository_id:repositoryId,head_repository_id:repositoryId}}]}};}
const assess=f=>validateRun(f.run,f.jobs,f.artifacts,source,now);
test('qualification selects the immutable artifact from the exact successful source/run/attempt',()=>{assert.equal(assess(runFixture()).artifactId,9);});
test('qualification rejects wrong repository, workflow, source, branch, event, status, conclusion and stale runs',()=>{for(const change of [f=>f.run.repository.id++,f=>f.run.head_repository.id++,f=>f.run.path='.github/workflows/other.yml',f=>f.run.head_sha='d'.repeat(40),f=>f.run.head_branch='other',f=>f.run.event='pull_request',f=>f.run.status='in_progress',f=>f.run.conclusion='failure',f=>f.run.created_at=new Date(now-86400001).toISOString()]){const f=runFixture();change(f);assert.throws(()=>assess(f));}});
test('qualification rejects every unsuccessful, skipped, missing, duplicate or previous-attempt required job',()=>{for(let i=0;i<3;i++)for(const change of [j=>j.conclusion='failure',j=>j.conclusion='skipped',j=>j.status='in_progress',j=>j.run_attempt=1,j=>j.run_id=41]){const f=runFixture();change(f.jobs.jobs[i]);assert.throws(()=>assess(f));}for(const change of [f=>f.jobs.jobs.pop(),f=>f.jobs.jobs[2]=clone(f.jobs.jobs[0])]){const f=runFixture();change(f);assert.throws(()=>assess(f));}});
test('qualification rejects expired, duplicate, foreign, wrong-attempt and unauthenticated artifacts',()=>{for(const change of [f=>f.artifacts.artifacts[0].expired=true,f=>f.artifacts.artifacts[0].name='zevyrn-v1.2.2-qualified-42-1',f=>f.artifacts.artifacts[0].digest='invalid',f=>f.artifacts.artifacts[0].workflow_run.head_sha='d'.repeat(40),f=>f.artifacts.artifacts[0].workflow_run.repository_id++,f=>f.artifacts.artifacts[0].created_at=new Date(now-86400000).toISOString(),f=>{f.artifacts.artifacts.push(clone(f.artifacts.artifacts[0]));f.artifacts.total_count++;}]){const f=runFixture();change(f);assert.throws(()=>assess(f));}});
function evidenceFixture(){const identity={version:'1.2.2',sourceCommit:source,sourceTree:tree,archiveSHA256:'c'.repeat(64),indexDigest:sha,assetsSHA256:'d'.repeat(64)};const context={purpose:'release',pullRequest:null,qualityEvent:'push',qualityBranch:'main',runId:42,runAttempt:2,sourceCommit:source,sourceTree:tree,startedAt:now-600000};const evidence={browser:{...context,archiveSHA256:identity.archiveSHA256,indexDigest:sha,assetsSHA256:identity.assetsSHA256,suites:suites.map(name=>({name,conclusion:'success'}))},health:{archiveSHA256:identity.archiveSHA256,indexDigest:sha,passed:true,checks:['image-config-and-rootfs','container-hardening','health','nginx-config','headers','assets','no-build-tools','graceful-stop']},runtime:{blocked:false,blockingVulnerabilities:0,secrets:0,results:[]},builder:{blocked:false,blockingVulnerabilities:0,secrets:0,approvedHighCount:3,unapprovedHighCount:0},builderIdentity:{sourceCommit:source,sourceTree:tree,imageID:sha,archiveSHA256:"f".repeat(64)},npm:{blocked:false,counts:{high:0,critical:0}},scanner:{Version:'0.76.0',VulnerabilityDB:{Version:2,UpdatedAt:new Date(now-600000).toISOString(),DownloadedAt:new Date(now).toISOString(),NextUpdate:new Date(now+86400000).toISOString()}},sbom:{bomFormat:'CycloneDX',components:[{name:'nginx'}]}};return {identity,context,evidence};}
const evidenceCheck=f=>validateEvidence(f.identity,f.evidence,f.context);
test('qualification evidence accepts exact archive/source/assets with all required results',()=>{evidenceCheck(evidenceFixture());});
test('qualification evidence rejects mismatched archives, source, assets, failed browser/runtime, missing SBOM and unsafe scans',()=>{for(const change of [f=>f.evidence.browser.archiveSHA256='e'.repeat(64),f=>f.evidence.browser.sourceTree='e'.repeat(40),f=>f.evidence.browser.assetsSHA256='e'.repeat(64),f=>f.evidence.browser.suites[0].conclusion='failure',f=>f.evidence.browser.suites.pop(),f=>f.evidence.health.passed=false,f=>f.evidence.health.checks.pop(),f=>f.evidence.runtime.blocked=true,f=>f.evidence.builder.secrets=1,f=>f.evidence.builder.unapprovedHighCount=1,f=>f.evidence.builderIdentity.sourceCommit=tree,f=>f.context.startedAt=null,f=>f.evidence.runtime.results=[{vulnerabilities:[{id:'CVE-2026-107891',severity:'MEDIUM'}]}],f=>delete f.evidence.sbom,f=>delete f.evidence.scanner.VulnerabilityDB,f=>f.evidence.scanner.Version='other',f=>f.evidence.scanner.VulnerabilityDB.DownloadedAt=new Date(now-86400000).toISOString()]){const f=evidenceFixture();change(f);assert.throws(()=>evidenceCheck(f));}});
test('derived Docker image must preserve exact rootfs and execution configuration',()=>{const identity={config:config(),diffIDs:[sha]},image={Os:'linux',Architecture:'amd64',Config:clone(identity.config.config),RootFS:{Layers:[sha]}};verifyLoaded(identity,image);for(const change of [i=>i.RootFS.Layers=[sha256Other()],i=>i.Config.Env.push('UNEXPECTED=1'),i=>i.Config.User='0']){const i=clone(image);change(i);assert.throws(()=>verifyLoaded(identity,i));}});
function sha256Other(){return 'sha256:'+'d'.repeat(64);}
test('container checks reject any loss of hardened execution settings',()=>{const c={Config:{User:'10001:10001'},State:{Running:true},HostConfig:{ReadonlyRootfs:true,Privileged:false,NetworkMode:'none',PidsLimit:128,Memory:134217728,CapDrop:['ALL'],CapAdd:null,SecurityOpt:['no-new-privileges'],Tmpfs:{'/tmp':'rw,noexec,nosuid,size=16m,mode=1777'}}};verifyContainer(c);for(const change of [x=>x.HostConfig.ReadonlyRootfs=false,x=>x.HostConfig.Privileged=true,x=>x.HostConfig.NetworkMode='default',x=>x.HostConfig.CapAdd=['SYS_ADMIN'],x=>x.HostConfig.SecurityOpt=[],x=>x.HostConfig.Tmpfs['/tmp']='rw',x=>x.Config.User='0']){const x=clone(c);change(x);assert.throws(()=>verifyContainer(x));}});
test('documented Skopeo Repository/Tags response accepts an absent destination and existing historical tags',()=>{
  validateTags({Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:['1.2.1','1.1.0']});
  validateTags({Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:[]});
});
test('Skopeo tag validation fails closed on wrong identity, missing fields, malformed tags or existing destination',()=>{
  for(const response of [null,{},[],{name:'thestateofwhere/zevyrn',Tags:[]},{Tags:[]},{Repository:'ghcr.io/thestateofwhere/zevyrn'},
    {Repository:'docker.io/thestateofwhere/zevyrn',Tags:[]},{Repository:'ghcr.io/other/zevyrn',Tags:[]},
    {Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:null},{Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:[null]},
    {Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:['']},{Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:['bad/tag']},
    {Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:['1.2.1','1.2.1']},{Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:['1.2.2']},
    {Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:[],unexpected:true}])assert.throws(()=>validateTags(response));
});

test('only the exact lightweight or peeled v1.2.2 release tag can authorize promotion',()=>{validateReleaseRef(source+'\trefs/tags/v1.2.2\n',source);validateReleaseRef(tree+'\trefs/tags/v1.2.2\n'+source+'\trefs/tags/v1.2.2^{}\n',source);for(const text of ['',source+'\trefs/tags/v1.2.1\n',tree+'\trefs/tags/v1.2.2\n',source+'\trefs/tags/v1.2.2\n'+source+'\trefs/tags/v1.2.2\n'])assert.throws(()=>validateReleaseRef(text,source));});
test('existing source CI cannot be replaced by a skipped, failed, unrelated or prior-attempt job',()=>{const f=runFixture();f.run.path='.github/workflows/quality-security.yml';f.run.event='push';f.jobs.total_count=2;f.jobs.jobs=f.jobs.jobs.slice(0,2);f.jobs.jobs[0].name='quality-image';validateQuality(f.run,f.jobs,source);for(const change of [x=>x.run.head_sha=tree,x=>x.run.conclusion='failure',x=>x.jobs.jobs[1].conclusion='skipped',x=>x.jobs.jobs[1].run_attempt=1,x=>x.run.path='.github/workflows/other.yml']){const x=clone(f);change(x);assert.throws(()=>validateQuality(x.run,x.jobs,source));}});

function prFixture(){return {env:{GITHUB_REPOSITORY:repository,GITHUB_EVENT_NAME:'pull_request',GITHUB_REF:'refs/pull/2/merge',GITHUB_SHA:tree},event:{repository:{id:repositoryId},number:2,pull_request:{number:2,head:{sha:source,ref:'codex/v1.2.2-security-maintenance',repo:{id:repositoryId}},base:{ref:'main',repo:{id:repositoryId}}}}};}
test('automatic PR qualification binds actual checked-out head, never the synthetic merge SHA',()=>{
  const f=prFixture(),identity=qualificationIdentity(f.env,f.event,source);
  assert.equal(identity.sourceCommit,source);assert.notEqual(identity.sourceCommit,f.env.GITHUB_SHA);
  assert.equal(identity.purpose,'pr');assert.equal(identity.pullRequest,2);assert.equal(identity.qualityEvent,'pull_request');
  assert.throws(()=>qualificationIdentity(f.env,f.event,tree));
});
test('PR qualification rejects wrong repository, foreign heads, wrong base, ref, number and unsafe branch',()=>{
  for(const change of [f=>f.env.GITHUB_REPOSITORY='other/repo',f=>f.event.repository.id++,f=>f.event.pull_request.head.repo.id++,
    f=>f.event.pull_request.base.repo.id++,f=>f.event.pull_request.base.ref='other',f=>f.env.GITHUB_REF='refs/heads/main',
    f=>f.event.number=3,f=>f.event.pull_request.head.sha=tree,f=>f.event.pull_request.head.ref='bad\nbranch']){
    const f=prFixture();change(f);assert.throws(()=>qualificationIdentity(f.env,f.event,source));
  }
});
test('release qualification still requires a fresh dispatch on exact main source',()=>{
  const env={GITHUB_REPOSITORY:repository,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REF:'refs/heads/main',GITHUB_SHA:source};
  const event={repository:{id:repositoryId},inputs:{source_commit:source}};
  assert.equal(qualificationIdentity(env,event,source).purpose,'release');
  assert.throws(()=>qualificationIdentity({...env,GITHUB_REF:'refs/heads/codex/test'},event,source));
  assert.throws(()=>qualificationIdentity(env,{...event,inputs:{source_commit:tree}},source));
  assert.throws(()=>qualificationIdentity(env,event,tree));
});
test('PR source CI requires the exact head and corresponding same-repository PR',()=>{
  const f=runFixture(),q=qualificationIdentity(prFixture().env,prFixture().event,source);
  f.run.path='.github/workflows/quality-security.yml';f.run.event='pull_request';f.run.head_branch=q.qualityBranch;
  f.run.pull_requests=[{number:2,head:{sha:source,ref:q.qualityBranch,repo:{id:repositoryId}},base:{ref:'main',repo:{id:repositoryId}}}];
  f.jobs.total_count=2;f.jobs.jobs=f.jobs.jobs.slice(0,2);f.jobs.jobs[0].name='quality-image';validateQuality(f.run,f.jobs,source,q);
  assert.throws(()=>validateQuality(f.run,f.jobs,source));
  for(const change of [x=>x.run.head_sha=tree,x=>x.run.pull_requests[0].number=3,x=>x.run.pull_requests[0].head.repo.id++,
    x=>x.run.head_branch='other',x=>x.jobs.jobs[1].conclusion='skipped']){const x=clone(f);change(x);assert.throws(()=>validateQuality(x.run,x.jobs,source,q));}
});
test('successful PR runs and PR-named artifacts remain rejected by the promotion run validator',()=>{
  const f=runFixture();f.run.event='pull_request';f.run.head_branch='codex/v1.2.2-security-maintenance';
  f.artifacts.artifacts[0].name='zevyrn-v1.2.2-pr-qualified-42-2';assert.throws(()=>assess(f));
  const other=runFixture();other.artifacts.artifacts[0].name='zevyrn-v1.2.2-pr-qualified-42-2';assert.throws(()=>assess(other));
});
test('PR packets are explicitly non-promotable even if their eligibility flag is tampered',()=>{
  const expected={purpose:'pr',pullRequest:2},packet={purpose:'pr',promotionEligible:false,context:{purpose:'pr',pullRequest:2,qualityEvent:'pull_request',qualityBranch:'codex/v1.2.2-security-maintenance'}};
  validatePacketPurpose(packet,expected);
  assert.throws(()=>validatePacketPurpose(packet,{purpose:'release',pullRequest:null}));
  assert.throws(()=>validatePacketPurpose({...packet,promotionEligible:true},expected));
  const disguised={...packet,purpose:'release',promotionEligible:true,context:{...packet.context,purpose:'release',pullRequest:null}};
  assert.throws(()=>validatePacketPurpose(disguised,{purpose:'release',pullRequest:null}));
  validatePacketPurpose({purpose:'release',promotionEligible:true,context:{purpose:'release',pullRequest:null,qualityEvent:'push',qualityBranch:'main'}},{purpose:'release',pullRequest:null});
});
