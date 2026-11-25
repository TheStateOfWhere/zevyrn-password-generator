import {test} from 'node:test';
import {gzipSync} from 'node:zlib';
import {Readable} from 'node:stream';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,readFileSync,existsSync,mkdirSync,renameSync,symlinkSync,cpSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import assert from 'node:assert/strict';
import {qualityIdentity,validateQualityArtifact,validateQualityRecord,validateQualitySecurity,validateQualityBrowser,inspectArchive,qualityZip,releaseFreshness,combinedEntry,selectQualityRun,authenticateMainQuality,inspectBuilderGraph,inspectBuilderArchive,validateBuilderBinding,validateCombinedPhase,validateReleaseReceipt,validateVersionCollision,authenticatePackets,combinedSecurity,snapshot} from '../scripts/release-integrity.mjs';
import {hash,inspectDockerGraph,inspectDockerArchive,validateScanIdentity,validateRuntimeReportIdentity,validateSBOMIdentity,validateCompleteScanEvidence,runtimeScanArgs,sanitizedFailureStages,sanitizedScannerMetadata,sanitizedScanSummary,assetSnapshot,validateRuntimeAssets,verifyRetainedAssets,nginxAssetSHA256,inspectGraph,diagnosticCode,inspectionDiagnostic,sanitizedToolIdentity,qualificationIdentity,validatePacketPurpose,validateConfig,validateRun,validateEvidence,validateTags,validateReleaseRef,validateQuality,verifyLoaded,verifyContainer,repository,repositoryId,suites} from '../scripts/release-integrity.mjs';
const source='a'.repeat(40),tree='b'.repeat(40),now=Date.UTC(2026,10,16,5),sha='sha256:'+'c'.repeat(64);
const clone=structuredClone;
const nginxPage=`<!DOCTYPE html>
<html>
<head>
<title>Error</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>An error occurred.</h1>
<p>Sorry, the page you are looking for is currently unavailable.<br/>
Please try again later.</p>
<p>If you are the system administrator of this resource then you should check
the error log for details.</p>
<p><em>Faithfully yours, nginx.</em></p>
</body>
</html>
`;
function assetFixture(){
  const root=mkdtempSync(join(tmpdir(),'zevyrn-asset-inventory-')),application=join(root,'application'),runtime=join(root,'assets');
  for(const directory of [application,runtime]){mkdirSync(join(directory,'licenses'),{recursive:true});writeFileSync(join(directory,'index.html'),'application fixture');writeFileSync(join(directory,'licenses','LICENSE.txt'),'license fixture');}
  writeFileSync(join(runtime,'50x.html'),nginxPage);return {root,application,runtime};
}
test('exact application-plus-approved-Nginx inventory validates actual recursive files and fixed hash',async()=>{
  assert.equal(hash(Buffer.from(nginxPage)),nginxAssetSHA256);const f=assetFixture();
  const runtime=await assetSnapshot(f.runtime);assert.deepEqual(validateRuntimeAssets(await assetSnapshot(f.application),runtime),runtime.files);
  assert.deepEqual(runtime.directories,['licenses']);assert.equal(runtime.files['50x.html'],nginxAssetSHA256);
});
test('asset inventory rejects missing, modified, renamed, extra and nested application files',async()=>{
  const f=assetFixture(),application=await assetSnapshot(f.application),runtime=await assetSnapshot(f.runtime);
  for(const change of [r=>delete r.files['index.html'],r=>r.files['index.html']='e'.repeat(64),r=>{r.files['renamed.html']=r.files['index.html'];delete r.files['index.html'];},
    r=>r.files['extra.txt']=sha.slice(7),r=>{r.files['unexpected/file.txt']=sha.slice(7);r.directories.push('unexpected');},r=>r.directories.push('empty')]){
    const r=clone(runtime);change(r);assert.throws(()=>validateRuntimeAssets(application,r));
  }
});
test('server asset must be present at the exact root path and cannot collide with application assets',async()=>{
  const f=assetFixture(),application=await assetSnapshot(f.application),runtime=await assetSnapshot(f.runtime);
  for(const change of [r=>delete r.files['50x.html'],r=>r.files['50x.html']='f'.repeat(64),r=>{r.files['licenses/50x.html']=r.files['50x.html'];delete r.files['50x.html'];}]){
    const r=clone(runtime);change(r);assert.throws(()=>validateRuntimeAssets(application,r));
  }
  for(const path of ['50x.html','licenses/50x.html']){const a=clone(application);a.files[path]=nginxAssetSHA256;assert.throws(()=>validateRuntimeAssets(a,runtime));}
  writeFileSync(join(f.runtime,'50x.html'),nginxPage.replace('Error','error'));assert.equal(readFileSync(join(f.runtime,'50x.html')).length,Buffer.byteLength(nginxPage));
  const awaitedRuntime=await assetSnapshot(f.runtime);assert.throws(()=>validateRuntimeAssets(application,awaitedRuntime));
});
test('asset paths reject traversal, absolute paths, separators, controls and portability collisions',async()=>{
  const f=assetFixture(),application=await assetSnapshot(f.application),runtime=await assetSnapshot(f.runtime);
  for(const path of ['../escape','/absolute','a/../escape','a//file','a/./file','a\\file','C:/file','bad\nfile','a/%2e%2e/file','NUL','con.txt','trailing.']){
    const r=clone(runtime);r.files[path]='a'.repeat(64);assert.throws(()=>validateRuntimeAssets(application,r));
  }
  const duplicate=clone(runtime);duplicate.files['INDEX.HTML']=duplicate.files['index.html'];assert.throws(()=>validateRuntimeAssets(application,duplicate));
  const collision=clone(runtime);collision.files.licenses='a'.repeat(64);assert.throws(()=>validateRuntimeAssets(application,collision));
});
test('filesystem enumeration rejects unexpected empty directories and changed or renamed files',async()=>{
  const f=assetFixture(),application=await assetSnapshot(f.application);renameSync(join(f.runtime,'index.html'),join(f.runtime,'renamed.html'));
  const awaitedRuntime=await assetSnapshot(f.runtime);assert.throws(()=>validateRuntimeAssets(application,awaitedRuntime));
  mkdirSync(join(f.application,'unexpected-empty'));await assert.rejects(assetSnapshot(f.application));
});
test('filesystem enumeration rejects directory symlinks/junctions including a linked root',async()=>{
  const f=assetFixture(),link=join(f.root,'linked-root');symlinkSync(f.application,link,process.platform==='win32'?'junction':'dir');await assert.rejects(assetSnapshot(link));
  symlinkSync(f.application,join(f.runtime,'linked-directory'),process.platform==='win32'?'junction':'dir');await assert.rejects(assetSnapshot(f.runtime));
});
test('filesystem enumeration rejects non-regular FIFO entries',{skip:process.platform==='win32'&&'POSIX FIFO entries are unavailable on Windows'},async()=>{
  const f=assetFixture();const fifo=spawnSync('mkfifo',[join(f.runtime,'pipe')],{encoding:'utf8'});assert.equal(fifo.status,0);await assert.rejects(assetSnapshot(f.runtime));
});
test('retained assets and manifest remain bound before browser qualification and packet sealing',async()=>{
  const f=assetFixture(),runtime=await assetSnapshot(f.runtime);validateRuntimeAssets(await assetSnapshot(f.application),runtime);
  const path=join(f.root,'assets.json');writeFileSync(path,JSON.stringify(runtime.files));const identity={assetsSHA256:hash(readFileSync(path))};await verifyRetainedAssets(f.root,identity);
  writeFileSync(join(f.runtime,'index.html'),'modified fixture!!!');await assert.rejects(verifyRetainedAssets(f.root,identity));
  const changed=await assetSnapshot(f.runtime);writeFileSync(path,JSON.stringify(changed.files));await assert.rejects(verifyRetainedAssets(f.root,identity));
  writeFileSync(path,JSON.stringify(runtime.files));writeFileSync(join(f.runtime,'index.html'),'application fixture');mkdirSync(join(f.runtime,'unexpected-empty'));await assert.rejects(verifyRetainedAssets(f.root,identity));
});
const mt='application/vnd.oci.image.manifest.v1+json',it='application/vnd.oci.image.index.v1+json',ct='application/vnd.oci.image.config.v1+json';
function config(){return {os:'linux',architecture:'amd64',rootfs:{type:'layers',diff_ids:[sha]},config:{User:'10001:10001',WorkingDir:'/',StopSignal:'SIGQUIT',Entrypoint:['nginx'],Cmd:['-g','daemon off;'],ExposedPorts:{'8080/tcp':{}},Healthcheck:{Test:['CMD-SHELL','wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1'],Interval:30000000000,Timeout:3000000000,StartPeriod:10000000000,Retries:3},Env:['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','NGINX_VERSION=1.30.8','PKG_RELEASE=1','DYNPKG_RELEASE=1','NJS_VERSION=1.0.2','NJS_RELEASE=1','ACME_VERSION=0.4.2'],Labels:{'org.opencontainers.image.version':'1.2.3','org.opencontainers.image.revision':source,'org.opencontainers.image.source':'https://github.com/'+repository}}};}
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
  const check=()=>inspectGraph(name=>{assert(members.has(name));return members.get(name);},names,source);
  check.members=members;return check;
}
test('OCI graph accepts only one runtime and recognized subject-bound provenance, including no-attestation case',()=>{assert.equal(graph()().version,'1.2.3');assert.equal(graph(()=>{},false)().version,'1.2.3');});
test('OCI graph separately accepts documented legacy image and OCI artifact attestation configurations',()=>{
  assert.equal(graph()().version,'1.2.3');assert.equal(graph(m=>m.artifact=true)().version,'1.2.3');
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
  const env={...process.env,GITHUB_SHA:source};delete env.QUALIFICATION_KIND;delete env.QUALITY_SOURCE;
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
  assert.deepEqual(JSON.parse(readFileSync(output)),{schemaVersion:1,promotionEligible:false,archiveSHA256:hash(Buffer.from('synthetic archive fixture')),indexDigest:sha,indexDigestVerified:false,runtimeConfigDigest:null,stages:null,failures:[],scanner:null,summaries:{runtime:null,builder:null},scanArchiveSHA256:null,buildxVersion:null,buildkitVersion:null,buildkitImageID:null});
  writeFileSync(metadata,JSON.stringify({'containerimage.digest':'TOKEN=fixture-secret'}));
  const malformed=spawnSync(process.execPath,['scripts/release-integrity.mjs','diagnostics',join(directory,'missing'),metadata,output],{env:{...process.env,RUNNER_TEMP:directory},encoding:'utf8'});
  assert.equal(malformed.status,0);const sanitized=JSON.parse(readFileSync(output));assert.equal(sanitized.archiveSHA256,null);assert.equal(sanitized.indexDigest,null);
});
test('OCI graph rejects additional platforms, duplicate runtimes, orphan blobs, corrupt blobs and duplicate members',()=>{for(const change of [m=>m.extra={os:'linux',architecture:'arm64'},m=>m.extra={os:'windows',architecture:'amd64'},m=>m.duplicate=true,m=>m.orphan=true,m=>m.corrupt=true,m=>m.duplicateMember=true])assert.throws(graph(change));});
test('OCI graph rejects unknown provenance and incorrect or multiple attestation subjects',()=>{for(const change of [m=>m.statement.predicateType='https://unrecognized',m=>m.statement._type='unknown',m=>m.statement.subject=[{digest:{sha256:'d'.repeat(64)}}],m=>m.statement.subject=[{digest:{sha256:'d'.repeat(64)}},{digest:{sha256:'e'.repeat(64)}}]])assert.throws(graph(change));});
test('archive config rejects historical version, false source labels and changed runtime protections',()=>{for(const change of [c=>c.config.Labels['org.opencontainers.image.version']='1.2.1',c=>c.config.Labels['org.opencontainers.image.revision']='f'.repeat(40),c=>c.config.User='0',c=>c.config.Entrypoint=['sh'],c=>c.config.Env.push('EXTRA=1'),c=>c.config.ExposedPorts['80/tcp']={},c=>c.config.Healthcheck.Retries=1]){const c=config();change(c);assert.throws(()=>validateConfig(c,source));}});
function runFixture(){const start=new Date(now-600000).toISOString();return {run:{id:42,run_attempt:2,repository:{id:repositoryId,full_name:repository},head_repository:{id:repositoryId},path:'.github/workflows/qualify-maintenance-image.yml',event:'workflow_dispatch',head_branch:'main',head_sha:source,status:'completed',conclusion:'success',created_at:start,run_started_at:start},jobs:{total_count:3,jobs:['runtime','browser','seal'].map((name,id)=>({id,name,run_id:42,run_attempt:2,status:'completed',conclusion:'success'}))},artifacts:{total_count:1,artifacts:[{id:9,name:'zevyrn-v1.2.3-qualified-42-2',size_in_bytes:100,digest:sha,expired:false,created_at:new Date(now).toISOString(),workflow_run:{id:42,head_sha:source,head_branch:'main',repository_id:repositoryId,head_repository_id:repositoryId}}]}};}
const assess=f=>validateRun(f.run,f.jobs,f.artifacts,source,now);
test('qualification selects the immutable artifact from the exact successful source/run/attempt',()=>{assert.equal(assess(runFixture()).artifactId,9);});
test('qualification rejects wrong repository, workflow, source, branch, event, status, conclusion and stale runs',()=>{for(const change of [f=>f.run.repository.id++,f=>f.run.head_repository.id++,f=>f.run.path='.github/workflows/other.yml',f=>f.run.head_sha='d'.repeat(40),f=>f.run.head_branch='other',f=>f.run.event='pull_request',f=>f.run.status='in_progress',f=>f.run.conclusion='failure',f=>f.run.created_at=new Date(now-86400001).toISOString()]){const f=runFixture();change(f);assert.throws(()=>assess(f));}});
test('qualification rejects every unsuccessful, skipped, missing, duplicate or previous-attempt required job',()=>{for(let i=0;i<3;i++)for(const change of [j=>j.conclusion='failure',j=>j.conclusion='skipped',j=>j.status='in_progress',j=>j.run_attempt=1,j=>j.run_id=41]){const f=runFixture();change(f.jobs.jobs[i]);assert.throws(()=>assess(f));}for(const change of [f=>f.jobs.jobs.pop(),f=>f.jobs.jobs[2]=clone(f.jobs.jobs[0])]){const f=runFixture();change(f);assert.throws(()=>assess(f));}});
test('qualification rejects expired, duplicate, foreign, wrong-attempt and unauthenticated artifacts',()=>{for(const change of [f=>f.artifacts.artifacts[0].expired=true,f=>f.artifacts.artifacts[0].name='zevyrn-v1.2.3-qualified-42-1',f=>f.artifacts.artifacts[0].digest='invalid',f=>f.artifacts.artifacts[0].workflow_run.head_sha='d'.repeat(40),f=>f.artifacts.artifacts[0].workflow_run.repository_id++,f=>f.artifacts.artifacts[0].created_at=new Date(now-86400000).toISOString(),f=>{f.artifacts.artifacts.push(clone(f.artifacts.artifacts[0]));f.artifacts.total_count++;}]){const f=runFixture();change(f);assert.throws(()=>assess(f));}});
function evidenceFixture(){const identity={version:'1.2.3',sourceCommit:source,sourceTree:tree,archiveSHA256:'c'.repeat(64),indexDigest:sha,assetsSHA256:'d'.repeat(64),configDigest:sha,diffIDs:[sha]};const context={purpose:'release',pullRequest:null,qualityEvent:'push',qualityBranch:'main',runId:42,runAttempt:2,sourceCommit:source,sourceTree:tree,startedAt:now-600000};const evidence={browser:{...context,archiveSHA256:identity.archiveSHA256,indexDigest:sha,assetsSHA256:identity.assetsSHA256,suites:suites.map(name=>({name,conclusion:'success'}))},health:{archiveSHA256:identity.archiveSHA256,indexDigest:sha,passed:true,checks:['image-config-and-rootfs','container-hardening','health','nginx-config','headers','assets','no-build-tools','graceful-stop']},runtime:{blocked:false,blockingVulnerabilities:0,secrets:0,results:[]},builder:{blocked:false,blockingVulnerabilities:0,secrets:0,approvedHighCount:0,rawBlockingVulnerabilities:0,unapprovedHighCount:0,results:[{type:'alpine',vulnerabilities:[],secrets:[]}]},builderIdentity:{sourceCommit:source,sourceTree:tree,imageID:sha,archiveSHA256:"f".repeat(64)},npm:{blocked:false,counts:{high:0,critical:0}},scanner:{Version:'0.76.0',VulnerabilityDB:{Version:2,UpdatedAt:new Date(now-600000).toISOString(),DownloadedAt:new Date(now).toISOString(),NextUpdate:new Date(now+86400000).toISOString()}},sbom:{bomFormat:'CycloneDX',metadata:{component:{properties:[{name:'aquasecurity:trivy:ImageID',value:sha},{name:'aquasecurity:trivy:DiffID',value:sha}]}},components:[{name:'nginx'}]},scanIdentity:{...identity,scanArchiveSHA256:'e'.repeat(64),runtimeImageID:sha,sbomImageID:sha,scanners:['vuln','secret'],imageConfigScanners:['secret']}};return {identity,context,evidence};}
const evidenceCheck=f=>validateEvidence(f.identity,f.evidence,f.context);
test('qualification evidence accepts exact archive/source/assets with all required results',()=>{evidenceCheck(evidenceFixture());});
test('release acceptance allows zero through three exact authorized remaining HIGH findings',()=>{
  const policy=JSON.parse(readFileSync(new URL('../scripts/ci-builder-exceptions.json',import.meta.url)));
  for(let count=0;count<=3;count++) {
    const f=evidenceFixture(),vulnerabilities=policy.exceptions.slice(0,count).map(e=>({id:e.cve,package:e.package,installed:e.version,path:e.path,severity:'HIGH',exception:{rationale:e.rationale,reviewReference:e.reviewReference}}));
    f.evidence.builder={...f.evidence.builder,approvedHighCount:count,rawBlockingVulnerabilities:count,results:[{type:'node-pkg',vulnerabilities,secrets:[]}]};
    evidenceCheck(f);
    if(count) {f.evidence.builder.results[0].vulnerabilities[0].path='other/package.json';assert.throws(()=>evidenceCheck(f));}
  }
});
test('qualification evidence rejects mismatched archives, source, assets, failed browser/runtime, missing SBOM and unsafe scans',()=>{for(const change of [f=>f.evidence.browser.archiveSHA256='e'.repeat(64),f=>f.evidence.browser.sourceTree='e'.repeat(40),f=>f.evidence.browser.assetsSHA256='e'.repeat(64),f=>f.evidence.browser.suites[0].conclusion='failure',f=>f.evidence.browser.suites.pop(),f=>f.evidence.health.passed=false,f=>f.evidence.health.checks.pop(),f=>f.evidence.runtime.blocked=true,f=>f.evidence.builder.secrets=1,f=>f.evidence.builder.unapprovedHighCount=1,f=>f.evidence.builderIdentity.sourceCommit=tree,f=>f.context.startedAt=null,f=>f.evidence.runtime.results=[{vulnerabilities:[{id:'CVE-2026-107891',severity:'MEDIUM'}]}],f=>delete f.evidence.sbom,f=>delete f.evidence.scanner.VulnerabilityDB,f=>f.evidence.scanner.Version='other',f=>f.evidence.scanner.VulnerabilityDB.DownloadedAt=new Date(now-86400000).toISOString()]){const f=evidenceFixture();change(f);assert.throws(()=>evidenceCheck(f));}});
test('derived Docker image must preserve exact rootfs and execution configuration',()=>{const identity={sourceCommit:source,configDigest:sha,config:config(),diffIDs:[sha]},image={Id:sha,Os:'linux',Architecture:'amd64',Config:clone(identity.config.config),RootFS:{Layers:[sha]}};verifyLoaded(identity,image);for(const change of [i=>i.RootFS.Layers=[sha256Other()],i=>i.Config.Env.push('UNEXPECTED=1'),i=>i.Config.User='0']){const i=clone(image);change(i);assert.throws(()=>verifyLoaded(identity,i));}});
function sha256Other(){return 'sha256:'+'d'.repeat(64);}
function mainReleaseFixture(){
  const f=runFixture();Object.assign(f.run,{path:'.github/workflows/quality-security.yml',event:'push',workflow_id:71});f.run.head_repository.full_name=repository;
  f.jobs={total_count:2,jobs:['quality-image','browser'].map((name,id)=>({id,name,run_id:42,run_attempt:2,status:'completed',conclusion:'success'}))};
  f.artifacts={total_count:3,artifacts:['runtime','builder','browser'].map((role,index)=>({...clone(f.artifacts.artifacts[0]),id:9+index,name:`quality-${role}-42-2`}))};
  f.workflow={id:71,path:'.github/workflows/quality-security.yml',state:'active'};f.sourceInfo={sha:source,tree:{sha:tree}};
  f.check=(refresh=false)=>authenticateMainQuality(f.run,f.jobs,f.artifacts,f.workflow,f.sourceInfo,source,now,refresh);return f;
}
function releaseEntryFixture(){
  return {GITHUB_REPOSITORY:repository,GITHUB_SHA:source,GITHUB_WORKFLOW_SHA:source,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REF:'refs/heads/main',GITHUB_WORKFLOW_REF:`${repository}/.github/workflows/release.yml@refs/heads/main`,GITHUB_RUN_ID:'90',GITHUB_RUN_ATTEMPT:'1',LIVE_PUBLICATION_ENABLED:'false'};
}
test('combined release authenticates exact main workflow/source/tree/run/attempt and all three artifact identities',()=>{
  const f=mainReleaseFixture(),selected=f.check();assert.equal(selected.sourceTree,tree);assert.equal(selected.workflowRevision,source);assert.equal(selected.artifacts.builder.id,10);
  for(const change of [x=>x.run.repository.id++,x=>x.run.repository.full_name='other/repo',x=>x.run.head_repository.id++,x=>x.run.head_repository.full_name='other/repo',x=>x.run.path='.github/workflows/other.yml',x=>x.run.workflow_id++,x=>x.workflow.state='disabled_manually',x=>x.sourceInfo.sha=tree,x=>x.sourceInfo.tree.sha='bad',x=>x.run.head_sha=tree,x=>x.run.head_branch='feature',x=>x.run.event='pull_request',x=>x.run.event='schedule',x=>x.run.status='in_progress',x=>x.run.conclusion='failure',x=>x.run.run_attempt++,x=>x.run.run_started_at=new Date(now-86400001).toISOString()]){
    const x=mainReleaseFixture();change(x);assert.throws(()=>x.check());
  }
});
test('main artifact selection rejects missing builder, duplicate identities, stale attempts, substituted IDs and expired coverage',()=>{
  const changes=[x=>x.artifacts.artifacts.splice(1,1),x=>x.artifacts.artifacts[1].id=9,x=>x.artifacts.artifacts[1].id=null,x=>x.artifacts.artifacts[1].name='quality-builder-42-1',x=>x.artifacts.artifacts[1].expired=true,x=>x.artifacts.artifacts[1].digest='bad',x=>x.artifacts.artifacts[1].workflow_run.id++,x=>x.artifacts.artifacts[1].workflow_run.head_sha=tree,x=>x.artifacts.artifacts[1].workflow_run.repository_id++,x=>x.artifacts.artifacts[1].workflow_run.head_repository_id++,x=>x.artifacts.artifacts[1].created_at=new Date(now-3600000).toISOString(),x=>x.artifacts.artifacts.push(clone(x.artifacts.artifacts[1]))];
  for(const change of changes){const x=mainReleaseFixture();change(x);x.artifacts.total_count=x.artifacts.artifacts.length;assert.throws(()=>x.check());}
});
test('main evidence rejects failed/cancelled/skipped/incomplete jobs, including previous attempts',()=>{
  for(const name of ['quality-image','browser'])for(const change of [j=>j.status='in_progress',j=>j.conclusion='failure',j=>j.conclusion='cancelled',j=>j.conclusion='skipped',j=>j.run_attempt--,j=>j.run_id--]){
    const x=mainReleaseFixture();change(x.jobs.jobs.find(j=>j.name===name));assert.throws(()=>x.check());
  }
  const queued=mainReleaseFixture();queued.run.created_at=new Date(now-86400001).toISOString();assert.throws(()=>queued.check(),/expired/);
});
test('explicit main manual quality refresh requires separate successful push-CI validation and never accepts a side branch',()=>{
  const f=mainReleaseFixture();f.run.event='workflow_dispatch';assert.throws(()=>f.check());assert.equal(f.check(true).event,'workflow_dispatch');
  // The unchanged push prerequisite rejects dispatch, and selectUpstream applies it separately.
  assert.throws(()=>validateQuality(f.run,f.jobs,source));f.run.head_branch='feature';assert.throws(()=>f.check(true));
});
test('run resolution pins newest exact-source main push run without falling back past a newer failure',()=>{
  const f=mainReleaseFixture(),older={...f.run,id:41,created_at:new Date(now-1200000).toISOString()},latest={...f.run,conclusion:'failure'};
  const runs={total_count:2,workflow_runs:[older,latest]};assert.equal(selectQualityRun(runs,source),42);
  assert.throws(()=>authenticateMainQuality(latest,f.jobs,f.artifacts,f.workflow,f.sourceInfo,source,now));
  assert.throws(()=>selectQualityRun({...runs,total_count:101},source));assert.throws(()=>selectQualityRun(runs,tree));
});
test('read-only dispatch cannot request publication; tag publication requires the literal migration activation',()=>{
  const env=releaseEntryFixture();assert.equal(combinedEntry(env,source,tree,true).publish,false);
  assert.equal(combinedEntry({...env,LIVE_PUBLICATION_ENABLED:'true'},source,tree,true).publish,false);
  const tag={...env,GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/tags/v1.2.3',GITHUB_WORKFLOW_REF:`${repository}/.github/workflows/release.yml@refs/tags/v1.2.3`};
  assert.throws(()=>combinedEntry(tag,source,tree,true),/disabled/);assert.equal(combinedEntry({...tag,LIVE_PUBLICATION_ENABLED:'true'},source,tree,true).publish,true);
  const recovery={...tag,GITHUB_EVENT_NAME:'workflow_dispatch',RELEASE_OPERATION:'release'};
  assert.throws(()=>combinedEntry(recovery,source,tree,true),/disabled/);
  assert.equal(combinedEntry({...recovery,LIVE_PUBLICATION_ENABLED:'true'},source,tree,true).publish,true);
  assert.throws(()=>combinedEntry({...recovery,RELEASE_OPERATION:'verify',LIVE_PUBLICATION_ENABLED:'true'},source,tree,true));
  assert.throws(()=>combinedEntry({...env,RELEASE_OPERATION:'release',LIVE_PUBLICATION_ENABLED:'true'},source,tree,true));
  for(const changes of [{GITHUB_REPOSITORY:'other/repo'},{GITHUB_WORKFLOW_SHA:tree},{GITHUB_SHA:tree},{GITHUB_WORKFLOW_REF:env.GITHUB_WORKFLOW_REF.replace('release.yml','other.yml')},{GITHUB_EVENT_NAME:'pull_request'},{GITHUB_REF:'refs/heads/feature'},{GITHUB_RUN_ATTEMPT:'0'}])assert.throws(()=>combinedEntry({...env,...changes},source,tree,true));
  assert.throws(()=>combinedEntry(env,source,tree,false));assert.throws(()=>combinedEntry(env,source,'bad',true));
});
test('release freshness never resets main evidence age and expires during owner approval',()=>{
  const scanner=evidenceFixture().evidence.scanner,start=new Date(now-600000).toISOString();releaseFreshness(start,scanner,now,true);
  assert.throws(()=>releaseFreshness(new Date(now-86400001).toISOString(),scanner,now),/expired/);
  assert.throws(()=>releaseFreshness(start,scanner,now+3600001,true),/freshness/);
  for(const change of [s=>s.VulnerabilityDB.DownloadedAt=new Date(now-1200000).toISOString(),s=>s.VulnerabilityDB.NextUpdate=new Date(now).toISOString(),s=>s.VulnerabilityDB.UpdatedAt=new Date(now+3600000).toISOString(),s=>s.Version='new']){
    const s=clone(scanner);change(s);assert.throws(()=>releaseFreshness(start,s,now));
  }
});
test('combined in-progress run accepts only successful read-only jobs from its own current attempt',()=>{
  const entry={...combinedEntry(releaseEntryFixture(),source,tree,true),workflowId:81},info={...mainReleaseFixture().run,id:90,run_attempt:1,path:'.github/workflows/release.yml',workflow_id:81,event:'workflow_dispatch',status:'in_progress',conclusion:null};
  const jobs={total_count:2,jobs:['resolve','qualify'].map(name=>({name,run_id:90,run_attempt:1,status:'completed',conclusion:'success'}))};
  validateCombinedPhase(info,jobs,entry);
  for(const event of ['push','workflow_dispatch']){
    const live={...entry,publish:true,event,operation:'release',ref:'refs/tags/v1.2.3'};
    validateCombinedPhase({...info,event,head_branch:'v1.2.3'},jobs,live);
  }
  for(const outcome of ['failure','cancelled','skipped',null])for(const name of ['resolve','qualify']){const j=clone(jobs);j.jobs.find(j=>j.name===name).conclusion=outcome;assert.throws(()=>validateCombinedPhase(info,j,entry));}
  for(const change of [j=>j.jobs.pop(),j=>j.jobs[1].run_attempt++,j=>j.jobs[1].run_id++,j=>j.jobs[1].name='publish']){const j=clone(jobs);change(j);j.total_count=j.jobs.length;assert.throws(()=>validateCombinedPhase(info,j,entry));}
  for(const change of [r=>r.run_attempt++,r=>r.workflow_id++,r=>r.head_sha=tree,r=>r.conclusion='cancelled']){const r=clone(info);change(r);assert.throws(()=>validateCombinedPhase(r,jobs,entry));}
});
test('separate verification receipt cannot relabel original quality evidence or become promotable',()=>{
  const selection=mainReleaseFixture().check(),entry={...combinedEntry(releaseEntryFixture(),source,tree,true),startedAt:new Date(now-100000).toISOString()},identity=evidenceFixture().identity,files={'runtime/quality.json':'a'.repeat(64)},scanner=evidenceFixture().evidence.scanner;
  const receipt={schemaVersion:1,version:'1.2.3',purpose:'verification',promotionEligible:false,entry,upstream:selection,qualifiedAt:now,archiveSHA256:identity.archiveSHA256,indexDigest:identity.indexDigest,files};
  validateReleaseReceipt(receipt,entry,selection,identity,files,scanner,now);
  for(const change of [r=>r.promotionEligible=true,r=>r.purpose='release',r=>r.upstream.sourceTree=source,r=>r.upstream.workflowRevision=tree,r=>r.upstream.artifacts.builder.id++,r=>r.archiveSHA256='f'.repeat(64),r=>r.indexDigest=sha256Other(),r=>r.files['runtime/quality.json']='e'.repeat(64),r=>r.entry.runAttempt++]){
    const r=clone(receipt);change(r);assert.throws(()=>validateReleaseReceipt(r,entry,selection,identity,files,scanner,now));
  }
  const oldSelection={...selection,createdAt:new Date(now-86400001).toISOString()};assert.throws(()=>validateReleaseReceipt({...receipt,upstream:oldSelection},entry,oldSelection,identity,files,scanner,now),/expired/);
  const live={...combinedEntry({...releaseEntryFixture(),GITHUB_REF:'refs/tags/v1.2.3',GITHUB_WORKFLOW_REF:`${repository}/.github/workflows/release.yml@refs/tags/v1.2.3`,RELEASE_OPERATION:'release',LIVE_PUBLICATION_ENABLED:'true'},source,tree,true),startedAt:entry.startedAt},release={...receipt,purpose:'release',promotionEligible:true,entry:live};validateReleaseReceipt(release,live,selection,identity,files,scanner,now);
  assert.throws(()=>validateReleaseReceipt(release,live,selection,identity,files,scanner,now+86400001));
});
test('builder reference binds config, OCI/archive, source/tree, run/attempt and exact artifact ID/checksum',()=>{
  const selection=mainReleaseFixture().check(),identity={sourceCommit:source,sourceTree:tree,runId:42,runAttempt:2,configDigest:sha,indexDigest:sha,archiveSHA256:'c'.repeat(64)},reference={identity:clone(identity),artifact:clone(selection.artifacts.builder)},summary={imageID:sha};
  validateBuilderBinding(identity,reference,selection,summary);
  for(const change of [r=>r.artifact.id++,r=>r.artifact.digest=sha256Other(),r=>r.identity.archiveSHA256='e'.repeat(64),r=>r.identity.configDigest=sha256Other()]){const r=clone(reference);change(r);assert.throws(()=>validateBuilderBinding(identity,r,selection,summary));}
  for(const change of [i=>i.sourceCommit=tree,i=>i.sourceTree=source,i=>i.runId++,i=>i.runAttempt++]){const i=clone(identity);change(i);assert.throws(()=>validateBuilderBinding(i,{...reference,identity:i},selection,summary));}
  assert.throws(()=>validateBuilderBinding(identity,reference,selection,{imageID:sha256Other()}));
});
test('existing version collision always stops, including when a different digest might replace it',()=>{
  validateVersionCollision({Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:['1.2.2']});
  assert.throws(()=>validateVersionCollision({Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:['1.2.3']}),/already exists/);
});
function builderGraphFixture(change=()=>{}){
  const layer=Buffer.from('builder filesystem fixture'),c={os:'linux',architecture:'amd64',config:{User:'',Env:['NODE_VERSION=24.22.1']},rootfs:{type:'layers',diff_ids:['sha256:'+hash(layer)]}};change(c);
  const members=new Map(),store=(bytes,mediaType)=>{bytes=Buffer.isBuffer(bytes)?bytes:Buffer.from(JSON.stringify(bytes));const descriptor={mediaType,digest:'sha256:'+hash(bytes),size:bytes.length};members.set('blobs/sha256/'+descriptor.digest.slice(7),bytes);return descriptor;};
  const m={schemaVersion:2,mediaType:mt,config:store(c,ct),layers:[store(gzipSync(layer),'application/vnd.oci.image.layer.v1.tar+gzip')]};
  members.set('index.json',Buffer.from(JSON.stringify({schemaVersion:2,manifests:[store(m,mt)]})));members.set('oci-layout',Buffer.from('{"imageLayoutVersion":"1.0.0"}'));
  return {members,config:c,layer,check:()=>inspectBuilderGraph(name=>members.get(name),[...members.keys()])};
}
test('builder OCI verification authenticates actual config and decompressed layers without relaxing runtime rules',()=>{
  const f=builderGraphFixture(),identity=f.check();assert.equal(identity.config.config.User,'');assert.throws(()=>validateConfig(identity.config,source));
  for(const change of [c=>c.architecture='arm64',c=>c.os='windows',c=>c.rootfs.diff_ids=[sha]])assert.throws(()=>builderGraphFixture(change).check());
  const corrupt=builderGraphFixture();corrupt.members.set('blobs/sha256/'+corrupt.check().configDigest.slice(7),Buffer.from('{}'));assert.throws(corrupt.check);
  const orphan=builderGraphFixture();orphan.members.set('blobs/sha256/'+'f'.repeat(64),Buffer.from('extra'));assert.throws(orphan.check);
});
test('main builder retention command verifies actual OCI against the exact original scanned Docker-save bytes',{skip:!existsSync('.github/workflows/quality-security.yml')&&'Requires a Git source checkout'},async()=>{
  const root=mkdtempSync(join(tmpdir(),'zevyrn-retain-builder-')),members=join(root,'members'),retained=join(root,'retained'),docker=join(root,'docker');for(const dir of [members,retained,docker])mkdirSync(dir);
  const f=builderGraphFixture();for(const [name,bytes] of f.members){const path=join(members,name);mkdirSync(join(path,'..'),{recursive:true});writeFileSync(path,bytes);}
  const archive=join(retained,'builder.oci.tar'),scan=join(root,'scan.tar');assert.equal(spawnSync('tar',['-cf',archive,'-C',members,...f.members.keys()],{encoding:'utf8'}).status,0);
  writeFileSync(join(docker,'config.json'),JSON.stringify(f.config));writeFileSync(join(docker,'layer.tar'),f.layer);writeFileSync(join(docker,'manifest.json'),JSON.stringify([{Config:'config.json',Layers:['layer.tar'],RepoTags:['zevyrn-ci-builder:latest']}]));
  assert.equal(spawnSync('tar',['-cf',scan,'-C',docker,'config.json','layer.tar','manifest.json'],{encoding:'utf8'}).status,0);
  const actualSource=spawnSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).stdout.trim(),event=join(root,'event.json');writeFileSync(event,JSON.stringify({repository:{id:repositoryId}}));
  const env={...process.env,QUALITY_SOURCE:actualSource,GITHUB_SHA:actualSource,GITHUB_REPOSITORY:repository,GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',GITHUB_WORKFLOW_REF:`${repository}/.github/workflows/quality-security.yml@refs/heads/main`,GITHUB_RUN_ID:'42',GITHUB_RUN_ATTEMPT:'2',GITHUB_EVENT_PATH:event};
  const result=spawnSync(process.execPath,['scripts/release-integrity.mjs','retain-builder',archive,scan,retained],{env,encoding:'utf8'});assert.equal(result.status,0,result.stderr);
  const identity=JSON.parse(readFileSync(join(retained,'builder-identity.json')));assert.equal(identity.scanArchiveSHA256,hash(readFileSync(scan)));
  const raw=join(root,'report.json');writeFileSync(raw,JSON.stringify({SchemaVersion:2,ArtifactType:'container_image',Metadata:{ImageID:identity.configDigest,DiffIDs:identity.diffIDs}}));
  const check=()=>spawnSync(process.execPath,['scripts/release-integrity.mjs','builder-scan-binding',join(retained,'builder-identity.json'),scan,raw],{encoding:'utf8'});
  assert.equal(check().status,0);writeFileSync(raw,JSON.stringify({SchemaVersion:2,ArtifactType:'container_image',Metadata:{ImageID:sha,DiffIDs:identity.diffIDs}}));assert.equal(check().status,1);
  writeFileSync(scan,Buffer.from('changed scanned archive'));assert.equal(check().status,1);
});
test('fresh combined security accepts zero approved findings and rejects unauthorized findings and missing config-secret coverage',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'zevyrn-combined-security-'));mkdirSync(join(directory,'builder'));
  const f=evidenceFixture();f.evidence.runtime.imageID=sha;f.evidence.runtime.results=[{type:'alpine',vulnerabilities:[],secrets:[]}];f.evidence.builder.imageID=sha;
  const write=()=>{for(const [name,value] of Object.entries({'runtime-scan.json':f.evidence.runtime,'builder-scan.json':f.evidence.builder,'release-scan-identity.json':f.evidence.scanIdentity,'builder/builder-identity.json':{configDigest:sha}}))writeFileSync(join(directory,name),JSON.stringify(value));};
  write();await combinedSecurity(directory,f.identity);
  const changes=[()=>f.evidence.builder.results[0].vulnerabilities.push({id:'CVE-2026-999999',severity:'HIGH'}),()=>f.evidence.builder.secrets=1,()=>f.evidence.runtime.imageID=sha256Other(),()=>f.evidence.scanIdentity.imageConfigScanners=[],()=>f.evidence.scanIdentity.scanners=['vuln'],()=>f.evidence.scanIdentity.runtimeImageID=sha256Other()];
  for(const change of changes){const before=clone(f);change();write();await assert.rejects(combinedSecurity(directory,f.identity));Object.assign(f,before);}
});
test('release ZIP transport and browser-only transfer preserve pre-extraction special-entry and checksum rejection',async()=>{
  const {yazl}=createRequire(import.meta.url)('playwright-core/lib/utilsBundle');
  const plain=async entries=>{const zip=new yazl.ZipFile(),chunks=[];const done=new Promise(resolve=>{zip.outputStream.on('data',b=>chunks.push(b));zip.outputStream.on('end',()=>resolve(Buffer.concat(chunks)));});for(const [name,bytes] of Object.entries(entries))zip.addReadStream(Readable.from([bytes]),name,{mode:0o100644,forceDosTimestamp:true});zip.end();return done;};
  const content=Buffer.from('{"suites":[]}'),browser=await plain({'browser-results.json':content}),root=mkdtempSync(join(tmpdir(),'zevyrn-release-zip-'));
  await qualityZip(browser,'sha256:'+hash(browser),join(root,'browser'),{files:['browser-results.json']});assert.equal(readFileSync(join(root,'browser/browser-results.json'),'utf8'),content.toString());
  const transport=Buffer.from(JSON.stringify({schemaVersion:1,purpose:'quality',promotionEligible:false,files:{'release.json':hash(content)}})),bundle=await plain({'release.json':content,'transport.json':transport});
  await qualityZip(bundle,'sha256:'+hash(bundle),join(root,'release'),{manifest:'transport.json'});
  await assert.rejects(qualityZip(bundle,sha,join(root,'bad-checksum'),{manifest:'transport.json'}));assert(!existsSync(join(root,'bad-checksum')));
  const symlink=await artifactZip([{name:'builder.oci.tar',mode:0o120777}]);await assert.rejects(qualityZip(symlink,'sha256:'+hash(symlink),join(root,'symlink'),{manifest:'quality.json',builder:true}));assert(!existsSync(join(root,'symlink')));
  await assert.rejects(qualityZip(bundle,'sha256:'+hash(bundle),join(root,'wrong-browser'),{files:['browser-results.json']}));assert(!existsSync(join(root,'wrong-browser')));
});
function dockerFixture(compressed=false){
  const layer=Buffer.from('synthetic layer bytes'),c=config();c.rootfs.diff_ids=['sha256:'+hash(layer)];c.history=[{created_by:'COPY runtime fixture',empty_layer:false}];
  const bytes=Buffer.from(JSON.stringify(c)),identity={sourceCommit:source,sourceTree:tree,archiveSHA256:'e'.repeat(64),indexDigest:sha,configDigest:'sha256:'+hash(bytes),config:c,diffIDs:c.rootfs.diff_ids};
  const files=new Map([['manifest.json',Buffer.from(JSON.stringify([{Config:'config.json',RepoTags:null,Layers:['layer.tar']}]))],['config.json',bytes],['layer.tar',compressed?gzipSync(layer):layer]]);
  return {identity,files,check:()=>inspectDockerGraph(name=>{assert(files.has(name));return files.get(name);},[...files.keys()],identity)};
}
test('Docker-save verification binds exact configuration/history and plain or gzip layer identities',()=>{
  for(const compressed of [false,true]){const f=dockerFixture(compressed);assert.equal(f.check(),f.identity.configDigest);const image={Id:f.identity.configDigest,Os:'linux',Architecture:'amd64',Config:clone(f.identity.config.config),RootFS:{Layers:f.identity.diffIDs}};verifyLoaded(f.identity,image);}
});
test('loaded image binding rejects tag-only selection, wrong ID, config digest, platform and diff IDs',()=>{
  const f=dockerFixture(),image={Id:f.identity.configDigest,Os:'linux',Architecture:'amd64',Config:clone(f.identity.config.config),RootFS:{Layers:f.identity.diffIDs}};
  for(const change of [i=>i.Id='zevyrn-release-runtime:1.2.3',i=>i.Id=sha,i=>i.Architecture='arm64',i=>i.Os='windows',i=>i.RootFS.Layers=[sha],i=>i.Config.User='0',i=>i.Config.Labels['org.opencontainers.image.revision']=tree]){const i=clone(image);change(i);assert.throws(()=>verifyLoaded(f.identity,i));}
  assert.throws(()=>verifyLoaded({...f.identity,configDigest:sha},image));
});
test('Docker-save verification rejects changed config/history, layers, unsafe references and multiple images',()=>{
  for(const change of [f=>f.files.set('config.json',Buffer.from('{}')),f=>{const c=clone(f.identity.config);c.history[0].created_by='changed';f.files.set('config.json',Buffer.from(JSON.stringify(c)));},
    f=>f.files.set('layer.tar',Buffer.from('modified layer bytes')),f=>f.identity.diffIDs=[sha],
    f=>f.files.set('manifest.json',Buffer.from(JSON.stringify([{Config:'../escape',Layers:['layer.tar']}]))),
    f=>f.files.set('manifest.json',Buffer.from(JSON.stringify([{Config:'config.json',Layers:['layer.tar']},{Config:'config.json',Layers:['layer.tar']}]))),
    f=>f.files.set('manifest.json',Buffer.from(JSON.stringify([{Config:'config.json',Layers:[]}])))] ) {const f=dockerFixture();change(f);assert.throws(f.check);}
});
test('scan evidence binds original OCI, source, immutable image, derived archive, report and SBOM',()=>{
  const f=evidenceFixture();validateCompleteScanEvidence(f.identity,f.evidence.scanIdentity,f.evidence.sbom);
  validateRuntimeReportIdentity(f.identity,{SchemaVersion:2,ArtifactType:'container_image',Metadata:{ImageID:sha,DiffIDs:[sha]}});
  for(const key of ['sourceCommit','sourceTree','archiveSHA256','indexDigest','configDigest','diffIDs','scanArchiveSHA256','runtimeImageID','sbomImageID','scanners','imageConfigScanners']){
    const scan=clone(f.evidence.scanIdentity);delete scan[key];assert.throws(()=>validateCompleteScanEvidence(f.identity,scan,f.evidence.sbom));
  }
  for(const report of [{},{SchemaVersion:2,ArtifactType:'container_image',Metadata:{ImageID:sha256Other(),DiffIDs:[sha]}},{SchemaVersion:2,ArtifactType:'container_image',Metadata:{ImageID:sha,DiffIDs:[sha256Other()]}}])assert.throws(()=>validateRuntimeReportIdentity(f.identity,report));
  const sbom=clone(f.evidence.sbom);sbom.metadata.component.properties[0].value=sha256Other();assert.throws(()=>validateSBOMIdentity(f.identity,sbom));
});
test('runtime command construction always enables vulnerability, file-secret and configuration-secret scanners',()=>{
  assert.deepEqual(runtimeScanArgs('/scan.tar','/report.json'),['image','--input','/scan.tar','--scanners','vuln,secret','--image-config-scanners','secret','--format','json','--output','/report.json']);
  assert.deepEqual(runtimeScanArgs('/scan.tar','/sbom.json',true),['image','--input','/scan.tar','--format','cyclonedx','--output','/sbom.json']);
  const f=evidenceFixture();for(const change of [s=>s.scanners=['vuln'],s=>s.imageConfigScanners=[],s=>s.runtimeImageID=sha256Other(),s=>s.sbomImageID=sha256Other()]){const scan=clone(f.evidence.scanIdentity);change(scan);assert.throws(()=>validateCompleteScanEvidence(f.identity,scan,f.evidence.sbom));}
});
test('CLI scan initialization failure blocks and modified Docker-save archives never reach the scanner',async()=>{
  const f=dockerFixture(),root=mkdtempSync(join(tmpdir(),'zevyrn-scan-archive-'));for(const [name,bytes] of f.files)writeFileSync(join(root,name),bytes);
  const archive=join(root,'scan.tar'),tar=spawnSync('tar',['-cf',archive,'-C',root,...f.files.keys()],{encoding:'utf8'});assert.equal(tar.status,0);
  const scanArchiveSHA256=await inspectDockerArchive(archive,f.identity),record={...f.identity,scanArchiveSHA256};
  const identityFile=join(root,'identity.json'),recordFile=join(root,'scan.json');writeFileSync(identityFile,JSON.stringify(f.identity));writeFileSync(recordFile,JSON.stringify(record));
  const result=spawnSync(process.execPath,['scripts/release-integrity.mjs','scan-runtime',process.execPath,identityFile,archive,recordFile,join(root,'report.json')],{encoding:'utf8'});
  assert.equal(result.status,1);assert.equal(result.stdout,'');assert.equal(result.stderr.trim(),'RUNTIME_SCAN_FAILED');assert(!JSON.parse(readFileSync(recordFile)).runtimeImageID);
  writeFileSync(archive,Buffer.from('modified archive TOKEN=fixture-secret'));await assert.rejects(inspectDockerArchive(archive,f.identity));
  const modified=spawnSync(process.execPath,['scripts/release-integrity.mjs','scan-runtime','TOKEN=fixture-secret',identityFile,archive,recordFile,join(root,'report.json')],{encoding:'utf8'});assert.equal(modified.status,1);assert.equal(modified.stdout,'');assert(!modified.stderr.includes('fixture-secret'));
});
test('failure metadata contains only fixed stage outcomes and pinned scanner/database fields',()=>{
  const stages={archive:'success',scanArchive:'success',security:'failure',sbom:'skipped',hardening:'skipped'};
  assert.deepEqual(sanitizedFailureStages({...stages,secret:'TOKEN=fixture-secret'}),stages);
  assert.throws(()=>sanitizedFailureStages({...stages,security:'TOKEN=fixture-secret'}));
  const scanner=evidenceFixture().evidence.scanner;assert.deepEqual(sanitizedScannerMetadata({...scanner,secret:'TOKEN=fixture-secret'}),scanner);
  assert.throws(()=>sanitizedScannerMetadata({...scanner,Version:'TOKEN=fixture-secret'}));
  assert.deepEqual(sanitizedScanSummary({blocked:true,blockingVulnerabilities:1,secrets:0,results:[{secret:'TOKEN=fixture-secret'}]}),{blocked:true,blockingVulnerabilities:1,secrets:0});
  assert.throws(()=>sanitizedScanSummary({blocked:true,blockingVulnerabilities:'TOKEN=fixture-secret',secrets:0}));
});
test('qualification and read-only publication validation scan verified derived archives and preserve guards',{skip:!existsSync('.github/workflows/qualify-maintenance-image.yml')&&'Workflow contracts execute on the source checkout, not inside Docker'},()=>{
  const require=createRequire(import.meta.url),{yaml}=require('playwright-core/lib/utilsBundle');
  for(const file of ['qualify-maintenance-image','publish-maintenance-image']){
    const doc=yaml.parse(readFileSync(`.github/workflows/${file}.yml`,'utf8'));const job=doc.jobs[file.startsWith('qualify')?'runtime':'validate'];const script=job.steps.map(s=>s.run??'').join('\n');
    assert(script.includes('prepare-scan'));assert(script.includes('scan-runtime'));assert(script.includes('$RUNNER_TEMP/runtime-scan.tar'));assert(!/trivy" image --input .*archive\.oci\.tar/.test(script));
    assert(script.includes('v0.76.0'));assert(script.includes('e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7'));assert(script.includes('--download-db-only'));
    for(const step of job.steps)assert(!step['continue-on-error']);
    if(file.startsWith('qualify')){assert(script.includes('sbom-runtime'));const collect=job.steps.findIndex(s=>s.name==='Collect sanitized failed-archive diagnostics'),hardening=job.steps.findIndex(s=>s.id==='hardening');assert(collect>hardening);assert.equal(job.steps[collect].if,"failure()");const upload=job.steps.find(s=>s.with?.name?.startsWith('zevyrn-v1.2.3-failed-diagnostics-'));assert.match(upload.with.path,/artifacts\/release\/diagnostics\/\*\.json/);assert.match(upload.with.path,/summary\.md/);assert.equal(upload.with['retention-days'],7);assert.deepEqual(doc.permissions,{contents:'read',actions:'read'});}
    else{assert.deepEqual(job.permissions,{contents:'read',actions:'read'});assert.equal(doc.jobs.promote.environment,'zevyrn-ghcr-publication');}
  }
});

test('security stages collect independent sanitized evidence and require every acceptance prerequisite',{skip:!existsSync('.github/workflows/quality-security.yml')&&'Workflow contracts execute on the source checkout'},()=>{
  const require=createRequire(import.meta.url),{yaml}=require('playwright-core/lib/utilsBundle');
  for(const [file,job] of [['quality-security','quality-image'],['qualify-maintenance-image','runtime']]) {
    const steps=yaml.parse(readFileSync(`.github/workflows/${file}.yml`,'utf8')).jobs[job].steps;
    for(const id of ['runtime_scan','builder_scan','sbom','security'])assert(steps.some(s=>s.id===id));
    const builder=steps.find(s=>s.id==='builder_scan'),gate=steps.find(s=>s.id==='security'),sbom=steps.find(s=>s.id==='sbom');
    assert.match(builder.if,/!cancelled\(\)/);assert.doesNotMatch(builder.if,/runtime_scan/);
    for(const id of ['runtime_scan','builder_scan','sbom'])assert(gate.run.includes(`steps.${id}.outcome`));
    assert.match(gate.run,/ci-security\.mjs trivy/);
    assert.match(sbom.run,/ci-security\.mjs sbom "\$RUNNER_TEMP\/runtime-sbom\.cdx\.json"/);
    const summary=steps.find(s=>s.name==='Actionable sanitized security summary');assert.equal(summary.if,'always()');
    assert(steps.some(s=>s.if==='always()'&&s.uses?.startsWith('actions/upload-artifact@'))||file.startsWith('qualify'));
    assert(steps.every(s=>!s['continue-on-error']));
  }
});
test('candidate quality validation checks pinned base, patched packages and hardened execution without publication',{skip:!existsSync('.github/workflows/quality-security.yml')&&'Workflow contracts execute on the source checkout'},()=>{
  const require=createRequire(import.meta.url),{yaml}=require('playwright-core/lib/utilsBundle');
  const quality=yaml.parse(readFileSync('.github/workflows/quality-security.yml','utf8'));
  assert(Object.hasOwn(quality.on,'pull_request'));assert.deepEqual(quality.permissions,{contents:'read'});
  const steps=quality.jobs['quality-image'].steps,base=steps.find(s=>s.id==='base'),health=steps.find(s=>s.id==='hardening');
  assert.match(base.run,/imagetools inspect/);assert.match(base.run,/\.digest == \$digest/);
  assert.match(base.run,/0616b208d25086f7a903e993626c56193787307fec4423bf7d3ce77194d2b1c5/);
  assert.match(health.run,/release-integrity\.mjs container/);assert.match(health.run,/State.Health.Status/);
  assert.match(health.run,/stat -c %u:%g/);assert.match(health.run,/! test -w \/usr\/share\/nginx\/html/);
  assert.match(health.run,/touch \/tmp\/zevyrn-write-probe/);
  for(const floor of ['nginx=1.30.8-r1','libxml2=2.13.9-r3','libxpm=3.5.20-r0','zlib=1.4-r0','libexpat=2.10.0-r0'])assert(health.run.includes(floor));
  assert(steps.findIndex(s=>s.name==='Actionable sanitized security summary')>steps.indexOf(health));
  for(const job of Object.values(quality.jobs)) {
    assert(!job.environment);assert(!JSON.stringify(job).includes('secrets.'));
    if(job.permissions)assert.deepEqual(job.permissions,{contents:'read',actions:'read'});
    for(const step of job.steps){
      assert(!/docker (?:push|login)|--push|skopeo login|gh (?:workflow run|release)|ssh\s/.test(step.run??''));
      for(const line of (step.run??'').split('\n').filter(line=>line.includes('skopeo copy')))assert.match(line,/(?:oci-archive:artifacts\/security\/archive\.oci\.tar docker-daemon:zevyrn-ci-runtime:latest|docker-daemon:zevyrn-ci-builder:latest "oci-archive:\$RUNNER_TEMP\/retained-builder\/builder\.oci\.tar")$/);
    }
  }
  for(const publisher of ['publish-qualified-image','publish-maintenance-image'])assert.deepEqual(Object.keys(yaml.parse(readFileSync(`.github/workflows/${publisher}.yml`,'utf8')).on),['workflow_dispatch']);
  const qualifier=yaml.parse(readFileSync('.github/workflows/qualify-maintenance-image.yml','utf8'));
  assert.deepEqual(qualifier.permissions,{contents:'read',actions:'read'});
  for(const job of Object.values(qualifier.jobs))assert(!job.environment&&!job.permissions);
});
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
    {Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:['1.2.1','1.2.1']},{Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:['1.2.3']},
    {Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:[],unexpected:true}])assert.throws(()=>validateTags(response));
});

test('only the exact lightweight or peeled v1.2.3 release tag can authorize promotion',()=>{validateReleaseRef(source+'\trefs/tags/v1.2.3\n',source);validateReleaseRef(tree+'\trefs/tags/v1.2.3\n'+source+'\trefs/tags/v1.2.3^{}\n',source);for(const text of ['',source+'\trefs/tags/v1.2.1\n',tree+'\trefs/tags/v1.2.3\n',source+'\trefs/tags/v1.2.3\n'+source+'\trefs/tags/v1.2.3\n'])assert.throws(()=>validateReleaseRef(text,source));});
test('v1.2.3 guards reject previous-version tags, image metadata and qualification artifacts',()=>{
  assert.throws(()=>validateReleaseRef(source+'\trefs/tags/v1.2.2\n',source));
  const c=config();c.config.Labels['org.opencontainers.image.version']='1.2.2';assert.throws(()=>validateConfig(c,source));
  const prior=runFixture();prior.artifacts.artifacts[0].name='zevyrn-v1.2.2-qualified-42-2';assert.throws(()=>assess(prior));
  const oldEvidence=evidenceFixture();oldEvidence.identity.version='1.2.2';assert.throws(()=>evidenceCheck(oldEvidence));
  validateTags({Repository:'ghcr.io/thestateofwhere/zevyrn',Tags:['1.2.1','1.2.2']});
});
test('existing source CI cannot be replaced by a skipped, failed, unrelated or prior-attempt job',()=>{const f=runFixture();f.run.path='.github/workflows/quality-security.yml';f.run.event='push';f.jobs.total_count=2;f.jobs.jobs=f.jobs.jobs.slice(0,2);f.jobs.jobs[0].name='quality-image';validateQuality(f.run,f.jobs,source);for(const change of [x=>x.run.head_sha=tree,x=>x.run.conclusion='failure',x=>x.jobs.jobs[1].conclusion='skipped',x=>x.jobs.jobs[1].run_attempt=1,x=>x.run.path='.github/workflows/other.yml']){const x=clone(f);change(x);assert.throws(()=>validateQuality(x.run,x.jobs,source));}});

function prFixture(){return {env:{GITHUB_REPOSITORY:repository,GITHUB_EVENT_NAME:'pull_request',GITHUB_REF:'refs/pull/2/merge',GITHUB_SHA:tree},event:{repository:{id:repositoryId},number:2,pull_request:{number:2,head:{sha:source,ref:'codex/v1.2.3-security-maintenance',repo:{id:repositoryId}},base:{ref:'main',repo:{id:repositoryId}}}}};}
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
  const f=runFixture();f.run.event='pull_request';f.run.head_branch='codex/v1.2.3-security-maintenance';
  f.artifacts.artifacts[0].name='zevyrn-v1.2.3-pr-qualified-42-2';assert.throws(()=>assess(f));
  const other=runFixture();other.artifacts.artifacts[0].name='zevyrn-v1.2.3-pr-qualified-42-2';assert.throws(()=>assess(other));
});
test('PR packets are explicitly non-promotable even if their eligibility flag is tampered',()=>{
  const expected={purpose:'pr',pullRequest:2},packet={purpose:'pr',promotionEligible:false,context:{purpose:'pr',pullRequest:2,qualityEvent:'pull_request',qualityBranch:'codex/v1.2.3-security-maintenance'}};
  validatePacketPurpose(packet,expected);
  assert.throws(()=>validatePacketPurpose(packet,{purpose:'release',pullRequest:null}));
  assert.throws(()=>validatePacketPurpose({...packet,promotionEligible:true},expected));
  const disguised={...packet,purpose:'release',promotionEligible:true,context:{...packet.context,purpose:'release',pullRequest:null}};
  assert.throws(()=>validatePacketPurpose(disguised,{purpose:'release',pullRequest:null}));
  validatePacketPurpose({purpose:'release',promotionEligible:true,context:{purpose:'release',pullRequest:null,qualityEvent:'push',qualityBranch:'main'}},{purpose:'release',pullRequest:null});
});

function qualityFixture(){
  const f=prFixture();Object.assign(f.env,{QUALITY_SOURCE:source,GITHUB_WORKFLOW_REF:`${repository}/.github/workflows/quality-security.yml@refs/pull/2/merge`,GITHUB_RUN_ID:'42',GITHUB_RUN_ATTEMPT:'2'});
  const ctx=qualityIdentity(f.env,f.event,source,tree);
  const files=Object.fromEntries(['archive.oci.tar','identity.json','assets.json','health.json','runtime-scan.json','runtime-scan-identity.json','builder-scan.json','scanner-version.json','runtime-sbom.cdx.json','npm-audit.json'].map(name=>[name,'c'.repeat(64)]));
  const record={schemaVersion:1,purpose:'quality',promotionEligible:false,context:ctx,archiveSHA256:files['archive.oci.tar'],indexDigest:sha,files:clone(files)};
  const artifact={id:9,name:'quality-runtime-42-2',digest:sha,expired:false,size_in_bytes:100,workflow_run:{id:42,repository_id:repositoryId,head_repository_id:repositoryId,head_sha:source}};
  return {...f,ctx,files,record,artifact,identity:evidenceFixture().identity};
}

test('quality binds actual PR head, workflow, source tree and attempt without granting release purpose',()=>{
  const f=qualityFixture();assert.equal(f.ctx.purpose,'quality');assert.equal(f.ctx.promotionEligible,false);
  for(const change of [x=>x.env.GITHUB_REPOSITORY='other/repo',x=>x.env.GITHUB_WORKFLOW_REF=x.env.GITHUB_WORKFLOW_REF.replace('quality-security','other'),x=>x.env.GITHUB_RUN_ID='0',x=>x.env.GITHUB_RUN_ATTEMPT='0',x=>x.env.QUALITY_SOURCE=tree,x=>x.event.repository.id++,x=>x.event.pull_request.base.repo.id++,x=>x.event.pull_request.head.sha=tree]){
    const x=qualityFixture();change(x);assert.throws(()=>qualityIdentity(x.env,x.event,source,tree));
  }
  assert.throws(()=>qualityIdentity(f.env,f.event,source,'invalid-tree'));
  // Fork and Dependabot code can run with read-only permissions; neither produces release authority.
  f.event.pull_request.head.repo.id=123;assert.equal(qualityIdentity(f.env,f.event,source,tree).headRepositoryId,123);
  for(const event of ['push','schedule','workflow_dispatch']){
    const env={...f.env,GITHUB_EVENT_NAME:event,GITHUB_REF:'refs/heads/main',GITHUB_SHA:source,GITHUB_WORKFLOW_REF:`${repository}/.github/workflows/quality-security.yml@refs/heads/main`};
    assert.equal(qualityIdentity(env,{repository:{id:repositoryId}},source,tree).promotionEligible,false);
  }
});

test('quality artifact selection rejects foreign, stale-attempt, wrong-source, wrong-ID and wrong-checksum artifacts',()=>{
  const f=qualityFixture();validateQualityArtifact(f.artifact,f.ctx,9,sha);
  for(const change of [a=>a.id++,a=>a.expired=true,a=>a.name='quality-runtime-42-1',a=>a.name='quality-runtime-41-2',a=>a.digest=sha256Other(),a=>a.size_in_bytes=0,a=>a.workflow_run.id++,a=>a.workflow_run.repository_id++,a=>a.workflow_run.head_repository_id++,a=>a.workflow_run.head_sha=tree]){
    const a=clone(f.artifact);change(a);assert.throws(()=>validateQualityArtifact(a,f.ctx,9,sha));
  }
  const fork=clone(f.ctx);fork.headRepositoryId=123;assert.throws(()=>validateQualityArtifact(f.artifact,fork,9,sha));
});

test('quality record rejects wrong workflow, run, source, archive, missing security/SBOM evidence and changed bytes',()=>{
  const f=qualityFixture();validateQualityRecord(f.record,f.ctx,f.files,f.identity);
  for(const key of Object.keys(f.ctx)){
    const r=clone(f.record);r.context[key]=null;assert.throws(()=>validateQualityRecord(r,f.ctx,f.files,f.identity),key);
  }
  for(const name of Object.keys(f.files)){
    const files=clone(f.files);delete files[name];const r={...f.record,files};assert.throws(()=>validateQualityRecord(r,f.ctx,files,f.identity),name);
    const changed=clone(f.files);changed[name]='e'.repeat(64);assert.throws(()=>validateQualityRecord(f.record,f.ctx,changed,f.identity),name);
  }
  for(const change of [r=>r.promotionEligible=true,r=>r.purpose='release',r=>r.archiveSHA256='e'.repeat(64),r=>r.indexDigest='bad',r=>r.indexDigest=sha256Other()]){
    const r=clone(f.record);change(r);assert.throws(()=>validateQualityRecord(r,f.ctx,f.files,f.identity));
  }
});

test('quality security acceptance requires complete bound scans, SBOM, audit and hardened runtime evidence',()=>{
  const f=evidenceFixture();Object.assign(f.evidence.runtime,{imageID:sha,results:[{type:'alpine',vulnerabilities:[],secrets:[]}]});validateQualitySecurity(f.identity,f.evidence);
  for(const change of [e=>delete e.sbom,e=>delete e.scanIdentity,e=>delete e.scanner,e=>delete e.health,e=>delete e.runtime,e=>delete e.builder,e=>e.runtime.results=[],e=>e.runtime.results[0].vulnerabilities=[{severity:'HIGH'}],e=>e.runtime.results[0].secrets=[{}],e=>e.runtime.imageID=sha256Other(),e=>e.scanIdentity.indexDigest=sha256Other(),e=>e.scanIdentity.archiveSHA256='f'.repeat(64),e=>e.runtime.blocked=true,e=>e.builder.unapprovedHighCount=1,e=>e.builder.secrets=1,e=>e.npm.counts.high=1,e=>e.health.checks.pop()]){
    const e=clone(f.evidence);change(e);assert.throws(()=>validateQualitySecurity(f.identity,e));
  }
});

test('quality browser results require exact archive/assets, source, workflow, run, attempt and all eight suites',()=>{
  const f=qualityFixture(),{identity}=evidenceFixture(),browser={...f.ctx,archiveSHA256:identity.archiveSHA256,indexDigest:identity.indexDigest,assetsSHA256:identity.assetsSHA256,suites:suites.map(name=>({name,conclusion:'success'}))};
  validateQualityBrowser(identity,browser,f.ctx);
  for(const change of [b=>b.sourceCommit=tree,b=>b.sourceTree=source,b=>b.workflow='.github/workflows/other.yml',b=>b.runId++,b=>b.runAttempt++,b=>b.archiveSHA256='f'.repeat(64),b=>b.indexDigest=sha256Other(),b=>b.assetsSHA256='f'.repeat(64),b=>b.suites.pop(),b=>b.suites[0].conclusion='failure',b=>b.suites.push(b.suites[0]),b=>b.promotionEligible=true]){
    const b=clone(browser);change(b);assert.throws(()=>validateQualityBrowser(identity,b,f.ctx));
  }
});

async function artifactZip(input=[{name:'assets/index.html'}],mutate=()=>{},zip64=false,context={}){
  const {yauzl,yazl}=createRequire(import.meta.url)('playwright-core/lib/utilsBundle');
  const entries=input.map(entry=>({...entry,data:Buffer.from(entry.data??'fixture contents')}));
  const record={...context,schemaVersion:1,purpose:'quality',promotionEligible:false,files:Object.fromEntries(entries.filter(e=>!e.name.endsWith('/')).map(e=>[e.name,hash(e.data)]))};
  entries.push({name:'quality.json',data:Buffer.from(JSON.stringify(record))});
  const archive=new yazl.ZipFile(),chunks=[],complete=new Promise((resolve,reject)=>{archive.outputStream.on('data',chunk=>chunks.push(chunk));archive.outputStream.on('end',()=>resolve(Buffer.concat(chunks)));archive.outputStream.on('error',reject);});
  for(const entry of entries){
    const directory=entry.name.endsWith('/'),placeholder='x'.repeat(Buffer.byteLength(entry.name)-(directory?1:0))+(directory?'/':'');
    const options={mode:directory?0o40755:0o100644,forceDosTimestamp:true,forceZip64Format:zip64};
    if(directory)archive.addEmptyDirectory(placeholder,options);
    else archive.addReadStream(Readable.from([entry.data]),placeholder,{...options,size:entry.data.length});
  }
  archive.end({forceZip64Format:zip64});const bytes=await complete;
  const reader=await yauzl.fromBufferPromise(bytes,{lazyEntries:true,decodeStrings:false,autoClose:false});
  const positions=[];let central=reader.readEntryCursor,index=0;
  try{for await(const entry of reader.eachEntry()){
    const wanted=entries[index++],name=Buffer.from(wanted.name),local=entry.relativeOffsetOfLocalHeader;
    name.copy(bytes,central+46);name.copy(bytes,local+30);
    // Match the Unix creator/modes and signed streaming descriptors observed in
    // retained ZIPs produced by the repository's pinned GitHub upload action.
    bytes.writeUInt16LE(813,central+4);
    bytes.writeUInt32LE((((wanted.mode??(wanted.name.endsWith('/')?0o40755:0o100644))<<16)|(wanted.dos??(wanted.name.endsWith('/')?0x10:0x20)))>>>0,central+38);
    for(const offset of [central+8,local+6])bytes.writeUInt16LE(bytes.readUInt16LE(offset)&~0x800,offset);
    positions.push({central,local,name:wanted.name});central=reader.readEntryCursor;
  }}finally{reader.close();}
  mutate(bytes,positions);return bytes;
}

function zipCLI(bytes,expectedDigest='sha256:'+hash(bytes)){
  const root=mkdtempSync(join(tmpdir(),'zevyrn-quality-zip-')),file=join(root,'artifact.zip'),destination=join(root,'packet');writeFileSync(file,bytes);
  const result=spawnSync(process.execPath,['scripts/release-integrity.mjs','quality-zip',file,expectedDigest,destination],{encoding:'utf8'});
  return {result,destination};
}

test('workflow ZIP command accepts GitHub streaming/ZIP64 semantics and manifest-derived directories',async()=>{
  for(const zip64 of [false,true]){
    const {result,destination}=zipCLI(await artifactZip([{name:'assets/'},{name:'assets/index.html'}],undefined,zip64));
    assert.equal(result.status,0,result.stderr);assert.equal(readFileSync(join(destination,'assets/index.html'),'utf8'),'fixture contents');
  }
  const data=Buffer.alloc(256*1024,0x61),large=zipCLI(await artifactZip([{name:'archive.oci.tar',data}]));
  assert.equal(large.result.status,0,large.result.stderr);assert.equal(hash(readFileSync(join(large.destination,'archive.oci.tar'))),hash(data));
});

test('workflow ZIP command rejects symlinks, special types, unexpected directories and conflicts before creating destination',async()=>{
  const cases=[
    [{name:'assets/index.html',mode:0o120777}],
    ...[0o010644,0o020644,0o060644,0o140644].map(mode=>[{name:'assets/index.html',mode}]),
    [{name:'assets/index.html',dos:0x420}],
    [{name:'assets/index.html'},{name:'unexpected-empty/'}],
    [{name:'assets/index.html'},{name:'assets/index.html'}],
    [{name:'assets'},{name:'assets/index.html'}],
    [{name:'assets/index.html'},{name:'ASSETS/INDEX.HTML'}],
    [{name:'assets/index.html'},{name:'ASSETS/other.html'}]
  ];
  for(const entries of cases){const {result,destination}=zipCLI(await artifactZip(entries));assert.equal(result.status,1,JSON.stringify(entries));assert.equal(result.stderr.trim(),'QUALITY_ZIP_INVALID');assert(!existsSync(destination));}
});

test('workflow ZIP command rejects traversal, absolute paths and Windows path aliases before extraction',async()=>{
  for(const name of ['../escaped.txt','/absolute.txt','C:/drive.txt','C:relative.txt','//server/share','assets\\file.txt','assets/../file.txt','assets//file.txt','assets/./file.txt','NUL.txt','COM1.txt','trailing.','trailing ','file:stream','bad\0name','bad\nname']){
    const {result,destination}=zipCLI(await artifactZip([{name}]));assert.equal(result.status,1,name);assert.equal(result.stderr.trim(),'QUALITY_ZIP_INVALID');assert(!existsSync(destination));
  }
});

test('workflow ZIP command rejects malformed, ambiguous, encrypted or unsupported metadata before extraction',async()=>{
  const mutations=[
    (b,p)=>b.writeUInt32LE(0,p[0].local),
    (b,p)=>b.writeUInt16LE(0x0809,p[0].central+8),
    (b,p)=>b.writeUInt16LE(99,p[0].central+10),
    (b,p)=>b.writeUInt16LE(0x0b2d,p[0].central+4),
    (b,p)=>b.writeUInt32LE(0,p[0].central+38),
    (b,p)=>b.writeUInt16LE(1,p[0].central+36),
    (b,p)=>b.writeUInt16LE(b.readUInt16LE(p[0].central+30)+1,p[0].central+30),
    (b,p)=>b[p[0].local+30]=0x79,
    (b,p)=>b.writeUInt16LE(0,p[0].local+6),
    (b,p)=>b.writeUInt32LE(42,p[0].local+14),
    (b,p)=>b[p[0].local+30+b.readUInt16LE(p[0].local+26)+b.readUInt16LE(p[0].local+28)]^=0xff
  ];
  for(const mutate of mutations){const {result,destination}=zipCLI(await artifactZip(undefined,mutate));assert.equal(result.status,1);assert.equal(result.stderr.trim(),'QUALITY_ZIP_INVALID');assert(!existsSync(destination));}
});

test('workflow ZIP command preserves checksum rejection and does not accept plain bytes as an archive',async()=>{
  for(const [bytes,digest,code] of [[await artifactZip(),sha,'QUALITY_ZIP_CHECKSUM_MISMATCH'],[Buffer.from('not a ZIP'),null,'QUALITY_ZIP_INVALID']]){
    const {result,destination}=zipCLI(bytes,digest??'sha256:'+hash(bytes));assert.equal(result.status,1);assert.equal(result.stderr.trim(),code);assert(!existsSync(destination));
  }
});

test('quality evidence cannot enter the existing release promotion path even with a modified eligibility flag',()=>{
  const f=qualityFixture();for(const promotionEligible of [false,true])assert.throws(()=>validatePacketPurpose({...f.record,promotionEligible},{purpose:'release',pullRequest:null}));
  const run=runFixture();run.run.path='.github/workflows/quality-security.yml';run.run.event='push';run.artifacts.artifacts[0].name='quality-runtime-42-2';assert.throws(()=>assess(run));
});

test('quality CLI authenticates an actual retained OCI packet and rejects changed archive, identity, assets, evidence and attempt',{skip:!existsSync('.github/workflows/quality-security.yml')&&'Requires a Git source checkout'},async()=>{
  const sourceCommit=spawnSync('git',['rev-parse','HEAD'],{encoding:'utf8'}),sourceTree=spawnSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8'});
  assert.equal(sourceCommit.status,0);assert.equal(sourceTree.status,0);
  const f=assetFixture(),packet=f.root,oci=join(packet,'oci-fixture'),archive=join(packet,'archive.oci.tar');mkdirSync(oci);
  const members=graph(model=>model.config.config.Labels['org.opencontainers.image.revision']=sourceCommit.stdout.trim()).members;
  for(const [name,bytes] of members){const path=join(oci,name);mkdirSync(join(path,'..'),{recursive:true});writeFileSync(path,bytes);}
  assert.equal(spawnSync('tar',['-cf',archive,'-C',oci,...members.keys()],{encoding:'utf8'}).status,0);
  const identity=await inspectArchive(archive,sourceCommit.stdout.trim());identity.sourceTree=sourceTree.stdout.trim();
  const assets=JSON.stringify((await assetSnapshot(f.runtime)).files);writeFileSync(join(packet,'assets.json'),assets);identity.assetsSHA256=hash(Buffer.from(assets));
  const identityBytes=JSON.stringify(identity);writeFileSync(join(packet,'identity.json'),identityBytes);
  const {evidence}=evidenceFixture();Object.assign(evidence.runtime,{imageID:identity.configDigest,results:[{type:'alpine',vulnerabilities:[],secrets:[]}]});
  evidence.health.archiveSHA256=identity.archiveSHA256;evidence.health.indexDigest=identity.indexDigest;
  Object.assign(evidence.scanIdentity,identity,{runtimeImageID:identity.configDigest,sbomImageID:identity.configDigest});
  evidence.sbom.metadata.component.properties[0].value=identity.configDigest;
  for(const [name,file] of Object.entries({health:'health.json',runtime:'runtime-scan.json',builder:'builder-scan.json',scanIdentity:'runtime-scan-identity.json',sbom:'runtime-sbom.cdx.json',scanner:'scanner-version.json',npm:'npm-audit.json'}))writeFileSync(join(packet,file),JSON.stringify(evidence[name]));
  const event=join(packet,'event.json');writeFileSync(event,JSON.stringify({repository:{id:repositoryId}}));
  const env={...process.env,QUALITY_SOURCE:identity.sourceCommit,GITHUB_SHA:identity.sourceCommit,GITHUB_REPOSITORY:repository,GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',GITHUB_WORKFLOW_REF:`${repository}/.github/workflows/quality-security.yml@refs/heads/main`,GITHUB_RUN_ID:'42',GITHUB_RUN_ATTEMPT:'2',GITHUB_EVENT_PATH:event};
  const cli=(mode,overrides={})=>spawnSync(process.execPath,['scripts/release-integrity.mjs',mode,packet],{env:{...env,...overrides},encoding:'utf8'});
  const record=cli('quality-record');assert.equal(record.status,0,record.stderr);assert.equal(cli('quality-verify').status,0);
  const manifest=JSON.parse(readFileSync(join(packet,'quality.json')));
  const transported=zipCLI(await artifactZip(Object.keys(manifest.files).map(name=>({name,data:readFileSync(join(packet,name))})),undefined,false,manifest));
  assert.equal(transported.result.status,0,transported.result.stderr);
  const consumed=spawnSync(process.execPath,['scripts/release-integrity.mjs','quality-verify',transported.destination],{env,encoding:'utf8'});
  assert.equal(consumed.status,0,consumed.stderr);
  assert.equal(JSON.parse(readFileSync(join(packet,'quality.json'))).promotionEligible,false);
  // Exercise the actual cross-run packet validator used by combined-fetch/seal,
  // including real tar bytes, retained inventories and independent browser record.
  const releaseRoot=mkdtempSync(join(tmpdir(),'zevyrn-cross-run-')),builderDir=join(releaseRoot,'builder'),builderOCI=join(builderDir,'builder.oci.tar'),builderFiles=join(releaseRoot,'builder-fixture');mkdirSync(builderDir);mkdirSync(builderFiles);
  const builderModel=builderGraphFixture();for(const [name,bytes] of builderModel.members){const path=join(builderFiles,name);mkdirSync(join(path,'..'),{recursive:true});writeFileSync(path,bytes);}
  assert.equal(spawnSync('tar',['-cf',builderOCI,'-C',builderFiles,...builderModel.members.keys()],{encoding:'utf8'}).status,0);
  const selected={...mainReleaseFixture().check(),sourceCommit:identity.sourceCommit,sourceTree:identity.sourceTree,createdAt:new Date(Date.now()-600000).toISOString(),startedAt:new Date(Date.now()-600000).toISOString()};
  const builderIdentity={...await inspectBuilderArchive(builderOCI),scanArchiveSHA256:'a'.repeat(64),sourceCommit:identity.sourceCommit,sourceTree:identity.sourceTree,runId:42,runAttempt:2};
  writeFileSync(join(builderDir,'builder-identity.json'),JSON.stringify(builderIdentity));
  writeFileSync(join(builderDir,'quality.json'),JSON.stringify({schemaVersion:1,purpose:'quality',promotionEligible:false,files:await snapshot(builderDir)}));
  writeFileSync(join(packet,'builder-reference.json'),JSON.stringify({identity:builderIdentity,artifact:selected.artifacts.builder}));
  const currentScanner={Version:'0.76.0',VulnerabilityDB:{Version:2,UpdatedAt:new Date(Date.now()-600000).toISOString(),DownloadedAt:new Date().toISOString(),NextUpdate:new Date(Date.now()+86400000).toISOString()}};
  writeFileSync(join(packet,'scanner-version.json'),JSON.stringify(currentScanner));
  const builderSummary={...evidence.builder,imageID:builderIdentity.configDigest};writeFileSync(join(packet,'builder-scan.json'),JSON.stringify(builderSummary));
  assert.equal(cli('quality-record').status,0);cpSync(packet,join(releaseRoot,'runtime'),{recursive:true});mkdirSync(join(releaseRoot,'browser'));
  const ctx=JSON.parse(readFileSync(join(packet,'quality.json'))).context,browserRecord={...ctx,archiveSHA256:identity.archiveSHA256,indexDigest:identity.indexDigest,assetsSHA256:identity.assetsSHA256,suites:suites.map(name=>({name,conclusion:'success'}))};
  const browserPath=join(releaseRoot,'browser/browser-results.json');writeFileSync(browserPath,JSON.stringify(browserRecord));
  await authenticatePackets(releaseRoot,selected);
  for(const change of [s=>s.sourceTree=source,s=>s.sourceCommit=tree,s=>s.runAttempt++,s=>s.artifacts.builder.id++]){const s=clone(selected);change(s);await assert.rejects(authenticatePackets(releaseRoot,s));}
  for(const change of [b=>b.suites.pop(),b=>b.assetsSHA256='a'.repeat(64),b=>b.promotionEligible=true]){const b=clone(browserRecord);change(b);writeFileSync(browserPath,JSON.stringify(b));await assert.rejects(authenticatePackets(releaseRoot,selected));}writeFileSync(browserPath,JSON.stringify(browserRecord));
  for(const name of ['builder/builder.oci.tar','runtime/runtime-sbom.cdx.json','runtime/health.json']){const file=join(releaseRoot,name);renameSync(file,file+'.missing');await assert.rejects(authenticatePackets(releaseRoot,selected));renameSync(file+'.missing',file);}
  writeFileSync(builderOCI,Buffer.from('substituted OCI archive'));await assert.rejects(authenticatePackets(releaseRoot,selected));
  assert.equal(cli('quality-verify',{GITHUB_RUN_ATTEMPT:'3'}).status,1);
  const original=readFileSync(archive);writeFileSync(archive,Buffer.concat([original,Buffer.from('changed')]));assert.equal(cli('quality-verify').status,1);writeFileSync(archive,original);
  writeFileSync(join(packet,'identity.json'),JSON.stringify({...identity,indexDigest:sha256Other()}));assert.equal(cli('quality-verify').status,1);writeFileSync(join(packet,'identity.json'),identityBytes);
  renameSync(join(packet,'runtime-sbom.cdx.json'),join(packet,'missing-sbom.json'));assert.equal(cli('quality-verify').status,1);renameSync(join(packet,'missing-sbom.json'),join(packet,'runtime-sbom.cdx.json'));
  writeFileSync(join(f.runtime,'index.html'),'modified application asset');assert.equal(cli('quality-verify').status,1);
});
