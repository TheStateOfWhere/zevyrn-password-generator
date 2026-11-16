// Small, version-specific validators. Artifact transport and orchestration use GitHub Actions.
import assert from 'node:assert/strict';
import {readFile,writeFile,readdir,lstat} from 'node:fs/promises';
import {readFileSync} from 'node:fs';
import {resolve,relative,sep} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {pathToFileURL} from 'node:url';
export const repository='TheStateOfWhere/zevyrn-password-generator';
export const repositoryId=1421770645;
export const version='1.2.2';
export const suites=['selection','keysmith','profiles','themes','contrast-regression','ui-corrections','focus-copy','regeneration'];
const sourceURL='https://github.com/'+repository;
const manifestType='application/vnd.oci.image.manifest.v1+json';
const indexType='application/vnd.oci.image.index.v1+json';
const configType='application/vnd.oci.image.config.v1+json';
const hex=/^[0-9a-f]{64}$/,digest=/^sha256:[0-9a-f]{64}$/;
export const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const json=bytes=>JSON.parse(bytes.toString());
const same=(a,b)=>assert.deepEqual(a,b);
const sha=value=>assert(digest.test(value),'Invalid digest');
const commit=value=>assert(/^[0-9a-f]{40}$/.test(value),'Invalid commit/tree');
const failureCodes=new WeakMap();
const codes=new Set(['OCI_LAYOUT_INVALID','OCI_RUNTIME_DESCRIPTOR_INVALID','OCI_RUNTIME_CONFIG_INVALID','OCI_ATTESTATION_DESCRIPTOR_INVALID','OCI_ATTESTATION_CONFIG_INVALID','OCI_PROVENANCE_INVALID','OCI_PROVENANCE_SUBJECT_INVALID','OCI_BLOB_DIGEST_MISMATCH','OCI_ARCHIVE_READ_INVALID','OCI_INSPECTION_OUTPUT_INVALID','SOURCE_IDENTITY_INVALID','RELEASE_INTEGRITY_UNEXPECTED']);
function stage(code,operation){try{return operation();}catch(error){if(failureCodes.has(error))throw error;const failure=new Error();failureCodes.set(failure,code);throw failure;}}
export const diagnosticCode=error=>failureCodes.get(error)??'RELEASE_INTEGRITY_UNEXPECTED';
export function inspectionDiagnostic(code){assert(code==='OK'||codes.has(code));return {schemaVersion:1,promotionEligible:false,stage:'archive-inspection',result:code==='OK'?'success':'failure',code};}
for(const code of ['SCAN_ARCHIVE_INVALID','RUNTIME_SCAN_FAILED','SBOM_GENERATION_FAILED'])codes.add(code);
export function sanitizedFailureStages(input){
  const result={};for(const name of ['archive','scanArchive','security','sbom','hardening']){
    const outcome=input?.[name];assert(['success','failure','skipped','cancelled'].includes(outcome));result[name]=outcome;
  }
  return result;
}
export function sanitizedScannerMetadata(input){
  if(!input)return null;
  assert(input.Version==='0.76.0'&&input.VulnerabilityDB?.Version===2);
  const db={Version:2};for(const name of ['UpdatedAt','DownloadedAt','NextUpdate']){const value=input.VulnerabilityDB[name];assert(typeof value==='string'&&/^\d{4}-\d\d-\d\dT[\d:.]+Z$/.test(value)&&Number.isFinite(Date.parse(value)));db[name]=value;}
  return {Version:input.Version,VulnerabilityDB:db};
}
export function sanitizedScanSummary(input){
  if(!input)return null;assert(typeof input.blocked==='boolean');const result={blocked:input.blocked};
  for(const name of ['blockingVulnerabilities','secrets','approvedHighCount','unapprovedHighCount']){
    if(Object.hasOwn(input,name)){assert(Number.isSafeInteger(input[name])&&input[name]>=0);result[name]=input[name];}
  }
  assert(Object.hasOwn(result,'blockingVulnerabilities')&&Object.hasOwn(result,'secrets'));return result;
}
export function sanitizedToolIdentity(buildx,buildkit,image){
  const version=/\bv\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\b/;
  return {buildxVersion:buildx.match(/^github\.com\/docker\/buildx\s+(v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)\b/)?.[1]??null,
    buildkitVersion:buildkit.split(/\r?\n/).find(line=>/^\s*BuildKit(?: version)?:\s*v/.test(line))?.match(version)?.[0]??null,
    buildkitImageID:/^sha256:[0-9a-f]{64}$/.test(image.trim())?image.trim():null};
}
export function qualificationIdentity(env,event,checkedOutCommit) {
  assert(env.GITHUB_REPOSITORY===repository&&event.repository?.id===repositoryId);
  commit(env.GITHUB_SHA);commit(checkedOutCommit);
  if(env.GITHUB_EVENT_NAME==='pull_request'){
    const pr=event.pull_request;
    assert(Number.isSafeInteger(event.number)&&event.number>0&&pr?.number===event.number);
    assert(env.GITHUB_REF===`refs/pull/${event.number}/merge`);
    assert(pr.head?.repo?.id===repositoryId&&pr.base?.repo?.id===repositoryId&&pr.base.ref==='main');
    commit(pr.head.sha);assert(checkedOutCommit===pr.head.sha,'Must check out the actual PR head');
    assert(typeof pr.head.ref==='string'&&pr.head.ref.length>0&&!/[\x00-\x20\x7f]/.test(pr.head.ref));
    return {purpose:'pr',sourceCommit:pr.head.sha,pullRequest:event.number,qualityEvent:'pull_request',qualityBranch:pr.head.ref};
  }
  assert(env.GITHUB_EVENT_NAME==='workflow_dispatch'&&env.GITHUB_REF==='refs/heads/main');
  assert(event.inputs?.source_commit===env.GITHUB_SHA&&checkedOutCommit===env.GITHUB_SHA);
  return {purpose:'release',sourceCommit:env.GITHUB_SHA,pullRequest:null,qualityEvent:'push',qualityBranch:'main'};
}
export function validateConfig(c,sourceCommit) {
  commit(sourceCommit);
  assert(c.os==='linux'&&c.architecture==='amd64');
  const p=c.config;
  assert(p.User==='10001:10001'&&p.WorkingDir==='/'&&p.StopSignal==='SIGQUIT');
  same(p.Entrypoint,['nginx']);same(p.Cmd,['-g','daemon off;']);same(p.ExposedPorts,{'8080/tcp':{}});
  same(p.Healthcheck.Test,['CMD-SHELL','wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1']);
  assert(p.Healthcheck.Interval===30000000000&&p.Healthcheck.Timeout===3000000000&&p.Healthcheck.StartPeriod===10000000000&&p.Healthcheck.Retries===3);
  same(p.Env,['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','NGINX_VERSION=1.30.6','PKG_RELEASE=1','DYNPKG_RELEASE=1','NJS_VERSION=1.0.2','NJS_RELEASE=1','ACME_VERSION=0.4.1']);
  assert(p.Labels['org.opencontainers.image.version']===version&&p.Labels['org.opencontainers.image.revision']===sourceCommit&&p.Labels['org.opencontainers.image.source']===sourceURL);
  assert(c.rootfs.type==='layers'&&c.rootfs.diff_ids.length>0);c.rootfs.diff_ids.forEach(sha);
}
export function inspectGraph(read,names,sourceCommit) {
  return stage('OCI_LAYOUT_INVALID',()=>{
  const seen=new Set(),used=new Set();
  for(const name of names){assert(!seen.has(name),'Duplicate archive member');seen.add(name);assert(/^(?:index\.json|oci-layout|blobs\/?|blobs\/sha256\/?|blobs\/sha256\/[0-9a-f]{64})$/.test(name),'Unexpected archive member');}
  same(json(read('oci-layout')),{'imageLayoutVersion':'1.0.0'});
  const blob=d=>stage('OCI_BLOB_DIGEST_MISMATCH',()=>{sha(d.digest);assert(Number.isSafeInteger(d.size)&&d.size>0);const name='blobs/sha256/'+d.digest.slice(7),bytes=read(name);assert(bytes.length===d.size&&'sha256:'+hash(bytes)===d.digest,'Blob digest/size mismatch');used.add(name);return bytes;});
  let bytes=read('index.json'),index=json(bytes);
  if(index.manifests?.length===1&&index.manifests[0].mediaType===indexType){bytes=blob(index.manifests[0]);index=json(bytes);}
  assert(index.schemaVersion===2&&index.mediaType===indexType&&Array.isArray(index.manifests));
  const descriptor=stage('OCI_RUNTIME_DESCRIPTOR_INVALID',()=>{
    const runtime=index.manifests.filter(d=>d.platform?.os==='linux'&&d.platform?.architecture==='amd64');
    assert(runtime.length===1,'Expected exactly one Linux/amd64 runtime');
    const d=runtime[0];assert(d.mediaType===manifestType);assert(!d.platform.variant);return d;
  });
  const runtimeManifest=json(blob(descriptor));assert(runtimeManifest.schemaVersion===2&&runtimeManifest.mediaType===manifestType&&runtimeManifest.config.mediaType===configType);
  const config=stage('OCI_RUNTIME_CONFIG_INVALID',()=>{const c=json(blob(runtimeManifest.config));validateConfig(c,sourceCommit);return c;});
  assert(runtimeManifest.layers.length>0);
  for(const layer of runtimeManifest.layers){assert(layer.mediaType==='application/vnd.oci.image.layer.v1.tar+gzip');blob(layer);}
  const attestations=index.manifests.filter(d=>d!==descriptor);stage('OCI_ATTESTATION_DESCRIPTOR_INVALID',()=>assert(attestations.length<=1,'Unexpected extra manifests'));
  for(const d of attestations){
    stage('OCI_ATTESTATION_DESCRIPTOR_INVALID',()=>{
    assert(d.mediaType===manifestType&&d.platform?.os==='unknown'&&d.platform?.architecture==='unknown','Unexpected platform');
    assert(d.annotations?.['vnd.docker.reference.type']==='attestation-manifest'&&d.annotations['vnd.docker.reference.digest']===descriptor.digest,'Unexpected attestation descriptor');
    const m=json(blob(d));assert(m.schemaVersion===2&&m.mediaType===manifestType);
    stage('OCI_ATTESTATION_CONFIG_INVALID',()=>{
      assert(m.layers.length===1);
      const c=json(blob(m.config));
      if(m.config.mediaType==='application/vnd.oci.empty.v1+json'){
        same(c,{});assert(m.config.size===2&&m.config.digest==='sha256:'+hash(Buffer.from('{}')));
        if(Object.hasOwn(m.config,'data'))assert(m.config.data==='e30=');
        assert(m.artifactType==='application/vnd.docker.attestation.manifest.v1+json');
        stage('OCI_PROVENANCE_SUBJECT_INVALID',()=>{assert(m.subject);same({mediaType:m.subject.mediaType,digest:m.subject.digest,size:m.subject.size},{mediaType:descriptor.mediaType,digest:descriptor.digest,size:descriptor.size});});
      }else{
        assert(m.config.mediaType===configType&&!Object.hasOwn(m,'artifactType')&&!Object.hasOwn(m,'subject'));
        same(c,{architecture:'unknown',os:'unknown',config:{},rootfs:{type:'layers',diff_ids:m.layers.map(layer=>layer.digest)}});
      }
    });
    for(const layer of m.layers){
      stage('OCI_PROVENANCE_INVALID',()=>{
      assert(layer.mediaType==='application/vnd.in-toto+json');const s=json(blob(layer));
      assert(['https://in-toto.io/Statement/v0.1','https://in-toto.io/Statement/v1'].includes(s._type));
      assert(['https://slsa.dev/provenance/v0.2','https://slsa.dev/provenance/v1'].includes(s.predicateType));
      assert(layer.annotations?.['in-toto.io/predicate-type']===s.predicateType);
      stage('OCI_PROVENANCE_SUBJECT_INVALID',()=>{assert(s.subject?.length===1);same(s.subject[0].digest,{sha256:descriptor.digest.slice(7)});});
      });
    }
    });
  }
  same([...seen].filter(n=>/^blobs\/sha256\/[0-9a-f]{64}$/.test(n)).sort(),[...used].sort());
  return {version,indexDigest:'sha256:'+hash(bytes),platformDigest:descriptor.digest,configDigest:runtimeManifest.config.digest,diffIDs:config.rootfs.diff_ids,config};
  });
}
const run=(program,args,input)=>{const r=spawnSync(program,args,{input,maxBuffer:512*1024*1024});if(r.error)throw r.error;assert(r.status===0,program+' failed');return r.stdout;};
export async function inspectArchive(path,sourceCommit) {
  const names=stage('OCI_ARCHIVE_READ_INVALID',()=>run('tar',['-tf',path]).toString().trim().split(/\r?\n/));
  const result=inspectGraph(name=>stage('OCI_ARCHIVE_READ_INVALID',()=>run('tar',['-xOf',path,name])),names,sourceCommit);
  return {...result,sourceCommit,archiveSHA256:hash(await readFile(path))};
}
export async function snapshot(directory) {
  const files={};
  async function walk(dir){for(const name of (await readdir(dir)).sort()){const path=resolve(dir,name),s=await lstat(path);assert(!s.isSymbolicLink(),'Symlink rejected');if(s.isDirectory())await walk(path);else{assert(s.isFile());files[relative(directory,path).split(sep).join('/')]=hash(await readFile(path));}}}
  await walk(resolve(directory));return files;
}
export const nginxAssetSHA256='876766b4e80133fd490603e073d3567425b88794828a9292104244c9e40875ed';
function safeAssetPath(path){
  assert(typeof path==='string'&&path.length>0&&path.split('/').every(part=>/^[A-Za-z0-9._-]+$/.test(part)&&part!=='.'&&part!=='..'&&!part.endsWith('.')&&!/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part)),'Unsafe asset path');
}
function assetDirectories(files){
  const directories=new Set();for(const path of Object.keys(files)){safeAssetPath(path);const parts=path.split('/');while(parts.length>1){parts.pop();directories.add(parts.join('/'));}}
  return [...directories].sort();
}
function validateAssetInventory(inventory){
  same(Object.keys(inventory).sort(),['directories','files']);
  assert(inventory.files&&typeof inventory.files==='object'&&!Array.isArray(inventory.files));
  assert(Object.keys(inventory.files).length>0&&Array.isArray(inventory.directories));
  for(const [path,digest] of Object.entries(inventory.files)){safeAssetPath(path);assert(typeof digest==='string'&&hex.test(digest));}
  inventory.directories.forEach(safeAssetPath);
  same(inventory.directories,assetDirectories(inventory.files));
  for(const path of inventory.directories)assert(!Object.hasOwn(inventory.files,path),'File/directory collision');
  const paths=[...Object.keys(inventory.files),...inventory.directories];assert(new Set(paths.map(path=>path.toLowerCase())).size===paths.length,'Non-portable asset collision');
}
export async function assetSnapshot(directory){
  const root=resolve(directory),entries=[],directories=[];
  const rootStat=await lstat(root);assert(rootStat.isDirectory()&&!rootStat.isSymbolicLink());
  async function walk(dir){for(const name of (await readdir(dir)).sort()){
    const path=resolve(dir,name),key=relative(root,path).split(sep).join('/');safeAssetPath(key);
    // Backslashes must not become path separators when artifacts cross platforms.
    assert(!name.includes('\\'));const stat=await lstat(path);assert(!stat.isSymbolicLink(),'Asset symlink rejected');
    if(stat.isDirectory()){directories.push(key);await walk(path);}else{assert(stat.isFile(),'Non-regular asset rejected');entries.push([key,hash(await readFile(path))]);}
  }}
  await walk(root);const inventory={files:Object.fromEntries(entries),directories:directories.sort()};validateAssetInventory(inventory);return inventory;
}
export function validateRuntimeAssets(application,runtime){
  validateAssetInventory(application);validateAssetInventory(runtime);
  assert(!Object.keys(application.files).some(path=>path.split('/').at(-1)==='50x.html'),'Application/server asset collision');
  same(runtime.files,{...application.files,'50x.html':nginxAssetSHA256});
  same(runtime.directories,application.directories);return runtime.files;
}
export async function verifyRetainedAssets(directory,identity){
  const bytes=await readFile(resolve(directory,'assets.json'));assert(identity.assetsSHA256===hash(bytes));
  const expected=json(bytes),actual=await assetSnapshot(resolve(directory,'assets'));same(actual.files,expected);return expected;
}
export function verifyLoaded(identity,image) {
  validateConfig(identity.config,identity.sourceCommit);
  sha(identity.configDigest);assert(image.Id===identity.configDigest,'Loaded image ID mismatch');
  assert(image.Os==='linux'&&image.Architecture==='amd64');same(image.RootFS.Layers,identity.diffIDs);
  for(const key of ['User','WorkingDir','StopSignal','Entrypoint','Cmd','ExposedPorts','Env','Labels'])same(image.Config[key],identity.config.config[key]);
  for(const key of ['Test','Interval','Timeout','StartPeriod','Retries'])same(image.Config.Healthcheck[key],identity.config.config.Healthcheck[key]);
}
export function inspectDockerGraph(read,names,identity){
  const seen=new Set();for(const name of names){const path=name.endsWith('/')?name.slice(0,-1):name;safeAssetPath(path);assert(!seen.has(name));seen.add(name);}
  const manifests=json(read('manifest.json'));assert(Array.isArray(manifests)&&manifests.length===1);
  const manifest=manifests[0];safeAssetPath(manifest.Config);assert(seen.has(manifest.Config));
  const bytes=read(manifest.Config);assert('sha256:'+hash(bytes)===identity.configDigest);
  const config=json(bytes);same(config,identity.config);validateConfig(config,identity.sourceCommit);
  assert(Array.isArray(manifest.Layers)&&manifest.Layers.length===identity.diffIDs.length&&new Set(manifest.Layers).size===manifest.Layers.length);
  const diffIDs=manifest.Layers.map(path=>{safeAssetPath(path);assert(seen.has(path));const layer=read(path);return 'sha256:'+hash(layer[0]===0x1f&&layer[1]===0x8b?gunzipSync(layer):layer);});
  same(diffIDs,identity.diffIDs);same(config.rootfs.diff_ids,diffIDs);return identity.configDigest;
}
export async function inspectDockerArchive(path,identity){
  const names=run('tar',['-tf',path]).toString().trim().split(/\r?\n/);
  inspectDockerGraph(name=>run('tar',['-xOf',path,name]),names,identity);return hash(await readFile(path));
}
export function validateScanIdentity(identity,scan){
  for(const key of ['sourceCommit','sourceTree','archiveSHA256','indexDigest','configDigest','diffIDs'])same(scan[key],identity[key]);
  sha(scan.configDigest);assert(hex.test(scan.scanArchiveSHA256));
}
export function validateRuntimeReportIdentity(identity,report){
  assert(report.SchemaVersion===2&&report.ArtifactType==='container_image');
  assert(report.Metadata?.ImageID===identity.configDigest);same(report.Metadata.DiffIDs,identity.diffIDs);
}
export function validateSBOMIdentity(identity,sbom){
  assert(sbom.bomFormat==='CycloneDX'&&sbom.components?.length>0);
  const properties=sbom.metadata?.component?.properties;
  const ids=properties?.filter(p=>p.name==='aquasecurity:trivy:ImageID');assert(ids?.length===1&&ids[0].value===identity.configDigest);
  same(properties.filter(p=>p.name==='aquasecurity:trivy:DiffID').map(p=>p.value),identity.diffIDs);
}
export function runtimeScanArgs(input,output,sbom=false){
  return ['image','--input',input,...(sbom?['--format','cyclonedx']:['--scanners','vuln,secret','--image-config-scanners','secret','--format','json']),'--output',output];
}
export function validateCompleteScanEvidence(identity,scan,sbom){
  validateScanIdentity(identity,scan);assert(scan.runtimeImageID===identity.configDigest&&scan.sbomImageID===identity.configDigest);
  same(scan.scanners,['vuln','secret']);same(scan.imageConfigScanners,['secret']);validateSBOMIdentity(identity,sbom);
}
export function verifyContainer(c) {
  const h=c.HostConfig;assert(c.Config.User==='10001:10001'&&c.State.Running);
  assert(h.ReadonlyRootfs&&h.Privileged===false&&h.NetworkMode==='none'&&h.PidsLimit===128&&h.Memory===134217728);
  same(h.CapDrop,['ALL']);assert(!h.CapAdd?.length&&h.SecurityOpt.some(v=>/^no-new-privileges(?::true)?$/.test(v)));
  const flags=h.Tmpfs?.['/tmp']?.split(',');for(const flag of ['rw','noexec','nosuid','size=16m','mode=1777'])assert(flags?.includes(flag));
}
export function validateRun(runInfo,jobs,artifacts,sourceCommit,now=Date.now()) {
  commit(sourceCommit);assert(runInfo.repository?.id===repositoryId&&runInfo.repository.full_name===repository);
  assert(runInfo.head_repository?.id===repositoryId&&runInfo.path==='.github/workflows/qualify-maintenance-image.yml');
  assert(runInfo.event==='workflow_dispatch'&&runInfo.head_branch==='main'&&runInfo.head_sha===sourceCommit&&runInfo.status==='completed'&&runInfo.conclusion==='success');
  assert(Number.isSafeInteger(runInfo.id)&&runInfo.id>0&&Number.isSafeInteger(runInfo.run_attempt)&&runInfo.run_attempt>0);
  const age=now-Date.parse(runInfo.created_at);assert(Number.isFinite(age)&&age>=-300000&&age<=86400000,'Qualification run is stale');
  assert(jobs.total_count===3&&jobs.jobs.length===3);same(jobs.jobs.map(j=>j.name).sort(),['browser','runtime','seal']);
  assert(jobs.jobs.every(j=>j.status==='completed'&&j.conclusion==='success'&&j.run_id===runInfo.id&&j.run_attempt===runInfo.run_attempt),'Required job did not succeed in this attempt');
  assert(artifacts.total_count===artifacts.artifacts.length&&artifacts.total_count<=100);
  const expected=`zevyrn-v1.2.2-qualified-${runInfo.id}-${runInfo.run_attempt}`;
  const matches=artifacts.artifacts.filter(a=>a.name===expected);assert(matches.length===1,'Expected one sealed artifact');
  const a=matches[0];assert(!a.expired&&Number.isSafeInteger(a.id)&&a.id>0&&a.size_in_bytes>0);sha(a.digest);
  assert(a.workflow_run?.id===runInfo.id&&a.workflow_run.head_sha===sourceCommit&&a.workflow_run.head_branch==='main'&&a.workflow_run.repository_id===repositoryId&&a.workflow_run.head_repository_id===repositoryId);
  assert(Date.parse(a.created_at)>=Date.parse(runInfo.run_started_at),'Artifact predates this attempt');
  return {runId:runInfo.id,runAttempt:runInfo.run_attempt,startedAt:Date.parse(runInfo.run_started_at),artifactCreatedAt:Date.parse(a.created_at),artifactId:a.id,artifactName:a.name,artifactDigest:a.digest,sourceCommit,jobs:jobs.jobs.map(j=>({id:j.id,name:j.name,conclusion:j.conclusion}))};
}
export function validateEvidence(identity,evidence,context) {
  assert(identity.version===version&&hex.test(identity.archiveSHA256));commit(identity.sourceCommit);commit(identity.sourceTree);
  assert(Number.isFinite(context.startedAt)&&context.startedAt>0,'Missing qualification start time');
  assert(identity.sourceCommit===context.sourceCommit&&identity.sourceTree===context.sourceTree);
  const {browser,health,runtime,builder,builderIdentity,scanner,sbom,npm,scanIdentity}=evidence;
  validateCompleteScanEvidence(identity,scanIdentity,sbom);
  assert(context.purpose==='release'?context.pullRequest===null:context.purpose==='pr'&&Number.isSafeInteger(context.pullRequest)&&context.pullRequest>0);
  same(browser.purpose,context.purpose);same(browser.pullRequest,context.pullRequest);
  assert(browser.runId===context.runId&&browser.runAttempt===context.runAttempt&&browser.sourceCommit===identity.sourceCommit&&browser.sourceTree===identity.sourceTree);
  assert(browser.archiveSHA256===identity.archiveSHA256&&browser.indexDigest===identity.indexDigest&&browser.assetsSHA256===identity.assetsSHA256);
  same(browser.suites.map(s=>s.name),suites);assert(browser.suites.every(s=>s.conclusion==='success'));
  assert(health.archiveSHA256===identity.archiveSHA256&&health.indexDigest===identity.indexDigest);
  same(health.checks,['image-config-and-rootfs','container-hardening','health','nginx-config','headers','assets','no-build-tools','graceful-stop']);assert(health.passed===true);
  for(const report of [runtime,builder])assert(report.blocked===false&&report.blockingVulnerabilities===0&&report.secrets===0);
  const fixed=['CVE-2026-113351','CVE-2026-115506','CVE-2026-117610','CVE-2026-118370','CVE-2026-125350','CVE-2026-87636','CVE-2026-9947','CVE-2026-107891'];
  assert(!runtime.results?.some(r=>r.vulnerabilities?.some(v=>fixed.includes(v.id))),'Previously blocked CVE remains');
  assert(builder.approvedHighCount===3&&builder.unapprovedHighCount===0);
  assert(builderIdentity.sourceCommit===identity.sourceCommit&&builderIdentity.sourceTree===identity.sourceTree&&hex.test(builderIdentity.archiveSHA256));sha(builderIdentity.imageID);
  assert(npm.blocked===false&&npm.counts.high===0&&npm.counts.critical===0);
  assert(scanner.Version==='0.76.0'&&scanner.VulnerabilityDB?.Version===2);
  for(const field of ['UpdatedAt','DownloadedAt','NextUpdate'])assert(Number.isFinite(Date.parse(scanner.VulnerabilityDB[field])));
  assert(Date.parse(scanner.VulnerabilityDB.DownloadedAt)>=context.startedAt&&Date.parse(scanner.VulnerabilityDB.UpdatedAt)<=Date.parse(scanner.VulnerabilityDB.DownloadedAt)+300000);
  assert(sbom.bomFormat==='CycloneDX'&&sbom.components?.length>0);
}
export function validateTags(response) {
  assert(response&&typeof response==='object'&&!Array.isArray(response));
  same(Object.keys(response).sort(),['Repository','Tags']);
  assert(response.Repository==='ghcr.io/thestateofwhere/zevyrn'&&Array.isArray(response.Tags));
  assert(response.Tags.every(t=>typeof t==='string'&&/^[\w][\w.-]{0,127}$/.test(t)));
  assert(new Set(response.Tags).size===response.Tags.length,'Duplicate registry tags');
  assert(!response.Tags.includes(version),'Destination tag already exists');
}
export function validateReleaseRef(text,expected) {
  commit(expected);const refs=text.trim().split(/\r?\n/).map(line=>line.split(/\s+/));
  assert(refs.length>=1&&refs.length<=2);assert(refs.every(([sha,ref])=>/^[0-9a-f]{40}$/.test(sha)&&['refs/tags/v1.2.2','refs/tags/v1.2.2^{}'].includes(ref)));
  assert(refs.filter(([,ref])=>ref==='refs/tags/v1.2.2').length===1);
  const peeled=refs.filter(([,ref])=>ref==='refs/tags/v1.2.2^{}');assert(peeled.length<=1);assert((peeled[0]??refs[0])[0]===expected,'Release tag moved');
}
export function validateQuality(info,jobs,source,qualification={purpose:'release',pullRequest:null,qualityEvent:'push',qualityBranch:'main'}) {
  assert(info.repository?.id===repositoryId&&info.head_repository?.id===repositoryId&&info.path==='.github/workflows/quality-security.yml');
  assert(info.head_sha===source&&info.status==='completed'&&info.conclusion==='success');
  if(qualification.purpose==='pr'){
    assert(qualification.qualityEvent==='pull_request'&&info.event==='pull_request'&&info.head_branch===qualification.qualityBranch);
    assert(Number.isSafeInteger(qualification.pullRequest)&&qualification.pullRequest>0);
    const matches=info.pull_requests?.filter(p=>p.number===qualification.pullRequest);
    assert(matches?.length===1&&matches[0].head.sha===source&&matches[0].head.ref===qualification.qualityBranch&&matches[0].base.ref==='main');
    assert(matches[0].head.repo.id===repositoryId&&matches[0].base.repo.id===repositoryId);
  }else{
    assert(qualification.purpose==='release'&&qualification.pullRequest===null&&qualification.qualityEvent==='push'&&qualification.qualityBranch==='main');
    assert(info.head_branch==='main'&&info.event==='push');
  }
  assert(jobs.total_count===2&&jobs.jobs.length===2);same(jobs.jobs.map(j=>j.name).sort(),['browser','quality-image']);
  assert(jobs.jobs.every(j=>j.run_id===info.id&&j.run_attempt===info.run_attempt&&j.status==='completed'&&j.conclusion==='success'));
}
const writeJSON=(path,value)=>writeFile(path,JSON.stringify(value,null,2)+'\n');
const readJSON=async path=>json(await readFile(path));
const context=()=>{
  const checkedOut=run('git',['rev-parse','HEAD']).toString().trim();
  const identity=process.env.QUALIFICATION_KIND
    ?qualificationIdentity(process.env,json(readFileSync(process.env.GITHUB_EVENT_PATH)),checkedOut)
    :{purpose:'release',sourceCommit:process.env.GITHUB_SHA,pullRequest:null,qualityEvent:'push',qualityBranch:'main'};
  if(process.env.QUALIFICATION_KIND){assert(identity.purpose===process.env.QUALIFICATION_KIND&&identity.sourceCommit===process.env.QUALIFICATION_SOURCE);}
  return {...identity,runId:Number(process.env.GITHUB_RUN_ID),runAttempt:Number(process.env.GITHUB_RUN_ATTEMPT),sourceTree:run('git',['rev-parse','HEAD^{tree}']).toString().trim(),startedAt:Date.parse(process.env.QUALIFICATION_STARTED_AT)};
};
const requiredFiles=['archive.oci.tar','identity.json','assets.json','browser-results.json','health.json','runtime-scan.json','runtime-scan-identity.json','builder-scan.json','builder-identity.json','scanner-version.json','runtime-sbom.cdx.json','npm-audit.json','build-metadata.json','quality-run.json','quality-jobs.json'];
export function validatePacketPurpose(seal,expected) {
  assert(['pr','release'].includes(expected.purpose));same(seal.purpose,expected.purpose);same(seal.context.purpose,expected.purpose);same(seal.context.pullRequest,expected.pullRequest);
  same(seal.promotionEligible,expected.purpose==='release');
  if(expected.purpose==='release')assert(expected.pullRequest===null&&seal.context.qualityEvent==='push'&&seal.context.qualityBranch==='main');
  else assert(Number.isSafeInteger(expected.pullRequest)&&expected.pullRequest>0&&seal.context.qualityEvent==='pull_request');
}
export async function verifyPacket(directory,expected) {
  const seal=await readJSON(resolve(directory,'qualification.json'));assert(seal.schemaVersion===1&&seal.version===version&&seal.repositoryId===repositoryId);
  validatePacketPurpose(seal,expected);
  same(seal.jobResults,{runtime:'success',browser:'success'});
  for(const key of ['sourceCommit','sourceTree','runId','runAttempt'])same(seal.context[key],expected[key]);
  assert(Number.isFinite(seal.context.startedAt)&&seal.context.startedAt>0);
  if(Number.isFinite(expected.startedAt))assert(seal.context.startedAt>=expected.startedAt);
  if(Number.isFinite(expected.artifactCreatedAt))assert(seal.context.startedAt<=expected.artifactCreatedAt);
  const actual=await snapshot(directory);delete actual['qualification.json'];same(actual,seal.files);
  for(const path of requiredFiles)assert(Object.hasOwn(actual,path),'Missing evidence: '+path);
  const identity=await readJSON(resolve(directory,'identity.json'));
  same(await inspectArchive(resolve(directory,'archive.oci.tar'),expected.sourceCommit),Object.fromEntries(Object.entries(identity).filter(([k])=>!['sourceTree','assetsSHA256'].includes(k))));
  await verifyRetainedAssets(directory,identity);
  const evidence={};for(const [name,file] of Object.entries({browser:'browser-results.json',health:'health.json',runtime:'runtime-scan.json',scanIdentity:'runtime-scan-identity.json',builder:'builder-scan.json',builderIdentity:'builder-identity.json',scanner:'scanner-version.json',sbom:'runtime-sbom.cdx.json',npm:'npm-audit.json'}))evidence[name]=await readJSON(resolve(directory,file));
  validateEvidence(identity,evidence,seal.context);same(seal.archiveSHA256,identity.archiveSHA256);same(seal.indexDigest,identity.indexDigest);
  validateQuality(await readJSON(resolve(directory,'quality-run.json')),await readJSON(resolve(directory,'quality-jobs.json')),expected.sourceCommit,seal.context);
  return {identity,seal};
}
async function main() {
  const [mode,...args]=process.argv.slice(2);
  if(mode==='qualification-context'){
    const ctx=context();
    assert(process.env.GITHUB_OUTPUT);
    await writeFile(process.env.GITHUB_OUTPUT,`purpose=${ctx.purpose}\nsource_commit=${ctx.sourceCommit}\nquality_event=${ctx.qualityEvent}\nquality_branch=${ctx.qualityBranch}\n`,{flag:'a'});
  }
  else if(mode==='prepare-scan'){
    const identity=await readJSON(args[0]);commit(identity.sourceCommit);commit(identity.sourceTree);sha(identity.configDigest);
    stage('SCAN_ARCHIVE_INVALID',()=>{const image=json(run('docker',['image','inspect',identity.configDigest]));assert(image.length===1);verifyLoaded(identity,image[0]);run('docker',['image','save','--output',args[1],identity.configDigest]);});
    const scanArchiveSHA256=await inspectDockerArchive(args[1],identity);
    const record=Object.fromEntries(['sourceCommit','sourceTree','archiveSHA256','indexDigest','configDigest','diffIDs'].map(key=>[key,identity[key]]));
    await writeJSON(args[2],{...record,scanArchiveSHA256});
  }
  else if(mode==='scan-runtime'||mode==='sbom-runtime'){
    const [scanner,identityFile,archive,recordFile,output]=args,identity=await readJSON(identityFile),record=await readJSON(recordFile);
    validateScanIdentity(identity,record);assert(await inspectDockerArchive(archive,identity)===record.scanArchiveSHA256);
    const sbom=mode==='sbom-runtime';if(sbom)assert(record.runtimeImageID===identity.configDigest);
    stage(sbom?'SBOM_GENERATION_FAILED':'RUNTIME_SCAN_FAILED',()=>run(scanner,runtimeScanArgs(archive,output,sbom)));
    assert(hash(await readFile(archive))===record.scanArchiveSHA256,'Scan archive changed');
    const report=await readJSON(output);
    if(sbom){validateSBOMIdentity(identity,report);record.sbomImageID=identity.configDigest;}
    else{validateRuntimeReportIdentity(identity,report);record.runtimeImageID=identity.configDigest;record.scanners=['vuln','secret'];record.imageConfigScanners=['secret'];}
    await writeJSON(recordFile,record);
  }
  else if(mode==='inspect'){
    let code='OK';
    try{
      const source=stage('SOURCE_IDENTITY_INVALID',()=>context().sourceCommit);
      const identity=await inspectArchive(args[0],source);
      try{await writeJSON(args[1],identity);}catch{stage('OCI_INSPECTION_OUTPUT_INVALID',()=>assert(false));}
    }catch(error){code=diagnosticCode(error);throw error;}
    finally{if(args[2])await writeJSON(args[2],inspectionDiagnostic(code));}
  }
  else if(mode==='diagnostics'){
    const safeRead=async path=>{try{return await readFile(path);}catch{return null;}};
    const archive=await safeRead(args[0]),metadata=await safeRead(args[1]),temp=process.env.RUNNER_TEMP;
    let indexDigest=null;try{const value=json(metadata)['containerimage.digest'];if(digest.test(value))indexDigest=value;}catch{}
    const text=async name=>(await safeRead(resolve(temp,name)))?.toString()??'';
    let stages=null,scanner=null;try{if(process.env.DIAGNOSTIC_STAGES)stages=sanitizedFailureStages(JSON.parse(process.env.DIAGNOSTIC_STAGES));}catch{}
    try{scanner=sanitizedScannerMetadata(json(await safeRead(resolve(args[0],'..','scanner-version.json'))));}catch{}
    const scanArchive=await safeRead(resolve(temp,'runtime-scan.tar'));
    let runtimeConfigDigest=null;try{const value=json(await safeRead(resolve(args[0],'..','identity.json'))).configDigest;if(digest.test(value))runtimeConfigDigest=value;}catch{}
    const summaries={};for(const role of ['runtime','builder']){try{summaries[role]=sanitizedScanSummary(json(await safeRead(resolve(args[0],'..',role+'-scan.json'))));}catch{summaries[role]=null;}}
    const stageCodes={archive:'ARCHIVE_STAGE_FAILED',scanArchive:'SCAN_ARCHIVE_STAGE_FAILED',security:'SECURITY_STAGE_FAILED',sbom:'SBOM_STAGE_FAILED',hardening:'HARDENING_STAGE_FAILED'};
    const failures=Object.entries(stages??{}).filter(([,outcome])=>outcome==='failure').map(([name])=>stageCodes[name]);
    await writeJSON(args[2],{schemaVersion:1,promotionEligible:false,archiveSHA256:archive?hash(archive):null,scanArchiveSHA256:scanArchive?hash(scanArchive):null,indexDigest,indexDigestVerified:false,runtimeConfigDigest,stages,failures,scanner,summaries,
      ...sanitizedToolIdentity(await text('release-buildx.txt'),await text('release-buildkit.txt'),await text('release-buildkit-image.txt'))});
  }
  else if(mode==='assets'){
    const directory=args[0],identity=await readJSON(resolve(directory,'identity.json'));
    const files=validateRuntimeAssets(await assetSnapshot(args[1]),await assetSnapshot(resolve(directory,'assets')));
    await writeJSON(resolve(directory,'assets.json'),files);
    identity.assetsSHA256=hash(await readFile(resolve(directory,'assets.json')));identity.sourceTree=context().sourceTree;
    await writeJSON(resolve(directory,'identity.json'),identity);
  } else if(mode==='check-assets')same((await assetSnapshot(args[0])).files,await readJSON(args[1]));
  else if(mode==='browser'){
    const directory=args[0],identity=await readJSON(resolve(directory,'identity.json')),ctx=context();
    const inspected=await inspectArchive(resolve(directory,'archive.oci.tar'),ctx.sourceCommit);
    same(inspected,Object.fromEntries(Object.entries(identity).filter(([k])=>!['sourceTree','assetsSHA256'].includes(k))));
    assert(identity.sourceTree===ctx.sourceTree&&identity.assetsSHA256===hash(await readFile(resolve(directory,'assets.json'))));
    const assets=await verifyRetainedAssets(directory,identity);same((await assetSnapshot('dist')).files,assets);
    const results=[];for(const name of suites){const r=spawnSync(process.execPath,['tests/browser-'+name+'.mjs'],{stdio:'inherit'});assert(r.status===0,'Browser suite failed: '+name);results.push({name,conclusion:'success'});}
    same((await assetSnapshot('dist')).files,assets);await verifyRetainedAssets(directory,identity);
    await writeJSON(resolve(directory,'browser-results.json'),{...ctx,archiveSHA256:identity.archiveSHA256,indexDigest:identity.indexDigest,assetsSHA256:identity.assetsSHA256,suites:results});
  }
  else if(mode==='loaded')verifyLoaded(await readJSON(args[0]),(await readJSON(args[1]))[0]);
  else if(mode==='container')verifyContainer((await readJSON(args[0]))[0]);
  else if(mode==='seal'){
    assert(process.env.RUNTIME_RESULT==='success'&&process.env.BROWSER_RESULT==='success');
    const directory=args[0],identity=await readJSON(resolve(directory,'identity.json')),ctx=context();
    await writeJSON(resolve(directory,'qualification.json'),{schemaVersion:1,version,repositoryId,purpose:ctx.purpose,promotionEligible:ctx.purpose==='release',context:ctx,jobResults:{runtime:process.env.RUNTIME_RESULT,browser:process.env.BROWSER_RESULT},archiveSHA256:identity.archiveSHA256,indexDigest:identity.indexDigest,files:await snapshot(directory)});
    await verifyPacket(directory,ctx);
  } else if(mode==='verify-run'){
    const selected=validateRun(await readJSON(args[0]),await readJSON(args[1]),await readJSON(args[2]),process.env.GITHUB_SHA);
    assert(selected.runId===Number(process.env.QUALIFICATION_RUN),'Unexpected qualification run ID');
    await writeJSON(args[3],selected);if(process.env.GITHUB_OUTPUT)await writeFile(process.env.GITHUB_OUTPUT,`artifact_id=${selected.artifactId}\nartifact_digest=${selected.artifactDigest}\n`,{flag:'a'});
  } else if(mode==='verify-packet'){
    const selected=await readJSON(args[1]);const result=await verifyPacket(args[0],{purpose:'release',pullRequest:null,sourceCommit:process.env.GITHUB_SHA,sourceTree:context().sourceTree,runId:selected.runId,runAttempt:selected.runAttempt,startedAt:selected.startedAt,artifactCreatedAt:selected.artifactCreatedAt});
    if(process.env.GITHUB_OUTPUT)await writeFile(process.env.GITHUB_OUTPUT,`archive_sha256=${result.identity.archiveSHA256}\nindex_digest=${result.identity.indexDigest}\n`,{flag:'a'});
  } else if(mode==='tags')validateTags(await readJSON(args[0]));
  else if(mode==='release-ref')validateReleaseRef(run('git',['ls-remote','--exit-code','origin','refs/tags/v1.2.2','refs/tags/v1.2.2^{}']).toString(),process.env.GITHUB_SHA);
  else if(mode==='quality'){const ctx=context();validateQuality(await readJSON(args[0]),await readJSON(args[1]),ctx.sourceCommit,ctx);}
  else if(mode==='zip-members'){
    const names=run('unzip',['-Z1',args[0]]).toString().trim().split('\n');const seen=new Set();
    for(const name of names){const path=name.endsWith('/')?name.slice(0,-1):name;assert(/^[A-Za-z0-9._/-]+$/.test(path)&&!path.startsWith('/')&&!path.split('/').some(p=>p==='..'||p==='.'||p===''),'Unsafe ZIP member');assert(!seen.has(name));seen.add(name);}
  }
  else throw Error('Unknown release-integrity operation');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main().catch(error=>{console.error(diagnosticCode(error));process.exitCode=1;});
