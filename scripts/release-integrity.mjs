// Small, version-specific validators. Artifact transport and orchestration use GitHub Actions.
import assert from 'node:assert/strict';
import {readFile,writeFile,readdir,lstat,mkdir,open} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import {resolve,relative,sep} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {pathToFileURL} from 'node:url';
import {validateBuilderAcceptance} from './ci-security.mjs';
const builderExceptions=JSON.parse(readFileSync(new URL('./ci-builder-exceptions.json',import.meta.url)));
export const repository='TheStateOfWhere/zevyrn-password-generator';
export const repositoryId=1421770645;
export const version='1.2.3';
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
  same(p.Env,['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','NGINX_VERSION=1.30.8','PKG_RELEASE=1','DYNPKG_RELEASE=1','NJS_VERSION=1.0.2','NJS_RELEASE=1','ACME_VERSION=0.4.2']);
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
export function inspectDockerGraph(read,names,identity,role='runtime'){
  assert(['runtime','builder'].includes(role));
  const seen=new Set();for(const name of names){const path=name.endsWith('/')?name.slice(0,-1):name;safeAssetPath(path);assert(!seen.has(name));seen.add(name);}
  const manifests=json(read('manifest.json'));assert(Array.isArray(manifests)&&manifests.length===1);
  const manifest=manifests[0];safeAssetPath(manifest.Config);assert(seen.has(manifest.Config));
  const bytes=read(manifest.Config);assert('sha256:'+hash(bytes)===identity.configDigest);
  const config=json(bytes);same(config,identity.config);
  if(role==='runtime')validateConfig(config,identity.sourceCommit);
  else assert(config.os==='linux'&&config.architecture==='amd64'&&config.rootfs.type==='layers');
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
  const expected=`zevyrn-v1.2.3-qualified-${runInfo.id}-${runInfo.run_attempt}`;
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
  validateBuilderAcceptance(builder,builderExceptions);
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
  assert(refs.length>=1&&refs.length<=2);assert(refs.every(([sha,ref])=>/^[0-9a-f]{40}$/.test(sha)&&['refs/tags/v1.2.3','refs/tags/v1.2.3^{}'].includes(ref)));
  assert(refs.filter(([,ref])=>ref==='refs/tags/v1.2.3').length===1);
  const peeled=refs.filter(([,ref])=>ref==='refs/tags/v1.2.3^{}');assert(peeled.length<=1);assert((peeled[0]??refs[0])[0]===expected,'Release tag moved');
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
const qualityWorkflow='.github/workflows/quality-security.yml';
codes.add('QUALITY_ZIP_INVALID');
codes.add('QUALITY_ZIP_CHECKSUM_MISMATCH');
function zipExtraFields(fields,length) {
  assert(fields.reduce((size,f)=>size+4+f.data.length,0)===length,'Malformed ZIP extra fields');
  const seen=new Set();for(const field of fields){
    assert(!seen.has(field.id));seen.add(field.id);
    // ZIP64 sizes/offsets and the single Unix mtime used by the pinned upload tooling.
    assert(field.id===1&&[8,16,24,28].includes(field.data.length)
      ||field.id===0x5455&&field.data.length===5&&field.data[0]===1,'Unsupported ZIP extra field');
  }
}
export async function qualityZip(bytes,expectedDigest,destination,layout={manifest:'quality.json'}) {
  stage('QUALITY_ZIP_CHECKSUM_MISMATCH',()=>{sha(expectedDigest);assert('sha256:'+hash(bytes)===expectedDigest);});
  return stageAsync('QUALITY_ZIP_INVALID',async()=>{
    // Reuse the ZIP reader already shipped in locked Playwright; no new dependency.
    const {yauzl}=createRequire(import.meta.url)('playwright-core/lib/utilsBundle');
    const {crc32}=await import('node:zlib');assert(typeof crc32==='function');
    const zip=await yauzl.fromBufferPromise(bytes,{lazyEntries:true,decodeStrings:false,autoClose:false,validateEntrySizes:true});
    try {
      assert(zip.entryCount>0&&zip.entryCount<=10000&&zip.comment.length===0);
      const centralStart=zip.readEntryCursor,entries=[],paths=new Map(),fileHashes=new Map(),ranges=[];
      assert(layout.manifest===undefined||['quality.json','transport.json'].includes(layout.manifest));
      assert(layout.manifest||Array.isArray(layout.files)&&layout.files.length>0);
      let record,total=0,centralCursor=centralStart;
      for await(const entry of zip.eachEntry()) {
        assert(Buffer.isBuffer(entry.fileName)&&entry.fileName.every(c=>c>=0x20&&c<=0x7e));
        const name=entry.fileName.toString('ascii'),directory=name.endsWith('/'),path=directory?name.slice(0,-1):name;
        safeAssetPath(path);assert(!paths.has(path.toLowerCase()),'Duplicate or colliding ZIP path');paths.set(path.toLowerCase(),{path,directory});
        const os=entry.versionMadeBy>>>8,mode=entry.externalFileAttributes>>>16,type=mode&0xf000,dos=entry.externalFileAttributes&0xffff;
        assert([0,3].includes(os)&&!(mode&0o7000)&&!(dos&~0x31)&&entry.internalFileAttributes===0);
        assert(type===(directory?0x4000:0x8000)||os===0&&mode===0,'Unsupported ZIP filesystem type');
        assert(!(dos&0x10)||directory);assert(!directory||type===0x4000||!!(dos&0x10));
        assert([10,20,45].includes(entry.versionNeededToExtract)&&[0,8].includes(entry.compressionMethod));
        assert(!(entry.generalPurposeBitFlag&~0x808)&&entry.fileComment.length===0,'Unsupported ZIP flags/comment');
        zipExtraFields(entry.extraFields,entry.extraFieldLength);
        const centralLarge=entry.extraFields.find(f=>f.id===1)?.data;
        const centralSizes64=bytes.readUInt32LE(centralCursor+24)===0xffffffff||bytes.readUInt32LE(centralCursor+20)===0xffffffff;
        const largeLength=(bytes.readUInt32LE(centralCursor+24)===0xffffffff?8:0)+(bytes.readUInt32LE(centralCursor+20)===0xffffffff?8:0)+(bytes.readUInt32LE(centralCursor+42)===0xffffffff?8:0)+(bytes.readUInt16LE(centralCursor+34)===0xffff?4:0);
        assert((centralLarge?.length??0)===largeLength);centralCursor=zip.readEntryCursor;
        const expanded=layout.builder===true||layout.manifest==='transport.json';
        assert(Number.isSafeInteger(entry.uncompressedSize)&&entry.uncompressedSize>=0&&entry.uncompressedSize<=(expanded?2:0.5)*1024*1024*1024);
        total+=entry.uncompressedSize;assert(total<=(expanded?3:1)*1024*1024*1024);
        if(directory)assert(entry.uncompressedSize===0);
        if(path===layout.manifest)assert(!directory&&entry.uncompressedSize<=4*1024*1024);
        const local=await zip.readLocalFileHeaderPromise(entry);
        same(local.fileName,entry.fileName);
        // A streaming writer can discover ZIP64 requirements only at finalization.
        assert(local.versionNeededToExtract===entry.versionNeededToExtract||!!centralLarge&&entry.versionNeededToExtract===45&&[10,20].includes(local.versionNeededToExtract));
        for(const key of ['generalPurposeBitFlag','compressionMethod','lastModFileTime','lastModFileDate'])same(local[key],entry[key]);
        const extra=yauzl.parseExtraFields(local.extraField);zipExtraFields(extra,local.extraFieldLength);
        const large=centralSizes64||local.uncompressedSize===0xffffffff||local.compressedSize===0xffffffff;
        const sizes=extra.find(f=>f.id===1)?.data;let sizeOffset=0;
        for(const key of ['uncompressedSize','compressedSize']) {
          let size=local[key];if(size===0xffffffff){assert(sizes&&sizeOffset+8<=sizes.length);size=Number(sizes.readBigUInt64LE(sizeOffset));sizeOffset+=8;}
          assert(size===entry[key]||!!(entry.generalPurposeBitFlag&8)&&size===0,'Conflicting ZIP sizes');
        }
        assert((sizes?.length??0)===sizeOffset);
        assert(local.crc32===entry.crc32||!!(entry.generalPurposeBitFlag&8)&&local.crc32===0);
        let end=local.fileDataStart+entry.compressedSize;
        if(entry.generalPurposeBitFlag&8) {
          assert(bytes.readUInt32LE(end)===0x08074b50,'Unsupported ZIP data descriptor');
          assert(bytes.readUInt32LE(end+4)===entry.crc32);
          same(large?[Number(bytes.readBigUInt64LE(end+8)),Number(bytes.readBigUInt64LE(end+16))]:[bytes.readUInt32LE(end+8),bytes.readUInt32LE(end+12)],[entry.compressedSize,entry.uncompressedSize]);
          end+=large?24:16;
        }
        assert(end<=centralStart);ranges.push([entry.relativeOffsetOfLocalHeader,end]);
        const stream=await zip.openReadStreamPromise(entry),digest=createHash('sha256'),chunks=[];let crc=0,length=0;
        for await(const chunk of stream){length+=chunk.length;assert(length<=entry.uncompressedSize);crc=crc32(chunk,crc);digest.update(chunk);if(path===layout.manifest)chunks.push(chunk);}
        assert(length===entry.uncompressedSize&&crc===entry.crc32,'ZIP payload integrity');
        if(!directory){fileHashes.set(path,digest.digest('hex'));if(path===layout.manifest)record=json(Buffer.concat(chunks));}
        entries.push({entry,path,directory});
      }
      // Require one unambiguous contiguous local graph and central directory, including ZIP64.
      let cursor=0;for(const [start,end] of ranges.sort((a,b)=>a[0]-b[0])){assert(start===cursor);cursor=end;}assert(cursor===centralStart);
      const trailer=bytes.length-22;assert(bytes.readUInt32LE(trailer)===0x06054b50&&bytes.readUInt16LE(trailer+20)===0);
      let centralSize=bytes.readUInt32LE(trailer+12),centralEnd=trailer;
      if(bytes.readUInt32LE(trailer-20)===0x07064b50||bytes.readUInt32LE(trailer+16)===0xffffffff||centralSize===0xffffffff||bytes.readUInt16LE(trailer+10)===0xffff){
        const locator=trailer-20;assert(bytes.readUInt32LE(locator)===0x07064b50&&bytes.readUInt32LE(locator+4)===0&&bytes.readUInt32LE(locator+16)===1);
        centralEnd=Number(bytes.readBigUInt64LE(locator+8));assert(bytes.readUInt32LE(centralEnd)===0x06064b50&&bytes.readBigUInt64LE(centralEnd+4)===44n&&centralEnd+56===locator);
        assert(bytes.readUInt32LE(centralEnd+16)===0&&bytes.readUInt32LE(centralEnd+20)===0);
        assert(Number(bytes.readBigUInt64LE(centralEnd+24))===zip.entryCount&&Number(bytes.readBigUInt64LE(centralEnd+32))===zip.entryCount);
        centralSize=Number(bytes.readBigUInt64LE(centralEnd+40));assert(Number(bytes.readBigUInt64LE(centralEnd+48))===centralStart);
      } else assert(bytes.readUInt32LE(trailer+16)===centralStart);
      for(const offset of [8,10])assert(bytes.readUInt16LE(trailer+offset)===zip.entryCount||bytes.readUInt16LE(trailer+offset)===0xffff);
      for(const [offset,value] of [[12,centralSize],[16,centralStart]])assert(bytes.readUInt32LE(trailer+offset)===value||bytes.readUInt32LE(trailer+offset)===0xffffffff);
      assert(bytes.readUInt16LE(trailer+4)===0&&bytes.readUInt16LE(trailer+6)===0&&zip.readEntryCursor===centralStart+centralSize&&zip.readEntryCursor===centralEnd);
      if(layout.manifest){
        assert(record?.schemaVersion===1&&record.purpose==='quality'&&record.promotionEligible===false&&record.files&&typeof record.files==='object'&&!Array.isArray(record.files));
        assert(!Object.hasOwn(record.files,layout.manifest));
        if(layout.manifest==='quality.json')assert(!Object.hasOwn(record.files,'browser-results.json'));
      }else{
        same([...fileHashes.keys()].sort(),[...layout.files].sort());
        record={files:Object.fromEntries(fileHashes)};
      }
      const expectedDirectories=new Set();for(const [path,digest] of Object.entries(record.files)){
        safeAssetPath(path);assert(hex.test(digest));const parts=path.split('/');while(parts.length>1){parts.pop();expectedDirectories.add(parts.join('/'));}
      }
      const canonical=new Map();for(const {path,directory} of entries){
        if(directory)assert(expectedDirectories.has(path),'Unexpected ZIP directory');
        const parts=path.split('/');while(parts.length){const prefix=parts.join('/'),old=canonical.get(prefix.toLowerCase());assert(!old||old===prefix,'Case-colliding ZIP directory');canonical.set(prefix.toLowerCase(),prefix);parts.pop();if(parts.length){const parent=paths.get(parts.join('/').toLowerCase());assert(!parent||parent.directory&&parent.path===parts.join('/'),'Conflicting ZIP parent');}}
      }
      if(layout.manifest)fileHashes.delete(layout.manifest);same(Object.fromEntries(fileHashes),record.files);
      if(destination){
        // No filesystem writes until the complete archive has passed. Never follow an existing destination.
        await mkdir(destination);
        for(const {entry,path,directory} of entries)if(!directory){
          const target=resolve(destination,path),parent=resolve(target,'..');await mkdir(parent,{recursive:true});
          const file=await open(target,'wx');try{for await(const chunk of await zip.openReadStreamPromise(entry))await file.writeFile(chunk);}finally{await file.close();}
        }
      }
      return {files:fileHashes.size,promotionEligible:false};
    } finally {zip.close();}
  });
}
async function stageAsync(code,operation){try{return await operation();}catch(error){if(failureCodes.has(error))throw error;const failure=new Error();failureCodes.set(failure,code);throw failure;}}
export function qualityIdentity(env,event,checkedOutCommit,sourceTree) {
  assert(env.GITHUB_REPOSITORY===repository&&event.repository?.id===repositoryId);
  assert(env.GITHUB_WORKFLOW_REF===`${repository}/${qualityWorkflow}@${env.GITHUB_REF}`);
  commit(checkedOutCommit);commit(sourceTree);commit(env.GITHUB_SHA);
  assert(checkedOutCommit===env.QUALITY_SOURCE);
  let pullRequest=null,headRepositoryId=repositoryId;
  if(env.GITHUB_EVENT_NAME==='pull_request') {
    const pr=event.pull_request;pullRequest=event.number;
    assert(Number.isSafeInteger(pullRequest)&&pullRequest>0&&pr?.number===pullRequest);
    assert(env.GITHUB_REF===`refs/pull/${pullRequest}/merge`&&pr.base?.repo?.id===repositoryId);
    // Forks and Dependabot remain read-only quality inputs, never release authority.
    assert(Number.isSafeInteger(pr.head?.repo?.id)&&pr.head.repo.id>0&&pr.head.sha===checkedOutCommit);
    headRepositoryId=pr.head.repo.id;
  } else {
    assert(['push','schedule','workflow_dispatch'].includes(env.GITHUB_EVENT_NAME));
    assert(env.GITHUB_REF.startsWith('refs/heads/')&&env.GITHUB_SHA===checkedOutCommit);
    if(env.GITHUB_EVENT_NAME!=='workflow_dispatch')assert(env.GITHUB_REF==='refs/heads/main');
  }
  const runId=Number(env.GITHUB_RUN_ID),runAttempt=Number(env.GITHUB_RUN_ATTEMPT);
  assert(Number.isSafeInteger(runId)&&runId>0&&Number.isSafeInteger(runAttempt)&&runAttempt>0);
  return {purpose:'quality',promotionEligible:false,repositoryId,headRepositoryId,workflow:qualityWorkflow,event:env.GITHUB_EVENT_NAME,pullRequest,sourceCommit:checkedOutCommit,sourceTree,runId,runAttempt};
}
export function validateQualityArtifact(artifact,expected,id,digest) {
  assert(expected.purpose==='quality'&&expected.promotionEligible===false);
  assert(expected.workflow===qualityWorkflow&&expected.repositoryId===repositoryId);
  sha(digest);assert(Number.isSafeInteger(id)&&id>0&&artifact.id===id&&artifact.digest===digest&&!artifact.expired);
  assert(artifact.name===`quality-runtime-${expected.runId}-${expected.runAttempt}`&&artifact.size_in_bytes>0);
  const run=artifact.workflow_run;
  assert(run?.id===expected.runId&&run.repository_id===repositoryId&&run.head_sha===expected.sourceCommit);
  assert(run.head_repository_id===expected.headRepositoryId);
}
export function validateQualityRecord(record,expected,files,identity) {
  assert(expected.purpose==='quality'&&expected.promotionEligible===false);
  assert(expected.workflow===qualityWorkflow&&expected.repositoryId===repositoryId);
  assert(record.schemaVersion===1&&record.purpose==='quality'&&record.promotionEligible===false);
  same(record.context,expected);same(record.files,files);
  for(const name of ['archive.oci.tar','identity.json','assets.json','health.json','runtime-scan.json','runtime-scan-identity.json','builder-scan.json','scanner-version.json','runtime-sbom.cdx.json','npm-audit.json'])assert(Object.hasOwn(files,name),'Missing quality evidence: '+name);
  for(const value of Object.values(files))assert(hex.test(value));
  assert(hex.test(record.archiveSHA256)&&record.archiveSHA256===files['archive.oci.tar']);sha(record.indexDigest);
  for(const key of ['sourceCommit','sourceTree'])same(identity[key],expected[key]);
  for(const key of ['archiveSHA256','indexDigest'])same(record[key],identity[key]);
}
export function validateQualitySecurity(identity,evidence) {
  validateCompleteScanEvidence(identity,evidence.scanIdentity,evidence.sbom);
  for(const role of ['runtime','builder'])assert(evidence[role]?.blocked===false&&evidence[role].blockingVulnerabilities===0&&evidence[role].secrets===0);
  assert(evidence.runtime.imageID===identity.configDigest);
  assert(Array.isArray(evidence.runtime.results)&&evidence.runtime.results.length>0);
  for(const result of evidence.runtime.results){
    assert(Array.isArray(result.vulnerabilities)&&Array.isArray(result.secrets)&&result.secrets.length===0);
    for(const finding of result.vulnerabilities)assert(['UNKNOWN','LOW','MEDIUM'].includes(finding.severity?.toUpperCase())&&!finding.exception);
  }
  validateBuilderAcceptance(evidence.builder,builderExceptions);
  assert(evidence.npm?.blocked===false&&evidence.npm.counts.high===0&&evidence.npm.counts.critical===0);
  assert(sanitizedScannerMetadata(evidence.scanner),'Missing scanner evidence');
  assert(evidence.health?.passed===true&&evidence.health.archiveSHA256===identity.archiveSHA256&&evidence.health.indexDigest===identity.indexDigest);
  same(evidence.health.checks,['image-config-and-rootfs','container-hardening','health','nginx-config','headers','assets','no-build-tools','graceful-stop']);
}
export function validateQualityBrowser(identity,browser,expected) {
  assert(expected.purpose==='quality'&&expected.promotionEligible===false&&expected.workflow===qualityWorkflow&&expected.repositoryId===repositoryId);
  for(const [key,value] of Object.entries(expected))same(browser[key],value);
  for(const key of ['archiveSHA256','indexDigest','assetsSHA256'])same(browser[key],identity[key]);
  same(browser.suites,suites.map(name=>({name,conclusion:'success'})));
}
async function qualityPacket(directory,ctx,recording=false) {
  assert(ctx.purpose==='quality'&&ctx.promotionEligible===false);
  const identity=await readJSON(resolve(directory,'identity.json'));
  same(identity.sourceCommit,ctx.sourceCommit);same(identity.sourceTree,ctx.sourceTree);
  same(await inspectArchive(resolve(directory,'archive.oci.tar'),ctx.sourceCommit),Object.fromEntries(Object.entries(identity).filter(([k])=>!['sourceTree','assetsSHA256'].includes(k))));
  await verifyRetainedAssets(directory,identity);
  const evidence={};for(const [name,file] of Object.entries({runtime:'runtime-scan.json',builder:'builder-scan.json',scanIdentity:'runtime-scan-identity.json',sbom:'runtime-sbom.cdx.json',scanner:'scanner-version.json',npm:'npm-audit.json',health:'health.json'}))evidence[name]=await readJSON(resolve(directory,file));
  validateQualitySecurity(identity,evidence);
  const files=await snapshot(directory);delete files['quality.json'];delete files['browser-results.json'];
  const record=recording?{schemaVersion:1,purpose:'quality',promotionEligible:false,context:ctx,archiveSHA256:identity.archiveSHA256,indexDigest:identity.indexDigest,files}:await readJSON(resolve(directory,'quality.json'));
  validateQualityRecord(record,ctx,files,identity);
  if(recording)await writeJSON(resolve(directory,'quality.json'),record);
  return identity;
}
const context=()=>{
  const checkedOut=run('git',['rev-parse','HEAD']).toString().trim();
  if(process.env.QUALITY_SOURCE)return qualityIdentity(process.env,json(readFileSync(process.env.GITHUB_EVENT_PATH)),checkedOut,run('git',['rev-parse','HEAD^{tree}']).toString().trim());
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
// Combined release transport uses the same strict ZIP boundary. Original quality
// records stay immutable and non-promotable; release.json is a separate receipt.
const releaseWorkflow='.github/workflows/release.yml';
const ageLimit=86400000;
const positive=value=>assert(Number.isSafeInteger(value)&&value>0,'Missing numeric identity');
function evidenceAge(createdAt,now){const age=now-Date.parse(createdAt);assert(Number.isFinite(age)&&age>=0&&age<=ageLimit,'Reused main evidence expired: explicitly refresh main quality');}
export function releaseFreshness(startedAt,scanner,now=Date.now(),promotion=false,databaseCurrent=true){
  const start=Date.parse(startedAt);assert(Number.isFinite(start)&&now>=start&&now-start<=ageLimit,'Reused main evidence expired: explicitly refresh main quality');
  sanitizedScannerMetadata(scanner);
  const db=scanner.VulnerabilityDB,download=Date.parse(db.DownloadedAt);
  assert(download>=start&&download<=now+300000&&Date.parse(db.UpdatedAt)<=download+300000&&(!databaseCurrent||Date.parse(db.NextUpdate)>now),'Scanner database is stale or invalid');
  if(promotion)assert(now>=download&&now-download<=3600000,'Approval exceeded promotion database freshness: new qualification and approval required');
}
export function combinedEntry(env,checkedOut,sourceTree,isMainAncestor){
  assert(env.GITHUB_REPOSITORY===repository);commit(checkedOut);commit(sourceTree);
  assert(checkedOut===env.GITHUB_SHA&&env.GITHUB_WORKFLOW_SHA===checkedOut&&isMainAncestor,'Release code/source must be reviewed main history');
  assert(env.GITHUB_WORKFLOW_REF===`${repository}/${releaseWorkflow}@${env.GITHUB_REF}`,'Wrong release workflow revision');
  const manual=env.GITHUB_EVENT_NAME==='workflow_dispatch';
  const operation=manual?(env.RELEASE_OPERATION??'verify'):'release';assert(['verify','release'].includes(operation));
  const publish=operation==='release';
  assert(publish?(manual||env.GITHUB_EVENT_NAME==='push')&&env.GITHUB_REF===`refs/tags/v${version}`:manual&&env.GITHUB_REF==='refs/heads/main','Unsupported release entry point');
  if(publish)assert(env.LIVE_PUBLICATION_ENABLED==='true','Live tag publication is disabled pending separate authorization');
  const runId=Number(env.GITHUB_RUN_ID),runAttempt=Number(env.GITHUB_RUN_ATTEMPT);positive(runId);positive(runAttempt);
  return {repositoryId,workflow:releaseWorkflow,workflowRevision:checkedOut,sourceCommit:checkedOut,sourceTree,runId,runAttempt,publish,event:env.GITHUB_EVENT_NAME,operation,ref:env.GITHUB_REF};
}
export function selectQualityRun(runs,source){
  commit(source);assert(runs.total_count===runs.workflow_runs.length&&runs.total_count>0&&runs.total_count<=100,'Quality run listing is incomplete');
  const matches=runs.workflow_runs.filter(r=>r.head_sha===source&&r.head_branch==='main'&&r.event==='push'&&r.path===qualityWorkflow);
  assert(matches.length>0,'No exact-source main push quality run; do not substitute another source');
  for(const info of matches){positive(info.id);assert(Number.isFinite(Date.parse(info.created_at)));}
  matches.sort((a,b)=>Date.parse(b.created_at)-Date.parse(a.created_at)||b.id-a.id);
  // Select first, then validate. Never fall back past a failed/incomplete run.
  return matches[0].id;
}
export function authenticateMainQuality(info,jobs,artifacts,workflow,sourceInfo,source,now=Date.now(),allowRefresh=false){
  assert(info.repository?.full_name===repository&&info.head_repository?.full_name===repository);
  assert(workflow.path===qualityWorkflow&&workflow.state==='active'&&info.workflow_id===workflow.id);positive(workflow.id);
  const checked=allowRefresh&&info.event==='workflow_dispatch'?{...info,event:'push'}:info;
  validateQuality(checked,jobs,source);
  positive(info.id);positive(info.run_attempt);commit(sourceInfo.tree?.sha);assert(sourceInfo.sha===source);
  const startedAt=info.run_started_at;assert(Number.isFinite(Date.parse(startedAt))&&Date.parse(info.created_at)<=Date.parse(startedAt));
  evidenceAge(info.created_at,now);
  assert(now>=Date.parse(startedAt)&&now-Date.parse(startedAt)<=ageLimit,'Selected main quality evidence expired');
  assert(artifacts.total_count===artifacts.artifacts.length&&artifacts.total_count<=100,'Incomplete artifact listing');
  const selected={};
  for(const role of ['runtime','builder','browser']){
    const name=`quality-${role}-${info.id}-${info.run_attempt}`,matches=artifacts.artifacts.filter(a=>a.name===name);
    assert(matches.length===1,`Missing or ambiguous ${role} artifact: run current main quality explicitly`);
    const a=matches[0];positive(a.id);sha(a.digest);assert(!a.expired&&a.size_in_bytes>0);
    const r=a.workflow_run;assert(r?.id===info.id&&r.repository_id===repositoryId&&r.head_repository_id===repositoryId&&r.head_sha===source&&r.head_branch==='main');
    assert(Date.parse(a.created_at)>=Date.parse(startedAt)&&Date.parse(a.created_at)<=now+300000,'Artifact predates selected attempt');
    selected[role]={id:a.id,name:a.name,digest:a.digest};
  }
  assert(new Set(Object.values(selected).map(a=>a.id)).size===3,'Artifact ID substitution');
  return {repository,repositoryId,workflow:qualityWorkflow,workflowId:workflow.id,workflowRevision:source,sourceCommit:source,sourceTree:sourceInfo.tree.sha,runId:info.id,runAttempt:info.run_attempt,event:info.event,createdAt:info.created_at,startedAt,artifacts:selected};
}
export function inspectBuilderGraph(read,names){
  const seen=new Set(),used=new Set();for(const name of names){assert(/^(?:index\.json|oci-layout|blobs\/?|blobs\/sha256\/?|blobs\/sha256\/[0-9a-f]{64})$/.test(name)&&!seen.has(name),'Invalid builder OCI member');seen.add(name);}
  same(json(read('oci-layout')),{'imageLayoutVersion':'1.0.0'});
  const blob=d=>{sha(d.digest);const name='blobs/sha256/'+d.digest.slice(7),bytes=read(name);assert(bytes.length===d.size&&'sha256:'+hash(bytes)===d.digest);used.add(name);return bytes;};
  const indexBytes=read('index.json'),index=json(indexBytes);assert(index.schemaVersion===2&&index.manifests.length===1);
  const d=index.manifests[0];assert(d.mediaType===manifestType);const m=json(blob(d));
  assert(m.schemaVersion===2&&m.config.mediaType===configType&&m.layers.length>0);
  const c=json(blob(m.config));assert(c.os==='linux'&&c.architecture==='amd64'&&c.rootfs.type==='layers');
  const diffIDs=m.layers.map(layer=>{assert(['application/vnd.oci.image.layer.v1.tar+gzip','application/vnd.oci.image.layer.v1.tar'].includes(layer.mediaType));const bytes=blob(layer);return 'sha256:'+hash(layer.mediaType.endsWith('+gzip')?gunzipSync(bytes):bytes);});
  same(c.rootfs.diff_ids,diffIDs);same([...seen].filter(n=>/^blobs\/sha256\/[0-9a-f]{64}$/.test(n)).sort(),[...used].sort());
  return {indexDigest:'sha256:'+hash(indexBytes),platformDigest:d.digest,configDigest:m.config.digest,diffIDs,config:c};
}
export async function inspectBuilderArchive(path){
  const names=run('tar',['-tf',path]).toString().trim().split(/\r?\n/);
  return {...inspectBuilderGraph(name=>run('tar',['-xOf',path,name]),names),archiveSHA256:hash(await readFile(path))};
}
export function validateBuilderBinding(identity,reference,selection,summary){
  assert(identity.sourceCommit===selection.sourceCommit&&identity.sourceTree===selection.sourceTree);
  same(reference.identity,identity);same(reference.artifact,selection.artifacts.builder);
  assert(identity.runId===selection.runId&&identity.runAttempt===selection.runAttempt);
  assert(summary.imageID===identity.configDigest,'Builder scan is not bound to retained image');
  sha(identity.indexDigest);sha(identity.configDigest);assert(hex.test(identity.archiveSHA256));
}
export function validateCombinedPhase(info,jobs,entry){
  assert(info.repository?.id===repositoryId&&info.head_repository?.id===repositoryId&&info.path===releaseWorkflow&&info.head_sha===entry.sourceCommit);
  assert(info.id===entry.runId&&info.run_attempt===entry.runAttempt);
  assert(info.workflow_id===entry.workflowId);positive(entry.workflowId);
  assert(info.event===entry.event&&info.head_branch===(entry.publish?`v${version}`:'main'));
  assert(['in_progress','waiting','pending','queued','completed'].includes(info.status)&&[null,'success'].includes(info.conclusion));
  assert(jobs.total_count===jobs.jobs.length&&jobs.jobs.length<=4);
  assert(jobs.jobs.every(j=>['resolve','qualify','publish','consumer'].includes(j.name)&&j.run_id===entry.runId&&j.run_attempt===entry.runAttempt));
  assert(new Set(jobs.jobs.map(j=>j.name)).size===jobs.jobs.length);
  for(const name of ['resolve','qualify']){
    const matches=jobs.jobs.filter(j=>j.name===name);assert(matches.length===1);
    assert(matches[0].run_id===entry.runId&&matches[0].run_attempt===entry.runAttempt&&matches[0].status==='completed'&&matches[0].conclusion==='success','Read-only release jobs did not succeed in this attempt');
  }
}
export function validateReleaseReceipt(receipt,entry,selection,identity,files,scanner,now=Date.now(),promotion=false){
  assert(receipt.schemaVersion===1&&receipt.version===version&&receipt.purpose===(entry.publish?'release':'verification')&&receipt.promotionEligible===entry.publish);
  same(receipt.entry,entry);same(receipt.upstream,selection);same(receipt.files,files);
  assert(receipt.archiveSHA256===identity.archiveSHA256&&receipt.indexDigest===identity.indexDigest);
  assert(receipt.qualifiedAt>=Date.parse(selection.startedAt)&&receipt.qualifiedAt<=now);
  evidenceAge(selection.createdAt,now);
  assert(Number.isFinite(Date.parse(entry.startedAt))&&Date.parse(scanner.VulnerabilityDB.DownloadedAt)>=Date.parse(entry.startedAt),'Release database predates this release attempt');
  releaseFreshness(selection.startedAt,scanner,now,promotion);
}
export function validateVersionCollision(tags){validateTags(tags);}
const apiJSON=path=>json(run('gh',['api',`repos/${repository}${path?'/'+path:''}`]));
const currentRun=id=>apiJSON(`actions/runs/${id}`);
const currentJobs=info=>apiJSON(`actions/runs/${info.id}/attempts/${info.run_attempt}/jobs?per_page=100`);
async function selectUpstream(id,entry,sourceCI){
  positive(id);const info=currentRun(id),workflow=apiJSON('actions/workflows/quality-security.yml'),sourceInfo=apiJSON(`git/commits/${entry.sourceCommit}`);
  const selected=authenticateMainQuality(info,currentJobs(info),apiJSON(`actions/runs/${id}/artifacts?per_page=100`),workflow,sourceInfo,entry.sourceCommit,Date.now(),true);
  same(sourceInfo.tree.sha,entry.sourceTree);
  const prerequisite=currentRun(sourceCI);validateQuality(prerequisite,currentJobs(prerequisite),entry.sourceCommit);
  assert(prerequisite.workflow_id===workflow.id&&prerequisite.repository.full_name===repository);
  return {...selected,sourceCIRun:sourceCI,sourceCIAttempt:prerequisite.run_attempt};
}
async function downloadZip(artifact,directory,layout){
  const bytes=run('gh',['api',`repos/${repository}/actions/artifacts/${artifact.id}/zip`]);
  await qualityZip(bytes,artifact.digest,directory,layout);
}
export async function authenticatePackets(root,selection){
  evidenceAge(selection.createdAt,Date.now());
  const runtime=resolve(root,'runtime'),builder=resolve(root,'builder');
  const record=await readJSON(resolve(runtime,'quality.json')),ctx={purpose:'quality',promotionEligible:false,repositoryId,headRepositoryId:repositoryId,workflow:qualityWorkflow,event:selection.event,pullRequest:null,sourceCommit:selection.sourceCommit,sourceTree:selection.sourceTree,runId:selection.runId,runAttempt:selection.runAttempt};
  same(record.context,ctx);
  const identity=await qualityPacket(runtime,ctx);
  validateQualityBrowser(identity,await readJSON(resolve(root,'browser/browser-results.json')),ctx);
  const builderIdentity=await readJSON(resolve(builder,'builder-identity.json')),reference=await readJSON(resolve(runtime,'builder-reference.json'));
  validateBuilderBinding(builderIdentity,reference,selection,await readJSON(resolve(runtime,'builder-scan.json')));
  same(await inspectBuilderArchive(resolve(builder,'builder.oci.tar')),Object.fromEntries(Object.entries(builderIdentity).filter(([k])=>!['sourceCommit','sourceTree','runId','runAttempt','scanArchiveSHA256'].includes(k))));
  assert(hex.test(builderIdentity.scanArchiveSHA256),'Missing original builder scan binding');
  const transport=await readJSON(resolve(builder,'quality.json')),files=await snapshot(builder);delete files['quality.json'];
  same(transport,{schemaVersion:1,purpose:'quality',promotionEligible:false,files});
  // Original main scans are historical evidence; the release scans use a new DB.
  // Their timestamps must remain valid, but fresh release intelligence supersedes
  // the old database's update deadline without extending the main evidence age.
  releaseFreshness(selection.startedAt,await readJSON(resolve(runtime,'scanner-version.json')),Date.now(),false,false);
  return identity;
}
async function combinedResolve(output){
  const env=process.env,source=run('git',['rev-parse','HEAD']).toString().trim(),tree=run('git',['rev-parse','HEAD^{tree}']).toString().trim();
  const ancestor=spawnSync('git',['merge-base','--is-ancestor',source,'origin/main']).status===0;
  const entry=combinedEntry(env,source,tree,ancestor);
  assert((await readJSON('package.json')).version===version,'Source metadata does not match release guard');
  assert(apiJSON('').id===repositoryId);
  const workflow=apiJSON('actions/workflows/release.yml');assert(workflow.path===releaseWorkflow&&workflow.state==='active');
  entry.workflowId=workflow.id;positive(entry.workflowId);
  const releaseRun=currentRun(entry.runId);assert(releaseRun.workflow_id===workflow.id&&releaseRun.head_sha===source&&releaseRun.run_attempt===entry.runAttempt&&releaseRun.repository?.id===repositoryId&&releaseRun.head_repository?.id===repositoryId&&releaseRun.path===releaseWorkflow);
  assert(releaseRun.event===entry.event&&releaseRun.head_branch===(entry.publish?`v${version}`:'main'));
  entry.startedAt=releaseRun.run_started_at;assert(Number.isFinite(Date.parse(entry.startedAt)));
  const runs=apiJSON(`actions/workflows/quality-security.yml/runs?branch=main&event=push&head_sha=${source}&per_page=100`),sourceCI=selectQualityRun(runs,source);
  const requested=env.QUALITY_RUN_ID?Number(env.QUALITY_RUN_ID):sourceCI;
  // Manual refresh is explicit. The original exact-source push-CI prerequisite remains mandatory.
  const selection=await selectUpstream(requested,entry,sourceCI);
  if(entry.publish)validateReleaseRef(run('git',['ls-remote','--exit-code','origin',`refs/tags/v${version}`,`refs/tags/v${version}^{}`]).toString(),source);
  await writeJSON(output,{entry,selection});
  if(env.GITHUB_OUTPUT)await writeFile(env.GITHUB_OUTPUT,`publish=${entry.publish}\n`,{flag:'a'});
}
async function combinedFetch(input,root){
  const {entry,selection}=await readJSON(input);same(await selectUpstream(selection.runId,entry,selection.sourceCIRun),selection);
  await mkdir(root);for(const role of ['runtime','builder','browser'])await downloadZip(selection.artifacts[role],resolve(root,role),role==='browser'?{files:['browser-results.json']}:role==='builder'?{manifest:'quality.json',builder:true}:undefined);
  await authenticatePackets(root,selection);await writeJSON(resolve(root,'selection.json'),{entry,selection});
}
async function combinedSeal(root){
  const {entry,selection}=await readJSON(resolve(root,'selection.json')),identity=await authenticatePackets(root,selection);
  const scanner=await readJSON(resolve(root,'scanner-version.json'));releaseFreshness(selection.startedAt,scanner);
  same(await selectUpstream(selection.runId,entry,selection.sourceCIRun),selection);
  await combinedSecurity(root,identity);
  const files=await snapshot(root);delete files['release.json'];delete files['transport.json'];
  const receipt={schemaVersion:1,version,purpose:entry.publish?'release':'verification',promotionEligible:entry.publish,entry,upstream:selection,qualifiedAt:Date.now(),archiveSHA256:identity.archiveSHA256,indexDigest:identity.indexDigest,files};
  validateReleaseReceipt(receipt,entry,selection,identity,files,scanner);
  await writeJSON(resolve(root,'release.json'),receipt);
  await writeJSON(resolve(root,'transport.json'),{schemaVersion:1,purpose:'quality',promotionEligible:false,files:await snapshot(root)});
}
export async function combinedSecurity(root,identity){
  const runtime=await readJSON(resolve(root,'runtime-scan.json')),builder=await readJSON(resolve(root,'builder-scan.json'));
  assert(runtime.imageID===identity.configDigest&&runtime.blocked===false&&runtime.blockingVulnerabilities===0&&runtime.secrets===0);
  assert(runtime.results?.length>0&&runtime.results.every(r=>r.secrets?.length===0&&r.vulnerabilities?.every(v=>['UNKNOWN','LOW','MEDIUM'].includes(v.severity)&&!v.exception)));
  validateBuilderAcceptance(builder,builderExceptions);
  assert(builder.imageID===(await readJSON(resolve(root,'builder/builder-identity.json'))).configDigest);
  const scan=await readJSON(resolve(root,'release-scan-identity.json'));validateScanIdentity(identity,scan);
  assert(scan.runtimeImageID===identity.configDigest);same(scan.scanners,['vuln','secret']);same(scan.imageConfigScanners,['secret']);
}
async function combinedRevalidate(root){
  const {entry,selection}=await readJSON(resolve(root,'selection.json'));
  const source=run('git',['rev-parse','HEAD']).toString().trim(),tree=run('git',['rev-parse','HEAD^{tree}']).toString().trim();
  const workflow=apiJSON('actions/workflows/release.yml');assert(workflow.path===releaseWorkflow&&workflow.state==='active');
  const releaseRun=currentRun(entry.runId);
  same(entry,{...combinedEntry(process.env,source,tree,spawnSync('git',['merge-base','--is-ancestor',source,'origin/main']).status===0),workflowId:workflow.id,startedAt:releaseRun.run_started_at});
  assert(entry.publish,'Read-only verification cannot publish');
  validateReleaseRef(run('git',['ls-remote','--exit-code','origin',`refs/tags/v${version}`,`refs/tags/v${version}^{}`]).toString(),source);
  same(await selectUpstream(selection.runId,entry,selection.sourceCIRun),selection);
  validateCombinedPhase(releaseRun,currentJobs(releaseRun),entry);
  const identity=await authenticatePackets(root,selection);await combinedSecurity(root,identity);
  const files=await snapshot(root);delete files['release.json'];delete files['transport.json'];
  validateReleaseReceipt(await readJSON(resolve(root,'release.json')),entry,selection,identity,files,await readJSON(resolve(root,'scanner-version.json')),Date.now(),true);
}
async function main() {
  const [mode,...args]=process.argv.slice(2);
  if(mode==='retain-builder'){
    const [oci,scan,directory]=args,ctx=context();assert(ctx.purpose==='quality'&&process.env.GITHUB_REF==='refs/heads/main');
    const inspected=await inspectBuilderArchive(oci),identity={...inspected,scanArchiveSHA256:hash(await readFile(scan)),sourceCommit:ctx.sourceCommit,sourceTree:ctx.sourceTree,runId:ctx.runId,runAttempt:ctx.runAttempt};
    const names=run('tar',['-tf',scan]).toString().trim().split(/\r?\n/);
    inspectDockerGraph(name=>run('tar',['-xOf',scan,name]),names,identity,'builder');
    await writeJSON(resolve(directory,'builder-identity.json'),identity);
    await writeJSON(resolve(directory,'quality.json'),{schemaVersion:1,purpose:'quality',promotionEligible:false,files:await snapshot(directory)});
  }
  else if(mode==='builder-reference'){
    const identity=await readJSON(args[0]),id=Number(args[1]);positive(id);sha(args[2]);
    const ctx=context();assert(identity.sourceCommit===ctx.sourceCommit&&identity.sourceTree===ctx.sourceTree&&identity.runId===ctx.runId&&identity.runAttempt===ctx.runAttempt);
    await writeJSON(args[3],{identity,artifact:{id,name:`quality-builder-${ctx.runId}-${ctx.runAttempt}`,digest:args[2]}});
  }
  else if(mode==='builder-scan-binding'){
    const identity=await readJSON(args[0]);assert(hash(await readFile(args[1]))===identity.scanArchiveSHA256,'Builder scan archive changed');
    validateRuntimeReportIdentity(identity,await readJSON(args[2]));
  }
  else if(mode==='combined-resolve')await combinedResolve(args[0]);
  else if(mode==='combined-fetch')await combinedFetch(args[0],args[1]);
  else if(mode==='combined-seal'){
    await combinedSeal(args[0]);const identity=await readJSON(resolve(args[0],'runtime/identity.json'));
    if(process.env.GITHUB_OUTPUT)await writeFile(process.env.GITHUB_OUTPUT,`index_digest=${identity.indexDigest}\nconfig_digest=${identity.configDigest}\n`,{flag:'a'});
  }
  else if(mode==='combined-revalidate')await combinedRevalidate(args[0]);
  else if(mode==='combined-download'){
    const id=Number(args[1]);positive(id);sha(args[2]);
    const artifact=apiJSON(`actions/artifacts/${id}`),ctx=combinedEntry(process.env,run('git',['rev-parse','HEAD']).toString().trim(),run('git',['rev-parse','HEAD^{tree}']).toString().trim(),spawnSync('git',['merge-base','--is-ancestor','HEAD','origin/main']).status===0);
    const workflow=apiJSON('actions/workflows/release.yml');assert(workflow.path===releaseWorkflow&&workflow.state==='active');ctx.workflowId=workflow.id;
    assert(ctx.publish&&artifact.id===id&&artifact.digest===args[2]&&!artifact.expired&&artifact.name===`release-qualified-${ctx.runId}-${ctx.runAttempt}`);
    const r=artifact.workflow_run;assert(r?.id===ctx.runId&&r.repository_id===repositoryId&&r.head_repository_id===repositoryId&&r.head_sha===ctx.sourceCommit&&r.head_branch===`v${version}`);
    const info=currentRun(ctx.runId);validateCombinedPhase(info,currentJobs(info),ctx);assert(Date.parse(artifact.created_at)>=Date.parse(info.run_started_at));
    await downloadZip({id,digest:args[2]},args[0],{manifest:'transport.json'});
    await combinedRevalidate(args[0]);
  }
  else if(mode==='scan-builder'){
    const [scanner,identityFile,scan,output]=args,identity=await readJSON(identityFile);
    const names=run('tar',['-tf',scan]).toString().trim().split(/\r?\n/);
    inspectDockerGraph(name=>run('tar',['-xOf',scan,name]),names,identity,'builder');
    const before=hash(await readFile(scan));run(scanner,runtimeScanArgs(scan,output));assert(before===hash(await readFile(scan)));
    validateRuntimeReportIdentity(identity,await readJSON(output));
  }
  else if(mode==='quality-record'||mode==='quality-verify')await qualityPacket(args[0],context(),mode==='quality-record');
  else if(mode==='quality-artifact')validateQualityArtifact(await readJSON(args[0]),context(),Number(args[1]),args[2]);
  else if(mode==='quality-zip')await qualityZip(await readFile(args[0]),args[1],args[2]);
  else if(mode==='quality-browser-result'){
    const ctx=context(),identity=await qualityPacket(args[0],ctx);
    validateQualityBrowser(identity,await readJSON(resolve(args[0],'browser-results.json')),ctx);
  }
  else if(mode==='qualification-context'){
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
    if(ctx.purpose==='quality')await qualityPacket(directory,ctx);
    else {
      const inspected=await inspectArchive(resolve(directory,'archive.oci.tar'),ctx.sourceCommit);
      same(inspected,Object.fromEntries(Object.entries(identity).filter(([k])=>!['sourceTree','assetsSHA256'].includes(k))));
    }
    assert(identity.sourceTree===ctx.sourceTree&&identity.assetsSHA256===hash(await readFile(resolve(directory,'assets.json'))));
    const assets=await verifyRetainedAssets(directory,identity);same((await assetSnapshot('dist')).files,assets);
    const results=[];for(const name of suites){
      const r=spawnSync(process.execPath,['tests/browser-'+name+'.mjs'],{stdio:'inherit'});
      results.push({name,conclusion:r.status===0?'success':'failure'});
      if(r.status!==0&&ctx.purpose==='quality')await writeJSON(resolve(directory,'browser-results.json'),{...ctx,archiveSHA256:identity.archiveSHA256,indexDigest:identity.indexDigest,assetsSHA256:identity.assetsSHA256,suites:results});
      assert(r.status===0,'Browser suite failed: '+name);
    }
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
  else if(mode==='release-ref')validateReleaseRef(run('git',['ls-remote','--exit-code','origin','refs/tags/v1.2.3','refs/tags/v1.2.3^{}']).toString(),process.env.GITHUB_SHA);
  else if(mode==='quality'){const ctx=context();validateQuality(await readJSON(args[0]),await readJSON(args[1]),ctx.sourceCommit,ctx);}
  else if(mode==='zip-members'){
    const names=run('unzip',['-Z1',args[0]]).toString().trim().split('\n');const seen=new Set();
    for(const name of names){const path=name.endsWith('/')?name.slice(0,-1):name;assert(/^[A-Za-z0-9._/-]+$/.test(path)&&!path.startsWith('/')&&!path.split('/').some(p=>p==='..'||p==='.'||p===''),'Unsafe ZIP member');assert(!seen.has(name));seen.add(name);}
  }
  else throw Error('Unknown release-integrity operation');
}
const combinedFailureHints={
  'combined-resolve':'SOURCE_OR_UPSTREAM_SELECTION: require reviewed main source, exact successful main push CI, and unexpired runtime/builder/browser artifacts. Tag publication is locked during migration.',
  'combined-fetch':'UPSTREAM_ARTIFACT_AUTHENTICATION: verify selected run/attempt, artifact IDs/checksums, strict ZIP entries, OCI graphs, SBOM, hardening and all eight browser results. Never substitute another source or artifact.',
  'combined-seal':'QUALIFICATION_REJECTED: review sanitized runtime/builder security reports and required upstream evidence; explicitly refresh main quality if missing or expired.',
  'combined-download':'APPROVAL_REVALIDATION_REJECTED: current-attempt qualification jobs, exact tag, artifact checksums and freshness must still pass. New qualification and owner approval are required after expiration.',
  'combined-revalidate':'PROMOTION_REVALIDATION_REJECTED: stop before registry access. Verify exact source/tag/attempt, unchanged artifacts, 24-hour evidence validity and one-hour database freshness.',
  'scan-builder':'BUILDER_SCAN_REJECTED: retained OCI/Docker-save configuration and layers must match, with complete vulnerability and file/configuration-secret coverage.'
};
const publicReleaseErrors=new Set(['Live tag publication is disabled pending separate authorization','Reused main evidence expired: explicitly refresh main quality','Selected main quality evidence expired','Approval exceeded promotion database freshness: new qualification and approval required','Release database predates this release attempt','Source metadata does not match release guard','No exact-source main push quality run; do not substitute another source',...['runtime','builder','browser'].map(role=>`Missing or ambiguous ${role} artifact: run current main quality explicitly`)]);
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main().catch(error=>{
  console.error(diagnosticCode(error));
  const hint=combinedFailureHints[process.argv[2]];
  if(hint){console.error(hint);if(publicReleaseErrors.has(error.message))console.error(error.message);}
  process.exitCode=1;
});
