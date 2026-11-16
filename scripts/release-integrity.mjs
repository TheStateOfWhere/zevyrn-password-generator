// Small, version-specific validators. Artifact transport and orchestration use GitHub Actions.
import assert from 'node:assert/strict';
import {readFile,writeFile,readdir,lstat} from 'node:fs/promises';
import {resolve,relative,sep} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
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
  const seen=new Set(),used=new Set();
  for(const name of names){assert(!seen.has(name),'Duplicate archive member');seen.add(name);assert(/^(?:index\.json|oci-layout|blobs\/?|blobs\/sha256\/?|blobs\/sha256\/[0-9a-f]{64})$/.test(name),'Unexpected archive member');}
  same(json(read('oci-layout')),{'imageLayoutVersion':'1.0.0'});
  const blob=d=>{sha(d.digest);assert(Number.isSafeInteger(d.size)&&d.size>0);const name='blobs/sha256/'+d.digest.slice(7),bytes=read(name);assert(bytes.length===d.size&&'sha256:'+hash(bytes)===d.digest,'Blob digest/size mismatch');used.add(name);return bytes;};
  let bytes=read('index.json'),index=json(bytes);
  if(index.manifests?.length===1&&index.manifests[0].mediaType===indexType){bytes=blob(index.manifests[0]);index=json(bytes);}
  assert(index.schemaVersion===2&&index.mediaType===indexType&&Array.isArray(index.manifests));
  const runtime=index.manifests.filter(d=>d.platform?.os==='linux'&&d.platform?.architecture==='amd64');
  assert(runtime.length===1,'Expected exactly one Linux/amd64 runtime');
  const descriptor=runtime[0];assert(descriptor.mediaType===manifestType);assert(!descriptor.platform.variant);
  const runtimeManifest=json(blob(descriptor));assert(runtimeManifest.schemaVersion===2&&runtimeManifest.mediaType===manifestType&&runtimeManifest.config.mediaType===configType);
  const config=json(blob(runtimeManifest.config));validateConfig(config,sourceCommit);
  assert(runtimeManifest.layers.length>0);
  for(const layer of runtimeManifest.layers){assert(layer.mediaType==='application/vnd.oci.image.layer.v1.tar+gzip');blob(layer);}
  const attestations=index.manifests.filter(d=>d!==descriptor);assert(attestations.length<=1,'Unexpected extra manifests');
  for(const d of attestations){
    assert(d.mediaType===manifestType&&d.platform?.os==='unknown'&&d.platform?.architecture==='unknown','Unexpected platform');
    assert(d.annotations?.['vnd.docker.reference.type']==='attestation-manifest'&&d.annotations['vnd.docker.reference.digest']===descriptor.digest,'Unexpected attestation descriptor');
    const m=json(blob(d));assert(m.schemaVersion===2&&m.mediaType===manifestType&&m.config.mediaType===configType);same(json(blob(m.config)),{});
    assert(m.layers.length===1);
    for(const layer of m.layers){
      assert(layer.mediaType==='application/vnd.in-toto+json');const s=json(blob(layer));
      assert(['https://in-toto.io/Statement/v0.1','https://in-toto.io/Statement/v1'].includes(s._type));
      assert(['https://slsa.dev/provenance/v0.2','https://slsa.dev/provenance/v1'].includes(s.predicateType));
      assert(layer.annotations?.['in-toto.io/predicate-type']===s.predicateType);
      assert(s.subject?.length===1);same(s.subject[0].digest,{sha256:descriptor.digest.slice(7)});
    }
  }
  same([...seen].filter(n=>/^blobs\/sha256\/[0-9a-f]{64}$/.test(n)).sort(),[...used].sort());
  return {version,indexDigest:'sha256:'+hash(bytes),platformDigest:descriptor.digest,configDigest:runtimeManifest.config.digest,diffIDs:config.rootfs.diff_ids,config};
}
const run=(program,args,input)=>{const r=spawnSync(program,args,{input,maxBuffer:512*1024*1024});if(r.error)throw r.error;assert(r.status===0,program+' failed');return r.stdout;};
export async function inspectArchive(path,sourceCommit) {
  const names=run('tar',['-tf',path]).toString().trim().split(/\r?\n/);
  const result=inspectGraph(name=>run('tar',['-xOf',path,name]),names,sourceCommit);
  return {...result,sourceCommit,archiveSHA256:hash(await readFile(path))};
}
export async function snapshot(directory) {
  const files={};
  async function walk(dir){for(const name of (await readdir(dir)).sort()){const path=resolve(dir,name),s=await lstat(path);assert(!s.isSymbolicLink(),'Symlink rejected');if(s.isDirectory())await walk(path);else{assert(s.isFile());files[relative(directory,path).split(sep).join('/')]=hash(await readFile(path));}}}
  await walk(resolve(directory));return files;
}
export function verifyLoaded(identity,image) {
  assert(image.Os==='linux'&&image.Architecture==='amd64');same(image.RootFS.Layers,identity.diffIDs);
  for(const key of ['User','WorkingDir','StopSignal','Entrypoint','Cmd','ExposedPorts','Env','Labels'])same(image.Config[key],identity.config.config[key]);
  for(const key of ['Test','Interval','Timeout','StartPeriod','Retries'])same(image.Config.Healthcheck[key],identity.config.config.Healthcheck[key]);
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
  const {browser,health,runtime,builder,builderIdentity,scanner,sbom,npm}=evidence;
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
export function validateTags(response) {assert(response.name==='thestateofwhere/zevyrn'&&Array.isArray(response.Tags)&&response.Tags.every(t=>typeof t==='string'));assert(!response.Tags.includes(version),'Destination tag already exists');}
export function validateReleaseRef(text,expected) {
  commit(expected);const refs=text.trim().split(/\r?\n/).map(line=>line.split(/\s+/));
  assert(refs.length>=1&&refs.length<=2);assert(refs.every(([sha,ref])=>/^[0-9a-f]{40}$/.test(sha)&&['refs/tags/v1.2.2','refs/tags/v1.2.2^{}'].includes(ref)));
  assert(refs.filter(([,ref])=>ref==='refs/tags/v1.2.2').length===1);
  const peeled=refs.filter(([,ref])=>ref==='refs/tags/v1.2.2^{}');assert(peeled.length<=1);assert((peeled[0]??refs[0])[0]===expected,'Release tag moved');
}
export function validateQuality(info,jobs,source) {
  assert(info.repository?.id===repositoryId&&info.head_repository?.id===repositoryId&&info.path==='.github/workflows/quality-security.yml');
  assert(info.head_sha===source&&info.head_branch==='main'&&info.event==='push'&&info.status==='completed'&&info.conclusion==='success');
  assert(jobs.total_count===2&&jobs.jobs.length===2);same(jobs.jobs.map(j=>j.name).sort(),['browser','quality-image']);
  assert(jobs.jobs.every(j=>j.run_id===info.id&&j.run_attempt===info.run_attempt&&j.status==='completed'&&j.conclusion==='success'));
}
const writeJSON=(path,value)=>writeFile(path,JSON.stringify(value,null,2)+'\n');
const readJSON=async path=>json(await readFile(path));
const context=()=>({runId:Number(process.env.GITHUB_RUN_ID),runAttempt:Number(process.env.GITHUB_RUN_ATTEMPT),sourceCommit:process.env.GITHUB_SHA,sourceTree:run('git',['rev-parse','HEAD^{tree}']).toString().trim(),startedAt:Date.parse(process.env.QUALIFICATION_STARTED_AT)});
const requiredFiles=['archive.oci.tar','identity.json','assets.json','browser-results.json','health.json','runtime-scan.json','builder-scan.json','builder-identity.json','scanner-version.json','runtime-sbom.cdx.json','npm-audit.json','build-metadata.json','quality-run.json','quality-jobs.json'];
export async function verifyPacket(directory,expected) {
  const seal=await readJSON(resolve(directory,'qualification.json'));assert(seal.schemaVersion===1&&seal.version===version&&seal.repositoryId===repositoryId);
  same(seal.jobResults,{runtime:'success',browser:'success'});
  for(const key of ['sourceCommit','sourceTree','runId','runAttempt'])same(seal.context[key],expected[key]);
  assert(Number.isFinite(seal.context.startedAt)&&seal.context.startedAt>0);
  if(Number.isFinite(expected.startedAt))assert(seal.context.startedAt>=expected.startedAt);
  if(Number.isFinite(expected.artifactCreatedAt))assert(seal.context.startedAt<=expected.artifactCreatedAt);
  const actual=await snapshot(directory);delete actual['qualification.json'];same(actual,seal.files);
  for(const path of requiredFiles)assert(Object.hasOwn(actual,path),'Missing evidence: '+path);
  const identity=await readJSON(resolve(directory,'identity.json'));
  same(await inspectArchive(resolve(directory,'archive.oci.tar'),expected.sourceCommit),Object.fromEntries(Object.entries(identity).filter(([k])=>!['sourceTree','assetsSHA256'].includes(k))));
  same(await snapshot(resolve(directory,'assets')),await readJSON(resolve(directory,'assets.json')));
  assert(identity.assetsSHA256===hash(await readFile(resolve(directory,'assets.json'))));
  const evidence={};for(const [name,file] of Object.entries({browser:'browser-results.json',health:'health.json',runtime:'runtime-scan.json',builder:'builder-scan.json',builderIdentity:'builder-identity.json',scanner:'scanner-version.json',sbom:'runtime-sbom.cdx.json',npm:'npm-audit.json'}))evidence[name]=await readJSON(resolve(directory,file));
  validateEvidence(identity,evidence,seal.context);same(seal.archiveSHA256,identity.archiveSHA256);same(seal.indexDigest,identity.indexDigest);
  validateQuality(await readJSON(resolve(directory,'quality-run.json')),await readJSON(resolve(directory,'quality-jobs.json')),expected.sourceCommit);
  return {identity,seal};
}
async function main() {
  const [mode,...args]=process.argv.slice(2);
  if(mode==='inspect')await writeJSON(args[1],await inspectArchive(args[0],process.env.GITHUB_SHA));
  else if(mode==='assets'){
    const directory=args[0],identity=await readJSON(resolve(directory,'identity.json'));
    await writeJSON(resolve(directory,'assets.json'),await snapshot(resolve(directory,'assets')));
    identity.assetsSHA256=hash(await readFile(resolve(directory,'assets.json')));identity.sourceTree=context().sourceTree;
    await writeJSON(resolve(directory,'identity.json'),identity);
  } else if(mode==='check-assets')same(await snapshot(args[0]),await readJSON(args[1]));
  else if(mode==='browser'){
    const directory=args[0],identity=await readJSON(resolve(directory,'identity.json')),ctx=context();
    const inspected=await inspectArchive(resolve(directory,'archive.oci.tar'),ctx.sourceCommit);
    same(inspected,Object.fromEntries(Object.entries(identity).filter(([k])=>!['sourceTree','assetsSHA256'].includes(k))));
    assert(identity.sourceTree===ctx.sourceTree&&identity.assetsSHA256===hash(await readFile(resolve(directory,'assets.json'))));
    const assets=await readJSON(resolve(directory,'assets.json'));same(await snapshot(resolve(directory,'assets')),assets);same(await snapshot('dist'),assets);
    const results=[];for(const name of suites){const r=spawnSync(process.execPath,['tests/browser-'+name+'.mjs'],{stdio:'inherit'});assert(r.status===0,'Browser suite failed: '+name);results.push({name,conclusion:'success'});}
    same(await snapshot('dist'),assets);
    await writeJSON(resolve(directory,'browser-results.json'),{...ctx,archiveSHA256:identity.archiveSHA256,indexDigest:identity.indexDigest,assetsSHA256:identity.assetsSHA256,suites:results});
  }
  else if(mode==='loaded')verifyLoaded(await readJSON(args[0]),(await readJSON(args[1]))[0]);
  else if(mode==='container')verifyContainer((await readJSON(args[0]))[0]);
  else if(mode==='seal'){
    assert(process.env.RUNTIME_RESULT==='success'&&process.env.BROWSER_RESULT==='success');
    const directory=args[0],identity=await readJSON(resolve(directory,'identity.json')),ctx=context();
    await writeJSON(resolve(directory,'qualification.json'),{schemaVersion:1,version,repositoryId,context:ctx,jobResults:{runtime:process.env.RUNTIME_RESULT,browser:process.env.BROWSER_RESULT},archiveSHA256:identity.archiveSHA256,indexDigest:identity.indexDigest,files:await snapshot(directory)});
    await verifyPacket(directory,ctx);
  } else if(mode==='verify-run'){
    const selected=validateRun(await readJSON(args[0]),await readJSON(args[1]),await readJSON(args[2]),process.env.GITHUB_SHA);
    assert(selected.runId===Number(process.env.QUALIFICATION_RUN),'Unexpected qualification run ID');
    await writeJSON(args[3],selected);if(process.env.GITHUB_OUTPUT)await writeFile(process.env.GITHUB_OUTPUT,`artifact_id=${selected.artifactId}\nartifact_digest=${selected.artifactDigest}\n`,{flag:'a'});
  } else if(mode==='verify-packet'){
    const selected=await readJSON(args[1]);const result=await verifyPacket(args[0],{sourceCommit:process.env.GITHUB_SHA,sourceTree:context().sourceTree,runId:selected.runId,runAttempt:selected.runAttempt,startedAt:selected.startedAt,artifactCreatedAt:selected.artifactCreatedAt});
    if(process.env.GITHUB_OUTPUT)await writeFile(process.env.GITHUB_OUTPUT,`archive_sha256=${result.identity.archiveSHA256}\nindex_digest=${result.identity.indexDigest}\n`,{flag:'a'});
  } else if(mode==='tags')validateTags(await readJSON(args[0]));
  else if(mode==='release-ref')validateReleaseRef(run('git',['ls-remote','--exit-code','origin','refs/tags/v1.2.2','refs/tags/v1.2.2^{}']).toString(),process.env.GITHUB_SHA);
  else if(mode==='quality')validateQuality(await readJSON(args[0]),await readJSON(args[1]),process.env.GITHUB_SHA);
  else if(mode==='zip-members'){
    const names=run('unzip',['-Z1',args[0]]).toString().trim().split('\n');const seen=new Set();
    for(const name of names){const path=name.endsWith('/')?name.slice(0,-1):name;assert(/^[A-Za-z0-9._/-]+$/.test(path)&&!path.startsWith('/')&&!path.split('/').some(p=>p==='..'||p==='.'||p===''),'Unsafe ZIP member');assert(!seen.has(name));seen.add(name);}
  }
  else throw Error('Unknown release-integrity operation');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main().catch(()=>{console.error('Release integrity validation failed.');process.exitCode=1;});
