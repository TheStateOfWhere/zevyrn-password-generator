import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {assessNpm,assessTrivy} from '../scripts/ci-security.mjs';

// Compact fixtures use the actual Trivy 0.76.0 image-report field structure.
const runtime=()=>({SchemaVersion:2,ArtifactType:'container_image',Trivy:{Version:'0.76.0'},
  Metadata:{ImageID:'sha256:'+'a'.repeat(64),OS:{Family:'alpine',Name:'3.24.2'}},
  Results:[{Target:'runtime.tar (alpine 3.24.2)',Class:'os-pkgs',Type:'alpine',Packages:[
    {Name:'nginx',Version:'1.30.6-r1'},{Name:'libexpat',Version:'2.9.0-r0'},{Name:'zlib',Version:'1.3.2-r1'}]}]});
function builder() {
  const r=runtime();r.Results[0].Target='builder.tar (alpine 3.24.2)';
  r.Results[0].Packages=[{Name:'alpine-baselayout',Version:'3.7.2-r1'}];
  r.Results.push({Target:'Node.js',Class:'lang-pkgs',Type:'node-pkg',Packages:[
    ['@typescript/typescript6','6.0.2','@typescript/typescript6'],['typescript','6.0.3','@typescript/old'],['playwright','1.62.1','playwright'],['playwright-core','1.62.1','playwright-core']
  ].map(([Name,Version,path])=>({Name,Version,FilePath:'app/node_modules/'+path+'/package.json'}))});
  return r;
}

const exceptionPolicy=JSON.parse(await readFile(new URL('../scripts/ci-builder-exceptions.json',import.meta.url),'utf8'));
function reviewedBuilder() {
  const report=builder();
  const entry=exceptionPolicy.exceptions[0];
  report.Results[1].Packages.push({Name:entry.package,Version:entry.version,FilePath:entry.path});
  report.Results[1].Vulnerabilities=exceptionPolicy.exceptions.map(entry=>({
    VulnerabilityID:entry.cve,PkgName:entry.package,InstalledVersion:entry.version,PkgPath:entry.path,
    Severity:'HIGH',FixedVersion:'6.29.1',Status:'fixed'
  }));
  return report;
}

test('reviewed builder HIGH occurrences remain visible with original severities and approval explanations',()=>{
  assert.deepEqual(exceptionPolicy.exceptions.map(e=>e.cve).sort(),['CVE-2026-109383','CVE-2026-109869','CVE-2026-87018']);
  for(const entry of exceptionPolicy.exceptions) {
    assert.equal(entry.package,'undici');assert.equal(entry.version,'6.29.0');
    assert.equal(entry.path,'usr/local/lib/node_modules/npm/node_modules/undici/package.json');
  }
  const report=reviewedBuilder(),original=structuredClone(report);
  const result=assessTrivy(report,'builder',exceptionPolicy);
  assert.equal(result.blocked,false);assert.equal(result.blockingVulnerabilities,0);
  assert.equal(result.rawBlockingVulnerabilities,3);assert.equal(result.approvedHighCount,3);assert.equal(result.unapprovedHighCount,0);
  assert.equal(result.results[1].vulnerabilities.length,3);
  for(const [i,finding] of result.results[1].vulnerabilities.entries()) {
    assert.equal(finding.id,report.Results[1].Vulnerabilities[i].VulnerabilityID);
    assert.equal(finding.severity,'HIGH');assert.equal(finding.installed,'6.29.0');assert.equal(finding.fixed,'6.29.1');
    assert.equal(finding.path,exceptionPolicy.exceptions[i].path);
    assert.deepEqual(finding.exception,{rationale:exceptionPolicy.exceptions[i].rationale,reviewReference:exceptionPolicy.exceptions[i].reviewReference});
  }
  assert.deepEqual(report,original,'Assessment must not modify the scanner report');
  assert.equal(assessTrivy(report,'builder').blocked,true,'No implicit exceptions in the assessment API');
});

test('other CVEs, package names, versions and paths remain blocking for each reviewed builder HIGH',()=>{
  for(let index=0;index<3;index++)for(const field of ['VulnerabilityID','PkgName','InstalledVersion','PkgPath']) {
    const report=reviewedBuilder(),v=report.Results[1].Vulnerabilities[index],pkg=report.Results[1].Packages.at(-1);
    if(field==='VulnerabilityID')v[field]='CVE-2099-99999';
    if(field==='PkgName'){v[field]='other-package';pkg.Name=v[field];}
    if(field==='InstalledVersion'){v[field]='6.29.1';pkg.Version=v[field];}
    if(field==='PkgPath'){v[field]='app/node_modules/undici/package.json';pkg.FilePath=v[field];}
    const result=assessTrivy(report,'builder',exceptionPolicy);
    assert.equal(result.blocked,true,field);assert.ok(result.unapprovedHighCount>=1,field);
    assert.equal(result.results[1].vulnerabilities.length,3);
  }
  for(const path of [undefined,'']) {
    const missing=reviewedBuilder();missing.Results[1].Vulnerabilities[0].PkgPath=path;
    assert.equal(assessTrivy(missing,'builder',exceptionPolicy).unapprovedHighCount,1);
  }
});

test('exceptions require matching package discovery and cannot exempt OS findings or another occurrence',()=>{
  for(const change of ['absent','version','name']) {
    const report=reviewedBuilder(),pkg=report.Results[1].Packages.at(-1);
    if(change==='absent')report.Results[1].Packages.pop();
    if(change==='version')pkg.Version='6.29.1';
    if(change==='name')pkg.Name='other-package';
    assert.equal(assessTrivy(report,'builder',exceptionPolicy).approvedHighCount,0);
  }
  const os=reviewedBuilder();os.Results[0].Vulnerabilities=[structuredClone(os.Results[1].Vulnerabilities[0])];
  assert.equal(assessTrivy(os,'builder',exceptionPolicy).blocked,true);
  os.Results[0].Vulnerabilities[0].PkgPath='';os.Results[0].Vulnerabilities[0].Severity='LOW';
  assert.equal(assessTrivy(os,'builder',exceptionPolicy).blocked,false,'OS findings do not require a Node.js package path');
  const duplicate=reviewedBuilder();
  duplicate.Results[1].Packages.push({Name:'undici',Version:'6.29.0',FilePath:'app/node_modules/undici/package.json'});
  duplicate.Results[1].Vulnerabilities.push({...duplicate.Results[1].Vulnerabilities[0],PkgPath:'app/node_modules/undici/package.json'});
  const result=assessTrivy(duplicate,'builder',exceptionPolicy);
  assert.equal(result.approvedHighCount,3);assert.equal(result.unapprovedHighCount,1);assert.equal(result.blocked,true);
});

test('every builder CRITICAL or secret blocks even when all three HIGH exceptions match',()=>{
  for(let index=0;index<3;index++) {
    const report=reviewedBuilder();report.Results[1].Vulnerabilities[index].Severity='CRITICAL';
    const result=assessTrivy(report,'builder',exceptionPolicy);
    assert.equal(result.blocked,true);assert.equal(result.blockingVulnerabilities,1);assert.equal(result.approvedHighCount,2);
    assert.equal(result.results[1].vulnerabilities[index].severity,'CRITICAL');
    assert.equal(result.results[1].vulnerabilities[index].exception,undefined);
  }
  const report=reviewedBuilder();report.Results.push({Target:'/fixture',Class:'secret',Secrets:[{RuleID:'fixture',Severity:'LOW',Match:'never-disclose-exception-fixture'}]});
  const result=assessTrivy(report,'builder',exceptionPolicy);
  assert.equal(result.approvedHighCount,3);assert.equal(result.blocked,true);assert.equal(result.secrets,1);
  assert.doesNotMatch(JSON.stringify(result),/never-disclose-exception-fixture/);
});

test('builder exceptions leave runtime decisions and report structure unchanged',()=>{
  for(const entry of exceptionPolicy.exceptions)for(const Severity of ['HIGH','CRITICAL']) {
    const report=runtime();report.Results[0].Vulnerabilities=[{VulnerabilityID:entry.cve,PkgName:entry.package,InstalledVersion:entry.version,PkgPath:entry.path,Severity}];
    const result=assessTrivy(report,'runtime',exceptionPolicy);
    assert.equal(result.blocked,true);assert.deepEqual(result,assessTrivy(report,'runtime'));
    assert.equal(result.results[0].vulnerabilities[0].severity,Severity);
  }
  const report=runtime();report.Results.push({Target:'/fixture',Class:'secret',Secrets:[{RuleID:'fixture'}]});
  assert.equal(assessTrivy(report,'runtime',exceptionPolicy).blocked,true);
});

test('missing review metadata, malformed policies, wildcards and duplicate exceptions fail closed',()=>{
  const invalid=[null,{},[],{...exceptionPolicy,schemaVersion:2},{...exceptionPolicy,exceptions:{}},{...exceptionPolicy,unexpected:true}];
  for(const change of [{cve:'*'},{package:'*'},{version:'6.*'},{path:'**/undici/package.json'},
    {path:'/usr/local/lib/node_modules/npm/node_modules/undici/package.json'},
    {path:'usr/local/../undici/package.json'},{rationale:''},{reviewReference:''},{reviewReference:123},{approved:true}]) {
    invalid.push({...exceptionPolicy,exceptions:[{...exceptionPolicy.exceptions[0],...change}]});
  }
  const missing={...exceptionPolicy.exceptions[0]};delete missing.reviewReference;
  invalid.push({...exceptionPolicy,exceptions:[missing]}, {...exceptionPolicy,exceptions:[exceptionPolicy.exceptions[0],exceptionPolicy.exceptions[0]]});
  for(const policy of invalid)assert.throws(()=>assessTrivy(reviewedBuilder(),'builder',policy));
  assert.equal(assessTrivy(reviewedBuilder(),'builder',{schemaVersion:1,exceptions:[]}).blocked,true);
});

test('image gate retains lower findings and rejects high/critical without filtering unfixed findings',()=>{
  for(const severity of ['LOW','MEDIUM','HIGH','CRITICAL']){
    const report=runtime();report.Results[0].Vulnerabilities=[{VulnerabilityID:'CVE-fixture',PkgName:'fixture',Severity:severity,InstalledVersion:'1',FixedVersion:'',Status:'affected'}];
    const result=assessTrivy(report,'runtime');
    assert.equal(result.blocked,['HIGH','CRITICAL'].includes(severity));
    assert.equal(result.results[0].vulnerabilities.length,1);
    assert.equal(result.results[0].vulnerabilities[0].fixed,'');
  }
});
test('secret findings fail and never disclose matching text, code, titles or arbitrary scanner fields',()=>{
  const report=runtime();report.extra='sensitive-fixture';report.Results.push({Target:'/app/example.txt',Class:'secret',Secrets:[{RuleID:'fixture-rule',Severity:'LOW',Match:'sensitive-fixture',Title:'sensitive-fixture',Code:{Lines:[{Content:'sensitive-fixture'}]}}]});
  const result=assessTrivy(report,'runtime');
  assert.equal(result.blocked,true);assert.equal(result.secrets,1);
  assert.doesNotMatch(JSON.stringify(result),/sensitive-fixture/);
});
test('empty, malformed, failed and unrecognized image reports fail closed',()=>{
  for(const Results of [[],null,{},'failed',[{}],[{Target:'unrecognized'}]]) assert.throws(()=>assessTrivy({...runtime(),Results},'runtime'));
  for(const change of [{SchemaVersion:3},{ArtifactType:'filesystem'},{Trivy:{}},{Metadata:{}},{error:'scanner failed'},{Error:null},{Errors:[]},{Results:undefined}]) assert.throws(()=>assessTrivy({...runtime(),...change},'runtime'));
  for(const report of [{}, {error:'fixture'}, {SchemaVersion:2,Results:null},{SchemaVersion:2,Results:[{Target:'fixture',Vulnerabilities:{}}]}, {SchemaVersion:2,Results:[{Target:'fixture',Vulnerabilities:[{}]}]}]) assert.throws(()=>assessTrivy(report,'runtime'));
  assert.throws(()=>assessNpm({error:'registry unavailable'}));
});

test('clean runtime and builder reports require discovery but need no positive vulnerability finding',()=>{
  assert.equal(assessTrivy(runtime(),'runtime').blocked,false);
  assert.equal(assessTrivy(builder(),'builder').blocked,false);
  assert.throws(()=>assessTrivy(runtime()));
  assert.throws(()=>assessTrivy(runtime(),'builder'));
  assert.throws(()=>assessTrivy(builder(),'runtime'));
});

test('missing OS discovery, packages and expected runtime dependencies are rejected',()=>{
  for(const Packages of [undefined,null,[],{},[{Name:'nginx'}],[{Name:'',Version:'1'}],[{Name:'nginx',Version:''}]]) {
    const r=runtime();r.Results[0].Packages=Packages;assert.throws(()=>assessTrivy(r,'runtime'));
  }
  for(const missing of ['nginx','libexpat','zlib']) {
    const r=runtime();r.Results[0].Packages=r.Results[0].Packages.filter(p=>p.Name!==missing);assert.throws(()=>assessTrivy(r,'runtime'));
  }
  for(const change of [{Type:'debian'},{Class:'lang-pkgs'},{Vulnerabilities:[{VulnerabilityID:'CVE-fixture',Severity:'LOW'}],Packages:undefined}]) {
    const r=runtime();Object.assign(r.Results[0],change);assert.throws(()=>assessTrivy(r,'runtime'));
  }
  const r=runtime();r.Results.push(structuredClone(r.Results[0]));assert.throws(()=>assessTrivy(r,'runtime'));
});

test('all locked builder dependencies and compiler discovery remain required',()=>{
  for(const index of [0,1]) {const r=builder();r.Results.splice(index,1);assert.throws(()=>assessTrivy(r,'builder'));}
  for(const name of ['@typescript/typescript6','typescript','playwright','playwright-core']) {
    const r=builder();r.Results[1].Packages=r.Results[1].Packages.filter(p=>p.Name!==name);assert.throws(()=>assessTrivy(r,'builder'));
  }
  for(const change of [{Name:'substitute'},{Version:'0.0.0'},{FilePath:'usr/local/lib/node_modules/typescript/package.json'},{FilePath:'app/../node_modules/typescript/package.json'}]) {
    const r=builder();Object.assign(r.Results[1].Packages[0],change);assert.throws(()=>assessTrivy(r,'builder'));
  }
  for(const change of [{Type:'npm'},{Class:'os-pkgs'}]) {const r=builder();Object.assign(r.Results[1],change);assert.throws(()=>assessTrivy(r,'builder'));}
  for(const Packages of [[{Name:'stdlib',Version:'v1.26.4'}],[{Name:'golang.org/x/text',Version:'v0.38.0'}]]) {
    const r=builder();r.Results.push({Target:'app/node_modules/@typescript/typescript-linux-x64/lib/tsc',Class:'lang-pkgs',Type:'gobinary',Packages});
    assert.throws(()=>assessTrivy(r,'builder'));
  }
  for(const path of ['app/node_modules/typescript/package.json','app/node_modules/@typescript/typescript-linux-x64/package.json']) {
    const r=builder();r.Results[1].Packages.push({Name:'typescript',Version:'7.0.2',FilePath:path});assert.throws(()=>assessTrivy(r,'builder'));
  }
});

test('duplicate or contradictory package coverage is rejected',()=>{
  const r=runtime();r.Results[0].Packages.push({...r.Results[0].Packages[0],Version:'other'});assert.throws(()=>assessTrivy(r,'runtime'));
  const b=builder();b.Results[1].Packages.push({...b.Results[1].Packages[0],FilePath:'/app/node_modules/@typescript/typescript6/package.json'});assert.throws(()=>assessTrivy(b,'builder'));
  const g=builder();g.Results.push(structuredClone(g.Results[1]));assert.throws(()=>assessTrivy(g,'builder'));
});

test('malformed findings never produce a passing decision and lower-case high still blocks',()=>{
  for(const Vulnerabilities of [{},[{}],[{Severity:'unrecognized',VulnerabilityID:'CVE-fixture'}],[{Severity:'LOW',VulnerabilityID:''}]]) {
    const r=runtime();r.Results[0].Vulnerabilities=Vulnerabilities;assert.throws(()=>assessTrivy(r,'runtime'));
  }
  for(const Secrets of [{},[{}],[]]) {
    const r=runtime();r.Results.push({Target:'/fixture',Class:'secret',Secrets});assert.throws(()=>assessTrivy(r,'runtime'));
  }
  const r=builder();r.Results[1].Vulnerabilities=[{VulnerabilityID:'CVE-fixture',Severity:'high'}];assert.equal(assessTrivy(r,'builder').blocked,true);
});

test('actual CI command requires both image roles and propagates coverage, severity and secret failures',async()=>{
  const root=await mkdtemp(join(tmpdir(),'zevyrn-ci-coverage-'));
  const command=fileURLToPath(new URL('../scripts/ci-security.mjs',import.meta.url));
  const paths=['runtime.json','runtime-summary.json','builder.json','builder-summary.json'].map(n=>join(root,n));
  const run=()=>spawnSync(process.execPath,[command,'trivy',...paths],{cwd:root,encoding:'utf8'});
  try {
    await writeFile(paths[0],JSON.stringify(runtime()));await writeFile(paths[2],JSON.stringify(builder()));
    assert.equal(run().status,0);
    assert.equal(JSON.parse(await readFile(paths[1],'utf8')).blocked,false);
    assert.equal(JSON.parse(await readFile(paths[3],'utf8')).blocked,false);
    await writeFile(paths[2],JSON.stringify(reviewedBuilder()));
    assert.equal(run().status,0);
    const reviewed=JSON.parse(await readFile(paths[3],'utf8'));
    assert.equal(reviewed.approvedHighCount,3);assert.equal(reviewed.rawBlockingVulnerabilities,3);
    assert.equal(reviewed.results[1].vulnerabilities.length,3);
    for(const Severity of ['HIGH','CRITICAL']) {
      const report=reviewedBuilder();report.Results[1].Vulnerabilities.push({VulnerabilityID:'CVE-2099-99999',PkgName:'fixture',Severity});
      await writeFile(paths[2],JSON.stringify(report));assert.notEqual(run().status,0);
    }
    for(const r of [{...builder(),Results:[]},runtime()]) {
      await writeFile(paths[2],JSON.stringify(r));assert.notEqual(run().status,0);
    }
    const high=builder();high.Results[1].Vulnerabilities=[{VulnerabilityID:'CVE-fixture',Severity:'HIGH'}];
    await writeFile(paths[2],JSON.stringify(high));assert.notEqual(run().status,0);
    await writeFile(paths[2],JSON.stringify(builder()));
    const secret=runtime();secret.Results.push({Target:'/fixture',Class:'secret',Secrets:[{RuleID:'fixture',Match:'never-log-fixture'}]});
    await writeFile(paths[0],JSON.stringify(secret));const blocked=run();assert.notEqual(blocked.status,0);
    assert.doesNotMatch(blocked.stdout+blocked.stderr,/never-log-fixture/);
    assert.doesNotMatch(await readFile(paths[1],'utf8'),/never-log-fixture/);
    assert.notEqual(spawnSync(process.execPath,[command,'trivy',...paths.slice(0,2)],{encoding:'utf8'}).status,0);
  } finally {await rm(root,{recursive:true,force:true});}
});
test('npm audit gate includes development findings and preserves lower advisory counts',()=>{
  for(const [high,critical] of [[0,0],[1,0],[0,1]]){
    const result=assessNpm({auditReportVersion:2,metadata:{vulnerabilities:{low:1,moderate:1,high,critical}},vulnerabilities:{fixture:{name:'fixture',isDirect:false,severity:critical?'critical':high?'high':'moderate'}}});
    assert.equal(result.blocked,high+critical>0);assert.equal(result.counts.low,1);
  }
});
