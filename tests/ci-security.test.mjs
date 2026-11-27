import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm,mkdir,copyFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {assessNpm,assessTrivy,validateBuilderAcceptance,validateRuntimeSBOM,sanitizedRuntimeSBOM,securitySummary,parseCiToolchain,approvedTrivy,validateTrivyVersion} from '../scripts/ci-security.mjs';

test('reviewed Trivy configuration is exact, immutable and rejects malformed or ambiguous identity',()=>{
  const approved={trivy:{version:'0.76.0',sha256:'e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7'}};
  assert.deepEqual(parseCiToolchain(JSON.stringify(approved)),approved);assert.deepEqual(approvedTrivy,approved.trivy);
  assert(Object.isFrozen(approvedTrivy));assert.throws(()=>approvedTrivy.version='0.77.0');
  for(const value of [undefined,null,{},[],{trivy:null},{trivy:[]},{grype:approved.trivy},
    {trivy:{...approved.trivy,other:true}},{...approved,other:true},
    ...[null,1,'','v0.76.0','00.76.0','0.76','0.76.0-rc1','0.76.0+alias','0.76.0;echo nope'].map(version=>({trivy:{...approved.trivy,version}})),
    ...[null,1,'','abc','A'.repeat(64),'sha256:'+'a'.repeat(64)].map(sha256=>({trivy:{...approved.trivy,sha256}}))])assert.throws(()=>parseCiToolchain(typeof value==='undefined'?value:JSON.stringify(value)),/INVALID_CI_TOOLCHAIN/);
  for(const text of ['{','{"trivy":{},"trivy":'+JSON.stringify(approved.trivy)+'}',
    '{"trivy":{"version":"0.77.0","version":"0.76.0","sha256":"'+approved.trivy.sha256+'"}}',
    JSON.stringify(approved).replace('version','ver\\u0073ion'),JSON.stringify(approved).replace('0.76.0','0.76.\\u0030')])assert.throws(()=>parseCiToolchain(text),/INVALID_CI_TOOLCHAIN/);
});

test('executed and report scanner versions must match reviewed source, not claimed artifact identity',()=>{
  validateTrivyVersion({Version:approvedTrivy.version});
  for(const report of [null,{},[],{Version:1},{Version:'0.77.0'},{Version:'0.76.0 ',trivy:approvedTrivy},Object.create({Version:approvedTrivy.version})])assert.throws(()=>validateTrivyVersion(report),/SCANNER_VERSION_MISMATCH/);
  const wrong=runtime();wrong.Trivy.Version='0.77.0';wrong.Trivy.approvedIdentity=approvedTrivy;
  assert.throws(()=>assessTrivy(wrong,'runtime'));
});

test('toolchain CLI uses only its source file and fails closed on missing, malformed or substituted config',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'zevyrn-toolchain-')),scripts=join(directory,'scripts');await mkdir(scripts);
  const cli=fileURLToPath(new URL('../scripts/ci-security.mjs',import.meta.url));
  const invoke=(file,args=[])=>spawnSync(process.execPath,[file,'toolchain',...args],{cwd:directory,encoding:'utf8',env:{...process.env,TRIVY_VERSION:'99.0.0',CI_TOOLCHAIN:join(scripts,'ci-toolchain.json')}});
  try{
    await writeFile(join(scripts,'ci-toolchain.json'),JSON.stringify({trivy:{version:'99.0.0',sha256:'a'.repeat(64)}}));
    assert.equal(invoke(cli).stdout.trim(),approvedTrivy.version+' '+approvedTrivy.sha256);
    assert.notEqual(invoke(cli,[join(scripts,'ci-toolchain.json')]).status,0);
    for(const file of ['ci-security.mjs','verify-compiler.mjs','compiler-integrity.json'])await copyFile(new URL('../scripts/'+file,import.meta.url),join(scripts,file));
    for(const file of ['package.json','package-lock.json'])await copyFile(new URL('../'+file,import.meta.url),join(directory,file));
    const copy=join(scripts,'ci-security.mjs'),config=join(scripts,'ci-toolchain.json');
    await writeFile(config,JSON.stringify({trivy:approvedTrivy}));assert.equal(invoke(copy).status,0);
    for(const text of ['{sensitive-config-fixture','{}','{"trivy":null}','{"trivy":{"version":"bad","sha256":"bad"}}']){
      await writeFile(config,text);const r=invoke(copy);assert.notEqual(r.status,0);assert(!r.stdout.includes('sensitive-config-fixture')&&!r.stderr.includes('sensitive-config-fixture'));
    }
    await rm(config);assert.notEqual(invoke(copy).status,0);
  }finally{await rm(directory,{recursive:true,force:true});}
});

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

test('zero through three remaining authorized builder HIGH occurrences are accepted',()=>{
  for(let count=0;count<=3;count++) {
    const report=reviewedBuilder();report.Results[1].Vulnerabilities.length=count;
    const summary=assessTrivy(report,'builder',exceptionPolicy);
    assert.equal(summary.approvedHighCount,count);assert.equal(summary.blocked,false);
    validateBuilderAcceptance(summary,exceptionPolicy);
    for(const change of [s=>s.approvedHighCount++,s=>s.rawBlockingVulnerabilities++,s=>s.secrets++,s=>s.blocked=true]) {
      const changed=structuredClone(summary);change(changed);assert.throws(()=>validateBuilderAcceptance(changed,exceptionPolicy));
    }
  }
});

test('retained builder dispositions cannot authorize tampered, duplicate or out-of-scope occurrences',()=>{
  const summary=assessTrivy(reviewedBuilder(),'builder',exceptionPolicy);
  for(const change of [
    s=>s.results[1].vulnerabilities[0].id='CVE-2099-99999',
    s=>s.results[1].vulnerabilities[0].installed='6.29.1',
    s=>s.results[1].vulnerabilities[0].path='app/node_modules/undici/package.json',
    s=>s.results[1].vulnerabilities[0].package='other',
    s=>s.results[1].vulnerabilities[0].severity='CRITICAL',
    s=>s.results[1].vulnerabilities[0].exception.reviewReference='self-approved',
    s=>s.results[1].vulnerabilities[0].severity='LOW',
    s=>s.results[1].type='alpine',
    s=>s.results[1].vulnerabilities.push(structuredClone(s.results[1].vulnerabilities[0])),
    s=>delete s.results
  ]) {const changed=structuredClone(summary);change(changed);assert.throws(()=>validateBuilderAcceptance(changed,exceptionPolicy));}
});

test('runtime SBOM binds image identity and every discovered OS package',()=>{
  const raw=runtime(),sbom={bomFormat:'CycloneDX',components:raw.Results[0].Packages.map(p=>({name:p.Name,version:p.Version})),metadata:{component:{properties:[{name:'aquasecurity:trivy:ImageID',value:raw.Metadata.ImageID}]}}};
  assert.equal(validateRuntimeSBOM(sbom,raw).passed,true);
  const labelled=structuredClone(sbom);labelled.metadata.component.properties.push({name:'aquasecurity:trivy:Labels:token',value:'never-publish-label-secret'});
  const sanitized=sanitizedRuntimeSBOM(labelled,raw);
  assert.doesNotMatch(JSON.stringify(sanitized),/never-publish-label-secret/);
  assert.deepEqual(sanitized.components,sbom.components);assert.equal(validateRuntimeSBOM(sanitized,raw).passed,true);
  for(const change of [s=>s.components.pop(),s=>s.components[0].version='other',s=>s.metadata.component.properties[0].value='sha256:'+'b'.repeat(64),s=>s.metadata.component.properties.push(s.metadata.component.properties[0]),s=>delete s.components,s=>s.bomFormat='other']) {
    const changed=structuredClone(sbom);change(changed);assert.throws(()=>validateRuntimeSBOM(changed,raw));
  }
});

test('security summaries distinguish findings, scanner, validation and SBOM failures without secret content',()=>{
  const raw=runtime();raw.Results[0].Vulnerabilities=[{VulnerabilityID:'CVE-2026-113425',Severity:'CRITICAL',PkgName:'nginx',InstalledVersion:'1.30.6-r1',FixedVersion:'1.30.7-r0'}];
  raw.Results.push({Target:'sensitive-fixture',Class:'secret',Secrets:[{RuleID:'fixture',Match:'sensitive-fixture',Title:'sensitive-fixture',Code:{Lines:[{Content:'sensitive-fixture'}]}}]});
  const report={...assessTrivy(raw,'runtime'),imageID:raw.Metadata.ImageID};
  const text=securitySummary({runtime:report,builder:{classification:'INVALID_EVIDENCE'}},{Version:'0.76.0',VulnerabilityDB:{UpdatedAt:'2026-11-24T00:00:00Z'}},{sbom:'failure'});
  assert.match(text,/SECRET_FINDING/);assert.match(text,/CVE-2026-113425.*CRITICAL.*nginx.*1.30.6-r1.*1.30.7-r0.*blocking/);
  assert.match(text,/INVALID_EVIDENCE/);assert.match(text,/SBOM_FAILURE/);assert.match(text,/0.76.0/);assert.match(text,/sha256:a{64}/);
  assert.doesNotMatch(text,/sensitive-fixture/);
  assert.match(securitySummary({},null,{runtimeScan:'failure'}),/runtime: SCANNER_FAILURE/);
  assert.match(securitySummary({},null,{}),/MISSING_EVIDENCE/);
  const infrastructure=securitySummary({},null,{base:'failure',runtimeHealth:'failure'});
  assert.match(infrastructure,/BASE_IMAGE_IDENTITY_FAILURE/);assert.match(infrastructure,/RUNTIME_HARDENING_OR_HEALTH_FAILURE/);
});

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

test('collection preserves independent role evidence while the final gate remains fail closed',async()=>{
  const root=await mkdtemp(join(tmpdir(),'zevyrn-security-stages-'));
  const command=fileURLToPath(new URL('../scripts/ci-security.mjs',import.meta.url));
  const invoke=args=>spawnSync(process.execPath,[command,...args],{encoding:'utf8'});
  const paths=['runtime-raw.json','runtime-scan.json','builder-raw.json','builder-scan.json'].map(n=>join(root,n));
  try {
    await writeFile(paths[0],JSON.stringify({error:'sensitive-stage-fixture'}));
    await writeFile(paths[2],JSON.stringify(builder()));
    const invalid=invoke(['report','runtime',...paths.slice(0,2)]);
    assert.notEqual(invalid.status,0);assert.doesNotMatch(invalid.stdout+invalid.stderr,/sensitive-stage-fixture/);
    assert.deepEqual(JSON.parse(await readFile(paths[1],'utf8')),{classification:'INVALID_EVIDENCE'});
    assert.equal(invoke(['report','builder',...paths.slice(2)]).status,0);
    assert.notEqual(invoke(['trivy',...paths]).status,0);
    assert.equal(JSON.parse(await readFile(paths[3],'utf8')).blocked,false);
    const blocked=runtime();blocked.Results[0].Vulnerabilities=[{VulnerabilityID:'CVE-2099-99999',Severity:'HIGH',PkgName:'fixture',InstalledVersion:'1'}];
    await writeFile(paths[0],JSON.stringify(blocked));
    assert.equal(invoke(['report','runtime',...paths.slice(0,2)]).status,0,'collection is not acceptance');
    assert.notEqual(invoke(['trivy',...paths]).status,0);
    const summary=invoke(['summary',root,JSON.stringify({runtimeScan:'failure',builderScan:'success',security:'failure'})]);
    assert.equal(summary.status,0);assert.match(summary.stdout,/VULNERABILITY_POLICY/);
    assert.match(await readFile(join(root,'summary.md'),'utf8'),/CVE-2099-99999/);
  } finally {await rm(root,{recursive:true,force:true});}
});
test('npm audit gate includes development findings and preserves lower advisory counts',()=>{
  for(const [high,critical] of [[0,0],[1,0],[0,1]]){
    const result=assessNpm({auditReportVersion:2,metadata:{vulnerabilities:{low:1,moderate:1,high,critical}},vulnerabilities:{fixture:{name:'fixture',isDirect:false,severity:critical?'critical':high?'high':'moderate'}}});
    assert.equal(result.blocked,high+critical>0);assert.equal(result.counts.low,1);
  }
});
