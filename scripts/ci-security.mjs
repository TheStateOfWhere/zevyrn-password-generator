// CI-only report reduction: never publish scanner secret matches or source snippets.
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {dirname,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

import {compilerPolicy} from './verify-compiler.mjs';
await compilerPolicy();
const requiredNode=[
  {name:'@typescript/typescript6',version:'6.0.2',path:'app/node_modules/@typescript/typescript6/package.json'},
  {name:'typescript',version:'6.0.3',path:'app/node_modules/@typescript/old/package.json'},
  ...['playwright','playwright-core'].map(name=>({name,version:'1.62.1',path:'app/node_modules/'+name+'/package.json'}))
];
function imagePath(path) {
  if(typeof path!=='string'||!path||/[\\:%\s\x00-\x1f\x7f]/.test(path)) throw Error('Invalid scanner package path');
  path=path.startsWith('./')?path.slice(2):path.startsWith('/')?path.slice(1):path;
  if(path.split('/').some(part=>!part||part==='.'||part==='..')) throw Error('Invalid scanner package path');
  return path;
}
function packages(result) {
  if(!Array.isArray(result.Packages)||!result.Packages.length) throw Error('Missing scanner package coverage');
  for(const p of result.Packages) if(!p||typeof p.Name!=='string'||!p.Name.trim()||typeof p.Version!=='string'||!p.Version.trim()) throw Error('Invalid scanner package identity');
  return result.Packages;
}

function builderExceptionPolicy(policy) {
  const fields=['cve','package','version','path','rationale','reviewReference'];
  if(!policy||policy.schemaVersion!==1||!Array.isArray(policy.exceptions)
    ||Object.keys(policy).sort().join(',')!=='exceptions,schemaVersion') throw Error('Invalid builder exception policy');
  const seen=new Set();
  for(const entry of policy.exceptions) {
    if(!entry||Object.keys(entry).sort().join(',')!==[...fields].sort().join(',')
      ||!fields.every(key=>typeof entry[key]==='string'&&entry[key].trim())
      ||!/^CVE-\d{4}-\d{4,}$/.test(entry.cve)||/[?*]/.test(entry.package+entry.version+entry.path)
      ||imagePath(entry.path)!==entry.path) throw Error('Invalid builder exception entry');
    const identity=JSON.stringify([entry.cve,entry.package,entry.version,entry.path]);
    if(seen.has(identity)) throw Error('Duplicate builder exception');
    seen.add(identity);
  }
  return policy.exceptions;
}

// Revalidate retained summaries against the active authority, rather than requiring
// accepted vulnerabilities to remain installed after maintenance.
export function validateBuilderAcceptance(summary,policy) {
  const exceptions=builderExceptionPolicy(policy);
  if(summary?.blocked!==false||summary.blockingVulnerabilities!==0||summary.secrets!==0
    ||summary.unapprovedHighCount!==0||!Array.isArray(summary.results)||!summary.results.length) throw Error('Invalid builder acceptance');
  let approved=0;const seen=new Set();
  for(const result of summary.results) {
    if(!Array.isArray(result.vulnerabilities)||!Array.isArray(result.secrets)||result.secrets.length) throw Error('Invalid builder findings');
    for(const finding of result.vulnerabilities) {
      const severity=finding.severity?.toUpperCase();
      if(!['UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'].includes(severity)||severity==='CRITICAL') throw Error('Unapproved builder finding');
      if(severity!=='HIGH') {if(finding.exception)throw Error('Out-of-scope disposition');continue;}
      const entry=result.type==='node-pkg'&&exceptions.find(e=>e.cve===finding.id&&e.package===finding.package
        &&e.version===finding.installed&&e.path===finding.path);
      if(!entry||finding.exception?.rationale!==entry.rationale||finding.exception?.reviewReference!==entry.reviewReference) throw Error('Unapproved builder HIGH');
      const identity=JSON.stringify([finding.id,finding.package,finding.installed,finding.path]);
      if(seen.has(identity))throw Error('Duplicate builder occurrence');seen.add(identity);approved++;
    }
  }
  if(summary.approvedHighCount!==approved||summary.rawBlockingVulnerabilities!==approved) throw Error('Invalid builder counts');
}

export function validateRuntimeSBOM(sbom,report) {
  if(sbom?.bomFormat!=='CycloneDX'||!Array.isArray(sbom.components)||!sbom.components.length) throw Error('Invalid runtime SBOM');
  const properties=sbom.metadata?.component?.properties;
  const values=name=>Array.isArray(properties)?properties.filter(p=>p.name===name).map(p=>p.value):[];
  const imageID=report?.Metadata?.ImageID;
  if(!/^sha256:[0-9a-f]{64}$/.test(imageID||'')||values('aquasecurity:trivy:ImageID').length!==1
    ||values('aquasecurity:trivy:ImageID')[0]!==imageID) throw Error('SBOM image identity mismatch');
  const packages=report.Results?.filter(r=>r.Class==='os-pkgs'&&r.Type==='alpine').flatMap(r=>r.Packages||[]);
  if(!packages?.length)throw Error('Missing SBOM package coverage');
  for(const p of packages)if(!sbom.components.some(c=>c.name===p.Name&&c.version===p.Version))throw Error('Missing SBOM package');
  return {passed:true,imageID,components:sbom.components.length};
}

export function sanitizedRuntimeSBOM(sbom,report) {
  validateRuntimeSBOM(sbom,report);
  const result=structuredClone(sbom);
  // Container labels may themselves contain a detected secret. Keep inventory
  // and image binding, but never publish arbitrary image-configuration labels.
  result.metadata.component.properties=result.metadata.component.properties.filter(p=>
    ['aquasecurity:trivy:ImageID','aquasecurity:trivy:DiffID','aquasecurity:trivy:SchemaVersion'].includes(p.name));
  return result;
}

// Only allow bounded identifiers into Markdown/console output. In particular,
// secret targets, matches, titles, snippets and exception text are never rendered.
const safe=value=>typeof value==='string'&&/^[A-Za-z0-9@_./:+, -]{1,200}$/.test(value)?value:'unavailable';
export function securitySummary(reports,scanner,stages={},roles=['runtime','builder'],identities={}) {
  const lines=['## Security acceptance','',`Scanner: ${safe(scanner?.Version)}; database updated: ${safe(scanner?.VulnerabilityDB?.UpdatedAt)}; downloaded: ${safe(scanner?.VulnerabilityDB?.DownloadedAt)}`,''];
  const labels={base:'BASE_IMAGE_IDENTITY_FAILURE',scanner:'SCANNER_OR_DATABASE_FAILURE',runtimeScan:'RUNTIME_SCAN_OR_EVIDENCE_FAILURE',builderScan:'BUILDER_SCAN_OR_EVIDENCE_FAILURE',sbom:'SBOM_FAILURE',security:'SECURITY_ACCEPTANCE_FAILED',runtimeHealth:'RUNTIME_HARDENING_OR_HEALTH_FAILURE'};
  for(const [key,label] of Object.entries(labels))if(stages[key]==='failure')lines.push(`- ${label}; stage=${key}`);
  for(const role of roles) {
    const report=reports[role];
    if(!report){lines.push(`- ${role}: ${stages[role+'Scan']==='failure'?'SCANNER_FAILURE':'MISSING_EVIDENCE'}; image=${safe(identities[role])}`);continue;}
    if(report.classification==='INVALID_EVIDENCE'){lines.push(`- ${role}: INVALID_EVIDENCE (report validation failed); image=${safe(identities[role])}`);continue;}
    lines.push('',`### ${role}: ${safe(report.imageID)}`);
    lines.push(`Classification: ${report.secrets?'SECRET_FINDING':report.blocked?'VULNERABILITY_POLICY':'ACCEPTED'}; detected secrets: ${Number.isSafeInteger(report.secrets)?report.secrets:'unavailable'}.`);
    lines.push('','| CVE | Severity | Package | Installed | Fixed | Disposition |','| --- | --- | --- | --- | --- | --- |');
    for(const result of report.results||[])for(const v of result.vulnerabilities||[])lines.push(`| ${safe(v.id)} | ${safe(v.severity)} | ${safe(v.package)} | ${safe(v.installed)} | ${safe(v.fixed)} | ${v.exception?'approved builder occurrence':['HIGH','CRITICAL'].includes(v.severity?.toUpperCase())?'blocking':'below blocking threshold'} |`);
  }
  return lines.join('\n')+'\n';
}

export function assessTrivy(report,role,exceptionPolicy={schemaVersion:1,exceptions:[]}) {
  // A CI coverage check, not the archive-bound image-qualification validator.
  if(!['runtime','builder'].includes(role)) throw Error('Expected CI image role');
  if(report?.SchemaVersion!==2||report.ArtifactType!=='container_image'||report.Trivy?.Version!=='0.76.0'
    ||!/^sha256:[0-9a-f]{64}$/.test(report.Metadata?.ImageID||'')||report.Metadata?.OS?.Family!=='alpine'
    ||['error','Error','Errors'].some(key=>Object.hasOwn(report,key))||!Array.isArray(report.Results)||!report.Results.length) throw Error('Invalid Trivy report or missing coverage');
  const exceptions=role==='builder'?builderExceptionPolicy(exceptionPolicy):[];
  let blockingVulnerabilities=0,secrets=0,rawBlockingVulnerabilities=0,approvedHighCount=0,unapprovedHighCount=0;
  const os=new Map(),node=new Map();let osTargets=0;
  const results=report.Results.map(result=>{
    if (!result || typeof result.Target!=='string'||!result.Target.trim()) throw Error('Invalid Trivy target');
    for(const key of ['Vulnerabilities','Secrets']) if(result[key]!==undefined&&!Array.isArray(result[key])) throw Error('Invalid Trivy findings');
    if(result.Class==='os-pkgs'&&result.Type==='alpine') {
      if(++osTargets!==1) throw Error('Duplicate OS coverage');
      for(const p of packages(result)) {if(os.has(p.Name)) throw Error('Duplicate OS package');os.set(p.Name,p.Version);}
    } else if(result.Class==='lang-pkgs'&&result.Type==='node-pkg'&&role==='builder') {
      for(const p of packages(result)) {
        const path=imagePath(p.FilePath);
        if(p.Name.startsWith('@typescript/typescript-')||(p.Name==='typescript'&&p.Version!=='6.0.3')||path==='app/node_modules/typescript/package.json') throw Error('Unexpected native TypeScript coverage');
        if(node.has(path)) throw Error('Duplicate Node.js coverage');
        node.set(path,p);
      }
    } else if(result.Class!=='secret'||!Array.isArray(result.Secrets)||!result.Secrets.length) throw Error('Unrecognized or unexpected scanner coverage');
    const vulnerabilities=(result.Vulnerabilities||[]).map(v=>{
      if(!v || typeof v.Severity!=='string' || !['UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'].includes(v.Severity.toUpperCase()) || typeof v.VulnerabilityID!=='string'||!v.VulnerabilityID) throw Error('Invalid vulnerability');
      const severity=v.Severity.toUpperCase();
      const path=role==='builder'&&result.Class==='lang-pkgs'&&result.Type==='node-pkg'
        &&typeof v.PkgPath==='string'&&v.PkgPath?imagePath(v.PkgPath):undefined;
      const pkg=path&&node.get(path);
      const exception=role==='builder'&&severity==='HIGH'&&result.Class==='lang-pkgs'&&result.Type==='node-pkg'
        &&pkg?.Name===v.PkgName&&pkg?.Version===v.InstalledVersion
        &&exceptions.find(entry=>entry.cve===v.VulnerabilityID&&entry.package===v.PkgName
          &&entry.version===v.InstalledVersion&&entry.path===path);
      if(['HIGH','CRITICAL'].includes(severity)) {
        rawBlockingVulnerabilities++;
        if(exception) approvedHighCount++;
        else {blockingVulnerabilities++;if(severity==='HIGH')unapprovedHighCount++;}
      }
      const finding={id:v.VulnerabilityID,package:v.PkgName,installed:v.InstalledVersion,fixed:v.FixedVersion,severity:v.Severity,status:v.Status,url:v.PrimaryURL};
      if(role==='builder'&&path)finding.path=path;
      if(exception)finding.exception={rationale:exception.rationale,reviewReference:exception.reviewReference};
      return finding;
    });
    const secretFindings=(result.Secrets||[]).map(s=>{
      if(!s||typeof s.RuleID!=='string'||!s.RuleID) throw Error('Invalid secret finding');
      secrets++;
      return {rule:s.RuleID,category:s.Category,severity:s.Severity,startLine:s.StartLine,endLine:s.EndLine};
    });
    return {target:result.Target,type:result.Type,vulnerabilities,secrets:secretFindings};
  });
  if(osTargets!==1) throw Error('Missing OS coverage');
  if(role==='runtime'&&!['nginx','libexpat','zlib'].every(name=>os.has(name))) throw Error('Missing runtime package coverage');
  if(role==='builder'&&(!requiredNode.every(p=>node.get(p.path)?.Name===p.name&&node.get(p.path)?.Version===p.version))) throw Error('Missing builder dependency coverage');
  const summary={blocked:blockingVulnerabilities>0||secrets>0,blockingVulnerabilities,secrets,results};
  if(role==='builder')Object.assign(summary,{rawBlockingVulnerabilities,approvedHighCount,unapprovedHighCount});
  return summary;
}

export function assessNpm(report) {
  if(report?.auditReportVersion!==2||!report.metadata?.vulnerabilities||!report.vulnerabilities||report.error) throw Error('Invalid npm audit report');
  const counts=report.metadata.vulnerabilities;
  for(const severity of ['low','moderate','high','critical']) if(!Number.isInteger(counts[severity])||counts[severity]<0) throw Error('Invalid advisory counts');
  return {blocked:counts.high+counts.critical>0,counts,packages:Object.values(report.vulnerabilities).map(v=>({name:v.name,severity:v.severity,isDirect:v.isDirect,range:v.range,fixAvailable:v.fixAvailable}))};
}

async function main() {
  const [kind,...pairs]=process.argv.slice(2);
  const readJSON=async path=>JSON.parse(await readFile(path,'utf8'));
  const writeJSON=async(path,value)=>{await mkdir(dirname(path),{recursive:true});await writeFile(path,JSON.stringify(value,null,2)+'\n');};
  const policy=async()=>readJSON(new URL('./ci-builder-exceptions.json',import.meta.url));
  if(kind==='report') {
    const [role,input,output]=pairs;if(pairs.length!==3)throw Error('Expected role and report paths');
    if(!['runtime','builder'].includes(role))throw Error('Expected image role');
    try {
      const raw=await readJSON(input),summary=assessTrivy(raw,role,role==='builder'?await policy():undefined);
      await writeJSON(output,{...summary,imageID:raw.Metadata.ImageID});
    } catch(error) {await writeJSON(output,{classification:'INVALID_EVIDENCE'});throw error;}
    return;
  }
  if(kind==='sbom') {
    if(pairs.length!==3)throw Error('Expected raw SBOM, runtime report and sanitized SBOM paths');
    await writeJSON(pairs[2],sanitizedRuntimeSBOM(await readJSON(pairs[0]),await readJSON(pairs[1])));return;
  }
  if(kind==='summary') {
    if(pairs.length!==2&&!(pairs.length===3&&pairs[2]==='promotion'))throw Error('Expected evidence directory and stage outcomes');
    const directory=pairs[0],reports={},identities={};let scanner;
    const promotion=pairs[2]==='promotion',roles=promotion?['runtime']:['runtime','builder'];
    for(const role of roles)try{reports[role]=await readJSON(resolve(directory,(promotion?'promotion-':'')+role+'-scan.json'));}catch{}
    try{scanner=await readJSON(resolve(directory,(promotion?'promotion-':'')+'scanner-version.json'));}catch{}
    try{const rows=(await readFile(resolve(directory,'image-identities.txt'),'utf8')).split('\n').filter(s=>/^sha256:[0-9a-f]{64} linux\/amd64 user=/.test(s));identities.builder=rows[0]?.split(' ')[0];identities.runtime=rows[1]?.split(' ')[0];}catch{}
    try{identities.runtime=(await readJSON(resolve(directory,promotion?'promotion-scan-identity.json':'identity.json'))).configDigest;}catch{}
    try{identities.builder=(await readJSON(resolve(directory,'builder-identity.json'))).imageID;}catch{}
    const summary=securitySummary(reports,scanner,JSON.parse(pairs[1]),roles,identities);
    await mkdir(directory,{recursive:true});await writeFile(resolve(directory,'summary.md'),summary);
    if(process.env.GITHUB_STEP_SUMMARY)await writeFile(process.env.GITHUB_STEP_SUMMARY,summary,{flag:'a'});
    console.log(summary);return;
  }
  if(!['trivy','npm'].includes(kind)||!pairs.length||pairs.length%2) throw Error('Expected kind and input/output pairs');
  // Preserve the existing workflow CLI contract: runtime pair, then builder pair.
  if(kind==='trivy'&&pairs.length!==4) throw Error('Expected runtime and builder report pairs');
  let blocked=false;
  for(let i=0;i<pairs.length;i+=2){
    const input=JSON.parse(await readFile(pairs[i],'utf8'));
    const policy=kind==='trivy'&&i===2?JSON.parse(await readFile(new URL('./ci-builder-exceptions.json',import.meta.url),'utf8')):undefined;
    const summary=kind==='trivy'?assessTrivy(input,i===0?'runtime':'builder',policy):assessNpm(input);
    await mkdir(dirname(pairs[i+1]),{recursive:true});
    await writeFile(pairs[i+1],JSON.stringify(kind==='trivy'?{...summary,imageID:input.Metadata.ImageID}:summary,null,2)+'\n');
    if(kind==='trivy'&&i===2&&!summary.blocked)validateBuilderAcceptance(summary,policy);
    blocked ||= summary.blocked;
  }
  if(blocked) {console.error('VULNERABILITY_OR_SECRET_POLICY: security findings block acceptance; see sanitized role reports.');process.exitCode=1;}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  main().catch(()=>{console.error('INVALID_OR_MISSING_SECURITY_EVIDENCE: security evidence validation failed; no raw scanner data was printed.');process.exitCode=1;});
}
