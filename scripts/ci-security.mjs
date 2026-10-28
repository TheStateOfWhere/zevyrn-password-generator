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
  if(!['trivy','npm'].includes(kind)||!pairs.length||pairs.length%2) throw Error('Expected kind and input/output pairs');
  // Preserve the existing workflow CLI contract: runtime pair, then builder pair.
  if(kind==='trivy'&&pairs.length!==4) throw Error('Expected runtime and builder report pairs');
  let blocked=false;
  for(let i=0;i<pairs.length;i+=2){
    const input=JSON.parse(await readFile(pairs[i],'utf8'));
    const policy=kind==='trivy'&&i===2?JSON.parse(await readFile(new URL('./ci-builder-exceptions.json',import.meta.url),'utf8')):undefined;
    const summary=kind==='trivy'?assessTrivy(input,i===0?'runtime':'builder',policy):assessNpm(input);
    await mkdir(dirname(pairs[i+1]),{recursive:true});
    await writeFile(pairs[i+1],JSON.stringify(summary,null,2)+'\n');
    blocked ||= summary.blocked;
  }
  if(blocked) process.exitCode=1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  main().catch(()=>{console.error('Security evidence validation failed; no raw scanner data was printed.');process.exitCode=1;});
}
