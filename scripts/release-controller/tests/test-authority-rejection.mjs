// Ordinary disposable manifest fixtures. No alternate executable is run.
import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';
import path from 'node:path';import {pathToFileURL,fileURLToPath} from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url));
const moduleBytes=fs.readFileSync(path.join(here,'browser-runtime-identity.mjs'));
const original=fs.readFileSync(path.join(here,'clipboard-authority.PROPOSED.json'));
const tests=[];
for(const [name,mutate,code] of [
 ['exact authority accepted',null,null],
 ['altered Node hash rejected',a=>{a.node.sha256='0'.repeat(64);},'AUTHORITY_HASH_MISMATCH'],
 ['old Node hash rejected',a=>{a.node.sha256='e921fe5307e29bf6fd00000dd594356affd3a7b044e52720c7f10decbdc305b9';},'AUTHORITY_HASH_MISMATCH'],
 ['wrong authority version rejected',a=>{a.node.version='26.7.0';},'AUTHORITY_HASH_MISMATCH'],
 ['wrong authority path rejected',a=>{a.node.path='C:\\other\\node.exe';},'AUTHORITY_HASH_MISMATCH'],
 ['wrong authority architecture rejected',a=>{a.node.architecture='arm64';},'AUTHORITY_HASH_MISMATCH'],
 ['unrelated tool substitution rejected',a=>{a.browser.sha256='0'.repeat(64);},'AUTHORITY_HASH_MISMATCH'],
 ['malformed authority rejected',()=>'{', 'AUTHORITY_HASH_MISMATCH']
]){
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'zevyrn-node-authority-'));
 try{
  fs.writeFileSync(path.join(temp,'browser-runtime-identity.mjs'),moduleBytes);
  let data=original;
  if(mutate){const object=JSON.parse(original.toString('utf8').replace(/^\uFEFF/,''));const returned=mutate(object);data=Buffer.from(typeof returned==='string'?returned:JSON.stringify(object));}
  fs.writeFileSync(path.join(temp,'clipboard-authority.PROPOSED.json'),data);
  const module=await import(pathToFileURL(path.join(temp,'browser-runtime-identity.mjs')).href);
  if(code)assert.throws(()=>module.authenticateBrowserTools(),e=>e.code===code);
  else assert.equal(module.authenticateBrowserTools().facts.version,'26.8.1');
  tests.push({name,passed:true});
 }catch(e){tests.push({name,passed:false,error:{name:e.name,code:e.code}});process.exitCode=1;}
 finally{
  const target=fs.realpathSync(temp);
  assert.equal(path.dirname(target),fs.realpathSync(os.tmpdir()));
  assert.ok(path.basename(target).startsWith('zevyrn-node-authority-'));
  fs.rmSync(target,{recursive:true,force:false});assert.equal(fs.existsSync(temp),false);
 }
}
const report={passed:tests.filter(t=>t.passed).length,failed:tests.filter(t=>!t.passed).length,skipped:0,tests,temporaryFixturesRemoved:true,qualificationExecuted:false};
fs.writeFileSync(path.join(here,'authority-rejection-results.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({passed:report.passed,failed:report.failed,skipped:0}));
