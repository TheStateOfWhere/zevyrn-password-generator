// Actual consumer command tests. These fixtures cannot issue Python controller authority.
import {test} from 'node:test';import assert from 'node:assert/strict';
import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';import {pathToFileURL} from 'node:url';
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
const guard=new URL('../browser-context.mjs',import.meta.url).href;
function fixture(){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'zevyrn-browser-context-')),run=path.join(root,'run'),modules=path.join(root,'modules');fs.mkdirSync(run);
 const files={};for(const pkg of ['playwright','playwright-core'])for(const name of ['package.json','index.js']){
  const rel=pkg+'/'+name,file=path.join(modules,rel);fs.mkdirSync(path.dirname(file),{recursive:true});const bytes=Buffer.from(name==='package.json'?'{}':'// synthetic nonexecuting library');fs.writeFileSync(file,bytes);files[rel]=digest(bytes);
 }
 const authority=path.join(root,'authority.json');fs.writeFileSync(authority,'{}');
 const context={scope:'canonical-browser-execution-v1',executionRoot:run,executionID:'run',records:{},authority:{path:authority,sha256:digest(fs.readFileSync(authority))},playwright:{root:modules,module:path.join(modules,'playwright'),files}};
 const file=path.join(root,'execution.json'),driver=path.join(root,'driver.mjs');
 fs.writeFileSync(driver,`import {browserExecution} from ${JSON.stringify(guard)};browserExecution(process.argv[3],{path:process.argv[4],sha256:process.argv[5]});console.log('CONSUMER_VALIDATED_NOT_APPROVED');`);
 return {root,run,file,driver,context,seal(){fs.writeFileSync(file,JSON.stringify(context));return digest(fs.readFileSync(file));},call({args=[],hash,parent=process.pid,env=process.env}={}){
  const sealed=this.seal();return spawnSync(process.execPath,[...args,driver,'--guarded-child',run,file,hash||sealed,String(parent)],{env,encoding:'utf8',timeout:30000});
 }};
}
test('external fixture validates exact library closure; it is not controller approval',()=>{const f=fixture(),r=f.call();assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/NOT_APPROVED/);});
test('wrong external record hash rejects',()=>{const f=fixture(),r=f.call({hash:'0'.repeat(64)});assert.notEqual(r.status,0);assert.match(r.stderr,/RECORD_IDENTITY/);});
test('wrong guarded parent rejects',()=>{const f=fixture(),r=f.call({parent:0});assert.notEqual(r.status,0);assert.match(r.stderr,/GUARDED_PARENT/);});
test('wrong root or execution identity rejects',()=>{const f=fixture();f.context.executionID='different';const r=f.call();assert.notEqual(r.status,0);});
test('empty library declaration cannot hide files',()=>{const f=fixture();f.context.playwright.files={};const r=f.call();assert.notEqual(r.status,0);assert.match(r.stderr,/LIBRARY_CLOSURE/);});
test('unexpected library file rejects before library import',()=>{const f=fixture();fs.writeFileSync(path.join(f.context.playwright.module,'unexpected.js'),'throw Error("MUST_NOT_EXECUTE")');const r=f.call();assert.notEqual(r.status,0);assert.match(r.stderr,/LIBRARY_CLOSURE/);assert.doesNotMatch(r.stderr,/Error: MUST_NOT_EXECUTE/);});
test('modified library file rejects',()=>{const f=fixture();fs.writeFileSync(path.join(f.context.playwright.module,'index.js'),'// altered');const r=f.call();assert.notEqual(r.status,0);assert.match(r.stderr,/RECORD_IDENTITY/);});
test('Node execution flags rejected even with otherwise valid fixture',()=>{const f=fixture(),r=f.call({args:['--no-warnings']});assert.notEqual(r.status,0);assert.match(r.stderr,/UNEXPECTED_NODE_EXECUTION_OPTIONS/);});
