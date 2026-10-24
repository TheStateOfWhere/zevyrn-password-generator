// Prepared operator harness. Never invoked by preparation or local unit tests.
import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';import {createRequire} from 'node:module';
import assert from 'node:assert/strict';
import {browserExecution} from './browser-context.mjs';
import {authenticateBrowserTools} from './browser-runtime-identity.mjs';
assert.equal(process.argv[2],'--guarded-child','Browser execution requires the guarded continuation entrypoint');
const root=path.resolve(process.argv[3]),read=p=>JSON.parse(fs.readFileSync(p,'utf8')),
 hash=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const execution=browserExecution(root,{path:process.argv[4],sha256:process.argv[5]});
const verified=authenticateBrowserTools(execution.authority),cfg=verified.authority;
const plan=read(path.join(root,'continuation.json')),seal=read(path.join(root,'preparation-seal.json'));
assert.equal(plan.executionID,execution.executionID);
assert.equal(path.basename(root),plan.executionID);assert.equal(plan.qualificationRunID,execution.qualificationRunID);
assert.equal(plan.sourceManifestSHA256,execution.sourceManifestSHA256);assert.deepEqual(plan.images,execution.images);
for(const [n,h] of Object.entries(seal))assert.equal(hash(path.join(root,n)),h);
// The Python entrypoint performs fresh strict acceptance before spawning us.
// Reject direct invocation and failed/partial phase evidence before any network,
// browser process, or output workspace is opened.
const order=['preflight','scan','scan-acceptance','reuse','audit','acceptance','runtime-creation','runtime-collection','runtime-removal','browser-creation','browser-collection'];
const safe=n=>{
 assert.ok(typeof n==='string'&&n&&!n.includes('\\')&&!n.includes(':')&&!n.startsWith('/')&&n.split('/').every(x=>x&&x!=='.'&&x!=='..'),'Unsafe phase artifact path');
 const p=path.join(root,n);assert.equal(fs.realpathSync(p),p,'Linked phase artifact');return p;
};
const identity=r=>{
 assert.equal(r.executionID,plan.executionID);assert.equal(r.qualificationRunID,plan.qualificationRunID);
 assert.equal(r.sourceManifestSHA256,plan.sourceManifestSHA256);assert.deepEqual(r.images,plan.images);
};
const names=fs.readdirSync(root);assert.ok(!names.some(n=>n.endsWith('-failed.json')),'Failed phase blocks browser');
for(const phase of order){
 const a=read(safe(phase+'-attempt.json')),r=read(safe(phase+'-completed.json'));identity(a);identity(r);
 assert.equal(a.startedUTC,r.startedUTC);assert.ok(Date.parse(r.finishedUTC)>=Date.parse(a.startedUTC),'Invalid phase interval');
 assert.ok(r.artifacts&&Object.keys(r.artifacts).length>0,'Missing phase artifacts');
 for(const [n,h] of Object.entries(r.artifacts))assert.equal(hash(safe(n)),h,'Changed phase evidence');
}
assert.ok(names.filter(n=>n.endsWith('-attempt.json')).every(n=>order.includes(n.slice(0,-13))||n==='browser-testing-attempt.json'),'Unexpected phase attempt');
assert.ok(!names.includes('browser-testing-completed.json'),'Browser phase already completed');
const attempt=read(safe('browser-testing-attempt.json'));identity(attempt);
assert.equal(attempt.ownerPID,process.ppid,'Browser must be launched by the guarded phase owner');
const proof=read(path.join(root,'browser-inspect.json'));
assert.equal(proof.Image,plan.images.runtime);assert.equal(proof.Name,'/zevyrn-'+plan.executionID+'-browser');
assert.equal(proof.Config.Labels['org.zevyrn.qualification'],plan.executionID);
const approval=read(path.join(root,'data/accepted.json'));assert.equal(approval.runtimeImageID,proof.Image);
for(const [n,h] of Object.entries(approval.boundFiles))assert.equal(hash(path.join(root,'data',n)),h);
const module=execution.playwright.module,browserPath=cfg.browser.path;
const browserEnvironment={...process.env,KEYSMITH_PLAYWRIGHT_MODULE:module,KEYSMITH_BROWSER_PATH:browserPath};
assert.ok(module&&path.isAbsolute(module)&&browserPath&&path.isAbsolute(browserPath),'Explicit existing Playwright module and browser path required');
const output=path.join(root,'browser-workspace');fs.mkdirSync(output);fs.mkdirSync(path.join(output,'scripts'));
fs.cpSync(path.join(root,'data/source/tests'),path.join(output,'tests'),{recursive:true,errorOnExist:true,force:false});
// Existing suite assertions remain byte-identical; only their child-server
// readiness adapter changes. HTTP is served by the real Docker image via SSH.
fs.writeFileSync(path.join(output,'scripts/serve.mjs'),"const r=await fetch('http://127.0.0.1:4173/healthz');if(r.status!==200)throw Error('Image health failed');console.log('Retained image tunnel ready');setInterval(()=>{},1000);\n",{flag:'wx'});
const source=read(path.join(root,'data/source-manifest.json'));
for(const row of source.filter(x=>x.path.startsWith('tests/')))assert.equal(hash(path.join(output,row.path)),row.sha256);
const assets=read(path.join(root,'production-assets.json'));
assert.equal(Object.keys(assets).length,16);
for(const [n,h] of Object.entries(assets)){
 const response=await fetch('http://127.0.0.1:4173/'+n);assert.equal(response.status,200,n);
 assert.equal(crypto.createHash('sha256').update(Buffer.from(await response.arrayBuffer())).digest('hex'),h,n);
}
const suites=['selection','keysmith','profiles','themes','contrast-regression','ui-corrections','focus-copy','direction-b','regeneration'];
const results={executionID:plan.executionID,qualificationRunID:plan.qualificationRunID,runtimeImageID:proof.Image,browserContainerID:proof.Id,suites:[],actualAssetHashesVerified:16,realClipboardPasteBack:false,consoleErrors:0};
for(const suite of suites){
 const stdout=fs.openSync(path.join(output,suite+'.stdout.log'),'wx'),stderr=fs.openSync(path.join(output,suite+'.stderr.log'),'wx');
 let r;try{r=spawnSync(process.execPath,['tests/browser-'+suite+'.mjs'],{cwd:output,env:browserEnvironment,stdio:['ignore',stdout,stderr],timeout:600000});}
 finally{fs.closeSync(stdout);fs.closeSync(stderr);}
 results.suites.push({suite,exitCode:r.status,signal:r.signal,error:r.error?String(r.error):null});
 assert.equal(r.error,undefined,suite);assert.equal(r.signal,null,suite);assert.equal(r.status,0,suite);
}
// Real Web Crypto and OS clipboard: no RNG or clipboard overrides in this context.
const clipboardModule=new URL('./clipboard-acceptance.mjs',import.meta.url),clipboardAuthorityPath=execution.authority.path;
assert.equal(hash(clipboardModule),'15d2a88e3eed4a3eaf2c98d2d51615a4cba78699a4d87f6fe97704f42e6319ef','Clipboard helper identity');
assert.equal(hash(clipboardAuthorityPath),execution.authority.sha256,'Clipboard authority identity');
const journalModule=new URL('./clipboard-journal.mjs',import.meta.url);
assert.equal(hash(journalModule),'a026697a9e9f20fbcb052425c9e1db3ebd1f6729df2047af386e04f438967a10','Clipboard journal identity');
const clipboardAuthority=JSON.parse(fs.readFileSync(clipboardAuthorityPath,'utf8').replace(/^\uFEFF/,''));
assert.equal(path.resolve(browserPath).toLowerCase(),path.resolve(clipboardAuthority.browser.path).toLowerCase(),'Clipboard browser identity');
const {acceptClipboardCopy,nativeClipboard}=await import(clipboardModule.href);
const {withClipboardJournal,safeFailure}=await import(journalModule.href);
await withClipboardJournal(path.join(root,'clipboard-observations.jsonl'),{executionID:plan.executionID,qualificationRunID:plan.qualificationRunID,sourceManifestSHA256:plan.sourceManifestSHA256,runtimeImageID:proof.Image},async clipboardJournal=>{
const nativeSession=nativeClipboard(clipboardAuthority,'session');
clipboardJournal.record({stage:'session',outcome:'PASS',session:nativeSession.session});
const {chromium}=createRequire(import.meta.url)(module),browser=await chromium.launch({headless:false,executablePath:browserPath});
let clipboardPrimary;
try{
 results.browserVersion=browser.version();clipboardJournal.record({stage:'browser-launch',outcome:'PASS',headed:true,browserVersion:results.browserVersion});
 const context=await browser.newContext({permissions:['clipboard-read','clipboard-write']}),page=await context.newPage(),errors=[];
 page.on('pageerror',e=>errors.push(e.name));page.on('console',m=>{if(m.type()==='error')errors.push('console error');});
 await page.goto('http://127.0.0.1:4173/',{waitUntil:'networkidle'});
 const {openSettings,closeSettings,selectProfile}=await import(new URL('./tests/browser-dialog.mjs','file:///'+output.replaceAll('\\','/')+'/'));
 for(const profile of ['readable','strong-random','custom-policy']){
  await openSettings(page);await selectProfile(page,profile);await closeSettings(page);
  for(const count of ['1','5']){
   await page.locator('#count').selectOption(count);await page.locator('#generate').click();
   await page.waitForFunction(n=>document.querySelectorAll('.password').length===n,Number(count));
   const values=await page.locator('.password').allTextContents();assert.ok(values.every(x=>x.length>0&&!/[lLiIoO01]/.test(x)));
   const copySelector=count==='1'?'.copy-password':'#copy-all';
   const clipboardProof=await acceptClipboardCopy(page,copySelector,values.join('\n'),clipboardAuthority,{reporter:clipboardJournal,caseID:profile+'-'+count});
   (results.clipboardChecks??=[]).push({profile,count:Number(count),...clipboardProof});
  }
 }
 assert.deepEqual(errors,[]);results.realClipboardPasteBack=true;results.browserVersion=browser.version();
}catch(error){clipboardPrimary=error;throw error;}finally{try{await browser.close();}catch(error){if(clipboardPrimary)clipboardPrimary.cleanupFailure=safeFailure(error,'browser-close');else throw error;}}
const artifacts=[];function walk(dir){for(const entry of fs.readdirSync(dir,{withFileTypes:true})){const p=path.join(dir,entry.name);if(entry.isDirectory())walk(p);else artifacts.push({path:path.relative(root,p).replaceAll('\\','/'),sha256:hash(p)});}}
walk(output);results.artifacts=artifacts;
fs.writeFileSync(path.join(root,'browser-results.json'),JSON.stringify(results,null,2)+'\n',{flag:'wx'});
console.log('PASS: nine unchanged suites, 16 actual-image asset hashes, real clipboard paste-back.');
});
