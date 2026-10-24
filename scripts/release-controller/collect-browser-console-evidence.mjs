// Authenticated canonical console/page-error producer. No automatic dispatch.
import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';
import assert from 'node:assert/strict';import http from 'node:http';
import {pathToFileURL} from 'node:url';import {createRequire} from 'node:module';
import {browserExecution,authenticatedRecord} from './browser-context.mjs';
import {authenticateBrowserTools} from './browser-runtime-identity.mjs';
const here=path.resolve(process.argv[3]);
const execution=browserExecution(here,{path:process.argv[4],sha256:process.argv[5]});
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const json=b=>JSON.parse(b.toString('utf8').replace(/^\uFEFF/,''));
const receiptBytes=authenticatedRecord(execution.records.activation),activation=json(receiptBytes);
assert.equal(activation.executionID,execution.executionID);
assert.equal(activation.sourceManifestSHA256,execution.sourceManifestSHA256);assert.deepEqual(activation.images,execution.images);
const verified=authenticateBrowserTools(execution.authority),cfg=verified.authority;
const assetManifestBytes=authenticatedRecord(execution.records.assetManifest),assetManifest=json(assetManifestBytes);
assert.equal(Object.keys(assetManifest).length,16);
const assets=new Map();for(const [name,digest]of Object.entries(assetManifest))assets.set(name,authenticatedRecord({path:path.join(execution.dist,name),sha256:digest}));
const dialogPath=execution.records.dialog.path;
const {openSettings,closeSettings,selectProfile}=await import(pathToFileURL(dialogPath).href);
const {nativeClipboard}=await import('./clipboard-acceptance.mjs');
const {clipboardJournal}=await import('./clipboard-journal.mjs');
const imageBytes=authenticatedRecord(execution.records.imageProof),imageProof=json(imageBytes);
assert.equal(imageProof.passed,true);assert.equal(imageProof.sourceManifestSHA256,activation.sourceManifestSHA256);
assert.equal(imageProof.builderImageID,activation.images.builder);assert.equal(imageProof.runtimeIdentityChain.imageID,activation.images.runtime);assert.equal(imageProof.applicationFiles,16);
const require=createRequire(import.meta.url),{chromium}=require(execution.playwright.module);
assert.equal(require(path.join(execution.playwright.module,'package.json')).version,execution.playwright.version);
const cases=['readable','strong-random','custom-policy'].flatMap(profile=>[1,5].map(count=>({id:`${profile}-${count}`,profile,count,status:'NOT_EXECUTED',finalAssertionsCompleted:false})));
const report={executionID:activation.executionID,scope:'SIX_CASE_CONSOLE_PAGEERROR_EVIDENCE_ONLY',startedUTC:new Date().toISOString(),
 activationReceiptSHA256:hash(receiptBytes),activationVerificationSHA256:execution.records.activationVerification.sha256,
 runtime:verified.facts,authoritySHA256:verified.authoritySHA256,runtimeGuardSHA256:activation.runtimeGuard.sha256,
 controllerReceiptSHA256:activation.activeRevision2ControllerReceiptSHA256,sourceManifestSHA256:activation.sourceManifestSHA256,
 images:activation.images,offlineImageProofSHA256:hash(imageBytes),assetManifestSHA256:hash(assetManifestBytes),assetHashes:assetManifest,
 priorClipboardReceiptSHA256:execution.records.priorClipboardReceipt.sha256,
 clipboardAcceptanceRerun:false,supersessionActivated:false,qualificationSettled:false,cases};
const journal=clipboardJournal(path.join(here,'browser-events.jsonl'),{executionID:report.executionID,sourceManifestSHA256:report.sourceManifestSHA256,images:report.images});
let sequence=0,diagnosticFailure=null;const log=(kind,details={})=>{const row={observationSequence:++sequence,kind,...details};journal.record(row);return row.observationSequence;};
let browser,server,currentCase=null,clipboardTouched=false,timedOut=false;const contexts=[];
const deadline=setTimeout(()=>{timedOut=true;void browser?.close();},180000);deadline.unref();
try{
 report.session=nativeClipboard(cfg,'session').session;log('session-authenticated',{session:report.session});
 server=http.createServer((req,res)=>{
  const name=new URL(req.url,'http://localhost').pathname.slice(1)||'index.html';
  const content=assets.get(name);if(!content){res.writeHead(404);res.end();return;}
  res.writeHead(200,{'Content-Type':({'.html':'text/html','.js':'application/javascript','.css':'text/css','.txt':'text/plain','.ico':'image/x-icon','.json':'application/json'})[path.extname(name)]||'application/octet-stream',
   'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
   'Permissions-Policy':'camera=(), microphone=(), geolocation=()','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY'});res.end(content);
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
 const origin=`http://127.0.0.1:${server.address().port}`;report.origin=origin;
 browser=await chromium.launch({headless:false,executablePath:cfg.browser.path});report.browserVersion=browser.version();
 assert.equal(report.browserVersion,execution.browserVersion);log('headed-browser-launched',{version:report.browserVersion});
 for(const item of cases){
  assert.equal(timedOut,false);currentCase=item;item.status='RUNNING';item.startedUTC=new Date().toISOString();
  const context=await browser.newContext({permissions:['clipboard-read','clipboard-write']});contexts.push(context);
  const page=await context.newPage(),errors=[];let consoleProbeSeen=false;
  const onConsole=message=>{try{
   if(message.type()==='error'){errors.push('console-error');log('console-error',{caseID:item.id});}
   if(message.type()==='debug'&&message.text()==='ZEVYRN-CONSOLE-LISTENER-PROBE'){consoleProbeSeen=true;log('console-probe-delivered',{caseID:item.id});}
  }catch(e){diagnosticFailure=e;}};
  const onPageError=error=>{errors.push('pageerror');try{log('page-error',{caseID:item.id,name:error.name});}catch(e){diagnosticFailure=e;}};
  page.on('console',onConsole);page.on('pageerror',onPageError);
  assert.ok(page.listeners('console').includes(onConsole)&&page.listeners('pageerror').includes(onPageError));
  item.listenerRegistrationSequence=log('listeners-registered',{caseID:item.id,console:true,pageerror:true});
  const probe=page.waitForEvent('console',m=>m.type()==='debug'&&m.text()==='ZEVYRN-CONSOLE-LISTENER-PROBE');
  await page.evaluate(()=>console.debug('ZEVYRN-CONSOLE-LISTENER-PROBE'));await probe;assert.equal(consoleProbeSeen,true);
  item.navigationStartSequence=log('navigation-start',{caseID:item.id});
  assert.ok(item.listenerRegistrationSequence<item.navigationStartSequence);
  const response=await page.goto(origin,{waitUntil:'networkidle'});assert.equal(response.status(),200);item.loadSucceeded=true;
  await page.bringToFront();assert.equal(await page.evaluate(()=>document.hasFocus()&&window.isSecureContext&&typeof crypto.getRandomValues==='function'),true);
  await openSettings(page);await selectProfile(page,item.profile);await closeSettings(page);
  assert.equal(await page.locator('#profile').inputValue(),item.profile);item.profileVerified=true;
  await page.locator('#count').selectOption(String(item.count));assert.equal(await page.locator('#count').inputValue(),String(item.count));item.countSettingVerified=true;
  await page.locator('#generate').click();await page.waitForFunction(n=>document.querySelectorAll('.password').length===n,item.count);
  const values=await page.locator('.password').allTextContents();assert.equal(values.length,item.count);
  assert.ok(values.every(value=>value.length>0&&!/[lLiIoO01]/.test(value)));item.generationVerified=true;
  assert.equal((await page.locator('#status').textContent()).startsWith('Copied.'),false);
  clipboardTouched=true;
  await (item.count===1?page.locator('.copy-password').first():page.locator('#copy-all')).click();
  await page.waitForFunction(()=>{const text=document.getElementById('status').textContent;if(text.startsWith('Clipboard unavailable.'))throw Error('COPY_INTERACTION_FAILED');return text.startsWith('Copied.');},undefined,{timeout:5000});
  item.copyInteractionCompleted=true;log('interactions-complete',{caseID:item.id,generation:true,copyAction:true,clipboardGateRetested:false});
  assert.equal(page.listeners('console').includes(onConsole)&&page.listeners('pageerror').includes(onPageError),true);
  assert.equal(diagnosticFailure,null,'DIAGNOSTIC_WRITE_FAILURE');assert.equal(timedOut,false,'EXECUTION_DEADLINE');assert.deepEqual(errors,[],'CONSOLE_PAGEERROR_ASSERTION');
  item.finalAssertionSequence=log('final-assertions-complete',{caseID:item.id,consoleErrors:0,pageErrors:0,listenersStillRegistered:true,consoleProbeDelivered:true});
  item.finalAssertionsCompleted=true;item.listenersStillRegisteredAtFinal=true;item.consoleProbeDelivered=true;
  await context.close();assert.deepEqual(errors,[],'LATE_BROWSER_ERRORS');assert.equal(diagnosticFailure,null);
  item.consoleErrors=0;item.pageErrors=0;item.finishedUTC=new Date().toISOString();item.status='PASS';
  log('case-complete',{caseID:item.id,status:'PASS',lateErrorsChecked:true});
 }
}catch(error){
 if(currentCase?.status==='RUNNING')currentCase.status='FAIL';
 report.failure={stage:currentCase?.id||'preflight',name:error.name,code:error.code||'ASSERTION_OR_OPERATION_FAILED'};
 process.exitCode=1;try{log('execution-failed',report.failure);}catch{}
}finally{
 try{
  // Existing reviewed hygiene mechanism; never compares any application value.
  if(clipboardTouched){nativeClipboard(cfg,'seed','ZEVYRN-CLIPBOARD-BOUNDARY-'+crypto.randomBytes(16).toString('hex'));report.clipboardHygieneCompleted=true;}
 }catch(error){report.cleanupFailure={stage:'synthetic-clipboard-hygiene',name:error.name,code:error.code};process.exitCode=1;}
 try{for(const context of contexts)await context.close();if(browser)await browser.close();if(server?.listening)await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));
  report.cleanup={browserClosed:!browser?.isConnected(),serverClosed:!server?.listening,ownedContexts:contexts.length};assert.ok(report.cleanup.browserClosed&&report.cleanup.serverClosed);
 }catch(error){report.cleanupFailure={stage:'owned-browser-resources',name:error.name};process.exitCode=1;}
 clearTimeout(deadline);report.finishedUTC=new Date().toISOString();report.passed=cases.filter(c=>c.status==='PASS').length;report.failed=cases.filter(c=>c.status==='FAIL').length;report.notExecuted=cases.filter(c=>c.status==='NOT_EXECUTED').length;
 report.status=report.passed===6&&!report.failure&&!report.cleanupFailure&&!diagnosticFailure&&!timedOut?'PASS':'BLOCKED';if(report.status!=='PASS')process.exitCode=1;
 log('execution-complete',{status:report.status,passed:report.passed,failed:report.failed,notExecuted:report.notExecuted});journal.close();
 fs.writeFileSync(path.join(here,'BROWSER-CONSOLE-RESULTS.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({executionID:report.executionID,status:report.status,passed:report.passed,failed:report.failed,notExecuted:report.notExecuted}));
}
