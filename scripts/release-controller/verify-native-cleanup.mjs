// Later cleanup completion, independently linked to historical failure; no auto retry.
import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';
import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';
import {browserExecution,authenticatedRecord} from './browser-context.mjs';
import {authenticateBrowserTools} from './browser-runtime-identity.mjs';
import {validateNative} from './clipboard-acceptance.mjs';
const here=path.resolve(process.argv[3]);
const execution=browserExecution(here,{path:process.argv[4],sha256:process.argv[5]});
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const decode=b=>JSON.parse(b.toString('utf8').replace(/^\uFEFF/,''));
const activation=decode(authenticatedRecord(execution.records.activation));
const result=decode(authenticatedRecord(execution.records.originalResult));
const originalExit=decode(authenticatedRecord(execution.records.originalExit));
assert.equal(originalExit.exitCode,1);assert.equal(result.status,'BLOCKED');assert.equal(result.passed,6);
assert.ok(result.cases.every(c=>c.status==='PASS'&&c.finalAssertionsCompleted&&c.consoleErrors===0&&c.pageErrors===0));
assert.equal(result.sourceManifestSHA256,execution.sourceManifestSHA256);assert.deepEqual(result.images,execution.images);
const verified=authenticateBrowserTools(execution.authority),cfg=verified.authority;
const independentReader=execution.records.independentReader.path;
const report={cleanupExecutionID:execution.executionID,scope:'POST_RUN_NATIVE_CLIPBOARD_HYGIENE_ONLY',
 originalExecutionID:result.executionID,originalResultSHA256:execution.records.originalResult.sha256,
 originalExitSHA256:execution.records.originalExit.sha256,originalExitCode:1,
 activationReceiptSHA256:execution.records.activation.sha256,
 sourceManifestSHA256:result.sourceManifestSHA256,images:result.images,runtime:verified.facts,authoritySHA256:verified.authoritySHA256,
 nativeHelperSHA256:cfg.nativeHelper.sha256,independentReaderSHA256:execution.records.independentReader.sha256,
 startedUTC:new Date().toISOString(),invocations:[],cleanupVerifiedNow:false,originalHistoricalCleanupSuccess:false,
 originalClipboardStateReconstructed:false,browserCasesRerun:0,qualificationSettled:false};
let stage='session';
function invoke(label,script,request){
 const start=new Date().toISOString();
 const r=spawnSync(cfg.powershell.path,['-NoProfile','-STA','-ExecutionPolicy','Bypass','-File',script],
  {input:JSON.stringify(request),encoding:'utf8',timeout:15000,maxBuffer:131072,windowsHide:true});
 const item={label,action:request.action||'independent-native-read',startedUTC:start,finishedUTC:new Date().toISOString(),
  exitCode:r.status,signal:r.signal,errorName:r.error?.name||null,errorCode:r.error?.code||null,
  stdoutSHA256:hash(r.stdout||''),stdoutBytes:Buffer.byteLength(r.stdout||''),stderrSHA256:hash(r.stderr||''),stderrBytes:Buffer.byteLength(r.stderr||'')};
 report.invocations.push(item);
 if(r.error||r.signal!==null)throw Object.assign(new Error('NATIVE_PROCESS_INVOCATION_FAILED'),{code:'NATIVE_PROCESS_INVOCATION_FAILED'});
 let parsed;
 try{parsed=JSON.parse(r.stdout);}catch{throw Object.assign(new Error('NATIVE_OUTPUT_MALFORMED'),{code:'NATIVE_OUTPUT_MALFORMED'});}
 // The authenticated helper/reader never emit clipboard text; retain structured
 // operations, Windows errors and process results rather than discarding them.
 const rejectText=value=>{if(value&&typeof value==='object')for(const [key,v]of Object.entries(value)){
  assert.ok(!/^(text|contents|password|observedText|expectedBase64)$/i.test(key),'CONTENTS_LOGGING_FORBIDDEN');rejectText(v);
 }};rejectText(parsed);
 assert.equal(parsed.nonce,request.nonce,'NATIVE_RESPONSE_NONCE');
 assert.equal(parsed.action,request.action||'independent-native-read','NATIVE_RESPONSE_ACTION');
 item.nativeFailure=parsed.failure||null;item.passed=parsed.passed;
 fs.writeFileSync(path.join(here,label+'.stdout.json'),JSON.stringify(parsed,null,2)+'\n',{flag:'wx'});
 if(r.stderr&&/^NATIVE_CLIPBOARD_FAILURE: [A-Z_]+\s*$/.test(r.stderr))
  fs.writeFileSync(path.join(here,label+'.stderr.txt'),r.stderr,{flag:'wx'});
 else if(r.stderr)fs.writeFileSync(path.join(here,label+'.stderr-summary.json'),JSON.stringify({sha256:item.stderrSHA256,bytes:item.stderrBytes,rawTextOmitted:true})+'\n',{flag:'wx'});
 return {raw:r,parsed};
}
function native(label,action,text){
 const request={nonce:crypto.randomBytes(16).toString('hex'),action,expectedSession:cfg.session};
 if(action!=='session')request.expectedBase64=Buffer.from(text,'utf8').toString('base64');
 const response=invoke(label,cfg.nativeHelper.path,request);
 return {...response,binding:{nonce:request.nonce,action,session:cfg.session,text}};
}
function accept(response){return validateNative(response.parsed,response.binding,response.raw.status,response.raw.stderr);}
try{
 const session=native('session','session');report.session=accept(session).session;
 stage='historical-marker-negative-control';
 const rejected=native('invalid-marker-control','seed','ZEVYRN-CONSOLE-EVIDENCE-CLEANUP-'+crypto.randomBytes(16).toString('hex'));
 assert.equal(rejected.raw.status,1);assert.equal(rejected.parsed.failure,'NON_DIAGNOSTIC_SEED_REJECTED');assert.deepEqual(rejected.parsed.operations,[]);
 assert.throws(()=>accept(rejected),e=>e.code==='NATIVE_PROCESS_FAILED'&&e.evidence.failure==='NON_DIAGNOSTIC_SEED_REJECTED');
 report.historicalMarkerControl={rejected:true,nativeExitCode:1,failure:'NON_DIAGNOSTIC_SEED_REJECTED',clipboardOperations:0,wrapperPreservesFailure:true};
 stage='fresh-controlled-cleanup';
 const sentinel='ZEVYRN-CLIPBOARD-BOUNDARY-'+crypto.randomBytes(16).toString('hex');
 report.sentinel={pattern:'ZEVYRN-CLIPBOARD-BOUNDARY-[a-f0-9]{32}',sha256:hash(sentinel),length:sentinel.length,valueLogged:false};
 const seeded=accept(native('fresh-seed','seed',sentinel));
 assert.equal(seeded.matches,true);assert.equal(seeded.rawExact,true);report.freshReplacementVerifiedByWriter=true;
 stage='separate-native-read';
 const read=accept(native('separate-native-read','read',sentinel));assert.equal(read.matches,true);assert.equal(read.rawExact,true);
 report.separateNativeReadVerified=true;
 function independent(label,expected){return invoke(label,independentReader,{nonce:crypto.randomBytes(16).toString('hex'),expectedSession:cfg.session,expectedBase64:Buffer.from(expected).toString('base64')});}
 stage='independent-reader-negative-control';
 const other=sentinel.slice(0,-1)+(sentinel.endsWith('0')?'1':'0');
 const mismatch=independent('independent-mismatch-control',other);
 assert.equal(mismatch.raw.status,1);assert.equal(mismatch.parsed.failure,'CLIPBOARD_SENTINEL_MISMATCH');assert.equal(mismatch.parsed.exactMatch,false);
 report.independentReaderRejectsMismatch=true;
 stage='independent-windows-native-verification';
 const verifiedRead=independent('independent-positive-read',sentinel);
 assert.equal(verifiedRead.raw.status,0);assert.equal(verifiedRead.raw.stderr,'');assert.equal(verifiedRead.parsed.passed,true);
 assert.equal(verifiedRead.parsed.exactMatch,true);assert.equal(verifiedRead.parsed.expectedSHA256,report.sentinel.sha256);
 report.independentWindowsReadVerified=true;report.cleanupVerifiedNow=true;report.status='CLEANUP_VERIFIED_LATER';
}catch(error){report.status='BLOCKED';report.failure={stage,name:error.name,code:error.code||'ASSERTION_OR_NATIVE_FAILURE'};process.exitCode=1;}
finally{
 report.finishedUTC=new Date().toISOString();report.processExitCode=process.exitCode||0;
 fs.writeFileSync(path.join(here,'CLEANUP-VERIFICATION-RESULT.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({executionID:report.cleanupExecutionID,status:report.status,cleanupVerifiedNow:report.cleanupVerifiedNow,browserCasesRerun:0,failure:report.failure||null}));
}
