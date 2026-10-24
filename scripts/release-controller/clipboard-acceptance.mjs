import fs from 'node:fs';import crypto from 'node:crypto';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {safeFailure} from './clipboard-journal.mjs';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function gate(ok,code,evidence){if(!ok)throw Object.assign(new Error(code),{code,evidence});}
export function windowsTextComparison(expected,observed){
 gate(typeof expected==='string'&&typeof observed==='string','INVALID_TEXT');
 const multiline=expected.includes('\n')&&!expected.includes('\r'),view=multiline?observed.replace(/\r\n/g,'\n'):observed;
 return {matches:view===expected,rawExact:observed===expected,mode:multiline?'CRLF_TO_LF_OBSERVATION_ONLY':'STRICT',expectedSHA256:sha(expected),observedSHA256:sha(observed),comparisonSHA256:sha(view),expectedLength:expected.length,observedLength:observed.length,crlfPairs:(observed.match(/\r\n/g)||[]).length};
}
export function validateNative(value,{nonce,action,session,text},exitCode,stderr){
 gate(value&&value.nonce===nonce&&value.action===action&&value.session&&value.session.interactive===true&&value.session.apartment==='STA','NATIVE_EVIDENCE_IDENTITY');
 for(const key of ['sessionId','sid','station','desktop','inputDesktop','state','protocol'])gate(value.session[key]===session[key],'SESSION_IDENTITY_MISMATCH');
 gate(Array.isArray(value.operations),'MALFORMED_NATIVE_OPERATIONS');
 for(const op of value.operations)gate(op&&typeof op.operation==='string'&&typeof op.succeeded==='boolean'&&Number.isInteger(op.win32Error)&&Number.isInteger(op.attempt)&&Number.isInteger(op.elapsedMs)&&op.elapsedMs>=0,'MALFORMED_NATIVE_OPERATIONS');
 const opens=value.operations.filter(o=>o.operation==='OpenClipboard');
 for(let i=0;i<opens.length;i++){const op=opens[i];gate(op.attempt===i+1&&i<21,'INVALID_NATIVE_RETRY');if(i){const prev=opens[i-1];gate(!prev.succeeded&&prev.win32Error===5&&typeof prev.ownerWindow==='string'&&/^[1-9][0-9]*$/.test(prev.ownerWindow)&&prev.elapsedMs<400,'INVALID_NATIVE_RETRY');}}
 gate(exitCode===0&&stderr===''&&value.passed===true,'NATIVE_PROCESS_FAILED',{action,exitCode,diagnostics:stderr?.slice(0,4096),failure:value.failure||null,operations:value.operations,nativeDiagnostics:value.diagnostics||null});
 if(action!=='session'){
  gate(opens.length>0&&opens.at(-1).succeeded&&value.operations.some(o=>o.operation==='CloseClipboard'&&o.succeeded)&&value.operations.some(o=>o.operation==='DestroyMessageWindow'&&o.succeeded)&&value.operations.every(o=>o.succeeded||o.operation==='OpenClipboard'),'INCOMPLETE_NATIVE_OPERATIONS');
  const mode=text.includes('\n')&&!text.includes('\r')?'CRLF_TO_LF_OBSERVATION_ONLY':'STRICT';
  gate(typeof value.matches==='boolean'&&typeof value.rawExact==='boolean'&&typeof value.empty==='boolean'&&value.mode===mode&&value.expectedSHA256===sha(text)&&value.expectedLength===text.length,'NATIVE_TEXT_BINDING');
  gate(Number.isSafeInteger(value.observedLength)&&value.observedLength>=0&&Number.isSafeInteger(value.crlfPairs)&&value.crlfPairs>=0&&/^[a-f0-9]{64}$/.test(value.observedSHA256)&&/^[a-f0-9]{64}$/.test(value.comparisonSHA256),'NATIVE_TEXT_BINDING');
  gate(value.matches===(value.comparisonSHA256===sha(text))&&value.rawExact===(value.observedSHA256===sha(text)),'NATIVE_TEXT_BINDING');
  const sequence=['CreateMessageWindow',...opens.map(()=>'OpenClipboard'),...(action==='seed'?['GlobalAlloc','GlobalLockWrite','GlobalUnlockWrite','EmptyClipboard','SetClipboardData']:[]),'UnicodeTextAvailable','GetClipboardData','GlobalLockRead','ReadUnicodeText','GlobalUnlockRead','CloseClipboard','DestroyMessageWindow'];
  gate(JSON.stringify(value.operations.map(o=>o.operation))===JSON.stringify(sequence),'INCOMPLETE_NATIVE_OPERATIONS');
  gate(value.empty===(value.observedLength===0),'NATIVE_TEXT_BINDING');
  if(mode==='STRICT')gate(value.matches===value.rawExact&&value.comparisonSHA256===value.observedSHA256,'NATIVE_TEXT_BINDING');
  if(value.matches)gate(value.observedLength-value.crlfPairs===value.expectedLength||mode==='STRICT'&&value.observedLength===value.expectedLength,'NATIVE_TEXT_BINDING');
 }
 return value;
}
export function nativeClipboard(config,action,text){
 gate(process.platform==='win32','WINDOWS_REQUIRED');
 for(const item of [config.nativeHelper,config.powershell,config.browser,config.node]){gate(item&&path.isAbsolute(item.path)&&/^[a-f0-9]{64}$/.test(item.sha256),'INVALID_TOOL_IDENTITY');gate(!fs.lstatSync(item.path).isSymbolicLink()&&sha(fs.readFileSync(item.path))===item.sha256,'TOOL_IDENTITY_MISMATCH');}
 gate(path.resolve(process.execPath).toLowerCase()===path.resolve(config.node.path).toLowerCase(),'NODE_PATH_MISMATCH');
 const request={nonce:crypto.randomBytes(16).toString('hex'),action,expectedSession:config.session};if(action!=='session')request.expectedBase64=Buffer.from(text,'utf8').toString('base64');
 const r=spawnSync(config.powershell.path,['-NoProfile','-STA','-ExecutionPolicy','Bypass','-File',config.nativeHelper.path],{input:JSON.stringify(request),encoding:'utf8',timeout:15000,maxBuffer:131072,windowsHide:true});
 gate(!r.error&&r.signal===null,'NATIVE_PROCESS_FAILED',{action,exitCode:r.status,signal:r.signal,errorName:r.error?.name});
 let value;try{value=JSON.parse(r.stdout);}catch{gate(false,'MALFORMED_NATIVE_EVIDENCE',{action,exitCode:r.status,stdoutBytes:Buffer.byteLength(r.stdout||'')});}
 return validateNative(value,{nonce:request.nonce,action,session:config.session,text},r.status,r.stderr);
}
export async function acceptClipboardCopy(page,copySelector,expectedText,config,{timeoutMs=5000,statusSelector='#status',reporter,caseID='clipboard'}={}){
 let stage='request',installed=false,target=null,primary=null;const boundary=crypto.randomBytes(16).toString('hex'),record=observation=>reporter?.record({caseID,...observation});
 try{
  gate(reporter&&typeof reporter.record==='function','DIAGNOSTIC_REPORT_REQUIRED');
  gate(typeof expectedText==='string'&&expectedText.length>0&&!expectedText.includes('\0'),'EMPTY_EXPECTED_TEXT');gate(Number.isSafeInteger(timeoutMs)&&timeoutMs>=100&&timeoutMs<=10000,'INVALID_TIMEOUT');
  stage='session';const session=nativeClipboard(config,'session');record({stage,outcome:'PASS',session:session.session});
  stage='environment';const environment=await page.evaluate(async()=>({secure:isSecureContext,focused:document.hasFocus(),headless:navigator.userAgent.includes('Headless'),read:(await navigator.permissions.query({name:'clipboard-read'})).state,write:(await navigator.permissions.query({name:'clipboard-write'})).state}));gate(environment.secure&&environment.focused&&!environment.headless&&environment.read==='granted'&&environment.write==='granted','BROWSER_CLIPBOARD_ENVIRONMENT');record({stage,outcome:'PASS',environment});
  stage='seed';const marker='ZEVYRN-CLIPBOARD-BOUNDARY-'+crypto.randomBytes(16).toString('hex'),seed=nativeClipboard(config,'seed',marker);record({stage,outcome:seed.matches?'PASS':'FAIL',native:seed});gate(marker!==expectedText&&seed.matches,'NATIVE_SEED_FAILED');
  stage='copy-boundary';const setup=await page.evaluate(({boundary,statusSelector,copySelector})=>{
   if(window.__zevyrnClipboardBoundary)throw Error('OVERLAPPING_CLIPBOARD_BOUNDARY');const status=document.querySelector(statusSelector),copy=document.querySelector(copySelector);if(!status||!copy)return {valid:false};if(status.textContent.startsWith('Copied.'))return {valid:false,stale:true};
   const state={boundary,clicked:false,success:false,failure:false,mutations:0,pastes:[],observer:null,listener:null,pasteListener:null};state.listener=e=>{if(e.isTrusted&&e.target.closest(copySelector)===copy)state.clicked=true;};state.pasteListener=e=>{if(e.target.id==='zevyrn-native-paste-'+boundary)state.pastes.push({trusted:e.isTrusted});};
   state.observer=new MutationObserver(()=>{if(!state.clicked)return;state.mutations++;if(status.textContent.startsWith('Copied.'))state.success=true;if(status.textContent.startsWith('Clipboard unavailable'))state.failure=true;});copy.addEventListener('click',state.listener,true);document.addEventListener('paste',state.pasteListener,true);state.observer.observe(status,{childList:true,subtree:true,characterData:true});state.copy=copy;window.__zevyrnClipboardBoundary=state;return {valid:true};
  },{boundary,statusSelector,copySelector});gate(setup.valid,setup.stale?'STALE_SUCCESS':'MISSING_COPY_SURFACE');installed=true;
  stage='copy-completion';await page.locator(copySelector).click({timeout:timeoutMs});let completion;
  try{const h=await page.waitForFunction(b=>{const s=window.__zevyrnClipboardBoundary;return s&&s.boundary===b&&s.clicked&&(s.success||s.failure)?{success:s.success,failure:s.failure,mutations:s.mutations}:false;},boundary,{timeout:timeoutMs});completion=await h.jsonValue();await h.dispose();}catch(e){gate(false,e.name==='TimeoutError'?'COPY_TIMEOUT':'COPY_OBSERVATION_FAILED');}
  record({stage,outcome:completion.failure?'FAIL':'PASS',completion});gate(!completion.failure&&completion.success&&completion.mutations>0,'COPY_FAILED');
  stage='native-read';const native=nativeClipboard(config,'read',expectedText);record({stage,outcome:native.matches?'PASS':'FAIL',native});gate(native.matches&&!native.empty,'NATIVE_CLIPBOARD_MISMATCH');
  stage='keyboard-paste';target='zevyrn-native-paste-'+boundary;await page.evaluate(id=>{const t=document.createElement('textarea');t.id=id;t.setAttribute('aria-label','Qualification native clipboard paste target');document.body.append(t);t.focus();},target);gate(await page.locator('#'+target).evaluate(t=>document.activeElement===t&&document.hasFocus()),'PASTE_FOCUS_FAILED');await page.keyboard.press('Control+V');
  try{await page.waitForFunction(({target,expectedText})=>{const v=document.getElementById(target)?.value;return typeof v==='string'&&(expectedText.includes('\n')&&!expectedText.includes('\r')?v.replace(/\r\n/g,'\n'):v)===expectedText;},{target,expectedText},{timeout:timeoutMs});}catch(e){gate(false,e.name==='TimeoutError'?'PASTE_TIMEOUT':'PASTE_OBSERVATION_FAILED');}
  const paste=windowsTextComparison(expectedText,await page.locator('#'+target).inputValue()),events=await page.evaluate(()=>window.__zevyrnClipboardBoundary.pastes);gate(paste.matches,'PASTE_MISMATCH');gate(events.length===1&&events[0].trusted,'UNTRUSTED_PASTE');record({stage,outcome:'PASS',paste,events});
  const proof={passed:true,headed:true,session:config.session,copyCompletionObserved:true,nativeEquality:true,realKeyboardPaste:true,pasteEquality:true,comparisonMode:native.mode,environment};record({stage:'case-complete',outcome:'PASS',proof});return proof;
 }catch(e){primary=e;e.stage??=stage;try{record({stage:'failure',outcome:'FAIL',failure:safeFailure(e,stage)});}catch(diagnostic){diagnostic.originalFailure=safeFailure(e,stage);throw diagnostic;}throw e;
 }finally{
  try{if(target)await page.locator('#'+target).evaluate(t=>t.remove());if(installed)await page.evaluate(b=>{const s=window.__zevyrnClipboardBoundary;if(s?.boundary===b){s.observer.disconnect();s.copy.removeEventListener('click',s.listener,true);document.removeEventListener('paste',s.pasteListener,true);delete window.__zevyrnClipboardBoundary;}},boundary);}catch(e){if(primary){primary.cleanupFailure=safeFailure(e,'cleanup');}else{gate(false,'CLIPBOARD_FIXTURE_CLEANUP_FAILED',{name:e.name});}}
 }
}
