import {openSettings as openDialog,closeSettings as closeDialog,selectProfile} from './browser-dialog.mjs';
// Actual application UI; only deterministic public fixtures may appear in screenshots.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {writeFile} from 'node:fs/promises';
import {screenshotDirectory} from './browser-artifacts.mjs';
const {chromium}=createRequire(import.meta.url)(process.env.KEYSMITH_PLAYWRIGHT_MODULE||'playwright');
const artifact=await screenshotDirectory('combined');
const server=spawn(process.execPath,['scripts/serve.mjs'],{cwd:fileURLToPath(new URL('../',import.meta.url)),stdio:['ignore','pipe','pipe']});
let browser;
const results={layouts:[],batches:[],mobile:[],screenshots:[],fixtureOnly:true};
try{
 await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('error',reject);server.once('exit',()=>reject(Error('Preview stopped')));});
 browser=await chromium.launch({headless:true,...(process.env.KEYSMITH_BROWSER_PATH?{executablePath:process.env.KEYSMITH_BROWSER_PATH}:{})});
 const context=await browser.newContext({viewport:{width:1280,height:1000},colorScheme:'light',reducedMotion:'reduce',serviceWorkers:'block'});
 const unexpected=[],errors=[];
 const assets=new Set(['/','/app.js','/theme.js','/styles.css','/core.js','/dictionary.js','/profiles.js','/policy.js','/random-password.js','/profile-output.js']);
 await context.route('**/*',route=>{
  const u=new URL(route.request().url());
  if(u.origin==='http://127.0.0.1:4173'&&u.pathname==='/favicon.ico')return route.fulfill({status:204});
  if(u.origin!=='http://127.0.0.1:4173'||u.search||!assets.has(u.pathname)||route.request().method()!=='GET'){
   unexpected.push('Unexpected request');return route.abort();
  }
  return route.continue();
 });
 await context.addInitScript(()=>{
  let word=0,rank=0;globalThis.fixtureCopies=[];globalThis.fixturePersistence=0;
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues(b){if(b instanceof Uint8Array){b.fill(0);b[b.length-1]=rank++%256;}else b[0]=[0,0,0,0,8,0,8,0,8][word++%9];return b;}}});
  Object.defineProperty(navigator.clipboard,'writeText',{configurable:true,value:async value=>{fixtureCopies.push(value);}});
  const set=Storage.prototype.setItem;
  Storage.prototype.setItem=function(k,v){if(this!==localStorage||k!=='keysmith.theme'||!['zevyrn','midnight','aurora','dusk','slate'].includes(v)){fixturePersistence++;throw Error('Unexpected persistence');}return set.call(this,k,v);};
 });
 const page=await context.newPage();page.on('pageerror',()=>errors.push('Page error'));
 const openSettings=()=>openDialog(page);
 const closeSettings=()=>closeDialog(page);
 const settle=()=>page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
 const noOverflow=async()=>assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'No horizontal page overflow');
 const noObscuring=async()=>{await settle();assert.ok(await page.locator('#generate').evaluate(e=>getComputedStyle(e).position!=='fixed'),'Generate stays in normal flow');};
 await page.goto('http://127.0.0.1:4173/',{waitUntil:'networkidle'});
 await page.locator('#theme').selectOption('zevyrn');
 for(const width of [1280,768,390,320]){
  await page.setViewportSize({width,height:1000});await page.reload({waitUntil:'networkidle'});
  assert.equal(await page.locator('#settings-disclosure').evaluate(e=>e.open),false,'Settings initially closed at every width');
  await page.locator('#generate').click();await closeSettings();await page.evaluate(()=>scrollTo(0,0));await settle();
  if(width<=680){const box=await page.locator('.password').boundingBox();assert.ok(box.y>=0&&box.y+box.height<850,'Generated output immediately visible without settings traversal');}
  await noOverflow();await noObscuring();
  if(width<=390){
   const passwordBox=await page.locator('.password').boundingBox();assert.ok(passwordBox.y<=405,'Mobile password is higher without shrinking text or controls');
   for(const target of await page.locator('.profiles button,#count,#settings-summary,.view-tools label,.copy-password,.regenerate,#generate,.component-disclosure summary').all()){
    const box=await target.boundingBox();assert.ok(box.width>=44&&box.height>=44,'Mobile controls retain 44px touch targets');
   }
  }
  const shot=artifact('zevyrn-'+width+'.png');await page.screenshot({path:shot,fullPage:true});results.screenshots.push(shot);
  results.layouts.push({width,pass:true});
  if(width===1280||width===390){
   await page.locator('#theme').selectOption('midnight');await page.evaluate(()=>document.activeElement?.blur());
   const darkShot=artifact('midnight-'+width+'.png');await page.screenshot({path:darkShot,fullPage:true});results.screenshots.push(darkShot);
   await page.locator('#theme').selectOption('zevyrn');await openSettings();
   await page.locator('#advanced').evaluate(e=>e.open=true);const settingsShot=artifact('settings-'+width+'.png');await page.screenshot({path:settingsShot,fullPage:false});results.screenshots.push(settingsShot);await page.locator('#advanced').evaluate(e=>e.open=false);await closeSettings();
  }

  if(width===1280||width===390){
   await page.locator('#count').selectOption('5');await page.locator('#generate').click();await closeSettings();await page.evaluate(()=>scrollTo(0,0));
   const batchShot=artifact('zevyrn-batch-'+width+'.png');await page.screenshot({path:batchShot,fullPage:true});results.screenshots.push(batchShot);
  }
  for(const profile of ['readable','strong-random','custom-policy'])for(const count of ['1','5','10','20']){
   await page.locator('#count').selectOption(count);await openSettings();await selectProfile(page,profile);
   if(profile==='readable'){await page.locator('#advanced').evaluate(e=>e.open=true);await page.locator('#suffix').fill('64');}
   if(profile==='custom-policy'){
    await page.locator('#custom-length').fill('128');await page.locator('#custom-symbol-list').fill('-_@#%*+ .<>&');
   }
   await page.locator(profile==='custom-policy'?'#generate':'#settings-generate').click();await closeSettings();
   assert.equal(await page.locator('.password').count(),Number(count));
   // Password values remain only inside the test process; reports contain booleans/counts.
   const values=await page.locator('.password').allTextContents();
   const normal=await page.locator('.password').evaluateAll(nodes=>nodes.map(e=>parseFloat(getComputedStyle(e).fontSize)));
   await page.locator('#manual').check();
   assert.ok(await page.locator('.password').evaluateAll((nodes,before)=>nodes.every((e,i)=>parseFloat(getComputedStyle(e).fontSize)>before[i]),normal),'Every result becomes larger in manual mode');
   assert.ok((await page.locator('.password').allTextContents()).every((v,i)=>v===values[i]),'Manual mode preserves exact bytes');
   await noOverflow();
   for(const index of [0,Number(count)-1]){
    const row=page.locator('.password-row').nth(index);
    await row.getByRole('button',{name:'Copy password '+(index+1),exact:true}).click();
    assert.ok(await page.evaluate(v=>fixtureCopies.at(-1)===v,values[index]),'Exact whole-password copying');
    await row.locator('.password').evaluate(e=>{const r=document.createRange();r.selectNodeContents(e);const s=getSelection();s.removeAllRanges();s.addRange(r);});
    assert.ok(await page.evaluate(v=>getSelection().toString()===v,values[index]),'Exact native selection including literal punctuation/spaces');
   }
   if(profile==='readable'){
    const row=page.locator('.password-row').last();assert.equal(await row.locator('.component-copy button').first().isVisible(),false);
    await row.locator('.component-disclosure summary').focus();await page.keyboard.press('Enter');
    assert.equal(await row.locator('.component-disclosure summary').textContent(),'Copy a word or suffix');
    await row.locator('.component-copy button').last().click();
    assert.ok(await page.evaluate(v=>fixtureCopies.at(-1)===v,values.at(-1).split('.').at(-1)),'Exact suffix copy through disclosure');
   }else assert.equal(await page.locator('.password .segment').count(),0,'Random profiles retain literal rendering');
   // Masked values must be absent from DOM text/attributes and the accessibility tree.
   await page.locator('#show').uncheck();
   assert.ok(await page.evaluate(values=>{
    const text=document.body.textContent,attributes=[...document.querySelectorAll('*')].flatMap(node=>[...node.attributes].map(a=>a.value));
    return values.every(value=>!text.includes(value)&&attributes.every(a=>!a.includes(value)));
   },values),'Hidden passwords have no DOM/attribute leak');
   const accessible=await page.locator('.results').ariaSnapshot();assert.ok(!values.some(value=>accessible.includes(value)),'Hidden passwords have no accessible plaintext');
   assert.equal(await page.locator('.password .segment,.password .dot').count(),0);
   await page.locator('#show').check();
   assert.ok(await page.locator('.password').evaluateAll(nodes=>nodes.every(node=>[node,...node.querySelectorAll('*')].every(part=>['::before','::after'].every(pseudo=>['none','normal','""'].includes(getComputedStyle(part,pseudo).content))))),'No generated password punctuation');
   for(const row of await page.locator('.password-row').all()){
    const copy=await row.locator('.copy-password').boundingBox(),regen=await row.locator('.regenerate').boundingBox();
    assert.ok(copy.x+copy.width<=regen.x||regen.x+regen.width<=copy.x||copy.y+copy.height<=regen.y||regen.y+regen.height<=copy.y,'Row actions never overlap');
    assert.ok((await row.locator('.row-metrics').textContent()).includes(await page.locator('#entropy').textContent()),'Every row retains its calculated entropy');
   }
   await page.locator('#manual').uncheck();await noObscuring();results.batches.push({width,profile,count:Number(count),pass:true});
  }
 }
 // Custom errors stay inline and signposted without opening a modal.
 await page.setViewportSize({width:390,height:844});await openSettings();await selectProfile(page,'custom-policy');
 await page.locator('#custom-min-uppercase').fill('128');
 assert.equal(await page.locator('#generate').isDisabled(),true);
 assert.equal(await page.locator('#settings-disclosure').evaluate(e=>e.open),false);assert.equal(await page.locator('#custom-policy-inline').isVisible(),true);
 await closeSettings();assert.equal(await page.locator('#settings-summary-error').isVisible(),true);
 assert.equal(await page.locator('[data-profile=custom-policy]').getAttribute('aria-pressed'),'true');
 assert.equal(await page.locator('#custom-min-uppercase').isVisible(),true);
 await page.locator('#custom-min-uppercase').fill('1');assert.equal(await page.locator('#settings-summary-error').isVisible(),false);
 // Reduced viewport models keyboard/reflow conditions; real-device keyboard remains a manual check.
 for(const height of [420,250]){
  await page.setViewportSize({width:320,height});await openSettings();await page.locator('#custom-exclusions').focus();
  await page.locator('#custom-exclusions').scrollIntoViewIfNeeded();await noObscuring();
  assert.equal(await page.locator('#generate').evaluate(e=>getComputedStyle(e).position),'static');
  await page.locator('#settings-summary').click();assert.equal(await page.locator('#settings-disclosure').evaluate(e=>e.matches(':modal')),true);
  await page.locator('#settings-done').scrollIntoViewIfNeeded();const doneBox=await page.locator('#settings-done').boundingBox();assert.ok(doneBox.y>=0&&doneBox.y+doneBox.height<=height,'Dialog footer reachable in short viewport');await page.locator('#settings-done').click();assert.equal(await page.locator('#settings-summary').evaluate(e=>e===document.activeElement),true);await closeSettings();await page.locator('#generate').scrollIntoViewIfNeeded();assert.equal(await page.locator('#generate').isVisible(),true);await noOverflow();results.mobile.push({height,normalFlow:true});
 }
 // Browser page scaling approximates 200%/400% zoom reflow; never obscure the focused control.
 const session=await context.newCDPSession(page);
 await page.setViewportSize({width:390,height:844});await closeSettings();await page.evaluate(()=>document.activeElement?.blur());
 for(const scale of [2,4]){await session.send('Emulation.setPageScaleFactor',{pageScaleFactor:scale});assert.ok(await page.evaluate(()=>visualViewport.scale>1),'Actual visual viewport scaling applied');await noObscuring();assert.equal(await page.locator('#generate').evaluate(e=>getComputedStyle(e).position),'static');results.mobile.push({scale,normalFlow:true});}
 await session.send('Emulation.setPageScaleFactor',{pageScaleFactor:1});await session.detach();
 // All results remain accessible without pagination; native modal traps focus and restores it.
 await page.setViewportSize({width:390,height:844});await page.reload({waitUntil:'networkidle'});
 await openSettings();assert.equal(await page.locator('#settings-disclosure').evaluate(e=>e.matches(':modal')),true);
 for(const profile of ['strong-random','custom-policy','readable']){
  await selectProfile(page,profile);if(profile==='readable')await page.locator('#advanced').evaluate(e=>e.open=true);
  const active=page.locator('#settings-form input:not(:disabled),#settings-form textarea:not(:disabled),#settings-form select:not(:disabled),#custom-settings input:not(:disabled),#custom-settings textarea:not(:disabled)');
  for(const field of await active.all()){
   if(!await field.isVisible())continue;await field.scrollIntoViewIfNeeded();await field.focus();
   assert.equal(await field.evaluate(e=>e===document.activeElement),true,'Every active profile control is keyboard accessible');
   const box=await field.boundingBox();assert.ok(box.width>0&&box.x>=0&&box.x+box.width<=390,'Dialog fields fit mobile width');
  }
 }

 for(let i=0;i<35;i++){await page.keyboard.press('Tab');assert.equal(await page.evaluate(()=>document.querySelector('#settings-disclosure').contains(document.activeElement)),true);}
 for(let i=0;i<20;i++){await page.keyboard.press('Shift+Tab');assert.equal(await page.evaluate(()=>document.querySelector('#settings-disclosure').contains(document.activeElement)),true);}
 await page.keyboard.press('Escape');assert.equal(await page.locator('#settings-summary').evaluate(e=>e===document.activeElement),true);
 await page.locator('#count').selectOption('5');assert.equal(await page.locator('#passwords').evaluate(e=>e.classList.contains('batch')),true);
 await page.locator('#batch-generate').click();assert.equal(await page.locator('.password').count(),5);
 await page.locator('#count').selectOption('1');assert.equal(await page.locator('#passwords').evaluate(e=>e.classList.contains('focus')),true);
 await page.locator('#generate').click();assert.equal(await page.locator('.password').count(),1);
 await page.locator('.component-disclosure summary').focus();await page.keyboard.press('Enter');await noObscuring();
 results.mobile.push({nativeModal:true,focusReturn:true,focusSheetSwitch:true});
 assert.equal(await page.evaluate(()=>fixturePersistence),0);assert.deepEqual(unexpected,[]);assert.deepEqual(errors,[]);
 results.status='PASS';await writeFile(artifact('results.png').replace(/\.png$/,'.json'),JSON.stringify(results,null,2)+'\n');
 console.log('PASS: Combined four layouts, 48 profile/batch combinations, all-result manual mode, exact selection/copy, disclosures/errors, normal-flow mobile actions, short viewports and 200%/400% page scaling. Public fixtures only.');
}finally{await browser?.close();server.kill();}
