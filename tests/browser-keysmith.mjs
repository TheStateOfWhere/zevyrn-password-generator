// Local-only UI regressions. Screenshots contain deterministic public fixtures.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {writeFile} from 'node:fs/promises';
import {screenshotDirectory} from './browser-artifacts.mjs';
const {chromium}=createRequire(import.meta.url)(process.env.KEYSMITH_PLAYWRIGHT_MODULE||'playwright');
const artifact=await screenshotDirectory('keysmith');
const server=spawn(process.execPath,['scripts/serve.mjs'],{cwd:fileURLToPath(new URL('../',import.meta.url)),stdio:['ignore','pipe','pipe']});
let browser;
const results={themes:[],layouts:[],screenshots:[],fixtureOnly:true};
try{
 await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('error',reject);server.once('exit',()=>reject(Error('Preview stopped')));});
 browser=await chromium.launch({headless:true,...(process.env.KEYSMITH_BROWSER_PATH?{executablePath:process.env.KEYSMITH_BROWSER_PATH}:{})});
 results.browser=browser.version();
 const context=await browser.newContext({viewport:{width:1280,height:1000},serviceWorkers:'block'});
 const requests=[],errors=[];
 const assets=new Set(['/','/theme.js','/styles.css','/app.js','/core.js','/dictionary.js','/profiles.js','/policy.js','/random-password.js','/profile-output.js']);
 await context.route('**/*',route=>{
  const u=new URL(route.request().url());
  if(u.origin==='http://127.0.0.1:4173'&&u.pathname==='/favicon.ico')return route.fulfill({status:204});
  if(u.origin!=='http://127.0.0.1:4173'||!assets.has(u.pathname)||u.search||route.request().method()!=='GET'){requests.push('Unexpected request');return route.abort();}
  return route.continue();
 });
 await context.addInitScript(()=>{
  let word=0,rank=0;globalThis.fixtureCopies=[];globalThis.fixtureWrites=0;
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues(b){if(b instanceof Uint8Array){b.fill(0);b[b.length-1]=rank++%256;}else b[0]=[0,0,0,0,8,0,8,0,8][word++%9];return b;}}});
  Object.defineProperty(navigator.clipboard,'writeText',{configurable:true,value:async value=>fixtureCopies.push(value)});
  const set=Storage.prototype.setItem;
  Storage.prototype.setItem=function(k,v){if(this!==localStorage||k!=='keysmith.theme'||!['zevyrn','midnight','aurora','dusk','slate'].includes(v)){fixtureWrites++;throw Error('Unexpected persistence');}return set.call(this,k,v);};
 });
 const page=await context.newPage();page.on('pageerror',()=>errors.push('Page error'));
 await page.goto('http://127.0.0.1:4173/',{waitUntil:'networkidle'});
 assert.equal(await page.title(),'Zevyrn');
 assert.equal(await page.getByRole('link',{name:'Zevyrn home',exact:true}).count(),1);
 assert.equal(await page.locator('.brand svg').count(),1);
 assert.match(await page.locator('footer').textContent(),/Zevyrn/);
 assert.equal(await page.locator('.version').textContent(),'v1.2.1');
 await page.locator('#generate').click();
 const shot=async name=>{const path=artifact(name+'.png');await page.screenshot({path,fullPage:true});results.screenshots.push(path);};
 const surfaces=new Map();
 for(const theme of ['zevyrn','midnight','aurora','dusk','slate']){
  await page.emulateMedia({colorScheme:'light'});await page.locator('#theme').selectOption(theme);
  for(const scheme of ['light','dark']){
   await page.emulateMedia({colorScheme:scheme});
   const state=await page.evaluate(()=>{
    const root=getComputedStyle(document.documentElement),select=document.querySelector('#theme'),option=select.options[0];
    return {surface:root.getPropertyValue('--surface').trim(),background:root.backgroundColor,scheme:getComputedStyle(select).colorScheme,optionColor:getComputedStyle(option).color,optionBackground:getComputedStyle(option).backgroundColor,selectColor:getComputedStyle(select).color};
   });
   assert.equal(state.optionColor,state.selectColor);
   assert.ok(!state.optionBackground.endsWith(', 0)'),'Native options have an opaque background');
   assert.equal(state.scheme,theme==='midnight'?'dark':'light');
   results.themes.push({theme,scheme,...state});
   surfaces.set(theme,state.background);
  }
  await shot(theme+'-focus-1280');
 }
 assert.equal(new Set(surfaces.values()).size,5,'All five theme backgrounds differ');
 await page.locator('#theme').selectOption('aurora');await page.reload();assert.equal(await page.locator('#theme').inputValue(),'aurora');
 // Native select keyboard interaction remains intact.
 await page.locator('#theme').focus();await page.keyboard.press('Home');await page.keyboard.press('ArrowDown');await page.keyboard.press('Enter');
 assert.equal(await page.locator('#theme').inputValue(),'midnight');
 await page.locator('[data-profile=custom-policy]').click();
 assert.equal(await page.locator('#settings-disclosure').evaluate(e=>e.open),false);
 assert.equal(await page.locator('#custom-policy-inline').isVisible(),true);
 assert.equal(await page.locator('#custom-settings').count(),1);
 assert.equal(await page.locator('#custom-settings input,#custom-settings textarea').evaluateAll(nodes=>nodes.every(e=>e.form?.id==='settings-form')),true);
 assert.equal(await page.locator('#policy-feedback').evaluate(e=>e.parentElement.id),'custom-feedback');
 await page.locator('#custom-length').fill('128');await page.locator('#generate').click();
 assert.equal((await page.locator('.password').textContent()).length,128);
 await shot('custom-inline-1280');
 for(const width of [1280,768,390,320]){
  await page.setViewportSize({width,height:900});
  for(const count of ['1','5','20']){
   await page.locator('#count').selectOption(count);await page.locator('#generate').click();
   assert.equal(await page.locator('.password').count(),Number(count));
   const values=await page.locator('.password').allTextContents();
   const normal=await page.locator('.password').evaluateAll(nodes=>nodes.map(e=>parseFloat(getComputedStyle(e).fontSize)));
   await page.locator('#manual').check();
   assert.equal(await page.locator('.password').evaluateAll((nodes,sizes)=>nodes.every((e,i)=>parseFloat(getComputedStyle(e).fontSize)>sizes[i]),normal),true,'Large text remains useful for every row');
   assert.deepEqual(await page.locator('.password').allTextContents(),values);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   await page.locator('.copy-password').last().click();assert.equal(await page.evaluate(()=>fixtureCopies.at(-1)),values.at(-1));
   await page.locator('#show').uncheck();
   assert.equal(await page.evaluate(v=>v.every(p=>!document.body.textContent.includes(p)&&[...document.querySelectorAll('*')].every(e=>[...e.attributes].every(a=>!a.value.includes(p)))),values),true);
   await page.locator('.copy-password').last().click();assert.equal(await page.evaluate(()=>fixtureCopies.at(-1)),values.at(-1),'Explicit hidden copying retains exact bytes');
   const snapshot=await page.locator('.results').ariaSnapshot();assert.equal(values.some(v=>snapshot.includes(v)),false);
   await page.locator('#show').check();await page.locator('#manual').uncheck();
   results.layouts.push({width,count:Number(count),pass:true});
  }
  if(width<=390){await page.locator('#count').selectOption('1');await page.locator('#generate').click();await shot('custom-inline-'+width);}
 }
 await page.locator('#custom-min-uppercase').fill('129');
 assert.equal(await page.locator('#generate').isDisabled(),true);
 assert.equal(await page.locator('#custom-min-uppercase-error').isVisible(),true);
 assert.equal(await page.locator('#policy-status').isVisible(),true);
 assert.equal(await page.locator('#settings-disclosure').evaluate(e=>e.open),false);
 assert.equal(await page.locator('.password').count(),0);
 await page.locator('#custom-min-uppercase').fill('1');
 // Native required-field validation and keyboard submission work outside the form subtree.
 await page.locator('#custom-length').fill('');await page.locator('#settings-form').evaluate(f=>f.requestSubmit());
 assert.equal(await page.locator('#custom-length').evaluate(e=>e===document.activeElement),true);
 await page.locator('#custom-length').fill('32');await page.locator('#custom-length').press('Enter');
 assert.equal(await page.locator('.password').count(),1);
 // Secondary Settings remains a real modal even with Custom Policy active.
 await page.locator('#settings-summary').click();
 assert.equal(await page.locator('#settings-disclosure').evaluate(e=>e.matches(':modal')),true);
 for(let i=0;i<18;i++){await page.keyboard.press('Tab');assert.equal(await page.evaluate(()=>document.querySelector('#settings-disclosure').contains(document.activeElement)),true);}
 await page.keyboard.press('Escape');assert.equal(await page.locator('#settings-summary').evaluate(e=>e===document.activeElement),true);
 await page.locator('[data-profile=readable]').click();
 assert.equal(await page.locator('#custom-policy-inline').isVisible(),false);
 assert.equal(await page.locator('#custom-length').isDisabled(),true);
 assert.equal(await page.locator('#policy-feedback').evaluate(e=>e.parentElement.id),'dialog-feedback');
 await page.locator('#settings-summary').click();await page.locator('#profile').selectOption('custom-policy');
 assert.equal(await page.locator('#settings-disclosure').evaluate(e=>e.open),false);
 assert.equal(await page.locator('#custom-length').inputValue(),'32','The same controls retain state without mirrors');
 assert.equal(await page.evaluate(()=>fixtureWrites),0);assert.deepEqual(requests,[]);assert.deepEqual(errors,[]);
 results.status='PASS';await writeFile(artifact('results.png').replace(/\.png$/,'.json'),JSON.stringify(results,null,2)+'\n');
 console.log('PASS: Zevyrn branding; native option palettes/keyboard; five themes; inline form ownership, errors and Enter; modal isolation; 12 responsive batch/large-text cases; exact hidden copying; no requests/persistence. '+artifact('results.png').replace(/\.png$/,'.json'));
}finally{await browser?.close();server.kill();}
