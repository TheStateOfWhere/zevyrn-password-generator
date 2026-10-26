// Development-only public fixtures. No qualification, production or Docker calls.
import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {spawn} from 'node:child_process';
import {mkdir,writeFile} from 'node:fs/promises';
import path from 'node:path';
const directory=process.env.ZEVYRN_REVIEW_OUTPUT;
if(!directory)throw Error('Set an isolated development evidence directory.');
await mkdir(directory,{recursive:true});
const screenshots=[],checks=[];
const server=spawn(process.execPath,['scripts/serve.mjs'],{stdio:['ignore','pipe','pipe']});let browser,nativePage;
const fixture=()=>{
  let words=0;
  globalThis.publicFixture={failRandom:false,copyMode:'success',pending:[],writes:[],byte:0};
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues(b){
    if(publicFixture.failRandom)throw Error('Internal fixture diagnostic must not appear');
    if(b instanceof Uint8Array)b.fill(publicFixture.byte);else b[0]=[0,0,0,0,8,0,8,0,8][words++%9];return b;
  }}});
  const native=navigator.clipboard.writeText.bind(navigator.clipboard);
  globalThis.developmentNativeClipboard=native;
  Object.defineProperty(navigator.clipboard,'writeText',{configurable:true,value:s=>{
    if(publicFixture.copyMode==='native')return native(s);
    if(publicFixture.copyMode==='failure')return Promise.reject(Error('Private clipboard diagnostic'));
    if(publicFixture.copyMode==='pending')return new Promise((resolve,reject)=>publicFixture.pending.push({resolve,reject}));
    publicFixture.writes.push(s);return Promise.resolve();
  }});
};
try{
  await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('error',reject);server.once('exit',()=>reject(Error('Development server could not start')));});
  browser=await chromium.launch({headless:true,executablePath:process.env.ZEVYRN_DEVELOPMENT_EDGE||'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
  const context=await browser.newContext({viewport:{width:1280,height:1000},permissions:['clipboard-read','clipboard-write']});
  await context.addInitScript(fixture);const page=await context.newPage();const errors=[];page.on('pageerror',()=>errors.push('Page error'));
  await page.goto('http://127.0.0.1:4173/',{waitUntil:'networkidle'});await page.waitForFunction(()=>!document.querySelector('#generate').disabled);
  for(const profile of ['readable','strong-random','custom-policy']){
    await page.locator(`[data-profile="${profile}"]`).click();
    for(const count of [1,5,20]){
      await page.locator('#count').selectOption(String(count));await page.locator('#generate').click();
      const before=await page.locator('.password').allTextContents();
      await page.evaluate(()=>{
        const text=document.querySelector('.password');globalThis.previousCard=text.closest('.password-row');
        const walker=document.createTreeWalker(text,NodeFilter.SHOW_TEXT),node=walker.nextNode();const range=document.createRange();range.setStart(node,0);range.setEnd(node,Math.min(2,node.length));getSelection().removeAllRanges();getSelection().addRange(range);globalThis.previousSelection=getSelection().toString();
        publicFixture.failRandom=true;document.querySelector('#settings-form').requestSubmit();
      });
      const after=await page.locator('.password').allTextContents();assert.ok(before.length===after.length&&before.every((v,i)=>v===after[i]),'Generation failure changed public output; values omitted');
      assert.ok(await page.evaluate(()=>document.querySelector('.password-row')===previousCard&&getSelection().toString()===previousSelection),'Failure must preserve cards and selection');
      assert.match(await page.locator('#status').textContent(),/Existing passwords? preserved/);
      await page.evaluate(()=>{publicFixture.failRandom=false;getSelection().removeAllRanges();});
    }
  }
  checks.push('All three profiles,1/5/20: failed Generate preserves exact results, DOM cards and native selection');
  await page.locator('[data-profile="readable"]').click();await page.locator('#count').selectOption('5');await page.locator('#generate').click();
  const copy=page.locator('.copy-password').first();await copy.click();await assertButton(copy,'Copied');
  const box=await copy.boundingBox();assert.ok(box.y>=0&&box.y+box.height<=1000,'Copy feedback visible in current viewport');
  await shot(page,'desktop-batch-copy-light.png');
  await page.evaluate(()=>publicFixture.copyMode='failure');await copy.click();await assertButton(copy,'Copy failed');assert.match(await page.locator('#status').textContent(),/Clipboard unavailable/);
  await page.evaluate(()=>publicFixture.copyMode='pending');await copy.click();await page.locator('#copy-all').click();
  assert.equal(await page.evaluate(()=>publicFixture.pending.length),1,'Native writes must be serialized');
  await page.evaluate(()=>publicFixture.pending[0].reject(Error('late fixture')));await page.waitForFunction(()=>publicFixture.pending.length===2);
  await page.evaluate(()=>publicFixture.pending[1].resolve());await assertButton(page.locator('#copy-all'),'Copied');assert.match(await page.locator('#status').textContent(),/All passwords copied/);
  await copy.click();await page.locator('[data-profile="strong-random"]').click();await page.evaluate(()=>publicFixture.pending[2].resolve());assert.match(await page.locator('#status').textContent(),/Settings changed/);
  checks.push('Local copy success/failure, serialized native writes and stale completions preserve latest-action feedback');
  await page.locator('#settings-summary').click();await page.locator('#strong-length').fill('32');await page.locator('#settings-done').click();assert.match(await page.locator('#active-settings').textContent(),/32 characters/);
  await page.locator('#generate').focus();await page.keyboard.press('Enter');assert.equal(await page.locator('.password').count(),5);assert.ok(await page.evaluate(()=>document.activeElement.getBoundingClientRect().top>=0),'Keyboard focus visible');
  await page.locator('#theme').selectOption('midnight');await shot(page,'desktop-strong-dark.png');
  checks.push('Settings summary updates immediately; keyboard generation retains visible focus; Midnight palette retained');
  await page.setViewportSize({width:390,height:900});await page.locator('[data-profile="custom-policy"]').click();
  await page.locator('#count').selectOption('1');await page.locator('#custom-length').fill('64');
  for(const id of ['uppercase','lowercase','digits']){await page.locator('#custom-min-'+id).fill('0');await page.locator('#custom-'+id).uncheck();}
  await page.locator('#custom-min-symbols').fill('0');await page.locator('#custom-symbol-list').fill(' !');
  await page.evaluate(()=>{publicFixture.byte=0x55;publicFixture.copyMode='success';});await page.locator('#generate').click();
  const literal=await page.locator('.password').textContent();assert.ok(literal.length===64&&literal.startsWith(' ')&&literal.includes('!'),'Public whitespace fixture malformed');
  assert.match(await page.locator('.password-space-note').textContent(),/Contains 32 spaces.*Starts with a space/);
  await page.locator('.copy-password').click();assert.ok(await page.evaluate(s=>publicFixture.writes.at(-1)===s,literal),'Copy must preserve whitespace, values omitted');
  await page.locator('.password-row').scrollIntoViewIfNeeded();await shot(page,'mobile-custom-spaces-dark.png');
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Mobile horizontal overflow');
  await page.locator('#show').uncheck();assert.equal(await page.locator('.password-space-note').count(),0);await page.locator('#show').check();assert.ok(await page.locator('.password').textContent()===literal);
  checks.push('390px Custom Policy: literal spaces, separate notice, exact copying and no horizontal overflow');
  // Native clipboard check uses public synthetic content, followed by a sentinel.
  nativePage=page;await page.evaluate(()=>publicFixture.copyMode='native');await page.locator('.copy-password').click();await assertButton(page.locator('.copy-password'),'Copied');
  assert.ok(await page.evaluate(async s=>await navigator.clipboard.readText()===s,literal),'Native clipboard mismatch; values omitted');
  await page.evaluate(()=>developmentNativeClipboard('Zevyrn development clipboard test complete'));checks.push('Native clipboard exact whitespace copy; replaced with nonsecret completion sentinel');nativePage=undefined;
  for(const theme of ['zevyrn','midnight','aurora','dusk','slate']){
    await page.locator('#theme').selectOption(theme);
    for(const width of [320,768,1280]){
      await page.setViewportSize({width,height:1000});
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`Horizontal overflow:${theme}/${width}`);
      const note=page.locator('.password-space-note');assert.equal(await note.count(),1);
      const dimensions=await page.locator('.copy-password').boundingBox();assert.ok(dimensions.width>=44&&dimensions.height>=44,`Copy target:${theme}/${width}`);
      assert.equal(await page.locator('#status').getAttribute('aria-live'),'polite');
    }
  }
  checks.push('All five themes at320/768/1280px: no horizontal overflow,44px copy targets and retained live status');
  await page.setViewportSize({width:390,height:900});await page.locator('#theme').selectOption('zevyrn');await page.locator('[data-profile="readable"]').click();await page.evaluate(()=>publicFixture.copyMode='success');await page.locator('#generate').click();await page.evaluate(()=>window.scrollTo(0,0));await shot(page,'mobile-readable-light.png');
  for(const mode of ['missing-app','missing-dictionary','initialization-error','missing-bootstrap','missing-styles']){
    const c=await browser.newContext({viewport:{width:390,height:844}});await c.addInitScript(fixture);
    const p=await c.newPage();
    const target=mode==='missing-app'?'app.js':mode==='missing-dictionary'?'dictionary.js':mode==='missing-bootstrap'?'startup.js':mode==='missing-styles'?'styles.css':'app.js';
    await p.route('**/'+target,route=>mode==='initialization-error'?route.fulfill({contentType:'text/javascript',body:"document.querySelector('#generate').disabled=false; throw Error('Private diagnostic');"}):route.fulfill({status:404,body:'Missing fixture resource'}));
    await p.goto('http://127.0.0.1:4173/',{waitUntil:'networkidle'});
    if(mode==='missing-bootstrap')assert.match(await p.locator('#status').textContent(),/If this message remains, reload/);
    else await p.waitForFunction(()=>document.querySelector('#status').textContent.includes('could not load'));
    assert.equal(await p.locator('#generate').isDisabled(),true);assert.equal(await p.locator('#settings-generate').isDisabled(),true);assert.doesNotMatch(await p.locator('#status').textContent(),/Private diagnostic/);
    await p.locator('#settings-form').evaluate(f=>f.requestSubmit());assert.equal(await p.locator('.password-row').count(),0);
    if(mode==='missing-app')await shot(p,'mobile-startup-failure.png');await c.close();
  }
  checks.push('Missing app/dictionary/bootstrap/stylesheet and partial initialization fail closed with reload guidance');
  assert.deepEqual(errors,[]);
  await writeFile(path.join(directory,'browser-results.json'),JSON.stringify({status:'PASS',browser:browser.version(),checks,screenshots,publicFixturesOnly:true,productionQualification:false},null,2)+'\n',{flag:'wx'});
  console.log('PASS development browser validation: '+checks.length+' workflow groups; screenshots '+screenshots.length);
}finally{
  if(nativePage)await nativePage.evaluate(()=>developmentNativeClipboard('Zevyrn development clipboard test complete')).catch(()=>{});
  await browser?.close();server.kill();
}
async function assertButton(button,text){await button.page().waitForFunction(({selector,text})=>[...document.querySelectorAll(selector)].some(b=>b.textContent===text),{selector:await button.evaluate(el=>el.id?'#'+el.id:el.classList.contains('copy-password')?'.copy-password':'button'),text});assert.equal(await button.textContent(),text);}
async function shot(page,name){const target=path.join(directory,name);await page.screenshot({path:target,fullPage:false});screenshots.push(target);}
