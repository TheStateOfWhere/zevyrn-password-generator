import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { prepareProfileOutput } from '../dist/profile-output.js';
import { DEFAULTS } from '../dist/core.js';
import { WORDS } from '../dist/dictionary.js';
class Element {
 children=[];listeners=new Map();attributes=new Map();value='';checked=false;disabled=false;hidden=false;text='';parent=null;
 classList={values:new Set(),toggle(name,on){on?this.values.add(name):this.values.delete(name);}};
 get valueAsNumber(){return this.value===''?NaN:Number(this.value);}
 get textContent(){return this.text+this.children.map(c=>c.textContent).join('');}set textContent(v){this.text=String(v);this.children=[];}
 append(...items){for(const x of items){x.parent=this;this.children.push(x);}}replaceChildren(...items){this.text='';this.children=[];this.append(...items);}
 replaceWith(next){const i=this.parent.children.indexOf(this);this.parent.children[i]=next;next.parent=this.parent;this.parent=null;}
 querySelector(selector){return this.children.find(c=>'.'+c.className===selector)||this.children.map(c=>c.querySelector(selector)).find(Boolean);}
 setAttribute(k,v){this.attributes.set(k,v);}focus(){document.activeElement=this;}addEventListener(t,fn){this.listeners.set(t,fn);}
 dispatch(t){this.listeners.get(t)?.({preventDefault(){}});}
}
let harnessId=0;
const settle=()=>new Promise(resolve=>setImmediate(resolve));
async function harness(run){
 const html=await readFile(new URL('../dist/index.html',import.meta.url),'utf8');
 const els=new Map([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],new Element()]));const get=id=>els.get(id);
 for(const m of html.matchAll(/<input\b([^>]+)>/g)){const id=/id="([^"]+)"/.exec(m[1])?.[1];if(id){get(id).value=/value="([^"]*)"/.exec(m[1])?.[1]||'';get(id).checked=/\bchecked\b/.test(m[1]);}}
 for(const m of html.matchAll(/<textarea\b([^>]+)>([\s\S]*?)<\/textarea>/g)){get(/id="([^"]+)"/.exec(m[1])[1]).value=m[2];}
 get('profile').value='readable';get('count').value='1';
 const saved=new Map(['document','window','crypto','navigator','isSecureContext'].map(k=>[k,Object.getOwnPropertyDescriptor(globalThis,k)]));
 const writes=[],events=new Map();let draws=0,failRandom=false,failCopy=false;
 const globals={document:{getElementById:get,createElement:()=>new Element(),addEventListener:(t,fn)=>events.set('document-'+t,fn)},window:{addEventListener:(t,fn)=>events.set(t,fn)},isSecureContext:true,
  crypto:{getRandomValues(b){if(failRandom)throw Error('Public fixture RNG failure');if(b instanceof Uint8Array){b.fill(0);b[b.length-1]=draws++%256;}else{const values=[0,0,0,0,8,0,8,0,8];b[0]=values[draws++%values.length];}return b;}},
  navigator:{clipboard:{async writeText(value){if(failCopy)throw Error('Public fixture clipboard failure');writes.push(value);}}}};
 for(const [k,v]of Object.entries(globals))Object.defineProperty(globalThis,k,{configurable:true,value:v});
 try{await import('../dist/app.js?profiles-ui-'+(++harnessId));await run({get,writes,events,draws:()=>draws,failRandom:v=>failRandom=v,failCopy:v=>failCopy=v,
  switchTo(value){get('profile').value=value;get('profile').dispatch('change');},rows:()=>get('passwords').children,generate:()=>get('settings-form').dispatch('submit')});}
 finally{for(const[k,d]of saved)d?Object.defineProperty(globalThis,k,d):delete globalThis[k];}
}

test('profile selector defaults to Readable; settings panels and format are accessible and isolated',async()=>{
 await harness(({get,switchTo,generate,rows,writes})=>{
  assert.equal(get('readable-settings').disabled,false);assert.equal(get('strong-settings').hidden,true);assert.equal(get('custom-settings').disabled,true);
  generate();assert.equal(rows()[0].children[2].children[1].children.length,4);
  const staleFull=rows()[0].children[0].children[1],stalePart=rows()[0].children[2].children[1].children[0];
  switchTo('strong-random');assert.equal(get('readable-settings').disabled,true);assert.equal(get('strong-settings').hidden,false);assert.equal(get('word-metric').hidden,true);
  assert.equal(get('copy-all').disabled,true);staleFull.dispatch('click');stalePart.dispatch('click');get('copy-all').dispatch('click');assert.equal(writes.length,0);
  assert.equal(get('readable-format').hidden,true);switchTo('custom-policy');assert.equal(get('custom-settings').disabled,false);assert.equal(get('strong-settings').disabled,true);
 });
});

test('Strong Random defaults, enabled-category requirements and exclusions use the exact engine',async()=>{
 await harness(({get,switchTo,generate,rows,draws})=>{
  switchTo('strong-random');assert.equal(get('strong-length').value,'20');assert.equal(get('strong-ambiguous').checked,true);
  generate();const value=rows()[0].children[1].textContent;assert.equal(value.length,20);assert.ok(!/[lLiIoO01]/.test(value));
  for(const re of [/[A-Z]/,/[a-z]/,/[2-9]/,/[-_@#%*+]/])assert.ok(re.test(value));
  assert.equal(rows()[0].children.length,3);assert.match(rows()[0].children[2].textContent,/Configured rules met/);
  get('strong-digits').checked=false;get('strong-digits').dispatch('input');get('strong-symbols').checked=false;get('strong-symbols').dispatch('change');
  get('strong-length').value='64';get('strong-length').dispatch('input');get('strong-exclusions').value='ABab';get('strong-exclusions').dispatch('input');
  generate();assert.ok(/^[A-Za-z]{64}$/.test(rows()[0].children[1].textContent));assert.ok(!/[ABab]/.test(rows()[0].children[1].textContent));
  for(const id of ['uppercase','lowercase'])get('strong-'+id).checked=false;
  get('strong-uppercase').dispatch('input');const before=draws();assert.equal(get('generate').disabled,true);generate();assert.equal(draws(),before);assert.match(get('strength-note').textContent,/Enable a category/);
 });
});

test('Custom Policy literal rendering preserves spaces, punctuation, minimums and exact entropy gate',async()=>{
 await harness(({get,switchTo,generate,rows,draws})=>{
  switchTo('custom-policy');get('custom-length').value='128';get('custom-symbol-list').value=' .<>&';
  for(const id of ['uppercase','lowercase','digits','symbols'])get('custom-min-'+id).value='32';
  get('custom-length').dispatch('input');generate();let value=rows()[0].children[1].textContent;
  assert.equal(value.length,128);assert.equal(rows()[0].children[1].children.length,0);
  assert.equal(rows()[0].children.length, value.includes(' ') ? 4 : 3);
  if(value.includes(' ')) assert.match(rows()[0].children[3].textContent,/Contains \d+ spaces?\./);
  assert.ok(/[.<>& ]/.test(value));assert.ok(!/[lLiIoO01]/.test(value));
  get('custom-digits').checked=false;get('custom-digits').dispatch('change');const before=draws();generate();assert.equal(draws(),before);assert.match(get('strength-note').textContent,/Enable digits/);
  get('custom-digits').checked=true;get('custom-min-uppercase').value='129';get('custom-min-uppercase').dispatch('input');assert.equal(get('generate').disabled,true);
  for(const id of ['uppercase','lowercase','digits','symbols'])get('custom-min-'+id).value='0';
  get('custom-digits').checked=false;get('custom-symbols').checked=false;get('custom-ambiguous').checked=false;
  get('custom-exclusions').value='BCDEFGHIJKLMNOPQRSTUVWXYZbcdefghijklmnopqrstuvwxyz';get('custom-length').value='64';get('custom-length').dispatch('input');
  assert.equal(get('entropy').textContent,'64.00 bits');assert.equal(get('generate').disabled,false);
  get('custom-min-uppercase').value='1';get('custom-min-uppercase').dispatch('input');assert.equal(get('entropy').textContent,'63.99 bits');assert.equal(get('generate').disabled,true);
  get('custom-min-uppercase').value='0';get('custom-symbol-list').value='!'.repeat(257);get('custom-symbol-list').dispatch('input');assert.match(get('strength-note').textContent,/256/);
 });
});

test('random profile batches, regeneration, hiding, manual entry and clipboard states remain correct',async()=>{
 await harness(async({get,switchTo,generate,rows,writes,failCopy,failRandom})=>{
  for(const name of ['strong-random','custom-policy'])for(const quantity of [1,5,20]){
   switchTo(name);get('count').value=String(quantity);generate();const before=rows().map(r=>r.children[1].textContent),old=[...rows()];
   const chosen=quantity-1,button=rows()[chosen].children[0].children[2];button.dispatch('click');
   assert.equal(writes.length,0);assert.notEqual(rows()[chosen].children[1].textContent,before[chosen]);
   for(let i=0;i<quantity-1;i++){assert.equal(rows()[i],old[i]);assert.equal(rows()[i].children[1].textContent,before[i]);}
   assert.equal(document.activeElement,rows()[chosen].children[0].children[2]);
   const replacement=rows()[chosen].children[1].textContent;rows()[chosen].children[0].children[1].dispatch('click');await settle();assert.equal(writes.pop(),replacement);
   get('copy-all').dispatch('click');await settle();assert.equal(writes.pop(),rows().map(r=>r.children[1].textContent).join('\n'));
   failCopy(true);get('copy-all').dispatch('click');await settle();assert.match(get('status').textContent,/Clipboard unavailable/);failCopy(false);
   get('show').checked=false;get('show').dispatch('change');assert.ok(!get('passwords').textContent.includes(replacement));
   get('manual').checked=true;get('manual').dispatch('change');assert.ok(get('passwords').classList.values.has('manual-mode'));
   failRandom(true);rows()[chosen].children[0].children[2].dispatch('click');assert.match(get('status').textContent,/Existing password preserved/);failRandom(false);
   get('show').checked=true;get('show').dispatch('change');assert.equal(rows()[chosen].children[1].textContent,replacement);
  }
 });
});

test('effective settings clear output and stale pending clipboard feedback cannot overwrite status',async()=>{
 await harness(async({get,switchTo,generate,rows,writes,events})=>{
  switchTo('strong-random');generate();const old=rows()[0].children[0].children[1];let finish;
  navigator.clipboard.writeText=()=>new Promise(resolve=>finish=resolve);old.dispatch('click');
  get('strong-length').value='21';get('strong-length').dispatch('input');assert.equal(get('copy-all').disabled,true);finish();await settle();assert.match(get('status').textContent,/Settings changed/);
  old.dispatch('click');assert.equal(writes.length,0);generate();get('custom-length').value='99';get('custom-length').dispatch('input');assert.equal(get('copy-all').disabled,false);
  events.get('pagehide')();assert.equal(get('copy-all').disabled,true);
 });
});

test('output contexts retain immutable settings without changing Readable randomness consumption',()=>{
 const descriptor=Object.getOwnPropertyDescriptor(globalThis,'crypto');let draws=0;
 try{
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues(b){if(b instanceof Uint8Array){b.fill(0);draws++;}else b[0]=[0,0,0,...Array(19).fill(0),8][draws++];return b;}}});
  const settings={...DEFAULTS,suffixLength:20},context=prepareProfileOutput({profile:'readable',settings},['abacus','banner','cactus']);settings.suffixLength=4;
  const value=context.generate();assert.equal(draws,23);assert.equal(context.validate(value),true);assert.equal(context.settings.suffixLength,20);assert.equal(Object.isFrozen(context.settings),true);
  const random=prepareProfileOutput({profile:'strong-random'},WORDS);assert.equal(Object.isFrozen(random.settings),true);assert.equal(random.validate(random.generate()),true);
 }finally{if(descriptor)Object.defineProperty(globalThis,'crypto',descriptor);else delete globalThis.crypto;}
});

test('profile controls have labels, live validation, raw limits and no password leak surfaces',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.match(html,/id="profile" aria-describedby="profile-help"/);assert.match(html,/id="policy-status"[^>]*aria-live="polite"/);
 for(const id of ['strong-exclusions','custom-exclusions','custom-symbol-list'])assert.doesNotMatch(html,new RegExp('id="'+id+'"[^>]*maxlength='));
 for(const m of html.matchAll(/<input\b([^>]+)>/g)){const id=/id="([^"]+)"/.exec(m[1])[1];assert.ok(html.includes('for="'+id+'"')||new RegExp('<label[^>]*>[^<]*<input id="'+id+'"').test(html),'Input must have an explicit or wrapping label');}
 for(const name of ['app','profile-output']){const s=await readFile(new URL('../src/'+name+'.ts',import.meta.url),'utf8');assert.doesNotMatch(s,/console\.|localStorage|sessionStorage|indexedDB|fetch\(|sendBeacon|XMLHttpRequest|WebSocket|location\./);}
});


test('complete over-limit text is retained and blocks generation without consuming randomness', async () => {
 await harness(({get,switchTo,generate,draws,rows,writes})=>{
  for(const [name,id,text] of [['strong-random','strong-exclusions','A'.repeat(256)+'Z'],
    ['custom-policy','custom-exclusions','A'.repeat(256)+'Z'],['custom-policy','custom-symbol-list','!'.repeat(257)]]){
   switchTo(name);get(id).value=id==='custom-symbol-list'?'-_@#%*+':'';get(id).dispatch('input');generate();const oldCopy=rows()[0].children[0].children[1];
   get(id).value=text;get(id).dispatch('input');const before=draws();generate();oldCopy.dispatch('click');get('copy-all').dispatch('click');
   assert.equal(get(id).value,text);assert.equal(get('generate').disabled,true);assert.equal(get('copy-all').disabled,true);
   assert.equal(get(id).attributes.get('aria-invalid'),'true');assert.match(get(id+'-error').textContent,/256/);assert.equal(draws(),before);assert.equal(writes.length,0);
   get(id).value=id==='custom-symbol-list'?'!'.repeat(256):'A'.repeat(256);get(id).dispatch('input');assert.equal(get('generate').disabled,false);
   get(id).value='';if(id==='custom-symbol-list')get(id).value='-_@#%*+';get(id).dispatch('input');
  }
 });
});

test('programmatic no-event changes cannot copy, regenerate or generate stale invalid policies',async()=>{
 await harness(({get,switchTo,generate,draws,rows,writes})=>{
  switchTo('strong-random');generate();const full=rows()[0].children[0].children[1];get('strong-exclusions').value='A'.repeat(256)+'Z';const before=draws();full.dispatch('click');
  assert.equal(writes.length,0);assert.equal(get('copy-all').disabled,true);assert.equal(get('generate').disabled,true);assert.equal(draws(),before);
  get('strong-exclusions').value='';generate();const regen=rows()[0].children[0].children[2];get('strong-length').value='3';regen.dispatch('click');assert.equal(get('copy-all').disabled,true);
  generate();assert.equal(get('copy-all').disabled,true);assert.match(get('strong-length-error').textContent,/Increase length|2\^64/);
  get('strong-length').value='20';generate();get('strong-exclusions').value='A'.repeat(257);get('copy-all').dispatch('click');assert.equal(writes.length,0);
 });
});

test('newlines and non-ASCII policy text are not silently sanitized by the interface',async()=>{
 await harness(({get,switchTo,generate,draws})=>{
  switchTo('custom-policy');for(const id of ['custom-exclusions','custom-symbol-list'])for(const text of ['A\nZ','!\t@','!é']){
   get(id).value=text;get(id).dispatch('input');const before=draws();generate();assert.equal(draws(),before);assert.equal(get(id).value,text);assert.equal(get('generate').disabled,true);assert.match(get(id+'-error').textContent,/ASCII/);
  }
 });
});

test('inline contradictions clear on correction and only one validation region is live',async()=>{
 await harness(({get,switchTo})=>{
  switchTo('custom-policy');get('custom-digits').checked=false;get('custom-digits').dispatch('change');
  for(const id of ['custom-digits','custom-min-digits']){assert.equal(get(id).attributes.get('aria-invalid'),'true');assert.match(get(id+'-error').textContent,/Enable digits/);assert.equal(get(id+'-error').hidden,false);}
  assert.equal(get('status').textContent,'');assert.match(get('policy-status').textContent,/Generation blocked/);
  get('custom-digits').checked=true;get('custom-digits').dispatch('change');assert.equal(get('generate').disabled,false);
  for(const id of ['custom-digits','custom-min-digits']){assert.equal(get(id).attributes.get('aria-invalid'),'false');assert.equal(get(id+'-error').hidden,true);}
  assert.equal(get('policy-status').textContent,'');
 });
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.doesNotMatch(html,/<[^>]*id="strength-note"[^>]*(?:aria-live|role="status")/);
 for(const id of ['strong-exclusions','custom-exclusions','custom-symbol-list'])assert.match(html,new RegExp('<textarea[^>]*id="'+id+'"[^>]*aria-describedby="[^"]*'+id+'-error'));
 assert.doesNotMatch(html,/maxlength=/);assert.match(html,/id="policy-status"[^>]*aria-live="polite"/);
});


test('unrelated native copy still synchronizes invalid eventless settings',async()=>{
 await harness(({get,switchTo,generate,events})=>{
  switchTo('strong-random');generate();let prevented=false;
  events.get('document-copy')({preventDefault(){prevented=true;}});assert.equal(prevented,false);
  get('strong-exclusions').value='A'.repeat(256)+'Z';events.get('document-copy')({preventDefault(){prevented=true;}});
  assert.equal(prevented,false);assert.equal(get('copy-all').disabled,true);assert.equal(get('generate').disabled,true);
 });
});


test('native copy blocks only selected stale password content, including hidden output',async()=>{
 for(const hidden of [false,true])await harness(({get,switchTo,generate,events,rows})=>{
  switchTo('strong-random');get('show').checked=!hidden;generate();
  const selected=rows()[0].children[1];
  get('passwords').querySelectorAll=()=>[selected];
  document.getSelection=()=>({isCollapsed:false,rangeCount:1,getRangeAt:()=>({intersectsNode:node=>node===selected})});
  get('strong-exclusions').value='A'.repeat(257);let prevented=false;
  events.get('document-copy')({preventDefault(){prevented=true;}});
  assert.equal(prevented,true);assert.equal(get('copy-all').disabled,true);
 });
 await harness(({get,switchTo,generate,events,rows})=>{
  switchTo('strong-random');generate();const selected=rows()[0].children[1];
  get('passwords').querySelectorAll=()=>[selected];
  document.getSelection=()=>({isCollapsed:false,rangeCount:1,getRangeAt:()=>({intersectsNode:()=>true})});
  get('strong-exclusions').value='A'.repeat(257);let prevented=false;
  events.get('document-copy')({target:{closest:()=>get('strong-exclusions')},preventDefault(){prevented=true;}});
  assert.equal(prevented,false);assert.equal(get('copy-all').disabled,true);
 });
});


test('combined layout follows batch settings and exposes only relevant batch actions',async()=>{
 await harness(({get,generate,rows})=>{
  assert.equal(get('passwords').classList.values.has('focus'),true);
  assert.equal(get('copy-all').hidden,true);assert.equal(get('batch-generate').hidden,true);
  for(const count of [5,10,20,1]){
   get('count').value=String(count);get('count').dispatch('change');
   assert.equal(get('passwords').classList.values.has('batch'),count>1);
   assert.equal(get('passwords').classList.values.has('focus'),count===1);
   assert.equal(get('copy-all').hidden,count===1);assert.equal(get('batch-generate').hidden,count===1);
   assert.equal(get('dialog-count').value,String(count));assert.equal(get('clear').textContent,count===1?'Clear':'Clear batch');
   generate();assert.equal(rows().length,count);
   assert.equal(rows()[0].children[0].children[1].textContent,count===1?'Copy Password':'Copy');
  }
 });
});

test('every row displays real calculated entropy and validated status without password attributes',async()=>{
 await harness(({get,switchTo,generate,rows})=>{
  for(const profile of ['readable','strong-random','custom-policy']){
   switchTo(profile);get('count').value='5';generate();
   for(const row of rows()){
    const metric=row.children.find(c=>c.className==='row-metrics');
    assert.ok(metric.textContent.includes(get('entropy').textContent));assert.match(metric.textContent,/64-bit minimum met/);
    assert.ok(![...row.attributes.values()].some(v=>v.includes(row.children[1].textContent)));
   }
  }
 });
});

test('dialog generate and workspace generate share the unchanged fail-closed policy state',async()=>{
 await harness(({get,switchTo,generate,draws,rows})=>{
  switchTo('custom-policy');get('custom-digits').checked=false;get('custom-digits').dispatch('change');
  for(const id of ['generate','settings-generate','batch-generate'])assert.equal(get(id).disabled,true);
  assert.equal(get('settings-summary-error').hidden,false);const before=draws();generate();assert.equal(draws(),before);
  assert.equal(get('copy-all').disabled,true);
  get('custom-digits').checked=true;get('custom-digits').dispatch('change');
  for(const id of ['generate','settings-generate','batch-generate'])assert.equal(get(id).disabled,false);
  assert.equal(get('settings-summary-error').hidden,true);generate();assert.ok(rows()[0].children[1].textContent.length>0);
 });
});
