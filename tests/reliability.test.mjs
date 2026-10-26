import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {initializeApplication} from '../public/startup.js';

// Public deterministic fixtures only. Real layout/native interaction is tested
// by browser-reliability.mjs; this surface exercises actual app event handlers.
class Element {
  children=[];listeners=new Map();attributes=new Map();value='';checked=false;disabled=false;hidden=false;text='';parent=null;
  classList={toggle(){}};
  get valueAsNumber(){return this.value===''?NaN:Number(this.value);}
  get textContent(){return this.text+this.children.map(c=>c.textContent).join('');}
  set textContent(v){this.text=String(v);this.children=[];}
  append(...items){for(const item of items){item.parent=this;this.children.push(item);}}
  replaceChildren(...items){this.text='';this.children=[];this.append(...items);}
  replaceWith(next){const i=this.parent.children.indexOf(this);this.parent.children[i]=next;next.parent=this.parent;}
  setAttribute(k,v){this.attributes.set(k,v);}getAttribute(k){return this.attributes.get(k)??null;}
  removeAttribute(k){this.attributes.delete(k);}
  addEventListener(t,fn){this.listeners.set(t,fn);}
  dispatch(t){this.listeners.get(t)?.({preventDefault(){},stopImmediatePropagation(){}});}
  querySelector(s){return this.querySelectorAll(s)[0];}
  querySelectorAll(s){return this.children.flatMap(c=>[...((s==='button[data-copy-feedback]'&&c.attributes.has('data-copy-feedback'))||s==='.'+c.className?[c]:[]),...c.querySelectorAll(s)]);}
  focus(){document.activeElement=this;}
}
let instance=0;
const settle=()=>new Promise(resolve=>setImmediate(resolve));
async function harness(run){
  const html=await readFile(new URL('../dist/index.html',import.meta.url),'utf8');
  const elements=new Map([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],new Element()]));const get=id=>elements.get(id);
  for(const m of html.matchAll(/<input\b([^>]+)>/g)){const id=/id="([^"]+)"/.exec(m[1])?.[1];if(id){get(id).value=/value="([^"]*)"/.exec(m[1])?.[1]||'';get(id).checked=/\bchecked\b/.test(m[1]);}}
  for(const m of html.matchAll(/<textarea\b([^>]+)>([\s\S]*?)<\/textarea>/g))get(/id="([^"]+)"/.exec(m[1])[1]).value=m[2];
  get('profile').value='readable';get('count').value='1';get('copy-all').textContent='Copy All';
  const original=new Map(['document','window','crypto','navigator','isSecureContext'].map(k=>[k,Object.getOwnPropertyDescriptor(globalThis,k)]));
  let draws=0,failAt=Infinity,rankByte=0;const writes=[];
  const globals={document:{getElementById:get,createElement:()=>new Element(),addEventListener(){},querySelectorAll(s){return [...elements.values()].flatMap(e=>[...(e.attributes.has('data-copy-feedback')?[e]:[]),...e.querySelectorAll(s)]);}},window:{addEventListener(){}},isSecureContext:true,
    crypto:{getRandomValues(b){if(draws++>=failAt)throw Error('Do not disclose this internal fixture diagnostic');if(b instanceof Uint8Array)b.fill(rankByte);else b[0]=[0,0,0,0,8,0,8,0,8][(draws-1)%9];return b;}},
    navigator:{clipboard:{async writeText(s){writes.push(s);}}}};
  for(const[k,v]of Object.entries(globals))Object.defineProperty(globalThis,k,{configurable:true,value:v});
  try{
    await import('../dist/app.js?reliability-'+(++instance));
    await run({get,writes,rows:()=>get('passwords').children,generate:()=>get('settings-form').dispatch('submit'),profile(v){get('profile').value=v;get('profile').dispatch('change');},failAfter(n){failAt=draws+n;},recover(){failAt=Infinity;},rankByte(v){rankByte=v;}});
  }finally{for(const[k,v]of original)v?Object.defineProperty(globalThis,k,v):delete globalThis[k];}
}

test('whole-result failure preserves exact cards, hidden state and values for all profiles and batch sizes; policy changes still invalidate',async()=>{
  for(const profile of ['readable','strong-random','custom-policy'])await harness(async h=>{
    h.profile(profile);
    for(const count of [1,5,20]){
      h.get('count').value=String(count);h.get('count').dispatch('change');h.generate();
      const rows=[...h.rows()],values=rows.map(r=>r.children[1].textContent);
      h.failAfter(count===1?0:2);h.generate();
      assert.deepEqual(h.rows(),rows);assert.deepEqual(h.rows().map(r=>r.children[1].textContent),values);
      assert.match(h.get('status').textContent,/Could not generate.*Existing passwords? preserved/);
      assert.doesNotMatch(h.get('status').textContent,/internal fixture diagnostic/);assert.equal(h.writes.length,0);
      h.get('show').checked=false;h.get('show').dispatch('change');const hidden=[...h.rows()];h.generate();
      assert.deepEqual(h.rows(),hidden);assert.ok(h.rows().every(r=>r.children[1].textContent==='•'.repeat(16)));
      h.recover();h.get('show').checked=true;h.get('show').dispatch('change');
      assert.deepEqual(h.rows().map(r=>r.children[1].textContent),values);
    }
    const field=profile==='readable'?'suffix':profile==='strong-random'?'strong-length':'custom-length';
    h.get(field).value='1';h.get(field).dispatch('input');assert.equal(h.get('copy-all').disabled,true);
    h.generate();assert.equal(h.get('generate').disabled,true);assert.ok(!h.rows().some(r=>r.className==='password-row'));
  });
});

test('copy feedback identifies the activated control, serializes exact writes, and rejects stale completions and failed-generation races',async()=>{
  await harness(async h=>{
    h.profile('strong-random');h.get('count').value='20';h.generate();const row=h.rows()[19],copy=row.children[0].children[1],value=row.children[1].textContent;
    copy.dispatch('click');assert.equal(copy.textContent,'Copying…');await settle();assert.equal(copy.textContent,'Copied');assert.equal(h.writes.at(-1),value);assert.match(h.get('status').textContent,/Password 20 copied/);
    navigator.clipboard.writeText=async()=>{throw Error('Private clipboard diagnostic');};copy.dispatch('click');await settle();assert.equal(copy.textContent,'Copy failed');assert.match(h.get('status').textContent,/Clipboard unavailable/);assert.doesNotMatch(h.get('status').textContent,/Private clipboard/);
    const pending=[];navigator.clipboard.writeText=text=>new Promise((resolve,reject)=>pending.push({text,resolve,reject}));
    copy.dispatch('click');h.get('copy-all').dispatch('click');assert.equal(copy.textContent,'Copy');
    assert.equal(pending.length,1,'New native writes wait for an in-flight write');
    pending[0].reject(Error('late failure'));await settle();assert.equal(pending.length,2);
    assert.ok(pending[1].text===h.rows().map(r=>r.children[1].textContent).join('\n'),'Queued Copy All must retain exact bytes; values omitted');
    pending[1].resolve();await settle();assert.equal(h.get('copy-all').textContent,'Copied');assert.match(h.get('status').textContent,/All passwords copied/);
    copy.dispatch('click');h.failAfter(0);h.generate();const failure=h.get('status').textContent;pending[2].resolve();await settle();assert.equal(h.get('status').textContent,failure);assert.equal(copy.textContent,'Copy');
    h.recover();copy.dispatch('click');h.get('copy-all').dispatch('click');h.get('strong-length').value='21';h.get('strong-length').dispatch('input');const changed=h.get('status').textContent;pending[3].resolve();await settle();assert.equal(h.get('status').textContent,changed);assert.equal(h.get('copy-all').disabled,true);assert.equal(pending.length,4,'A queued stale copy must never call the native clipboard');
  });
});

test('active summary follows real profile settings and effective symbol exclusions without exposing invalid raw fields',async()=>{
  await harness(async h=>{
    assert.match(h.get('active-settings').textContent,/Readable.*4–12.*6-character suffix/);
    h.profile('strong-random');assert.match(h.get('active-settings').textContent,/20 characters.*uppercase.*numbers.*Ambiguous/);
    h.get('strong-length').value='32';h.get('strong-length').dispatch('input');assert.match(h.get('active-settings').textContent,/32 characters/);
    h.profile('custom-policy');h.get('custom-symbol-list').value='!@!';h.get('custom-exclusions').value='!';h.get('custom-exclusions').dispatch('input');
    assert.match(h.get('active-settings').textContent,/symbols \(minimum 1\).*1 additional exclusion.*1 allowed symbol/);
    h.get('custom-min-digits').value='129';h.get('custom-min-digits').dispatch('input');assert.match(h.get('active-settings').textContent,/Review the marked settings/);assert.equal(h.get('generate').disabled,true);
  });
});

test('space notices remain separate from literal output; hidden output hides notices and every copy preserves whitespace exactly',async()=>{
  await harness(async h=>{
    h.profile('custom-policy');h.get('custom-length').value='64';h.get('custom-symbol-list').value=' !';
    for(const id of ['uppercase','lowercase','digits']){h.get('custom-'+id).checked=false;h.get('custom-min-'+id).value='0';}
    h.get('custom-min-symbols').value='0';h.get('custom-length').dispatch('input');h.rankByte(0);h.generate();
    const value=h.rows()[0].children[1].textContent;assert.equal(value,' '.repeat(64));
    const note=h.rows()[0].querySelector('.password-space-note');assert.equal(note.textContent,'Contains 64 spaces. Starts with a space. Ends with a space.');assert.equal(h.rows()[0].children[1].textContent,value);
    h.rows()[0].children[0].children[1].dispatch('click');await settle();assert.equal(h.writes.at(-1),value);
    h.get('show').checked=false;h.get('show').dispatch('change');assert.equal(h.rows()[0].querySelector('.password-space-note'),undefined);
    h.get('show').checked=true;h.get('show').dispatch('change');assert.equal(h.rows()[0].children[1].textContent,value);
    h.rankByte(0x55);h.generate();const mixed=h.rows()[0].children[1].textContent;assert.equal(mixed.length,64);assert.equal([...mixed].filter(c=>c===' ').length,32);assert.match(h.rows()[0].querySelector('.password-space-note').textContent,/Contains 32 spaces/);
    h.profile('strong-random');h.rankByte(0);h.generate();assert.equal(h.rows()[0].querySelector('.password-space-note'),undefined);
  });
});

test('startup waits for successful initialization, blocks partial submissions and reports generic load errors without enabling generation',async()=>{
  const controls=new Map(['settings-form','status','generate','batch-generate','settings-generate'].map(id=>[id,new Element()]));const page={getElementById:id=>controls.get(id)};
  let complete;const result=initializeApplication(()=>new Promise(resolve=>complete=resolve),page);
  const event=()=>({prevented:false,stopped:false,preventDefault(){this.prevented=true;},stopImmediatePropagation(){this.stopped=true;}});
  let e=event();controls.get('settings-form').listeners.get('submit')(e);assert.ok(e.prevented&&e.stopped);complete();assert.equal(await result,true);
  e=event();controls.get('settings-form').listeners.get('submit')(e);assert.equal(e.prevented,false);
  assert.equal(await initializeApplication(async()=>{throw Error('Private module URL / confidential diagnostic');},page),false);
  for(const id of ['generate','batch-generate','settings-generate'])assert.equal(controls.get(id).disabled,true);
  assert.match(controls.get('status').textContent,/could not load.*Reload/);assert.doesNotMatch(controls.get('status').textContent,/Private|confidential/);
  e=event();controls.get('settings-form').listeners.get('submit')(e);assert.ok(e.prevented&&e.stopped);
  let imported=false;
  const noStyles={...page,readyState:'complete',defaultView:{},querySelector(){return {sheet:{cssRules:[]}};}};
  assert.equal(await initializeApplication(async()=>{imported=true;},noStyles),false);assert.equal(imported,false);
});
