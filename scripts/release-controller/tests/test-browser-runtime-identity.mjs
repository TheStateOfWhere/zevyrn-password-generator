import assert from 'node:assert/strict';
import fs from 'node:fs';
import {authenticateBrowserTools,checkRuntimeFacts,expectedNode} from './browser-runtime-identity.mjs';
const tests=[];
function test(name,fn){try{fn();tests.push({name,passed:true});}catch(e){tests.push({name,passed:false,error:{name:e.name,code:e.code}});process.exitCode=1;}}
test('actual exact runtime and pinned tools authenticate',()=>assert.deepEqual(authenticateBrowserTools().facts,expectedNode));
test('approved exact runtime facts accepted',()=>checkRuntimeFacts({...expectedNode}));
for(const [name,key,value,code] of [
 ['old hash rejected','sha256','e921fe5307e29bf6fd00000dd594356affd3a7b044e52720c7f10decbdc305b9','NODE_HASH_MISMATCH'],
 ['arbitrary hash rejected','sha256','0'.repeat(64),'NODE_HASH_MISMATCH'],
 ['altered hash rejected','sha256',expectedNode.sha256.slice(0,63)+'0','NODE_HASH_MISMATCH'],
 ['other path rejected','path','C:\\other\\node.exe','NODE_PATH_MISMATCH'],
 ['relative path rejected','path','node.exe','NODE_PATH_MISMATCH'],
 ['old version rejected','version','26.7.0','NODE_VERSION_MISMATCH'],
 ['newer patch rejected','version','26.8.2','NODE_VERSION_MISMATCH'],
 ['version range rejected','version','>=26.8.1','NODE_VERSION_MISMATCH'],
 ['x86 rejected','architecture','ia32','NODE_ARCHITECTURE_MISMATCH'],
 ['arm64 rejected','architecture','arm64','NODE_ARCHITECTURE_MISMATCH']
])test(name,()=>assert.throws(()=>checkRuntimeFacts({...expectedNode,[key]:value}),e=>e.code===code));
test('missing runtime facts rejected',()=>assert.throws(()=>checkRuntimeFacts(null),e=>e.code==='NODE_PATH_MISMATCH'));
test('returned authority is immutable',()=>{
 const {authority}=authenticateBrowserTools();
 assert.throws(()=>{authority.node.sha256='0'.repeat(64);},TypeError);
 assert.throws(()=>{authority.node={...expectedNode};},TypeError);
});
test('identity evidence round trips without version coercion',()=>assert.deepEqual(JSON.parse(JSON.stringify(authenticateBrowserTools().facts)),expectedNode));
const report={scope:'NODE_BROWSER_TOOL_IDENTITY_ONLY',passed:tests.filter(t=>t.passed).length,failed:tests.filter(t=>!t.passed).length,skipped:0,tests,qualificationExecuted:false};
fs.writeFileSync(new URL('./identity-test-results.json',import.meta.url),JSON.stringify(report,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({passed:report.passed,failed:report.failed,skipped:0}));
