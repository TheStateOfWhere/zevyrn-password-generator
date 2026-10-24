// Isolated proposal only. Authenticate actual runtime before browser-tool imports.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';

export const expectedNode=Object.freeze({
 path:'C:\\Program Files\\nodejs\\node.exe',version:'26.8.1',architecture:'x64',
 sha256:'5cba0ea928508c65ddadefc0681d2fb6d95f1f3beea4428f04397631140ee8e5'
});
const authoritySHA256='e3383a148686bbfb42c7b16fb84cfa44efe876424a563463d66a397a21d5e968';
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
function gate(ok,code){if(!ok)throw Object.assign(new Error(code),{code});}

// Pure comparison for defensive unit controls; actual authentication below never
// accepts caller-supplied runtime observations or alternate authority paths.
export function checkRuntimeFacts(facts,expected=expectedNode){
 gate(facts?.path===expected.path,'NODE_PATH_MISMATCH');
 gate(facts?.version===expected.version,'NODE_VERSION_MISMATCH');
 gate(facts?.architecture===expected.architecture,'NODE_ARCHITECTURE_MISMATCH');
 gate(facts?.sha256===expected.sha256,'NODE_HASH_MISMATCH');
}

export function authenticateBrowserTools(descriptor){
 const facts={path:process.execPath,version:process.versions.node,architecture:process.arch,
  sha256:hash(fs.readFileSync(process.execPath))};
 const authorityPath=descriptor?.path||fileURLToPath(new URL('./clipboard-authority.PROPOSED.json',import.meta.url));
 gate(!fs.lstatSync(authorityPath).isSymbolicLink(),'LINKED_AUTHORITY');
 const bytes=fs.readFileSync(authorityPath);
 const selectedHash=descriptor?.sha256||authoritySHA256;
 gate(hash(bytes)===selectedHash,'AUTHORITY_HASH_MISMATCH');
 const authority=JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/,''));
 checkRuntimeFacts(facts,descriptor?authority.node:expectedNode);
 checkRuntimeFacts(authority.node,descriptor?authority.node:expectedNode);
 for(const key of ['node','browser','powershell','nativeHelper']){
  const item=authority[key];
  gate(!fs.lstatSync(item.path).isSymbolicLink()&&hash(fs.readFileSync(item.path))===item.sha256,
   'TOOL_IDENTITY_MISMATCH');
 }
 for(const value of Object.values(authority))if(value&&typeof value==='object')Object.freeze(value);
 return Object.freeze({authority:Object.freeze(authority),authorityPath,authoritySHA256:selectedHash,facts:Object.freeze(facts)});
}
