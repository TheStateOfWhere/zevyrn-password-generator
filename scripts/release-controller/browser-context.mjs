// Consumer of an external controller-approved execution record, not an approval authority.
// The authenticated Python parent validates this exact record before spawning Node;
// settlement independently authenticates its record identity. Standalone output grants no authority.
import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';
import assert from 'node:assert/strict';import {fileURLToPath} from 'node:url';
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
export function authenticatedRecord(record){
 assert.ok(record&&path.isAbsolute(record.path)&&/^[a-f0-9]{64}$/.test(record.sha256),'EXTERNAL_RECORD');
 assert.equal(fs.realpathSync(record.path),record.path,'LINKED_RECORD');
 const b=fs.readFileSync(record.path);assert.equal(hash(b),record.sha256,'RECORD_IDENTITY');return b;
}
export function browserExecution(root,descriptor){
 assert.deepEqual(process.execArgv,[],'UNEXPECTED_NODE_EXECUTION_OPTIONS');
 assert.equal(process.argv[2],'--guarded-child','EXTERNAL_CONTROLLER_REQUIRED');
 const repository=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
 const relative=path.relative(repository,descriptor.path);
 assert.ok(relative.startsWith('..'+path.sep)||path.isAbsolute(relative),'REPOSITORY_CANNOT_APPROVE');
 const context=JSON.parse(authenticatedRecord(descriptor).toString('utf8').replace(/^\uFEFF/,''));
 assert.equal(context.scope,'canonical-browser-execution-v1');
 assert.equal(context.executionRoot,root);assert.equal(context.executionID,path.basename(root));
 assert.equal(Number(process.argv[6]),process.ppid,'GUARDED_PARENT');
 assert.ok(context.records&&context.authority&&context.playwright,'BROWSER_DEPENDENCIES');
 assert.ok(path.isAbsolute(context.playwright.root),'LIBRARY_ROOT');
 assert.equal(context.playwright.module,path.join(context.playwright.root,'playwright'),'LIBRARY_MODULE');
 const libraryFiles=[];
 function walk(dir){assert.equal(fs.realpathSync(dir),dir,'LINKED_LIBRARY');for(const item of fs.readdirSync(dir,{withFileTypes:true})){
  const file=path.join(dir,item.name);assert.equal(fs.realpathSync(file),file,'LINKED_LIBRARY');
  if(item.isDirectory())walk(file);else {assert.ok(item.isFile(),'NONREGULAR_LIBRARY');libraryFiles.push(path.relative(context.playwright.root,file).split(path.sep).join('/'));}
 }}
 for(const name of ['playwright','playwright-core'])walk(path.join(context.playwright.root,name));
 assert.deepEqual(libraryFiles.sort(),Object.keys(context.playwright.files).sort(),'LIBRARY_CLOSURE');
 for(const name of ['playwright/package.json','playwright/index.js','playwright-core/package.json','playwright-core/index.js'])assert.ok(context.playwright.files[name],'MISSING_LIBRARY_ENTRY');
 for(const record of Object.values(context.records))authenticatedRecord(record);
 for(const [name,digest]of Object.entries(context.playwright.files)){
  assert.ok(name&&!name.includes('\\')&&!name.includes(':')&&name.split('/').every(p=>p&&p!=='.'&&p!=='..'),'LIBRARY_PATH');
  authenticatedRecord({path:path.join(context.playwright.root,name),sha256:digest});
 }
 return context;
}
