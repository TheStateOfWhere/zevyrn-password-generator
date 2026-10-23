import {test} from 'node:test';
import assert from 'node:assert/strict';
import {cp,mkdtemp,mkdir,readFile,writeFile,rm,rmdir,lstat,rename} from 'node:fs/promises';
import {join,resolve,sep} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {verifyCompiler,compilerPolicy} from '../scripts/verify-compiler.mjs';
const source=fileURLToPath(new URL('../',import.meta.url));
test('official JavaScript compiler has exact artifact bytes, alias and lock identities',async()=>{
  assert.deepEqual(await verifyCompiler(),{wrapper:'6.0.2',compiler:'6.0.3',nativeCompilerAbsent:true});
  const c=await compilerPolicy();assert.equal(c.artifacts.length,2);
  assert.deepEqual(c.artifacts.map(a=>[a.name,a.version]),[['@typescript/typescript6','6.0.2'],['typescript','6.0.3']]);
  assert.ok(c.artifacts.every(a=>a.integrity.startsWith('sha512-')&&Object.keys(a.files).length>0));
});
test('compiler integrity fails closed on artifact, manifest, alias, catalog and lock substitution',async()=>{
  const root=await mkdtemp(join(tmpdir(),'zevyrn-js-compiler-integrity-'));
  assert.ok(resolve(root).startsWith(resolve(tmpdir())+sep));
  try {
    for(const path of ['scripts','node_modules/@typescript'])await mkdir(join(root,path),{recursive:true});
    for(const path of ['package.json','package-lock.json','scripts/verify-compiler.mjs','scripts/compiler-integrity.json'])await cp(join(source,path),join(root,path));
    for(const name of ['old','typescript6'])await cp(join(source,'node_modules/@typescript',name),join(root,'node_modules/@typescript',name),{recursive:true});
    const run=()=>spawnSync(process.execPath,['scripts/verify-compiler.mjs'],{cwd:root,encoding:'utf8'});
    assert.equal(run().status,0);
    for(const path of ['scripts/compiler-integrity.json','package.json','package-lock.json','node_modules/@typescript/typescript6/package.json','node_modules/@typescript/typescript6/lib/tsc.js','node_modules/@typescript/old/package.json','node_modules/@typescript/old/lib/_tsc.js']) {
      const original=await readFile(join(root,path));await writeFile(join(root,path),Buffer.concat([original,Buffer.from('\n/* altered */')]));
      assert.notEqual(run().status,0,path);await writeFile(join(root,path),original);
    }
    const entry=join(root,'node_modules/@typescript/old/lib/tsc.js');await rename(entry,entry+'.missing');assert.notEqual(run().status,0);await rename(entry+'.missing',entry);
    const unknown=join(root,'node_modules/@typescript/old/unexpected.js');await writeFile(unknown,'unexpected');assert.notEqual(run().status,0);await rm(unknown);
    const nativeDirectory=join(root,'node_modules/@typescript/typescript-linux-x64');
    await mkdir(nativeDirectory);assert.notEqual(run().status,0);await rmdir(nativeDirectory);
    await assert.rejects(lstat(nativeDirectory),{code:'ENOENT'},'temporary native-package directory removed');
    assert.equal(run().status,0,'all negative controls restored, positive still passes');
  } finally {
    await rm(root,{recursive:true,force:true});
    await assert.rejects(lstat(root),{code:'ENOENT'},'entire scoped integrity fixture removed');
  }
});
