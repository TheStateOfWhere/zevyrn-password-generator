import {test} from 'node:test';
import assert from 'node:assert/strict';
import {cp,mkdtemp,mkdir,readFile,writeFile,rm,rmdir,lstat,rename,symlink} from 'node:fs/promises';
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

test('project metadata uses exact LF checkout bytes and rejects CRLF, mixed endings and otherwise valid JSON changes',async()=>{
  const root=await mkdtemp(join(tmpdir(),'zevyrn-checkout-metadata-'));
  const files=['scripts/compiler-integrity.json','package.json','package-lock.json'];
  try {
    await mkdir(join(root,'scripts'));
    for(const path of [...files,'scripts/verify-compiler.mjs'])await cp(join(source,path),join(root,path));
    // Exercise the same metadata-only path as CI, without installed dependencies.
    const run=()=>spawnSync(process.execPath,['--input-type=module','-e',
      "import {compilerPolicy} from './scripts/verify-compiler.mjs'; await compilerPolicy();"],{cwd:root,encoding:'utf8'});
    assert.equal(run().status,0);
    for(const path of files) {
      const original=await readFile(join(root,path));
      assert.equal(original.includes(13),false,'Canonical checkout must contain LF bytes: '+path);
      const text=original.toString('utf8');
      for(const altered of [text.replaceAll('\n','\r\n'),text.replace('\n','\r\n'),text+'\n']) {
        await writeFile(join(root,path),altered);
        assert.notEqual(run().status,0,'Changed representation must fail: '+path);
      }
      // Still valid JSON, but a changed identity: comparison is not semantic-only.
      const changed=JSON.parse(text);changed.unapprovedMetadata=true;
      await writeFile(join(root,path),JSON.stringify(changed,null,2)+'\n');
      assert.notEqual(run().status,0,'Changed JSON must fail: '+path);
      await writeFile(join(root,path),original);
      assert.equal(run().status,0,'Restored exact LF bytes must pass');
      await rename(join(root,path),join(root,path)+'.missing');
      assert.notEqual(run().status,0,'Missing metadata must fail: '+path);
      await rename(join(root,path)+'.missing',join(root,path));
    }
  } finally { await rm(root,{recursive:true,force:true}); }
});

test('metadata symlinks cannot substitute exact approved bytes',async t=>{
  const root=await mkdtemp(join(tmpdir(),'zevyrn-metadata-link-'));
  const files=['scripts/compiler-integrity.json','package.json','package-lock.json'];
  try {
    await mkdir(join(root,'scripts'));
    for(const path of [...files,'scripts/verify-compiler.mjs'])await cp(join(source,path),join(root,path));
    for(const path of files) {
      const file=join(root,path),saved=file+'.saved';await rename(file,saved);
      try { await symlink(saved,file,'file'); }
      catch(error) {
        if(process.platform==='win32'&&error.code==='EPERM') {t.skip('Windows account cannot create file symlinks');return;}
        throw error;
      }
      const run=spawnSync(process.execPath,['--input-type=module','-e',
        "import {compilerPolicy} from './scripts/verify-compiler.mjs'; await compilerPolicy();"],{cwd:root,encoding:'utf8'});
      assert.notEqual(run.status,0,'Symlink must fail: '+path);
      assert.match(run.stderr,/Expected regular project metadata/);
      await rm(file);await rename(saved,file);
    }
  } finally {await rm(root,{recursive:true,force:true});}
});
