// Canonical Git LF project metadata; exact official compiler artifact bytes.
// No source rewriting, network, subprocess or compiler fallback.
import {readFile,readdir,lstat,realpath} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve,relative,sep} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const root=fileURLToPath(new URL('../',import.meta.url));
const catalogSHA256='491484c5789eebbefd8e51c52bb30b4c4ea0656b17929a66a3a8b51b0ac5c7d8';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
async function metadataBytes(path) {
  const file=resolve(root,path),stat=await lstat(file);
  assert(stat.isFile()&&!stat.isSymbolicLink(),'Expected regular project metadata: '+path);
  return readFile(file);
}
export async function compilerPolicy() {
  const bytes=await metadataBytes('scripts/compiler-integrity.json');
  assert.equal(hash(bytes),catalogSHA256,'Compiler catalog integrity');
  const catalog=JSON.parse(bytes),pkgBytes=await metadataBytes('package.json'),lockBytes=await metadataBytes('package-lock.json');
  assert.equal(hash(pkgBytes),catalog.packageSHA256,'Approved project compiler metadata');
  assert.equal(hash(lockBytes),catalog.lockSHA256,'Approved dependency lock');
  const pkg=JSON.parse(pkgBytes),lock=JSON.parse(lockBytes);
  assert.deepEqual(pkg.devDependencies,{'@typescript/typescript6':'6.0.2',playwright:'1.62.1'});
  assert.equal(lock.lockfileVersion,3);
  for(const name of Object.keys(lock.packages)) assert(!/^node_modules\/(?:typescript$|@typescript\/typescript-)/.test(name),'Unexpected native TypeScript lock entry');
  for(const artifact of catalog.artifacts) {
    const entry=lock.packages[artifact.installPath];assert(entry,'Missing locked compiler');
    assert.equal(entry.version,artifact.version);assert.equal(entry.integrity,artifact.integrity);assert.equal(entry.resolved,artifact.tarball);
  }
  assert.equal(lock.packages['node_modules/@typescript/typescript6'].dependencies['@typescript/old'],'npm:typescript@^6');
  assert.equal(lock.packages['node_modules/@typescript/old'].name,'typescript');
  return catalog;
}
export async function verifyCompiler() {
  const catalog=await compilerPolicy();
  const scope=resolve(root,'node_modules/@typescript');
  assert.deepEqual((await readdir(scope)).sort(),['old','typescript6'],'Unexpected TypeScript package');
  await assert.rejects(lstat(resolve(root,'node_modules/typescript')),e=>e.code==='ENOENT','Native TypeScript must be absent');
  for(const artifact of catalog.artifacts) {
    const directory=resolve(root,artifact.installPath);assert.equal(await realpath(directory),directory,'Compiler package redirect');
    const actual={};
    async function walk(dir) {
      for(const item of await readdir(dir,{withFileTypes:true})) {
        const path=resolve(dir,item.name),key=relative(directory,path).split(sep).join('/');
        assert(!item.isSymbolicLink(),'Compiler symlink rejected');
        if(item.isDirectory())await walk(path);
        else {assert(item.isFile(),'Compiler file type');actual[key]=hash(await readFile(path));}
      }
    }
    await walk(directory);assert.deepEqual(actual,artifact.files,'Compiler artifact contents');
    const manifest=JSON.parse(await readFile(resolve(directory,'package.json'),'utf8'));
    assert.equal(manifest.name,artifact.name);assert.equal(manifest.version,artifact.version);
    if(manifest.name==='@typescript/typescript6')assert.equal(manifest.dependencies['@typescript/old'],'npm:typescript@^6');
    else assert.equal(Object.keys(manifest.dependencies||{}).length,0);
  }
  return {wrapper:'6.0.2',compiler:'6.0.3',nativeCompilerAbsent:true};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  verifyCompiler().then(()=>console.log('Official JavaScript compiler integrity verified.')).catch(()=>{console.error('Compiler integrity verification failed.');process.exitCode=1;});
}
