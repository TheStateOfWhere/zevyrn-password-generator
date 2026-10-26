// Source-checkout regression; run separately before dependency installation.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const source=fileURLToPath(new URL('../',import.meta.url));

test('both CI jobs verify checkout metadata without rewriting it; Docker invokes the full compiler check',async()=>{
  const workflow=await readFile(join(source,'.github/workflows/quality-security.yml'),'utf8');
  const command=/^          node --input-type=module -e "([^"]+)"/gm;
  const checks=[...workflow.matchAll(command)].map(match=>match[1]);
  assert.equal(checks.length,2,'Linux and Windows jobs must both check canonical metadata');
  assert.doesNotMatch(workflow,/LF-to-CRLF|Materialized source identity|writeFileSync/);
  const files=['scripts/compiler-integrity.json','package.json','package-lock.json'];
  const before=await Promise.all(files.map(file=>readFile(join(source,file))));
  for(const check of checks) {
    assert.equal(check,"import {compilerPolicy} from './scripts/verify-compiler.mjs'; await compilerPolicy();");
    const run=spawnSync(process.execPath,['--input-type=module','-e',check],{cwd:source,encoding:'utf8'});
    assert.equal(run.status,0,run.stderr);
  }
  for(const [i,file] of files.entries())assert.deepEqual(await readFile(join(source,file)),before[i]);
  const pkg=JSON.parse(await readFile(join(source,'package.json'),'utf8'));
  assert.match(pkg.scripts.build,/node scripts\/verify-compiler\.mjs && tsc6/);
  assert.match(await readFile(join(source,'Dockerfile'),'utf8'),/^RUN npm test$/m);
});
