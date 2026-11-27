import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { screenshotDirectory } from './browser-artifacts.mjs';
const read = name => readFile(new URL('../'+name, import.meta.url), 'utf8');

test('Dependabot checks exactly three root ecosystems weekly and excludes only historical workflow paths', {skip:!existsSync('.github/workflows/quality-security.yml')&&'Dependabot contracts run on the source checkout'},async()=>{
  const {yaml}=createRequire(import.meta.url)('playwright-core/lib/utilsBundle');
  const config=yaml.parse(await read('.github/dependabot.yml'));
  assert.deepEqual(Object.keys(config).sort(),['updates','version']);assert.equal(config.version,2);
  assert(Array.isArray(config.updates));assert.equal(config.updates.length,3);
  assert.deepEqual(config.updates.map(update=>update['package-ecosystem']).sort(),['docker','github-actions','npm']);
  for(const update of config.updates){
    const keys=['directory','package-ecosystem','schedule'];if(update['package-ecosystem']==='github-actions')keys.push('exclude-paths');
    // No groups, dependency-name ignores, credentials, custom update hooks or alternate targets.
    assert.deepEqual(Object.keys(update).sort(),keys.sort());
    assert.equal(update.directory,'/');assert.deepEqual(update.schedule,{interval:'weekly'});
  }
  const actions=config.updates.find(update=>update['package-ecosystem']==='github-actions');
  const historical=['.github/workflows/ghcr-readonly-diagnostic.yml','.github/workflows/publish-qualified-image.yml'];
  assert.deepEqual([...actions['exclude-paths']].sort(),historical);
  // These are literal paths relative to directory '/', not action-name ignores or globs.
  const excluded=new Set(actions['exclude-paths']);
  const workflows=(await readdir(new URL('../.github/workflows/',import.meta.url))).filter(file=>/\.ya?ml$/.test(file)).map(file=>'.github/workflows/'+file);
  assert.deepEqual(workflows.filter(path=>excluded.has(path)).sort(),historical);
  assert.deepEqual(workflows.filter(path=>!excluded.has(path)).sort(),['.github/workflows/quality-security.yml','.github/workflows/release.yml']);
  const uses=async path=>{
    const workflow=yaml.parse(await read(path));
    return Object.values(workflow.jobs).flatMap(job=>job.steps.flatMap(step=>step.uses?[step.uses]:[]));
  };
  const maintained=(await Promise.all(workflows.filter(path=>!excluded.has(path)).map(uses))).flat();
  assert(maintained.length>0);assert(maintained.every(action=>/^[^@]+@[0-9a-f]{40}$/.test(action)));
  const historicalUses=(await Promise.all(historical.map(uses))).flat();
  assert(maintained.some(action=>historicalUses.includes(action)),'Shared actions remain eligible in maintained files');
});

test('quality retains exact image/browser coverage with read-only fork-safe artifact transport', {skip:!existsSync('.github/workflows/quality-security.yml')&&'Workflow contracts run on the source checkout'},async()=>{
  const require=createRequire(import.meta.url),{yaml}=require('playwright-core/lib/utilsBundle');
  const workflow=yaml.parse(await read('.github/workflows/quality-security.yml'));
  assert.deepEqual(workflow.permissions,{contents:'read'});
  assert(!workflow.on.pull_request_target&&!workflow.on.workflow_run);
  assert(Object.hasOwn(workflow.on,'pull_request'));assert(Object.hasOwn(workflow.on,'push'));
  assert.equal(workflow.env.QUALITY_SOURCE,'${{ github.event.pull_request.head.sha || github.sha }}');
  assert.deepEqual(Object.keys(workflow.jobs).sort(),['browser','quality-image']);
  const image=workflow.jobs['quality-image'],browser=workflow.jobs.browser;
  assert.equal(browser.needs,'quality-image');assert.deepEqual(browser.permissions,{contents:'read',actions:'read'});
  for(const job of [image,browser]) {
    assert(!job.environment&&!job.secrets);
    const checkout=job.steps.find(step=>step.uses?.startsWith('actions/checkout@'));
    assert.equal(checkout.with.ref,'${{ env.QUALITY_SOURCE }}');assert.equal(checkout.with['persist-credentials'],false);
    for(const step of job.steps)assert(!step['continue-on-error']);
    assert(!JSON.stringify(job).includes('secrets.'));
  }
  const script=image.steps.map(step=>step.run??'').join('\n');
  for(const text of ['type=oci,dest=artifacts/security/archive.oci.tar','--provenance=mode=min','release-integrity.mjs loaded','release-integrity.mjs assets','prepare-scan','scan-runtime','sbom-runtime','quality-record','ci-security.mjs trivy','--target build --load','--driver docker-container'])assert(script.includes(text),text);
  for(const text of ['npm test','tsc6 --noEmit','ZEVYRN_COMPOSE_BIN','compilerPolicy','npm audit','container-hardening','graceful-stop'])assert(script.includes(text),text);
  const packet=image.steps.find(step=>step.id==='packet');assert.equal(packet.with.name,'quality-runtime-${{ github.run_id }}-${{ github.run_attempt }}');
  assert.equal(image.outputs.artifact_digest,'sha256:${{ steps.packet.outputs.artifact-digest }}');
  const diagnostics=image.steps.find(step=>step.with?.name==='security-evidence');assert.equal(diagnostics.if,'always()');
  assert(!/archive\.oci|identity\.json|assets\//.test(diagnostics.with.path));
  const transport=browser.steps.find(step=>step.name==='Authenticate exact same-run artifact before extraction').run;
  assert(transport.indexOf('quality-artifact')<transport.indexOf('quality-zip'));
  assert.match(transport,/quality-zip \$zip \$env:ARTIFACT_DIGEST packet\n\s*if \(\$LASTEXITCODE -ne 0\)/);
  assert(!transport.includes('Expand-Archive'));
  assert(transport.indexOf('quality-verify')>transport.indexOf('quality-zip'));
  const browserScript=browser.steps.map(step=>step.run??'').join('\n');
  assert(!browserScript.includes('npm run build'));
  assert(browserScript.includes('packet/assets'));assert(browserScript.includes('release-integrity.mjs browser packet'));assert(browserScript.includes('quality-browser-result'));
});

test('retired maintenance entry points are absent and active manual recovery contracts remain available', {skip:!existsSync('.github/workflows/quality-security.yml')&&'Workflow contracts run on the source checkout'},async()=>{
  const {yaml}=createRequire(import.meta.url)('playwright-core/lib/utilsBundle');
  const retired=['qualify-maintenance-image.yml','publish-maintenance-image.yml'];
  for(const file of retired)assert(!existsSync('.github/workflows/'+file),file+' must remain retired');
  const files=(await readdir(new URL('../.github/workflows/',import.meta.url))).filter(f=>/\.ya?ml$/.test(f)).sort();
  assert.deepEqual(files,['ghcr-readonly-diagnostic.yml','publish-qualified-image.yml','quality-security.yml','release.yml']);
  for(const file of files){const text=await read('.github/workflows/'+file);for(const target of retired)assert(!text.includes(target),'Active workflow references '+target);}
  const guide=await read('docs/RELEASING.md'),security=await read('SECURITY.md');
  const [active,restoration]=guide.split('### Superseded maintenance workflow retirement');
  assert(restoration,'Git restoration guidance must remain available');
  for(const target of retired){assert(!active.includes(target));assert(!security.includes(target));assert(restoration.includes(target));}
  const quality=yaml.parse(await read('.github/workflows/quality-security.yml'));
  assert(Object.hasOwn(quality.on,'workflow_dispatch'));assert.deepEqual(quality.on.push,{branches:['main']});
  assert(Object.hasOwn(quality.on,'pull_request'));
  const release=yaml.parse(await read('.github/workflows/release.yml'));
  assert.deepEqual(release.on.workflow_dispatch.inputs.quality_run_id,{description:'Exact successful main quality run; no automatic substitution',required:true,type:'string'});
  const resolve=release.jobs.resolve.steps.find(s=>s.id==='select');
  assert.equal(resolve.env.QUALITY_RUN_ID,'${{ inputs.quality_run_id }}');
  assert.equal(resolve.run,'node scripts/release-integrity.mjs combined-resolve selection.json');
  const seal=release.jobs.qualify.steps.find(s=>s.id==='seal');assert.equal(seal.run,'node scripts/release-integrity.mjs combined-seal qualified');
  const packet=release.jobs.qualify.steps.find(s=>s.id==='packet');
  assert.equal(packet.with.path,'qualified/');assert.equal(packet.with['if-no-files-found'],'error');
  assert.equal(packet.with.name,'release-qualified-${{ github.run_id }}-${{ github.run_attempt }}');
});

test('combined release isolates manual verification and enables only exact v1.2.4 publication', {skip:!existsSync('.github/workflows/release.yml')&&'Workflow contracts run on the source checkout'},async()=>{
  const {yaml}=createRequire(import.meta.url)('playwright-core/lib/utilsBundle');
  const w=yaml.parse(await read('.github/workflows/release.yml'));
  assert.deepEqual(Object.keys(w.on).sort(),['push','workflow_dispatch']);assert.deepEqual(w.on.push,{tags:['v*']});
  assert.deepEqual(Object.keys(w.on.workflow_dispatch.inputs),['operation','quality_run_id']);
  assert.deepEqual(w.on.workflow_dispatch.inputs.operation.options,['verify','release']);assert.equal(w.on.workflow_dispatch.inputs.operation.default,'verify');
  assert.deepEqual(w.permissions,{});assert.equal(w.env.LIVE_PUBLICATION_ENABLED,'true');
  assert.equal(w.concurrency.group,'zevyrn-ghcr-${{ github.ref_name }}-publication');assert.equal(w.concurrency['cancel-in-progress'],false);
  assert.deepEqual(Object.keys(w.jobs),['resolve','qualify','publish','consumer']);
  const {resolve:resolveJob,qualify,publish,consumer}=w.jobs;
  for(const job of [resolveJob,qualify]){assert.deepEqual(job.permissions,{contents:'read',actions:'read'});assert(!job.environment&&!job.secrets);}
  assert.deepEqual(publish.needs,['resolve','qualify']);assert.deepEqual(publish.permissions,{contents:'read',actions:'read',packages:'write'});
  assert.equal(publish.environment,'zevyrn-ghcr-publication');
  assert.equal(publish.if,"${{ startsWith(github.ref, 'refs/tags/v') && github.ref == 'refs/tags/v1.2.4' && needs.resolve.outputs.publish == 'true' && (github.event_name == 'push' || (github.event_name == 'workflow_dispatch' && inputs.operation == 'release')) }}");
  assert.deepEqual(consumer.permissions,{});assert.deepEqual(consumer.needs,['qualify','publish']);assert(!consumer.environment);
  const all=JSON.stringify(w);assert(!all.includes('secrets.')&&!all.includes('vars.')&&!all.includes('pull_request_target'));
  for(const job of Object.values(w.jobs))for(const step of job.steps){assert(!step['continue-on-error']);if(step.uses?.startsWith('actions/checkout@')){assert.equal(step.with['persist-credentials'],false);assert.equal(step.with['fetch-depth'],0);}}
  const script=qualify.steps.map(s=>s.run??'').join('\n');
  for(const required of ['combined-resolve','cmp selection/selection.json','combined-fetch','prepare-scan','scan-runtime','scan-builder','ci-security.mjs trivy','combined-seal','--download-db-only'])assert(script.includes(required),required);
  assert(!/docker (?:build|buildx build)|npm (?:test|run build)|release-integrity\.mjs browser/.test(script));
  const gate=qualify.steps.find(s=>s.id==='security');assert(gate.run.includes('steps.runtime_scan.outcome')&&gate.run.includes('steps.builder_scan.outcome'));
  const diagnostics=qualify.steps.find(s=>s.with?.name?.startsWith('release-security-'));assert.equal(diagnostics.if,'always()');
  assert(!/raw\.json|\.tar|assets\//.test(diagnostics.with.path));
  const promotion=publish.steps.map(s=>s.run??'').join('\n');
  assert(promotion.includes('combined-download'));assert(promotion.indexOf('combined-revalidate')<promotion.indexOf('skopeo login'));
  assert(promotion.includes('--all --preserve-digests'));assert(promotion.indexOf('release-integrity.mjs tags')<promotion.indexOf('skopeo copy'));
  assert(!/docker build|npm test|release-integrity\.mjs browser/.test(promotion));
  const anonymous=consumer.steps.map(s=>s.run??'').join('\n');
  assert(anonymous.includes('mktemp -d')&&anonymous.includes("printf '{}\\n'"));assert(anonymous.includes('unset DOCKER_AUTH_CONFIG REGISTRY_AUTH_FILE GH_TOKEN GITHUB_TOKEN'));
  assert.equal((anonymous.match(/docker pull --platform linux\/amd64/g)||[]).length,4); // two recorded commands plus two actual pulls
  assert(!/login|secrets\.|github\.token|download-artifact|checkout@/.test(JSON.stringify(consumer)));
  assert(anonymous.includes('tagExitCode')&&anonymous.includes('digestExitCode')&&anonymous.includes('docker version'));
});

// Local evaluation of the current condition's Boolean/string subset, using
// canonical strings, plus GitHub's implicit success() dependency requirement.
// This is not a hosted Actions expression engine or a hosted execution test.
function locallyEligible(job,context){
  const dependencies=Array.isArray(job.needs)?job.needs:job.needs?[job.needs]:[];
  if(!dependencies.every(name=>context.needs[name]?.result==='success'))return false;
  if(job.if===undefined)return true;
  const expression=job.if.match(/^\$\{\{\s*([\s\S]*?)\s*\}\}$/)?.[1];assert(expression);
  const evaluate=new Function('github','needs','inputs','vars','env','startsWith','return Boolean('+expression+');');
  return evaluate(context.github,context.needs,context.inputs,context.vars,context.env,(value,prefix)=>value.startsWith(prefix));
}
const publicationContext=(event,ref,operation)=>({
  github:{event_name:event,ref},inputs:{operation},vars:{},env:{LIVE_PUBLICATION_ENABLED:'true'},
  needs:{resolve:{result:'success',outputs:{publish:'true'}},qualify:{result:'success'}}
});

test('activated publication condition rejects inconsistent resolver outputs outside exact release entry points', {skip:!existsSync('.github/workflows/release.yml')&&'Workflow contracts run on the source checkout'},async t=>{
  const {yaml}=createRequire(import.meta.url)('playwright-core/lib/utilsBundle'),w=yaml.parse(await read('.github/workflows/release.yml')),job=w.jobs.publish;
  assert.doesNotMatch(job.if,/^\$\{\{\s*false\s*&&/);assert.equal(w.env.LIVE_PUBLICATION_ENABLED,'true');
  const cases=[
    ['version-tag push',publicationContext('push','refs/tags/v1.2.4'),true],
    ['manual release',publicationContext('workflow_dispatch','refs/tags/v1.2.4','release'),true],
    ['manual verification',publicationContext('workflow_dispatch','refs/heads/main','verify'),false],
    ['main push',publicationContext('push','refs/heads/main'),false],
    ['pull request',publicationContext('pull_request','refs/pull/4/merge'),false],
    ['verification from tag',publicationContext('workflow_dispatch','refs/tags/v1.2.4','verify'),false],
    ['release from main',publicationContext('workflow_dispatch','refs/heads/main','release'),false],
    ['previous tag',publicationContext('push','refs/tags/v1.2.3'),false],
    ['future tag',publicationContext('push','refs/tags/v1.2.5'),false],
    ['lookalike tag',publicationContext('push','refs/tags/v1.2.4-rc1'),false],
    ['PR with tag ref',publicationContext('pull_request','refs/tags/v1.2.4','release'),false],
    ['schedule with tag ref',publicationContext('schedule','refs/tags/v1.2.4','release'),false],
    ['missing manual operation',publicationContext('workflow_dispatch','refs/tags/v1.2.4'),false]
  ];
  // Evaluate the actual parsed job expression, with GitHub's implicit successful
  // needs requirement. A forged resolver output cannot change event/ref/mode.
  for(const [name,context,eligible] of cases){
    assert.equal(locallyEligible(job,context),eligible,name+' actual condition');
    t.diagnostic(name+': eligible='+eligible+' (local evaluation)');
    for(const override of [
      c=>c.vars.LIVE_PUBLICATION_ENABLED='true',
      c=>c.env.LIVE_PUBLICATION_ENABLED='true',
      c=>Object.assign(c.inputs,{LIVE_PUBLICATION_ENABLED:'true',publish:true}),
      c=>c.needs.resolve.outputs.publish='true',
      c=>{c.vars.LIVE_PUBLICATION_ENABLED='true';c.env.LIVE_PUBLICATION_ENABLED='true';Object.assign(c.inputs,{LIVE_PUBLICATION_ENABLED:'true',publish:true});c.needs.resolve.outputs.publish='true';}
    ]){const changed=structuredClone(context);override(changed);assert.equal(locallyEligible(job,changed),eligible,name+' runtime override');}
    for(const dependency of ['resolve','qualify'])for(const outcome of ['failure','cancelled','skipped','in_progress',undefined]){const changed=structuredClone(context);changed.needs[dependency].result=outcome;assert.equal(locallyEligible(job,changed),false,name+' incomplete '+dependency);}
  }
  for(const output of ['',false,true,'false','TRUE',"true' || true"]){const c=publicationContext('push','refs/tags/v1.2.4');c.needs.resolve.outputs.publish=output;assert.equal(locallyEligible(job,c),false);}
  const noOutput=publicationContext('push','refs/tags/v1.2.4');delete noOutput.needs.resolve.outputs.publish;assert.equal(locallyEligible(job,noOutput),false);
  const noDependency=publicationContext('push','refs/tags/v1.2.4');delete noDependency.needs.qualify;assert.equal(locallyEligible(job,noDependency),false);
});

test('consumer success dependencies remain enforced and manual read-only qualification remains available', {skip:!existsSync('.github/workflows/release.yml')&&'Workflow contracts run on the source checkout'},async()=>{
  const {yaml}=createRequire(import.meta.url)('playwright-core/lib/utilsBundle'),w=yaml.parse(await read('.github/workflows/release.yml'));
  assert.deepEqual(w.jobs.consumer.needs,['qualify','publish']);assert.equal(w.jobs.consumer.if,undefined);
  const context=publicationContext('workflow_dispatch','refs/heads/main','verify');context.needs.publish={result:'success'};
  assert.equal(locallyEligible(w.jobs.consumer,context),true);
  for(const name of ['qualify','publish'])for(const outcome of ['failure','cancelled','skipped']){const c=structuredClone(context);c.needs[name].result=outcome;assert.equal(locallyEligible(w.jobs.consumer,c),false,name+' '+outcome);}
  assert.equal(w.jobs.qualify.needs,'resolve');assert.equal(w.jobs.qualify.if,undefined);
  assert.equal(locallyEligible(w.jobs.resolve,context),true);assert.equal(locallyEligible(w.jobs.qualify,context),true);
  assert.equal(locallyEligible(w.jobs.publish,context),false);
  for(const name of ['resolve','qualify']){assert.deepEqual(w.jobs[name].permissions,{contents:'read',actions:'read'});assert(!w.jobs[name].environment);}
});

test('main-only builder retention is separate, scan-bound, success-only and absent from PR/Windows transfers', {skip:!existsSync('.github/workflows/quality-security.yml')&&'Workflow contracts run on the source checkout'},async()=>{
  const {yaml}=createRequire(import.meta.url)('playwright-core/lib/utilsBundle'),w=yaml.parse(await read('.github/workflows/quality-security.yml'));
  const steps=w.jobs['quality-image'].steps,retain=steps.find(s=>s.name==='Retain exact main builder OCI without rebuilding'),upload=steps.find(s=>s.id==='retained_builder'),reference=steps.find(s=>s.name==='Bind main builder artifact to quality evidence');
  const mainOnly="${{ github.ref == 'refs/heads/main' && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') }}";
  assert.equal(retain.if,mainOnly);assert.equal(upload.if,mainOnly);assert.equal(reference.if,"${{ steps.retained_builder.outcome == 'success' }}");
  assert(retain.run.includes('retain-builder')&&retain.run.includes('$RUNNER_TEMP/builder.tar'));assert(!/buildx|docker build|skopeo copy/.test(retain.run));
  const build=steps.find(s=>s.id==='images').run;
  assert(build.includes('--target build --provenance=false --output "type=oci,dest=$RUNNER_TEMP/retained-builder/builder.oci.tar"'));
  assert(build.includes('"oci-archive:$RUNNER_TEMP/retained-builder/builder.oci.tar" docker-daemon:zevyrn-ci-builder:latest'));
  for(const [before,after] of [['inspect-builder','skopeo copy'],['skopeo copy','builder-loaded'],['builder-loaded','docker save -o "$RUNNER_TEMP/builder.tar"']])assert(build.indexOf(before)<build.indexOf(after));
  const diagnostics=steps.find(s=>s.with?.name==='security-evidence');assert(diagnostics.with.path.includes('artifacts/security/builder-inspection.json'));
  assert.equal(upload.with.name,'quality-builder-${{ github.run_id }}-${{ github.run_attempt }}');assert.equal(upload.with.path,'${{ runner.temp }}/retained-builder/');assert.equal(upload.with['retention-days'],7);
  assert(steps.indexOf(upload)>steps.findIndex(s=>s.id==='hardening'));assert(steps.indexOf(upload)>steps.findIndex(s=>s.id==='security'));assert(steps.indexOf(upload)>steps.findIndex(s=>s.id==='quality_record'));
  assert(reference.run.includes('builder-reference.json'));assert(reference.run.includes('quality-record'));assert(steps.indexOf(reference)<steps.findIndex(s=>s.id==='packet'));
  assert(!JSON.stringify(w.jobs.browser).includes('quality-builder-'));assert.equal(steps.find(s=>s.id==='packet').with.path,'artifacts/security/');
});

test('builder export shell selects one build per role and preserves the PR path (recording stubs, no Engine)', {skip:!existsSync('.github/workflows/quality-security.yml')&&'Workflow contracts run on the source checkout'},async()=>{
  const {yaml}=createRequire(import.meta.url)('playwright-core/lib/utilsBundle'),w=yaml.parse(await read('.github/workflows/quality-security.yml')),script=w.jobs['quality-image'].steps.find(s=>s.id==='images').run;
  const conditional=script.match(/if \[\[ "\$GITHUB_REF"[\s\S]*?\nfi\n/)?.[0];assert(conditional);
  const runtime=script.split('\n').find(line=>line.startsWith('docker buildx build --platform linux/amd64 --provenance=mode=min'));assert(runtime);
  const directory=await mkdtemp(join(tmpdir(),'zevyrn-builder-control-')),calls=join(directory,'calls.txt');
  const shell=process.platform==='win32'?'C:/Program Files/Git/bin/bash.exe':'/bin/bash';
  const functions='record() { printf "%s" "$1" >> "$CALLS_FILE"; shift; printf " <%s>" "$@" >> "$CALLS_FILE"; printf "\\n" >> "$CALLS_FILE"; }\ndocker() { record docker "$@"; }\nskopeo() { record skopeo "$@"; }\nnode() { record node "$@"; }\nmkdir() { record mkdir "$@"; }\n';
  try{
    for(const [ref,event,canonical] of [['refs/heads/main','push',true],['refs/heads/main','workflow_dispatch',true],['refs/pull/5/merge','pull_request',false],['refs/heads/main','schedule',false],['refs/heads/feature','workflow_dispatch',false]]){
      await writeFile(calls,'');
      const r=spawnSync(shell,['-e','-u','-o','pipefail','-c',functions+conditional+runtime],{encoding:'utf8',env:{...process.env,GITHUB_REF:ref,GITHUB_EVENT_NAME:event,RUNNER_TEMP:directory.replaceAll('\\','/'),CALLS_FILE:calls.replaceAll('\\','/'),QUALITY_SOURCE:'a'.repeat(40)}});assert.equal(r.status,0,r.stderr);
      const recorded=await readFile(calls,'utf8'),builds=recorded.split('\n').filter(line=>line.startsWith('docker <buildx> <build>'));assert.equal(builds.length,2,ref+' '+event);
      assert.equal(builds[0].includes('<--output>'),canonical);assert.equal(builds[0].includes('<--load>'),!canonical);
      assert.equal(recorded.includes('<inspect-builder>'),canonical);assert.equal(recorded.includes('<builder-loaded>'),canonical);
      assert(!recorded.includes('docker-daemon:zevyrn-ci-builder:latest> <oci-archive:'));
    }
  }finally{await rm(directory,{recursive:true,force:true});}
});

test('standalone is loopback-only; HTTPS alternatives do not publish the backend', async () => {
  const local = await read('compose.yaml');
  assert.match(local, /127\.0\.0\.1:\$\{KEYSMITH_PORT:-18080\}:8080/);
  for (const name of ['compose.yaml','compose.traefik.yaml','compose.caddy.yaml']) {
    const config = await read(name);
    const app = config.split(/\n  (?:traefik|caddy):/)[0];
    assert.match(app, /build:\n\s+context: \./);
    for (const value of ['platform: linux/amd64','pull_policy: never','user: "10001:10001"','read_only: true','cap_drop: [ALL]','no-new-privileges:true','pids_limit: 128','mem_limit: 128m','/tmp:rw,noexec,nosuid,size=16m,mode=1777','http://127.0.0.1:8080/healthz']) assert.ok(app.includes(value), name+': '+value);
    assert.doesNotMatch(config, /container_name:|privileged:\s*true|docker\.sock|network_mode:\s*host/);
    if (name !== 'compose.yaml') {
      assert.doesNotMatch(app, /^\s+ports:/m);
      assert.match(config, /:443:8443\/tcp/);
      assert.match(config, /user: "65532:65532"/);
      assert.match(config, /driver: bridge/);
      assert.doesNotMatch(config, /internal:\s*true/);
      assert.match(config, /create_host_path: false/);
    }
  }
});

test('Docker build retains regression inputs and bundles application and data licenses', async () => {
  const [build,runtime] = (await read('Dockerfile')).split(/\nFROM nginx:/);
  assert.match(build,/RUN npm ci --no-audit --no-fund/);
  assert.match(build,/RUN npm test/);
  assert.match(build,/COPY compose\.yaml compose\.traefik\.yaml compose\.caddy\.yaml \.gitignore \.dockerignore Dockerfile LICENSE \.\//);
  assert.match(build,/COPY examples \.\/examples/);
  assert.doesNotMatch(runtime,/COPY (?:compose|tests|scripts|examples)/);
  assert.match(runtime,/USER 10001:10001/);
  assert.equal(await read('dist/licenses/LICENSE.txt'),await read('LICENSE'));
  assert.equal(await read('dist/licenses/ESDB-Copyright.txt'),await read('data/ESDB-Copyright.txt'));
  assert.equal(await read('dist/licenses/CC-BY-4.0.txt'),await read('data/CC-BY-4.0.txt'));
});

test('builder pins supported npm maintenance before lockfile installation without runtime changes', async () => {
  const dockerfile = await read('Dockerfile');
  const [builder, runtime] = dockerfile.split(/\nFROM nginx:/);
  const install = 'npm install --global /tmp/zevyrn-npm-tool/npm-11.21.1.tgz --ignore-scripts --no-audit --no-fund';
  assert.ok(builder.includes(install));
  assert.match(builder, /test "\$\(npm --version\)" = "11\.21\.1"/);
  assert.ok(builder.indexOf(install) < builder.indexOf('COPY package.json package-lock.json ./'));
  assert.match(builder, /RUN npm ci --no-audit --no-fund/);
  assert.doesNotMatch(builder, /npm (?:update|audit fix)|--force|--legacy-peer-deps/);
  assert.doesNotMatch(runtime, /npm install|npm@11\.21\.1/);
  assert.equal(JSON.parse(await read('package.json')).devDependencies['@typescript/typescript6'], '6.0.2');
  assert.equal(JSON.parse(await read('package.json')).devDependencies.typescript, undefined);
  const lock = JSON.parse(await read('package-lock.json'));
  assert.equal(lock.packages['node_modules/@typescript/typescript6'].version, '6.0.2');
  assert.equal(lock.packages['node_modules/@typescript/old'].name, 'typescript');
  assert.equal(lock.packages['node_modules/@typescript/old'].version, '6.0.3');
  assert.equal(lock.packages['node_modules/@typescript/typescript6'].dependencies['@typescript/old'], 'npm:typescript@^6');
  assert.equal(lock.packages['node_modules/typescript'], undefined);
  assert.ok(!Object.keys(lock.packages).some(p=>p.startsWith('node_modules/@typescript/typescript-')));
});

test('builder verifies frozen artifact bytes and identity before npm installation', async () => {
  const builder = (await read('Dockerfile')).split(/\nFROM nginx:/)[0];
  const code = builder.match(/&& node -e '([^']+)'/)[1];
  const expected = 'sha512-YTzL6QBEJXyHcTu0JiUc7RKMp+mzlJtl7rGLmERaXUQeFHIMc9atdr6G9M9C8vDWbv40epoTQAzNL2/PtZVDhQ==';
  assert.ok(code.includes(expected));
  assert.ok(builder.indexOf('&& node -e') < builder.indexOf('&& npm install --global'));
  assert.match(builder, /npm pack npm@11\.21\.1 --registry=https:\/\/registry\.npmjs\.org --ignore-scripts --json --pack-destination/);
  const directory = await mkdtemp(join(tmpdir(),'zevyrn-npm-integrity-'));
  try {
    const root = directory.replaceAll('\\','/')+'/';
    const isolated = code.replace('root="/tmp/zevyrn-npm-tool/"','root='+JSON.stringify(root));
    const artifact = Buffer.from('synthetic npm artifact, not a distributable package');
    const digest = 'sha512-'+createHash('sha512').update(artifact).digest('base64');
    const metadata = {name:'npm',version:'11.21.1',filename:'npm-11.21.1.tgz',integrity:expected};
    await writeFile(join(directory,metadata.filename),artifact);
    await writeFile(join(directory,'pack.json'),JSON.stringify([metadata]));
    // Only this isolated control replaces the frozen digest to test the hash algorithm.
    const synthetic = isolated.replaceAll(expected,digest);
    await writeFile(join(directory,'pack.json'),JSON.stringify([{...metadata,integrity:digest}]));
    assert.equal(spawnSync(process.execPath,['-e',synthetic]).status,0);
    await writeFile(join(directory,metadata.filename),Buffer.concat([artifact,Buffer.from('tampered')]));
    assert.notEqual(spawnSync(process.execPath,['-e',synthetic]).status,0);
    await writeFile(join(directory,metadata.filename),artifact);
    for (const change of [{integrity:undefined},{integrity:'sha512-invalid'},{name:'substitute'},{version:'11.21.2'},{filename:'../escape.tgz'}]) {
      await writeFile(join(directory,'pack.json'),JSON.stringify([{...metadata,integrity:digest,...change}]));
      assert.notEqual(spawnSync(process.execPath,['-e',synthetic]).status,0);
    }
    for (const rows of [[],[metadata,metadata],{},null,{0:{...metadata,integrity:digest},length:1}]) {
      await writeFile(join(directory,'pack.json'),JSON.stringify(rows));
      assert.notEqual(spawnSync(process.execPath,['-e',isolated]).status,0);
    }
  } finally { await rm(directory,{recursive:true,force:true}); }
});

test('runtime port reset uses the complete patched pinned filesystem without ownership overrides', async () => {
  const dockerfile = await read('Dockerfile');
  assert.match(dockerfile, /^FROM nginx:1\.30\.8-alpine@sha256:6437a63b5c529f0e06162b3f593c0154cff6fa2ea0f94fd7c27928cb399e022d AS runtime-rootfs$/m);
  const [before, final] = dockerfile.split(/^FROM scratch AS runtime$/m);
  assert.ok(final, 'a fresh final configuration must not inherit the base ExposedPorts');
  assert.match(before, /RUN apk add --no-cache --upgrade \\\n\s+'libexpat>=2\.10\.0-r0' 'zlib>=1\.4-r0'/);
  assert.match(before, /COPY nginx\.conf \/etc\/nginx\/nginx\.conf/);
  assert.match(before, /COPY --from=build --chown=10001:10001 \/app\/dist \/usr\/share\/nginx\/html/);
  assert.deepEqual(final.match(/^COPY .+$/gm), ['COPY --from=runtime-rootfs / /']);
  assert.doesNotMatch(final, /^(?:RUN|ADD|FROM|VOLUME|ONBUILD)\s/m);
  assert.deepEqual(final.match(/^EXPOSE .+$/gm), ['EXPOSE 8080']);
});

test('runtime HIGH fixes retain minimum security versions without removing dependencies or expanding APK upgrades', async () => {
  const dockerfile = await read('Dockerfile');
  const expected = [
    'RUN apk add --no-cache --upgrade \\',
    "    'libexpat>=2.10.0-r0' 'zlib>=1.4-r0' \\",
    "    'libx11>=1.8.14-r0' 'brotli-libs>=1.2.1-r0' \\",
    "    'curl>=8.23.0-r0' 'libcurl>=8.23.0-r0' \\",
    "    'libxslt>=1.1.43-r4' 'musl-utils>=1.2.6-r3' \\",
    "    'libxml2>=2.13.9-r3'",
  ].join('\n');
  const verify = text => {
    const stage = text.split(/^FROM nginx:[^\n]+ AS runtime-rootfs$/m)[1]?.split(/^FROM scratch AS runtime$/m)[0];
    assert.ok(stage, 'the existing pinned runtime stages must remain');
    assert.deepEqual(stage.match(/^RUN [^\n]*(?:\n[ \t]+[^\n]*)*/gm), [expected]);
    assert.doesNotMatch(stage, /apk del|--allow-untrusted|--repository|--repositories-file|\/edge\/|\/testing\//);
  };
  verify(dockerfile);
  for (const changed of [
    ...[
      ['libexpat','2.10.0-r0','2.9.0-r0'],
      ['zlib','1.4-r0','1.3.2-r1'],
      ['libx11','1.8.14-r0','1.8.13-r0'],
      ['brotli-libs','1.2.1-r0','1.2.0-r1'],
      ['curl','8.23.0-r0','8.22.0-r0'],
      ['libcurl','8.23.0-r0','8.22.0-r0'],
      ['libxslt','1.1.43-r4','1.1.43-r3'],
      ['musl-utils','1.2.6-r3','1.2.6-r2'],
      ['libxml2','2.13.9-r3','2.13.9-r2'],
    ].flatMap(([name,minimum,older]) => {
      const constraint = "'"+name+'>='+minimum+"'";
      return ['',name,"'"+name+'>='+older+"'"].map(replacement => dockerfile.replace(constraint,replacement));
    }),
    dockerfile.replace("'libx11>=1.8.14-r0'", "'libx11>=1.8.14-r0' libxpm"),
    dockerfile.replace(expected, expected+'\nRUN apk upgrade'),
    dockerfile.replace(expected, expected+'\nRUN apk del libx11'),
    dockerfile.replace('--no-cache --upgrade', '--no-cache --upgrade --allow-untrusted'),
    dockerfile.replace('--no-cache --upgrade', '--no-cache --upgrade --repository https://dl-cdn.alpinelinux.org/alpine/edge/main'),
    dockerfile.replace('--no-cache --upgrade', '--no-cache --upgrade --repositories-file /tmp/repositories'),
  ]) assert.throws(() => verify(changed));
});

test('fresh runtime configuration preserves pinned base environment and graceful stop semantics', async () => {
  const final = (await read('Dockerfile')).split(/^FROM scratch AS runtime$/m)[1];
  assert.ok(final);
  const env = final.match(/^ENV (?:.*\\\n)*.*$/m)?.[0].replace(/\\\n\s*/g, ' ').slice(4).trim().split(/\s+/);
  assert.deepEqual(env, [
    'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'NGINX_VERSION=1.30.8', 'PKG_RELEASE=1', 'DYNPKG_RELEASE=1',
    'NJS_VERSION=1.0.2', 'NJS_RELEASE=1', 'ACME_VERSION=0.4.2',
  ]);
  assert.match(final, /^WORKDIR \/$/m);
  assert.match(final, /^STOPSIGNAL SIGQUIT$/m);
  assert.match(final, /maintainer="NGINX Docker Maintainers <docker-maint@nginx\.com>"/);
});

test('final runtime keeps the approved non-root user, exact healthcheck and direct nginx startup', async () => {
  const final = (await read('Dockerfile')).split(/^FROM scratch AS runtime$/m)[1];
  assert.ok(final);
  assert.deepEqual(final.match(/^USER .+$/gm), ['USER 10001:10001']);
  assert.deepEqual(final.match(/^HEALTHCHECK .+$/gm), ['HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1']);
  assert.deepEqual(final.match(/^ENTRYPOINT .+$/gm), ['ENTRYPOINT ["nginx"]']);
  assert.deepEqual(final.match(/^CMD .+$/gm), ['CMD ["-g", "daemon off;"]']);
});

test('proxy routes use existing certificates without Docker discovery', async () => {
  const staticConfig=await read('examples/traefik/traefik.yaml');
  const dynamic=await read('examples/traefik/dynamic/keysmith.yaml');
  const caddy=await read('examples/caddy/Caddyfile');
  assert.doesNotMatch(staticConfig,/docker:|dashboard:|insecure:/);
  assert.match(dynamic,/http:\/\/keysmith:8080/);
  assert.match(dynamic,/\/certs\/fullchain\.pem/);
  assert.match(dynamic,/\/certs\/privkey\.pem/);
  assert.match(dynamic,/minVersion: VersionTLS12/);
  assert.match(dynamic,/sniStrict: true/);
  assert.match(caddy,/admin off/);
  assert.match(caddy,/auto_https disable_redirects/);
  assert.match(caddy,/https_port 8443/);
  assert.match(caddy,/reverse_proxy keysmith:8080/);
  assert.doesNotMatch(caddy,/tls internal/);
});

test('browser screenshots stay in separate ignored per-run directories', async () => {
  const first=await screenshotDirectory('fixture'),second=await screenshotDirectory('fixture');
  assert.notEqual(first('one.png'),second('one.png'));
  assert.throws(()=>first('../escape.png'));
  assert.match(await read('.gitignore'),/artifacts\//);
  assert.doesNotMatch(await read('scripts/build.mjs'),/browser-artifacts|tests\//);
});

test('release metadata agrees and historical dictionary provenance stays unchanged', async () => {
  const pkg=JSON.parse(await read('package.json')),lock=JSON.parse(await read('package-lock.json'));
  assert.equal(pkg.name,'zevyrn');
  assert.equal(lock.name,pkg.name);
  assert.equal(lock.packages[''].name,pkg.name);
  assert.equal(pkg.version,'1.2.4');
  assert.equal(lock.version,pkg.version);
  assert.equal(lock.packages[''].version,pkg.version);
  assert.match(await read('Dockerfile'),/org.opencontainers.image.title="Zevyrn"/);
  assert.match(await read('Dockerfile'),/org.opencontainers.image.version="1.2.4"/);
  assert.match(await read('public/index.html'),/class="version">v1.2.4/);
  assert.equal(JSON.parse(await read('data/readability-overrides.json')).version,'0.4.0');
});

// Fixed v1.1.0 compatibility contracts. Normalize line endings only for portable
// checkout verification; configuration values and every other byte are pinned.
test('all legacy installation and proxy entry points retain their v1.1.0 contents', async () => {
  const expected = {
  "compose.caddy.yaml": "86de62d004bab84fbb5f91a4ef2373caca26936e6076ae370989593520f57eef",
  "compose.traefik.yaml": "5ffba9f3873413e35b2df5a59efbf30b245c69ae0792694066468dbaf15a6138",
  "compose.yaml": "dd7a6426ff1c813df7ff9349e5ad1eb78c28d3c8cd336c75c3919478c4f218f5",
  "examples/caddy/Caddyfile": "d67d24f69fbd5872b973091ed52fa481460fdbc3813b0a302eaabec0fa295449",
  "examples/traefik/dynamic/keysmith.yaml": "d91e871d1e86b89dbee87a93265b6776cd84db14027d11117802a268321a645a",
  "examples/traefik/traefik.yaml": "f6af2655317abc56d3abf02eb612443d7a57e9923694defc6da20cf944b89f19"
};
  for (const [path,hash] of Object.entries(expected)) {
    assert.equal(createHash('sha256').update((await read(path)).replace(/\r\n/g,'\n')).digest('hex'),hash,path);
  }
});

function legacyEquivalent(config) {
  return config
    .replaceAll('zevyrn:1.2.4-local','keysmith:1.0.0-local')
    .replaceAll('${ZEVYRN_PORT:-${KEYSMITH_PORT:-18080}}','${KEYSMITH_PORT:-18080}')
    .replaceAll('${ZEVYRN_DOMAIN:-${KEYSMITH_DOMAIN:?Set ZEVYRN_DOMAIN or KEYSMITH_DOMAIN in .env}}','${KEYSMITH_DOMAIN:?Set KEYSMITH_DOMAIN in .env}')
    .replaceAll('${ZEVYRN_BIND_IP:-${KEYSMITH_BIND_IP:?Set ZEVYRN_BIND_IP or KEYSMITH_BIND_IP in .env}}','${KEYSMITH_BIND_IP:?Set KEYSMITH_BIND_IP in .env}')
    .replaceAll('${ZEVYRN_TLS_DIR:-${KEYSMITH_TLS_DIR:?Set an absolute external ZEVYRN_TLS_DIR or KEYSMITH_TLS_DIR}}','${KEYSMITH_TLS_DIR:?Set an absolute external TLS directory}')
    .replaceAll('      ZEVYRN_DOMAIN:','      KEYSMITH_DOMAIN:')
    .replaceAll('./examples/traefik/zevyrn-dynamic','./examples/traefik/dynamic')
    .replaceAll('./examples/caddy/Caddyfile.zevyrn','./examples/caddy/Caddyfile')
    .replaceAll('zevyrn','keysmith');
}

test('native configurations preserve the complete legacy security and networking contract', async () => {
  for (const suffix of ['','.traefik','.caddy']) {
    const native=await read('compose.zevyrn'+suffix+'.yaml');
    assert.equal(legacyEquivalent(native),await read('compose'+suffix+'.yaml'));
    assert.match(native,/^  zevyrn:$/m);
    assert.match(native,/image: zevyrn:1\.2\.4-local/);
    assert.match(native,new RegExp('^name: zevyrn'+suffix.replace('.','-')+'$','m'));
    const app=native.split(/\n  (?:traefik|caddy):/)[0];
    assert.doesNotMatch(app,/cap_add:/);
    if(suffix) assert.doesNotMatch(app,/^\s+ports:/m);
    else assert.match(app,/127\.0\.0\.1:\$\{ZEVYRN_PORT:-\$\{KEYSMITH_PORT:-18080\}\}:8080/);
  }
});

test('native proxy routes, TLS, and independent watched directory are consistent', async () => {
  const dynamic=await read('examples/traefik/zevyrn-dynamic/zevyrn.yaml');
  assert.equal(dynamic.replaceAll('zevyrn','keysmith').replaceAll('ZEVYRN_DOMAIN','KEYSMITH_DOMAIN'),await read('examples/traefik/dynamic/keysmith.yaml'));
  const caddy=await read('examples/caddy/Caddyfile.zevyrn');
  assert.equal(caddy.replaceAll('zevyrn','keysmith').replaceAll('ZEVYRN_DOMAIN','KEYSMITH_DOMAIN'),await read('examples/caddy/Caddyfile'));
  assert.deepEqual(await readdir(new URL('../examples/traefik/dynamic',import.meta.url)),['keysmith.yaml']);
  assert.deepEqual(await readdir(new URL('../examples/traefik/zevyrn-dynamic',import.meta.url)),['zevyrn.yaml']);
  const compose=await read('compose.zevyrn.traefik.yaml');
  assert.match(compose,/source: \.\/examples\/traefik\/zevyrn-dynamic\n/);
  assert.doesNotMatch(compose,/source: \.\/examples\/traefik\/dynamic\n/);
  assert.match(await read('compose.zevyrn.caddy.yaml'),/source: \.\/examples\/caddy\/Caddyfile\.zevyrn\n/);
});

// Execute only the trusted expressions extracted from these source files.
// POSIX shell parameter expansion is an operator-contract check, not a
// substitute for Docker Compose's YAML loading or .env-file precedence.
const shell=process.platform==='win32'
  ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/sh';
for (const suffix of ['PORT','DOMAIN','BIND_IP','TLS_DIR']) {
  test('native '+suffix+' fallback handles unset, empty and conflicting values', {skip:!existsSync(shell)&&'POSIX shell unavailable'}, async () => {
    const name=suffix==='PORT'?'compose.zevyrn.yaml':'compose.zevyrn.traefik.yaml';
    const config=await read(name);
    const expression=config.match(new RegExp('\\$\\{ZEVYRN_'+suffix+':-\\$\\{KEYSMITH_'+suffix+':[?\\-][^}]+\\}\\}'))?.[0];
    assert.ok(expression,name+': '+suffix);
    if(suffix!=='PORT') assert.ok((await read('compose.zevyrn.caddy.yaml')).includes(expression));
    const native='ZEVYRN_'+suffix,legacy='KEYSMITH_'+suffix;
    const cases=[
      [{},suffix==='PORT'?'18080':null],
      [{[native]:'',[legacy]:''},suffix==='PORT'?'18080':null],
      [{[native]:'new-value'},'new-value'],
      [{[legacy]:'old-value'},'old-value'],
      [{[native]:'',[legacy]:'old-value'},'old-value'],
      [{[native]:'new-value',[legacy]:''},'new-value'],
      [{[native]:'new-value',[legacy]:'old-value'},'new-value'],
      [{[native]:''},suffix==='PORT'?'18080':null],
      [{[legacy]:''},suffix==='PORT'?'18080':null],
    ];
    for(const [values,expected] of cases) {
      const env=Object.fromEntries(Object.entries(process.env).filter(([k])=>!/^ZEVYRN_|^KEYSMITH_/.test(k)));
      const result=spawnSync(shell,['-c',`printf '%s' "${expression}"`],{env:{...env,...values},encoding:'utf8'});
      assert.ifError(result.error);
      if(expected===null) {
        assert.notEqual(result.status,0,JSON.stringify(values));
        assert.match(result.stderr,new RegExp('KEYSMITH_'+suffix));
      } else {
        assert.equal(result.status,0,result.stderr);
        assert.equal(result.stdout,expected,JSON.stringify(values));
      }
    }
  });
}

test('native example uses canonical settings and Docker build includes regression inputs', async () => {
  const example=await read('zevyrn.env.example');
  assert.deepEqual(example.split('\n').filter(l=>l&&!l.startsWith('#')).map(l=>l.split('=')[0]),['ZEVYRN_PORT','ZEVYRN_DOMAIN','ZEVYRN_BIND_IP','ZEVYRN_TLS_DIR']);
  assert.match(example,/ZEVYRN_BIND_IP=127\.0\.0\.1/);
  assert.match(example,/ZEVYRN_TLS_DIR=\/etc\/zevyrn\/tls/);
  assert.match(await read('Dockerfile'),/COPY compose\.zevyrn\.yaml compose\.zevyrn\.traefik\.yaml compose\.zevyrn\.caddy\.yaml zevyrn\.env\.example \.\//);
});

// No daemon, containers, networks or ports are used: this calls only the real
// Compose configuration loader. Optional because the source build has no Docker.
// A standalone official Compose binary supports daemon-free local validation.
// CI still uses the normal Docker CLI plugin unless this test-only override is set.
const composeCommand=process.env.ZEVYRN_COMPOSE_BIN||'docker';
const composePrefix=process.env.ZEVYRN_COMPOSE_BIN?[]:['compose'];
const composeAvailable=spawnSync(composeCommand,[...composePrefix,'version','--short'],{encoding:'utf8'}).status===0;
test('Compose CLI renders both families and enforces .env/shell precedence and required settings',
  {skip:!composeAvailable&&'Docker Compose CLI unavailable; operator checks above are not Compose rendering'}, async () => {
  const root=fileURLToPath(new URL('../',import.meta.url));
  const temporary=await mkdtemp(join(tmpdir(),'zevyrn-config-'));
  const envFile=join(temporary,'settings.env');
  const tls=temporary.replaceAll('\\','/');
  const cleanEnv=Object.fromEntries(Object.entries(process.env).filter(([key])=>! /^(?:ZEVYRN_|KEYSMITH_|COMPOSE_)/.test(key)));
  async function render(file,settings={},shellValues={}) {
    await writeFile(envFile,Object.entries(settings).map(([k,v])=>`${k}=${v}`).join('\n')+'\n');
    return spawnSync(composeCommand,[...composePrefix,'--project-directory',root,'--env-file',envFile,'-p','zevyrn-config-test','-f',join(root,file),'config','--format','json'],
      {env:{...cleanEnv,...shellValues},encoding:'utf8'});
  }
  try {
    for(const family of ['legacy','native']) {
      const service=family==='legacy'?'keysmith':'zevyrn';
      const prefix=family==='legacy'?'KEYSMITH':'ZEVYRN';
      const settings={};
      for(const [key,value] of Object.entries({PORT:'18081',DOMAIN:'keys.example.com',BIND_IP:'127.0.0.1',TLS_DIR:tls})) settings[prefix+'_'+key]=value;
      for(const suffix of ['','.traefik','.caddy']) {
        const file='compose'+(family==='native'?'.zevyrn':'')+suffix+'.yaml';
        const result=await render(file,settings);
        assert.ifError(result.error); assert.equal(result.status,0,result.stderr);
        const config=JSON.parse(result.stdout),app=config.services[service];
        assert.equal(app.image,family==='native'?'zevyrn:1.2.4-local':'keysmith:1.0.0-local');
        assert.equal(app.user,'10001:10001'); assert.equal(app.read_only,true);
        assert.deepEqual(app.cap_drop,['ALL']); assert.ok(app.security_opt.includes('no-new-privileges:true'));
        if(suffix) {
          assert.ok(!app.ports?.length);
          const proxy=config.services[suffix.slice(1)];
          assert.equal(proxy.ports.length,1); assert.equal(proxy.ports[0].target,8443);
          assert.equal(String(proxy.ports[0].published),'443'); assert.equal(proxy.ports[0].host_ip,'127.0.0.1');
          assert.equal(proxy.environment[prefix+'_DOMAIN'],'keys.example.com');
        } else {
          assert.equal(app.ports.length,1); assert.equal(app.ports[0].target,8080);
          assert.equal(String(app.ports[0].published),'18081'); assert.equal(app.ports[0].host_ip,'127.0.0.1');
        }
      }
    }
    const cases=[
      [{}, {},null],
      [{ZEVYRN_DOMAIN:'',KEYSMITH_DOMAIN:''},{},null],
      [{KEYSMITH_DOMAIN:'legacy.example.com'}, {},'legacy.example.com'],
      [{ZEVYRN_DOMAIN:'',KEYSMITH_DOMAIN:'legacy.example.com'}, {},'legacy.example.com'],
      [{ZEVYRN_DOMAIN:'new.example.com',KEYSMITH_DOMAIN:'legacy.example.com'}, {},'new.example.com'],
      [{ZEVYRN_DOMAIN:'new.example.com'}, {ZEVYRN_DOMAIN:'shell.example.com'},'shell.example.com'],
      [{ZEVYRN_DOMAIN:'new.example.com'}, {KEYSMITH_DOMAIN:'legacy-shell.example.com'},'new.example.com'],
      [{ZEVYRN_DOMAIN:'new.example.com',KEYSMITH_DOMAIN:'legacy.example.com'}, {ZEVYRN_DOMAIN:''},'legacy.example.com'],
    ];
    for(const suffix of ['traefik','caddy']) {
      const file='compose.zevyrn.'+suffix+'.yaml';
      for(const [settings,shellValues,expected] of cases) {
        const result=await render(file,{ZEVYRN_BIND_IP:'127.0.0.1',ZEVYRN_TLS_DIR:tls,...settings},shellValues);
        if(expected===null) assert.notEqual(result.status,0,'Missing domain must fail');
        else { assert.equal(result.status,0,result.stderr); assert.equal(JSON.parse(result.stdout).services[suffix].environment.ZEVYRN_DOMAIN,expected); }
      }
      for(const missing of ['BIND_IP','TLS_DIR']) {
        for(const value of [undefined,'']) {
          const settings={ZEVYRN_DOMAIN:'keys.example.com',ZEVYRN_BIND_IP:'127.0.0.1',ZEVYRN_TLS_DIR:tls};
          delete settings['ZEVYRN_'+missing];
          if(value!==undefined) settings['ZEVYRN_'+missing]=settings['KEYSMITH_'+missing]=value;
          assert.notEqual((await render(file,settings)).status,0,missing+' required');
        }
      }
    }
    for(const [settings,shellValues,expected] of [[{}, {},'18080'],[{ZEVYRN_PORT:'',KEYSMITH_PORT:''},{},'18080'],[{KEYSMITH_PORT:'18082'},{},'18082'],[{ZEVYRN_PORT:'18083',KEYSMITH_PORT:'18082'},{},'18083'],[{ZEVYRN_PORT:'18083'},{ZEVYRN_PORT:'18084'},'18084']]) {
      const result=await render('compose.zevyrn.yaml',settings,shellValues);
      assert.equal(result.status,0,result.stderr); assert.equal(String(JSON.parse(result.stdout).services.zevyrn.ports[0].published),expected);
    }
    const prebuilt=await render('compose.ghcr.yaml');
    assert.equal(prebuilt.status,0,prebuilt.stderr);
    const app=JSON.parse(prebuilt.stdout).services.zevyrn;
    assert.equal(app.image,'ghcr.io/thestateofwhere/zevyrn:1.2.4');assert.equal(app.build,undefined);
    assert.equal(app.user,'10001:10001');assert.equal(app.read_only,true);
    const override='ghcr.io/thestateofwhere/zevyrn@sha256:'+'a'.repeat(64);
    const selected=await render('compose.ghcr.yaml',{ZEVYRN_IMAGE:override});
    assert.equal(selected.status,0,selected.stderr);assert.equal(JSON.parse(selected.stdout).services.zevyrn.image,override);
  } finally {
    // Only the exact directory allocated by mkdtemp can be removed.
    assert.equal(resolve(temporary),join(resolve(tmpdir()),temporary.split(/[\\/]/).at(-1)));
    assert.ok(temporary.split(/[\\/]/).at(-1).startsWith('zevyrn-config-'));
    await rm(temporary,{recursive:true,force:true});
  }
});
