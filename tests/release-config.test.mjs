import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { screenshotDirectory } from './browser-artifacts.mjs';
const read = name => readFile(new URL('../'+name, import.meta.url), 'utf8');

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
  assert.match(dockerfile, /^FROM nginx:1\.30\.6-alpine@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5 AS runtime-rootfs$/m);
  const [before, final] = dockerfile.split(/^FROM scratch AS runtime$/m);
  assert.ok(final, 'a fresh final configuration must not inherit the base ExposedPorts');
  assert.match(before, /RUN apk add --no-cache --upgrade \\\n\s+libexpat=2\.9\.0-r0 zlib=1\.3\.2-r1/);
  assert.match(before, /COPY nginx\.conf \/etc\/nginx\/nginx\.conf/);
  assert.match(before, /COPY --from=build --chown=10001:10001 \/app\/dist \/usr\/share\/nginx\/html/);
  assert.deepEqual(final.match(/^COPY .+$/gm), ['COPY --from=runtime-rootfs / /']);
  assert.doesNotMatch(final, /^(?:RUN|ADD|FROM|VOLUME|ONBUILD)\s/m);
  assert.deepEqual(final.match(/^EXPOSE .+$/gm), ['EXPOSE 8080']);
});

test('runtime HIGH fix pins libx11 without removing dependencies or expanding APK upgrades', async () => {
  const dockerfile = await read('Dockerfile');
  const expected = 'RUN apk add --no-cache --upgrade \\\n      libexpat=2.9.0-r0 zlib=1.3.2-r1 libx11=1.8.14-r0';
  const verify = text => {
    const stage = text.split(/^FROM nginx:[^\n]+ AS runtime-rootfs$/m)[1]?.split(/^FROM scratch AS runtime$/m)[0];
    assert.ok(stage, 'the existing pinned runtime stages must remain');
    assert.deepEqual(stage.match(/^RUN [^\n]*(?:\n[ \t]+[^\n]*)*/gm), [expected]);
    assert.doesNotMatch(stage, /apk del|--allow-untrusted|--repository|--repositories-file|\/edge\/|\/testing\//);
  };
  verify(dockerfile);
  for (const changed of [
    dockerfile.replace(' libx11=1.8.14-r0', ''),
    dockerfile.replace('libx11=1.8.14-r0', 'libx11=1.8.13-r0'),
    dockerfile.replace('libx11=1.8.14-r0', 'libx11'),
    dockerfile.replace('libx11=1.8.14-r0', 'libx11=1.8.14-r0 libxpm'),
    dockerfile.replace(expected, expected+'\nRUN apk upgrade'),
    dockerfile.replace(expected, expected+'\nRUN apk del libx11'),
    dockerfile.replace('--no-cache --upgrade', '--no-cache --upgrade --allow-untrusted'),
    dockerfile.replace('--no-cache --upgrade', '--no-cache --upgrade --repository https://dl-cdn.alpinelinux.org/alpine/edge/main'),
  ]) assert.throws(() => verify(changed));
});

test('fresh runtime configuration preserves pinned base environment and graceful stop semantics', async () => {
  const final = (await read('Dockerfile')).split(/^FROM scratch AS runtime$/m)[1];
  assert.ok(final);
  const env = final.match(/^ENV (?:.*\\\n)*.*$/m)?.[0].replace(/\\\n\s*/g, ' ').slice(4).trim().split(/\s+/);
  assert.deepEqual(env, [
    'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'NGINX_VERSION=1.30.6', 'PKG_RELEASE=1', 'DYNPKG_RELEASE=1',
    'NJS_VERSION=1.0.2', 'NJS_RELEASE=1', 'ACME_VERSION=0.4.1',
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
  assert.equal(pkg.version,'1.2.1');
  assert.equal(lock.version,pkg.version);
  assert.equal(lock.packages[''].version,pkg.version);
  assert.match(await read('Dockerfile'),/org.opencontainers.image.title="Zevyrn"/);
  assert.match(await read('Dockerfile'),/org.opencontainers.image.version="1.2.1"/);
  assert.match(await read('public/index.html'),/class="version">v1.2.1/);
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
    .replaceAll('zevyrn:1.2.1-local','keysmith:1.0.0-local')
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
    assert.match(native,/image: zevyrn:1\.2\.1-local/);
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
        assert.equal(app.image,family==='native'?'zevyrn:1.2.1-local':'keysmith:1.0.0-local');
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
  } finally {
    // Only the exact directory allocated by mkdtemp can be removed.
    assert.equal(resolve(temporary),join(resolve(tmpdir()),temporary.split(/[\\/]/).at(-1)));
    assert.ok(temporary.split(/[\\/]/).at(-1).startsWith('zevyrn-config-'));
    await rm(temporary,{recursive:true,force:true});
  }
});
