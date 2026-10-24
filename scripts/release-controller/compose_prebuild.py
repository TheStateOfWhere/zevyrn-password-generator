"""Daemonless, fail-closed Compose rendering. No build/up/pull or privilege calls.

Session-09 assertions are retained as named checks. Every case writes immutable
start/execution/check/result records; unknown strings are redacted, not logged.
"""
from pathlib import Path
import datetime, hashlib, inspect, json, math, os, re, subprocess, traceback

MISSING = object()
SAFE = set(('main legacy native keysmith zevyrn traefik caddy app bridge ingress tcp '
            'ALL NET_BIND_SERVICE CMD wget -q -O /dev/null no-new-privileges:true '
            'keysmith-traefik keysmith-caddy zevyrn-traefik zevyrn-caddy '
            'keysmith:1.0.0-local zevyrn:1.2.1-local 10001:10001 65532:65532 '
            '127.0.0.1 keys.example.com legacy.example.com new.example.com '
            'shell.example.com legacy-shell.example.com service_healthy '
            'unless-stopped never linux/amd64 /healthz 16m 128m 256m 1.0 '
            'http://127.0.0.1:8080/healthz http://keysmith:8080 http://zevyrn:8080 '
            'compose --project-directory --env-file -f config --format json '
            'version --short').split())
SAFE.update(('JSON object', 'zero', 'positive config-error status', 'readonly/no docker socket', 'legacy fallback', '5.6.0'))


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def redact(value, root, context=None):
    """Allowlisted values only. Unknown strings (including stderr) become hashes."""
    if isinstance(value, str):
        if value in SAFE or re.fullmatch(r'[0-9]{1,12}', value):
            return value
        # Retain workspace-local paths without exposing user directory names.
        for prefix in (str(root), str(root).replace('\\', '/')):
            if value == prefix or value.startswith(prefix+'/') or value.startswith(prefix+'\\'):
                tail = value[len(prefix):].replace('\\', '/')
                if re.fullmatch(r'[/A-Za-z0-9_.-]*', tail):
                    return '<WORKSPACE>'+tail
        return {'redacted': True, 'utf8Bytes': len(value.encode()), 'sha256': digest(value.encode())}
    if isinstance(value, list):
        return [redact(v, root, context) for v in value]
    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            key = k if isinstance(k, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,100}', k) else '<KEY-'+digest(str(k).encode())[:16]+'>'
            sensitive = bool(re.search(r'pass(word|wd)?|token|secret|credential|authorization|private.?key|api.?key|ssh.?key|signing.?key', str(k), re.I))
            unknown_environment = context == 'environment' and not re.fullmatch(r'(ZEVYRN|KEYSMITH)_(PORT|DOMAIN|BIND_IP|TLS_DIR)', str(k))
            if sensitive or unknown_environment:
                result[key] = {'redacted': True, 'sha256': digest(json.dumps(v, sort_keys=True, allow_nan=False).encode())}
            else:
                result[key] = redact(v, root, str(k))
        return result
    if type(value) is float and not math.isfinite(value):
        return {'nonFiniteNumber': True}
    if value is None or type(value) in (bool, int, float):
        return value
    raise TypeError('Unsupported diagnostic value type')


def typed(value, root):
    if value is MISSING:
        return {'jsonType': 'missing'}
    kind = {type(None): 'null', bool: 'boolean', int: 'integer', float: 'number',
            str: 'string', list: 'array', dict: 'object'}.get(type(value))
    if kind is None:
        raise TypeError('Unsupported assertion value type')
    return {'jsonType': kind, 'value': redact(value, root)}


def exact_memory(value):
    # No coercion: bool, float, signs, units and noncanonical strings fail.
    return (type(value) is int and value == 134217728) or (type(value) is str and value == '134217728')


def exact_pids(value):
    return type(value) is int and value == 128


def exact_cpus(value):
    return type(value) in (int, float) and math.isfinite(value) and value == 1


class CheckFailure(AssertionError):
    pass


def write_new(path, value):
    """Exclusive, flushed records. A persistence error is never swallowed."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(value, f, indent=2, allow_nan=False)
        f.write('\n'); f.flush(); os.fsync(f.fileno())


def strict_json(text):
    def unique(rows):
        obj = {}
        for k, v in rows:
            if k in obj: raise ValueError('Duplicate JSON key')
            obj[k] = v
        return obj
    return json.loads(text, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))


class Runner:
    def __init__(self, root, prefix, identity, environment=None, execute=subprocess.run):
        self.root = Path(root).resolve()
        self.source = self.root/'source'
        self.prefix = list(prefix)
        # Only a Compose executable or Docker's Compose plugin; never sudo/shell.
        basename = Path(self.prefix[0]).name.lower() if self.prefix else ''
        if not ((len(self.prefix) == 1 and basename in ('docker-compose', 'docker-compose.exe')) or
                (len(self.prefix) == 2 and basename in ('docker', 'docker.exe') and self.prefix[1] == 'compose')):
            raise ValueError('Only ordinary-user Compose command prefixes are allowed')
        if set(identity) != {'runID', 'sourceManifestSHA256'} or not re.fullmatch(r'[a-zA-Z0-9-]+', identity['runID']) or not re.fullmatch(r'[a-f0-9]{64}', identity['sourceManifestSHA256']):
            raise ValueError('Invalid source/session identity')
        self.identity = identity.copy()
        manifest_path = self.root/'source-manifest.json'
        if manifest_path.is_symlink() or digest(manifest_path.read_bytes()) != identity['sourceManifestSHA256']:
            raise ValueError('Source manifest identity mismatch')
        manifest = strict_json(manifest_path.read_text())
        if type(manifest) is not list or len(manifest) != 97:
            raise ValueError('Expected frozen 97-file source manifest')
        paths = []
        for row in manifest:
            name = row['path']; p = self.source/name
            if not isinstance(name, str) or Path(name).is_absolute() or '..' in Path(name).parts or '\\' in name or not p.resolve().is_relative_to(self.source) or p.is_symlink():
                raise ValueError('Unsafe source manifest path')
            if digest(p.read_bytes()) != row['sha256']:
                raise ValueError('Frozen source file mismatch')
            paths.append(name)
        if len(set(paths)) != 97 or sorted(paths) != sorted(p.relative_to(self.source).as_posix() for p in self.source.rglob('*') if p.is_file()):
            raise ValueError('Frozen source inventory mismatch')
        self.helper_sha = digest(Path(__file__).read_bytes())
        self.execute = execute
        original = os.environ if environment is None else environment
        self.env = {k: v for k, v in original.items() if not k.startswith(('DOCKER_', 'BUILDX_', 'BUILDKIT_', 'COMPOSE_', 'ZEVYRN_', 'KEYSMITH_'))}
        self.directory = self.root/'compose-validation-v2'
        self.directory.mkdir(mode=0o700)
        self.config = self.directory/'docker-config'
        self.config.mkdir(mode=0o700)
        self.env.update(DOCKER_HOST='tcp://127.0.0.1:1', DOCKER_CONFIG=str(self.config))
        self.current = None
        self.completed = []
        # Persist before even the version command can run.
        command = self.prefix+['version', '--short']
        write_new(self.directory/'version-before.json', {**self.identity, 'helperSHA256': self.helper_sha,
                  'startedUTC': utc(), 'command': self.safe_command(command)})
        result = self.execute(command, env=self.env, capture_output=True, text=True, timeout=30)
        write_new(self.directory/'version-after.json', {**self.identity, 'finishedUTC': utc(), 'exitCode': result.returncode,
                  'stdout': redact(result.stdout, self.root), 'stderr': redact(result.stderr, self.root),
                  'stdoutSHA256': digest(result.stdout.encode()), 'stderrSHA256': digest(result.stderr.encode())})
        if result.returncode != 0 or result.stdout.strip() != '5.6.0':
            raise CheckFailure('compose.version: requires verified Compose 5.6.0')
        self.version = result.stdout.strip()

    def safe_command(self, command):
        return [Path(command[0]).name]+redact(command[1:], self.root)

    def check(self, identifier, condition, expected, actual):
        frame = inspect.currentframe().f_back
        try:
            record = {**self.identity, 'caseID': self.current['caseID'], 'helperSHA256': self.helper_sha,
                      'composeVersion': self.version, 'assertionID': identifier, 'utc': utc(),
                      'location': {'file': Path(frame.f_code.co_filename).name, 'line': frame.f_lineno},
                      'expected': typed(expected, self.root), 'actual': typed(actual, self.root), 'passed': bool(condition)}
        finally:
            del frame
        self.current['checks'] += 1
        self.current['lastAssertionID'] = identifier
        write_new(self.current['directory']/('check-%03d.json' % self.current['checks']), record)
        if not condition:
            raise CheckFailure(identifier)

    def case(self, identifier, family, file, settings, shell, success, verify, error_field=None):
        if not re.fullmatch(r'[a-z0-9-]+', identifier) or family not in ('legacy', 'native'):
            raise ValueError('Invalid case identifier')
        if file not in ('compose.yaml', 'compose.traefik.yaml', 'compose.caddy.yaml', 'compose.zevyrn.yaml', 'compose.zevyrn.traefik.yaml', 'compose.zevyrn.caddy.yaml'):
            raise ValueError('Unexpected Compose file')
        for mapping in (settings, shell):
            for k, v in mapping.items():
                if not re.fullmatch(r'(ZEVYRN|KEYSMITH)_(PORT|DOMAIN|BIND_IP|TLS_DIR)', k) or not isinstance(v, str) or any(x in v for x in ('\r', '\n', '\0')):
                    raise ValueError('Unsafe synthetic environment setting')
        directory = self.directory/identifier
        directory.mkdir(mode=0o700)
        self.current = {'caseID': identifier, 'directory': directory, 'checks': 0}
        envfile = directory/'settings.env'
        command = self.prefix+['--project-directory', str(self.source), '--env-file', str(envfile), '-f', str(self.source/file), 'config', '--format', 'json']
        write_new(directory/'before.json', {**self.identity, 'caseID': identifier, 'family': family,
                  'helperSHA256': self.helper_sha, 'composeVersion': self.version, 'startedUTC': utc(),
                  'command': self.safe_command(command), 'expectedSuccess': success,
                  'settings': redact(settings, self.root), 'shellOverrides': redact(shell, self.root),
                  'daemonEndpoint': 'tcp://127.0.0.1:1', 'ordinaryUser': True})
        try:
            fd = os.open(envfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
                f.write(''.join(k+'='+v+'\n' for k, v in settings.items())); f.flush(); os.fsync(f.fileno())
            result = self.execute(command, env={**self.env, **shell}, capture_output=True, text=True, timeout=30)
            rendered = None
            parse_error = None
            if result.returncode == 0:
                try: rendered = strict_json(result.stdout)
                except (ValueError, TypeError) as e: parse_error = e
            write_new(directory/'execution.json', {**self.identity, 'caseID': identifier, 'finishedUTC': utc(),
                      'exitCode': result.returncode, 'stdoutSHA256': digest(result.stdout.encode()),
                      'stderrSHA256': digest(result.stderr.encode()), 'redactedStdout': redact(result.stdout, self.root),
                      'renderedJSON': redact(rendered, self.root), 'redactedStderr': redact(result.stderr, self.root)})
            self.check('compose.exit', result.returncode == 0 if success else result.returncode > 0,
                       'zero' if success else 'positive config-error status', result.returncode)
            if success:
                self.check('compose.json', parse_error is None and type(rendered) is dict, 'JSON object', type(rendered).__name__)
                verify(rendered)
            elif error_field:
                self.check('compose.required-setting', error_field in result.stderr, error_field, result.stderr)
            write_new(directory/'result.json', {**self.identity, 'caseID': identifier, 'finishedUTC': utc(),
                      'status': 'PASS', 'checks': self.current['checks']})
            self.completed.append(identifier)
        except BaseException as error:
            frames = [{'file': Path(f.filename).name, 'line': f.lineno, 'function': f.name}
                      for f in traceback.extract_tb(error.__traceback__)]
            # No locals, exception values, source snippets, or raw environment.
            write_new(directory/'failure.json', {**self.identity, 'caseID': identifier, 'finishedUTC': utc(),
                      'helperSHA256': self.helper_sha, 'composeVersion': self.version, 'errorType': type(error).__name__,
                      'assertionID': self.current.get('lastAssertionID') if isinstance(error, CheckFailure) else None,
                      'tracebackWithoutLocals': frames})
            raise
        finally:
            self.current = None


def verify_model(c, native, suffix, r):
    service = 'zevyrn' if native else 'keysmith'
    key = 'ZEVYRN' if native else 'KEYSMITH'
    check = r.check
    check('project.name', c.get('name') == service+('-'+suffix if suffix else ''), service+('-'+suffix if suffix else ''), c.get('name', MISSING))
    services = c.get('services', {})
    check('service.set', set(services) == ({service, suffix} if suffix else {service}), sorted({service, suffix} if suffix else {service}), sorted(services))
    app = services[service]
    image = 'zevyrn:1.2.1-local' if native else 'keysmith:1.0.0-local'
    check('app.image', app.get('image') == image, image, app.get('image', MISSING))
    for field, expected in [('user', '10001:10001'), ('read_only', True), ('cap_drop', ['ALL'])]:
        equal = app.get(field) is True if field == 'read_only' else app.get(field) == expected
        check('app.'+field, equal, expected, app.get(field, MISSING))
    check('app.no-cap-add', not app.get('cap_add'), [], app.get('cap_add', []))
    check('app.not-privileged', not app.get('privileged', False), False, app.get('privileged', False))
    check('app.security-opt', 'no-new-privileges:true' in app.get('security_opt', []), ['no-new-privileges:true'], app.get('security_opt', MISSING))
    check('app.mem-limit', exact_memory(app.get('mem_limit')), 134217728, app.get('mem_limit', MISSING))
    check('app.pids-limit', exact_pids(app.get('pids_limit')), 128, app.get('pids_limit', MISSING))
    check('app.cpus', exact_cpus(app.get('cpus')), 1, app.get('cpus', MISSING))
    health = app.get('healthcheck', {}).get('test', [])
    check('app.health', '/healthz' in ' '.join(health), '/healthz', health)
    if not suffix:
        ports = app.get('ports', [])
        check('app.loopback-port', len(ports) == 1 and ports[0].get('target') == 8080 and str(ports[0].get('published')) == '18081' and ports[0].get('host_ip') == '127.0.0.1',
              [{'target': 8080, 'published': '18081', 'host_ip': '127.0.0.1'}], ports)
        return
    check('app.unpublished', not app.get('ports'), [], app.get('ports', []))
    check('app.network', set(app.get('networks', {})) == {'app'}, ['app'], list(app.get('networks', {})))
    network = c.get('networks', {}).get('app', {})
    check('network.bridge', network.get('driver') == 'bridge', 'bridge', network.get('driver', MISSING))
    proxy = services[suffix]; ports = proxy.get('ports', [])
    check('proxy.https-port', len(ports) == 1 and ports[0].get('target') == 8443 and str(ports[0].get('published')) == '443' and ports[0].get('host_ip') == '127.0.0.1' and ports[0].get('protocol') == 'tcp',
          [{'target': 8443, 'published': '443', 'host_ip': '127.0.0.1', 'protocol': 'tcp'}], ports)
    check('proxy.domain', proxy.get('environment', {}).get(key+'_DOMAIN') == 'keys.example.com', 'keys.example.com', proxy.get('environment', {}).get(key+'_DOMAIN', MISSING))
    check('proxy.network', set(proxy.get('networks', {})) == {'app'}, ['app'], list(proxy.get('networks', {})))
    condition = proxy.get('depends_on', {}).get(service, {}).get('condition')
    check('proxy.health-dependency', condition == 'service_healthy', 'service_healthy', condition)
    for field, expected in [('read_only', True), ('cap_drop', ['ALL']), ('user', '65532:65532')]:
        equal = proxy.get(field) is True if field == 'read_only' else proxy.get(field) == expected
        check('proxy.'+field, equal, expected, proxy.get(field, MISSING))
    check('proxy.not-privileged', not proxy.get('privileged', False), False, proxy.get('privileged', False))
    check('proxy.security-opt', 'no-new-privileges:true' in proxy.get('security_opt', []), ['no-new-privileges:true'], proxy.get('security_opt', MISSING))
    caps = ['NET_BIND_SERVICE'] if suffix == 'caddy' else []
    check('proxy.cap-add', proxy.get('cap_add', []) == caps, caps, proxy.get('cap_add', []))
    volumes = proxy.get('volumes', [])
    check('proxy.readonly-mounts-no-socket', bool(volumes) and all(v.get('read_only') is True and 'docker.sock' not in v.get('source', '') for v in volumes), 'readonly/no docker socket', volumes)
    if suffix == 'traefik':
        dynamic = [v for v in volumes if v.get('target') == '/etc/traefik/dynamic']
        expected = r.source/'examples/traefik'/('zevyrn-dynamic' if native else 'dynamic')
        check('traefik.dynamic-directory', len(dynamic) == 1 and Path(dynamic[0]['source']).resolve() == expected.resolve(), str(expected), dynamic)
        text = (expected/(service+'.yaml')).read_text()
        check('traefik.backend', 'http://'+service+':8080' in text, 'http://'+service+':8080', text)
    else:
        text = (r.source/'examples/caddy'/('Caddyfile.zevyrn' if native else 'Caddyfile')).read_text()
        check('caddy.backend', 'reverse_proxy '+service+':8080' in text, 'reverse_proxy '+service+':8080', text)


def validate(root, prefix, environment, identity):
    """All original 35 CLI cases, plus explicit legacy/native fallback controls."""
    r = Runner(root, prefix, identity, environment)
    tls = str(r.directory)
    for native in (False, True):
        family = 'native' if native else 'legacy'; key = 'ZEVYRN' if native else 'KEYSMITH'
        settings = {key+'_'+k: v for k, v in {'PORT': '18081', 'DOMAIN': 'keys.example.com', 'BIND_IP': '127.0.0.1', 'TLS_DIR': tls}.items()}
        for suffix in ('', 'traefik', 'caddy'):
            file = 'compose'+('.zevyrn' if native else '')+('.'+suffix if suffix else '')+'.yaml'
            r.case(family+'-baseline-'+(suffix or 'standalone'), family, file, settings, {}, True,
                   lambda c, n=native, s=suffix: verify_model(c, n, s, r))
    domains = [({}, {}, None), ({'ZEVYRN_DOMAIN': '', 'KEYSMITH_DOMAIN': ''}, {}, None),
               ({'KEYSMITH_DOMAIN': 'legacy.example.com'}, {}, 'legacy.example.com'),
               ({'ZEVYRN_DOMAIN': '', 'KEYSMITH_DOMAIN': 'legacy.example.com'}, {}, 'legacy.example.com'),
               ({'ZEVYRN_DOMAIN': 'new.example.com', 'KEYSMITH_DOMAIN': 'legacy.example.com'}, {}, 'new.example.com'),
               ({'ZEVYRN_DOMAIN': 'new.example.com'}, {'ZEVYRN_DOMAIN': 'shell.example.com'}, 'shell.example.com'),
               ({'ZEVYRN_DOMAIN': 'new.example.com'}, {'KEYSMITH_DOMAIN': 'legacy-shell.example.com'}, 'new.example.com'),
               ({'ZEVYRN_DOMAIN': 'new.example.com', 'KEYSMITH_DOMAIN': 'legacy.example.com'}, {'ZEVYRN_DOMAIN': ''}, 'legacy.example.com')]
    for proxy in ('traefik', 'caddy'):
        file = 'compose.zevyrn.'+proxy+'.yaml'
        for i, (values, shell, expected) in enumerate(domains):
            r.case('native-'+proxy+'-domain-'+str(i), 'native', file, {'ZEVYRN_BIND_IP': '127.0.0.1', 'ZEVYRN_TLS_DIR': tls, **values}, shell, expected is not None,
                   lambda c, e=expected: r.check('environment.domain', c['services'][proxy]['environment']['ZEVYRN_DOMAIN'] == e, e, c['services'][proxy]['environment']['ZEVYRN_DOMAIN']), 'KEYSMITH_DOMAIN')
        for missing in ('BIND_IP', 'TLS_DIR'):
            for empty in (False, True):
                values = {'ZEVYRN_DOMAIN': 'keys.example.com', 'ZEVYRN_BIND_IP': '127.0.0.1', 'ZEVYRN_TLS_DIR': tls}
                del values['ZEVYRN_'+missing]
                if empty: values['ZEVYRN_'+missing] = values['KEYSMITH_'+missing] = ''
                r.case('native-'+proxy+'-missing-'+missing.lower().replace('_', '-')+'-'+str(int(empty)), 'native', file, values, {}, False, None, 'KEYSMITH_'+missing)
    ports = [({}, {}, '18080'), ({'ZEVYRN_PORT': '', 'KEYSMITH_PORT': ''}, {}, '18080'),
             ({'KEYSMITH_PORT': '18082'}, {}, '18082'), ({'ZEVYRN_PORT': '18083', 'KEYSMITH_PORT': '18082'}, {}, '18083'),
             ({'ZEVYRN_PORT': '18083'}, {'ZEVYRN_PORT': '18084'}, '18084')]
    for i, (values, shell, expected) in enumerate(ports):
        r.case('native-port-'+str(i), 'native', 'compose.zevyrn.yaml', values, shell, True,
               lambda c, e=expected: r.check('environment.port', str(c['services']['zevyrn']['ports'][0]['published']) == e, e, c['services']['zevyrn']['ports'][0]['published']))
    # Verify old required inputs and that new variables do not silently migrate old files.
    for proxy in ('traefik', 'caddy'):
        values = {'KEYSMITH_DOMAIN': 'keys.example.com', 'KEYSMITH_BIND_IP': '127.0.0.1', 'KEYSMITH_TLS_DIR': tls}
        for missing in ('DOMAIN', 'BIND_IP', 'TLS_DIR'):
            for empty in (False, True):
                v = values.copy(); del v['KEYSMITH_'+missing]
                if empty: v['KEYSMITH_'+missing] = ''
                r.case('legacy-'+proxy+'-missing-'+missing.lower().replace('_', '-')+'-'+str(int(empty)), 'legacy', 'compose.'+proxy+'.yaml', v, {}, False, None, 'KEYSMITH_'+missing)
        # Legacy-only fallback for all native required fields, then conflicting
        # namespace values: the native family must prefer ZEVYRN_*.
        r.case('native-'+proxy+'-all-legacy-fallback', 'native', 'compose.zevyrn.'+proxy+'.yaml', values, {}, True,
               lambda c, p=proxy: r.check('environment.full-fallback', c['services'][p]['environment']['ZEVYRN_DOMAIN'] == 'keys.example.com' and c['services'][p]['ports'][0]['host_ip'] == '127.0.0.1', 'legacy fallback', c['services'][p]['ports']))
        for field in ('BIND_IP', 'TLS_DIR'):
            v = {**values, 'ZEVYRN_DOMAIN': 'keys.example.com', 'ZEVYRN_BIND_IP': '127.0.0.1', 'ZEVYRN_TLS_DIR': tls}
            v['KEYSMITH_'+field] = '192.0.2.1' if field == 'BIND_IP' else str(r.directory/'unused-legacy-tls')
            def selected(c, p=proxy, field=field):
                proxy_c = c['services'][p]
                actual = proxy_c['ports'][0]['host_ip'] if field == 'BIND_IP' else next(x['source'] for x in proxy_c['volumes'] if x['target'] == '/certs')
                expected = '127.0.0.1' if field == 'BIND_IP' else tls
                equal = actual == expected if field == 'BIND_IP' else Path(actual).resolve() == Path(expected).resolve()
                r.check('environment.'+field.lower(), equal, expected, actual)
            r.case('native-'+proxy+'-conflict-'+field.lower().replace('_', '-'), 'native', 'compose.zevyrn.'+proxy+'.yaml', v, {}, True, selected)
    write_new(r.directory/'summary.json', {**identity, 'helperSHA256': r.helper_sha, 'composeVersion': r.version,
              'passed': True, 'caseCount': len(r.completed), 'caseIDs': r.completed,
              'daemonless': True, 'daemonEndpoint': 'tcp://127.0.0.1:1', 'sudoUsed': False})
    return {'passed': True, 'caseCount': len(r.completed), 'directory': str(r.directory)}
