"""Attempt-scoped adaptation of the existing standalone Docker validation drivers.
Preparation is not authorization. Invoked only by the separately approved launcher.
No canonical controller imports, exception handling, publication or global cleanup.
"""
import base64, binascii, contextlib, datetime, hashlib, io, json, os, pathlib, shutil, socket
import stat, subprocess, sys, tarfile, time, urllib.request, signal, re

R = pathlib.Path('/home/user/zevyrn-candidate-7989bc8-20261026-01')
D = ['docker', '--host', 'unix:///var/run/docker.sock']
PLAN = None
E = None
ENV = None
DEADLINE = None
PENDING = {}
PROBE_NUMBER = 0
WORK_SECONDS = 7200
FINALIZATION_SECONDS = 300
AUDIT_USER_CONFIG = '/tmp/zevyrn-user.npmrc'
AUDIT_GLOBAL_CONFIG = '/tmp/zevyrn-global.npmrc'

class ExecutionDeadline(TimeoutError):
    pass

def deadline_signal(signum, frame):
    raise ExecutionDeadline('REMOTE_EXECUTION_DEADLINE')

def start_deadline(seconds):
    global DEADLINE
    DEADLINE = time.monotonic() + seconds
    if sys.platform == 'linux':
        signal.signal(signal.SIGALRM, deadline_signal)
        # Individual subprocess budgets expire first, leaving time for their receipt.
        signal.setitimer(signal.ITIMER_REAL, seconds + 2)

def end_deadline():
    global DEADLINE
    if sys.platform == 'linux':
        signal.setitimer(signal.ITIMER_REAL, 0)
    DEADLINE = None

def timeout_budget(requested):
    remaining = requested if DEADLINE is None else DEADLINE - time.monotonic()
    if remaining <= 0:
        raise ExecutionDeadline('REMOTE_EXECUTION_DEADLINE')
    return min(requested, remaining)

def store(name, data):
    if E is None:
        PENDING[name] = data
    else:
        p = E / name
        p.write_bytes(data)
        p.chmod(0o600)

def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def save(name, value):
    store(name, (json.dumps(value, indent=2) + '\n').encode('utf8'))

def command(args, name, cwd=None, allowed=(0,), timeout=120, env=None, capture=True):
    started = time.monotonic()
    effective = None
    try:
        effective = timeout_budget(timeout)
        result = subprocess.run(args, cwd=cwd, env=env or ENV, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=effective)
        out, err = result.stdout, result.stderr
        failure = None
    except Exception as error:
        out = getattr(error, 'output', None) or b''
        err = getattr(error, 'stderr', None) or b''
        failure = error
        result = None
    if capture:
        store(name + '.stdout', out)
    # Snapshot stdout can contain unrelated container environment values; keep hashes only.
    store(name + '.stderr', err)
    save(name + '.receipt.json', {'command': args, 'cwd': str(cwd or R),
         'exitCode': result.returncode if result is not None else None,
         'timedOut': isinstance(failure, (subprocess.TimeoutExpired, TimeoutError)),
         'errorType': type(failure).__name__ if failure else None,
         'timeoutSeconds': effective, 'durationSeconds': time.monotonic() - started,
         'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
         'stdoutCapture': 'raw' if capture else 'metadata-only',
         'stdoutBytes': len(out), 'stderrBytes': len(err),
         'stdoutSHA256': digest(out), 'stderrSHA256': digest(err)})
    if failure is not None:
        raise failure
    require(result.returncode in allowed, 'COMMAND_FAILED:' + name)
    return result

def bounded_output(args):
    global PROBE_NUMBER
    PROBE_NUMBER += 1
    return command(args, 'probe-' + str(PROBE_NUMBER).zfill(4), timeout=20, capture=False).stdout

def snapshot():
    ids = bounded_output(D + ['ps', '-aq']).decode().split()
    data = json.loads(bounded_output(D + ['inspect', *ids])) if ids else []
    containers = {c['Id']: {'name': c['Name'], 'image': c['Image'],
        'status': c['State']['Status'], 'started': c['State']['StartedAt'],
        'restartCount': c['RestartCount'], 'health': c['State'].get('Health', {}).get('Status')}
        for c in data}
    lines = bounded_output(D + ['image', 'ls', '--no-trunc', '--format', '{{json .}}']).decode().splitlines()
    images = [json.loads(line) for line in lines]
    return {'containers': containers,
            'tags': {x['Repository'] + ':' + x['Tag']: x['ID'] for x in images
                     if x['Repository'] != '<none>' and x['Tag'] != '<none>'},
            'images': sorted(set(x['ID'] for x in images))}

def unchanged(before):
    after = snapshot()
    # Only a container with this exact attempt label/name may have been created.
    existing = {k: after['containers'].get(k) for k in before['containers']}
    require(existing == before['containers'], 'EXISTING_WORKLOAD_CHANGED')
    require(all(after['tags'].get(k) == v for k, v in before['tags'].items()), 'EXISTING_IMAGE_TAG_CHANGED')
    require(set(before['images']) <= set(after['images']), 'EXISTING_IMAGE_REMOVED')
    additions = [v['name'].lstrip('/') for k, v in after['containers'].items() if k not in before['containers']]
    require(all(n.startswith(PLAN['resourcePrefix'] + '-') for n in additions), 'UNEXPECTED_NEW_CONTAINER')
    save('workloads-after.json', after)

def capacity():
    paths = ['/', '/home/user', '/var/lib/containerd', '/var/lib/docker']
    free = {p: shutil.disk_usage(p).free for p in paths}
    require(all(v >= 8589934592 for v in free.values()), 'CAPACITY_BELOW_UNCHANGED_8_GIB')
    memory = int(next(x.split()[1] for x in pathlib.Path('/proc/meminfo').read_text().splitlines()
                      if x.startswith('MemAvailable:'))) * 1024
    require((os.cpu_count() or 0) >= 2 and memory >= 2 * 1024**3, 'CPU_OR_MEMORY_GATE')
    return {'availableBytes': free, 'cpus': os.cpu_count(), 'availableMemory': memory}

def safe_source(archive, manifest, target):
    expected = {r['path']: r for r in manifest['files']}
    require(len(expected) == len(manifest['files']) == 186, 'SOURCE_INVENTORY')
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as tf:
        for member in tf:
            name = member.name.rstrip('/')
            p = pathlib.PurePosixPath(name)
            require(name and not p.is_absolute() and '..' not in p.parts and '\\' not in name, 'UNSAFE_ARCHIVE_PATH')
            if member.isdir():
                require(any(n.startswith(name + '/') for n in expected), 'UNEXPECTED_DIRECTORY')
                if target:
                    (target / name).mkdir(parents=True, exist_ok=True)
                    (target / name).chmod(0o755)
                continue
            require(member.isfile() and name in expected and name not in seen, 'UNEXPECTED_SOURCE_MEMBER')
            row = expected[name]
            data = tf.extractfile(member).read()
            require(member.mode == row['mode'] == 0o644 and len(data) == row['bytes'] and
                    digest(data) == row['sha256'], 'SOURCE_MEMBER_IDENTITY')
            if target:
                parent = (target / name).parent
                parent.mkdir(parents=True, exist_ok=True)
                for q in [parent, *parent.parents]:
                    if q == target.parent:
                        break
                    q.chmod(0o755)
                with (target / name).open('xb') as stream:
                    stream.write(data)
                (target / name).chmod(0o644)
            seen.add(name)
    require(seen == set(expected), 'MISSING_SOURCE_MEMBER')

# OCI objects have distinct identities: index -> runnable manifest -> configuration.
# Read archive members only; never extract the image filesystem or trust scanner IDs.
def image_archive_identity(archive, inspected):
    INDEX = 'application/vnd.oci.image.index.v1+json'
    MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
    CONFIG = 'application/vnd.oci.image.config.v1+json'
    EMPTY = 'application/vnd.oci.empty.v1+json'
    EMPTY_DIGEST = 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'
    with tarfile.open(archive, mode='r:') as tf:
        members = {}
        for member in tf:
            name = member.name
            require(name not in members and not member.issym() and not member.islnk(), 'OCI_MEMBER_DUPLICATE_OR_LINK')
            require(name in ('oci-layout', 'index.json', 'manifest.json', 'repositories', 'blobs', 'blobs/sha256') or
                    re.fullmatch(r'blobs/sha256/[a-f0-9]{64}', name), 'OCI_MEMBER_PATH')
            require(member.isfile() or (member.isdir() and name in ('blobs', 'blobs/sha256')), 'OCI_MEMBER_TYPE')
            members[name] = member

        def read_json(name):
            member = members.get(name)
            require(member is not None and member.isfile() and member.size <= 8 * 1024**2, 'OCI_JSON_MEMBER')
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    require(key not in result, 'OCI_DUPLICATE_JSON_KEY')
                    result[key] = value
                return result
            value = json.loads(tf.extractfile(member).read(), object_pairs_hook=unique)
            require(isinstance(value, dict), 'OCI_JSON_OBJECT')
            return value

        def blob(desc):
            require(isinstance(desc, dict) and isinstance(desc.get('digest'), str) and
                    re.fullmatch(r'sha256:[a-f0-9]{64}', desc['digest']) and
                    type(desc.get('size')) is int and desc['size'] >= 0 and
                    'urls' not in desc, 'OCI_DESCRIPTOR')
            embedded = None
            if 'data' in desc:
                require(isinstance(desc['data'], str) and desc['size'] <= 65536 and
                        len(desc['data']) <= 4 * ((65536 + 2) // 3), 'OCI_EMBEDDED_DATA_LIMIT')
                try:
                    embedded = base64.b64decode(desc['data'], validate=True)
                except (ValueError, binascii.Error):
                    raise RuntimeError('OCI_EMBEDDED_DATA_ENCODING') from None
                require(len(embedded) == desc['size'] and
                        'sha256:' + digest(embedded) == desc['digest'], 'OCI_EMBEDDED_DATA_IDENTITY')
            name = 'blobs/sha256/' + desc['digest'][7:]
            member = members.get(name)
            require(member is not None and member.isfile() and member.size == desc['size'], 'OCI_DESCRIPTOR_SIZE_OR_MISSING')
            h = hashlib.sha256()
            with tf.extractfile(member) as stream:
                for block in iter(lambda: stream.read(1024**2), b''):
                    h.update(block)
            require('sha256:' + h.hexdigest() == desc['digest'], 'OCI_DESCRIPTOR_HASH')
            if embedded is not None:
                require(tf.extractfile(member).read() == embedded, 'OCI_EMBEDDED_BLOB_MISMATCH')
            return name

        require(read_json('oci-layout') == {'imageLayoutVersion': '1.0.0'}, 'OCI_LAYOUT')
        root = read_json('index.json')
        candidates = []
        attestations = []
        visited = set()

        def walk(index, chain, depth):
            require(depth <= 4 and index.get('schemaVersion') == 2 and index.get('mediaType') == INDEX and
                    isinstance(index.get('manifests'), list) and 0 < len(index['manifests']) <= 64, 'OCI_INDEX')
            for desc in index['manifests']:
                name = blob(desc)
                require(desc['digest'] not in visited, 'OCI_DUPLICATE_DESCRIPTOR')
                visited.add(desc['digest'])
                obj = read_json(name)
                kind = desc.get('mediaType')
                if kind == INDEX:
                    walk(obj, chain + [desc['digest']], depth + 1)
                    continue
                require(kind == MANIFEST and obj.get('mediaType') == MANIFEST and obj.get('schemaVersion') == 2,
                        'OCI_MANIFEST')
                config_desc = obj.get('config')
                config_name = blob(config_desc)
                layers = obj.get('layers')
                require(isinstance(layers, list) and 0 < len(layers) <= 256, 'OCI_LAYERS')
                for layer in layers:
                    blob(layer)
                platform = desc.get('platform')
                require(isinstance(platform, dict), 'OCI_PLATFORM_MISSING')
                attestation = desc.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest'
                if attestation:
                    require(platform.get('os') == platform.get('architecture') == 'unknown' and
                            not platform.get('variant'), 'OCI_ATTESTATION_PLATFORM')
                    if config_desc.get('mediaType') == EMPTY:
                        require(config_desc['digest'] == EMPTY_DIGEST and config_desc['size'] == 2 and
                                tf.extractfile(members[config_name]).read() == b'{}', 'OCI_ATTESTATION_EMPTY_CONFIG')
                    else:
                        require(config_desc.get('mediaType') == CONFIG, 'OCI_CONFIG_TYPE')
                        config = read_json(config_name)
                        require(config.get('os') == config.get('architecture') == 'unknown', 'OCI_ATTESTATION_PLATFORM')
                    reference = desc['annotations'].get('vnd.docker.reference.digest')
                    require(isinstance(reference, str) and re.fullmatch(r'sha256:[a-f0-9]{64}', reference),
                            'OCI_ATTESTATION_REFERENCE')
                    attestations.append(reference)
                    continue
                require(config_desc.get('mediaType') == CONFIG, 'OCI_CONFIG_TYPE')
                config = read_json(config_name)
                require(config.get('os') == platform.get('os') and
                        config.get('architecture') == platform.get('architecture'), 'OCI_CONFIG_PLATFORM')
                if platform.get('os') != 'linux' or platform.get('architecture') != 'amd64':
                    continue
                require(not platform.get('variant') or platform['variant'] == 'v1', 'OCI_PLATFORM_VARIANT')
                diffids = config.get('rootfs', {}).get('diff_ids')
                require(config.get('rootfs', {}).get('type') == 'layers' and isinstance(diffids, list) and
                        len(diffids) == len(layers) and all(isinstance(x, str) and re.fullmatch(r'sha256:[a-f0-9]{64}', x) for x in diffids), 'OCI_DIFFIDS')
                for layer, expected in zip(layers, diffids):
                    kind = layer.get('mediaType')
                    require(kind in ('application/vnd.oci.image.layer.v1.tar',
                                     'application/vnd.oci.image.layer.v1.tar+gzip'), 'OCI_LAYER_TYPE')
                    with tf.extractfile(members['blobs/sha256/' + layer['digest'][7:]]) as stream:
                        if kind.endswith('+gzip'):
                            import gzip
                            stream = gzip.GzipFile(fileobj=stream)
                        h = hashlib.sha256()
                        for block in iter(lambda: stream.read(1024**2), b''):
                            h.update(block)
                        require('sha256:' + h.hexdigest() == expected, 'OCI_LAYER_DIFFID')
                candidates.append({'indexDigests': chain, 'manifestDigest': desc['digest'],
                    'configurationDigest': config_desc['digest'], 'os': 'linux', 'architecture': 'amd64',
                    'diffIDs': diffids})

        root_digest = 'sha256:' + digest(tf.extractfile(members['index.json']).read())
        walk(root, [root_digest], 0)
        require(len(candidates) == 1, 'OCI_RUNNABLE_SELECTION')
        identity = candidates[0]
        require(all(reference == identity['manifestDigest'] for reference in attestations), 'OCI_ATTESTATION_REFERENCE')
        require(inspected.get('Os') == 'linux' and inspected.get('Architecture') == 'amd64' and
                inspected.get('RootFS', {}).get('Type') == 'layers' and
                inspected['RootFS'].get('Layers') == identity['diffIDs'], 'DOCKER_CONFIGURATION_MISMATCH')
        descriptor = inspected.get('Descriptor')
        if descriptor is None:
            # Classic Docker image IDs identify the configuration, not an index.
            require(inspected.get('Id') == identity['configurationDigest'], 'DOCKER_CONFIG_BINDING')
        else:
            require(descriptor.get('digest') == inspected.get('Id'), 'DOCKER_DESCRIPTOR_ID')
            blob_name = blob(descriptor) if descriptor['digest'] != root_digest else 'index.json'
            require(members[blob_name].size == descriptor.get('size'), 'DOCKER_DESCRIPTOR_SIZE')
            if descriptor.get('mediaType') == INDEX:
                require(descriptor['digest'] in identity['indexDigests'], 'DOCKER_INDEX_BINDING')
            else:
                require(descriptor.get('mediaType') == MANIFEST and
                        descriptor['digest'] == identity['manifestDigest'], 'DOCKER_MANIFEST_BINDING')
        return identity


def verify_scanner_identity(report, identity):
    metadata = report.get('Metadata', {})
    config = metadata.get('ImageConfig', {})
    require(metadata.get('ImageID') == identity['configurationDigest'], 'SCANNER_IMAGE_BINDING')
    require(config.get('os') == identity['os'] and config.get('architecture') == identity['architecture'] and
            config.get('rootfs', {}).get('type') == 'layers' and
            config['rootfs'].get('diff_ids') == identity['diffIDs'] and
            metadata.get('DiffIDs') == identity['diffIDs'], 'SCANNER_CONFIGURATION_BINDING')


def database(cache):
    p = cache / 'db'
    m = json.loads((p / 'metadata.json').read_bytes())
    now = datetime.datetime.now(datetime.timezone.utc)
    parse = lambda s: datetime.datetime.fromisoformat(s.replace('Z', '+00:00'))
    require(m['Version'] == 2, 'DATABASE_SCHEMA')
    age = (now - parse(m['UpdatedAt'])).total_seconds()
    require(0 <= age <= 86400 and parse(m['NextUpdate']) > now and
            parse(m['UpdatedAt']) <= parse(m['DownloadedAt']) <= now, 'DATABASE_FRESHNESS')
    return {'metadata': m, 'databaseSHA256': digest((p / 'trivy.db').read_bytes()),
            'metadataSHA256': digest((p / 'metadata.json').read_bytes()), 'ageSeconds': age}

def container_options(name, network='bridge', user='1000:1000'):
    return ['run', '--rm', '--name', PLAN['resourcePrefix'] + '-' + name,
        '--label', 'io.zevyrn.validation-attempt=' + PLAN['attempt'],
        '--user', user, '--read-only', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges:true', '--pids-limit', '128',
        '--memory', '512m', '--cpus', '1', '--tmpfs', '/tmp:rw,noexec,nosuid,size=128m,mode=1777',
        '--network', network]

def audit_shell():
    require(AUDIT_USER_CONFIG != AUDIT_GLOBAL_CONFIG, 'AUDIT_CONFIG_COLLISION')
    return ('umask 077; : > ' + AUDIT_USER_CONFIG + '; : > ' + AUDIT_GLOBAL_CONFIG +
            '; exec npm audit --json --cache /tmp/npm-cache --registry=https://registry.npmjs.org' +
            ' --userconfig=' + AUDIT_USER_CONFIG + ' --globalconfig=' + AUDIT_GLOBAL_CONFIG)

def validate_dispatch(dispatch, plan):
    require(isinstance(dispatch, dict) and
            re.fullmatch('[a-f0-9]{64}', dispatch.get('dispatchId', '')) and
            re.fullmatch('[a-f0-9]{64}', dispatch.get('bundleManifestSHA256', '')) and
            all(dispatch.get(k) == plan[k] for k in ('commit', 'tree', 'attempt')) and
            dispatch.get('automaticRetries') == 0, 'DISPATCH_IDENTITY')

def finalize(status, before, dispatch, primary_error=None):
    start_deadline(FINALIZATION_SECONDS)
    failures = []
    try:
        unchanged(before)
        save('preservation-result.json', {'passed': True})
    except Exception as error:
        status = 'FAILED_PRESERVATION'
        failures.append({'phase': 'preservation', 'type': type(error).__name__, 'message': str(error)})
        save('preservation-result.json', {'passed': False, 'failure': failures[-1]})
    try:
        save('capacity-after.json', {p: shutil.disk_usage(p).free for p in ['/', '/var/lib/docker', '/var/lib/containerd']})
    except Exception as error:
        status = 'FAILED_FINALIZATION'
        failures.append({'phase': 'capacity-after', 'type': type(error).__name__, 'message': str(error)})
    document = {'status': status, 'dispatchId': dispatch['dispatchId'], 'commit': dispatch['commit'],
        'tree': dispatch['tree'], 'publicationAuthorized': False, 'canonicalControllerActivated': False,
        'CVE-2026-109869': 'NOT APPROVED', 'primaryError': primary_error, 'finalizationFailures': failures}
    try:
        save('attempt-status.json', document)
        files = [{'path': p.name, 'bytes': p.stat().st_size, 'sha256': digest(p.read_bytes())}
                 for p in sorted(E.iterdir()) if p.is_file() and not p.is_symlink() and p.name != 'EVIDENCE-MANIFEST.json']
        save('EVIDENCE-MANIFEST.json', {'dispatchId': dispatch['dispatchId'], 'files': files})
    except Exception as error:
        document['status'] = 'FAILED_FINALIZATION'
        document['finalizationFailures'].append({'phase': 'evidence-seal', 'type': type(error).__name__, 'message': str(error)})
        save('attempt-status.json', document)
        # An unsealed result is never collectable or a successful development result.
        print(json.dumps({'event': 'UNSEALED_FAILURE', 'dispatchId': dispatch['dispatchId'], 'status': document['status']}), flush=True)
        end_deadline()
        return document
    print(json.dumps({'event': 'FINALIZED', 'workspace': str(R), 'dispatchId': dispatch['dispatchId'],
        'bundleManifestSHA256': dispatch['bundleManifestSHA256'], 'commit': dispatch['commit'],
        'tree': dispatch['tree'], 'status': document['status'],
        'evidenceManifestSHA256': digest((E / 'EVIDENCE-MANIFEST.json').read_bytes())}), flush=True)
    end_deadline()
    return document

def execute(plan, manifest, archive, scanner, preflight, references, dispatch):
    global E, ENV, PLAN
    PLAN = plan
    validate_dispatch(dispatch, plan)
    require(str(pathlib.Path(sys.executable).resolve()) == '/usr/bin/python3.12' and
            digest(pathlib.Path(sys.executable).read_bytes()) == 'e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f', 'PYTHON_IDENTITY')
    require(plan['commit'] == '7989bc8bcf6d9e69137966d2829f2da6917e49ca' and
            plan['tree'] == '0361a62cbe974d5ad3ba3285db3d648947edab5c' and str(R) == plan['workspace'], 'EXECUTION_BINDING')
    require(socket.gethostname() == 'fnxa-dk02' and os.getuid() == 1000 and
            pathlib.Path('/etc/machine-id').read_text().strip() == 'f5cf9b91ec464c73afb914149cd2ee17', 'HOST_IDENTITY')
    require(digest(archive) == plan['sourceArchiveSHA256'] and digest(scanner) == plan['scanner']['sha256'], 'INPUT_IDENTITY')
    require(manifest['baseCommit'] == plan['commit'] and manifest['tree'] == plan['tree'], 'SOURCE_COMMIT')
    require(not any(v for k, v in os.environ.items() if k.startswith(('DOCKER_', 'BUILDX_', 'BUILDKIT_', 'TRIVY_')) or
                    k.upper() in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'LD_PRELOAD', 'NODE_OPTIONS')), 'UNEXPECTED_ENVIRONMENT')
    ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
           'HOME': '/home/user', 'LANG': 'C.UTF-8', 'TRIVY_DISABLE_TELEMETRY': 'true'}
    before = snapshot()
    require(all(not p.is_symlink() for p in R.parents), 'LINKED_WORKSPACE_PARENT')
    require(not R.exists() and not R.is_symlink(), 'WORKSPACE_COLLISION')
    require(not any(tag in before['tags'] for tag in plan['tags'].values()), 'IMAGE_TAG_COLLISION')
    require(not any(c['name'].lstrip('/').startswith(plan['resourcePrefix']) for c in before['containers'].values()), 'CONTAINER_COLLISION')
    networks = bounded_output(D + ['network', 'ls', '--format', '{{.Name}}']).decode().splitlines()
    require(not any(n.startswith(plan['resourcePrefix']) for n in networks), 'NETWORK_COLLISION')
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exec(compile(preflight, '<retained-readonly-preflight>', 'exec'), {'__name__': 'retained_preflight'})
    checked = json.loads(buf.getvalue())
    require(checked['capacityPass'], 'PRECHECK_CAPACITY')
    require(checked['versions']['docker'] == '29.9.2' and checked['versions']['compose'] == '5.6.1' and
            checked['versions']['buildx'] == 'github.com/docker/buildx v0.38.1 0dbe87f36ed472fe36b6796c3f70b4210a731fc5', 'HOST_TOOL_VERSION_DRIFT')
    safe_source(archive, manifest, None)
    os.umask(0o077)
    R.mkdir(mode=0o700)
    with (R / 'DISPATCH-ONCE.json').open('x', encoding='utf8') as receipt:
        receipt.write(json.dumps(dispatch, indent=2) + '\n')
    E = R / 'evidence'
    E.mkdir(mode=0o700)
    status = 'FAILED'
    primary_error = None
    try:
        save('DISPATCH-RECEIPT.json', dispatch)
        print(json.dumps({'event': 'WORKSPACE_OWNED', 'dispatchId': dispatch['dispatchId'], 'workspace': str(R)}), flush=True)
        for name, data in list(PENDING.items()):
            store(name, data)
        PENDING.clear()
        save('execution-plan.json', plan)
        save('source-manifest.json', manifest)
        save('workloads-before.json', before)
        save('preflight.json', checked)
        save('capacity-before.json', capacity())
        driver = command(D + ['buildx', 'inspect'], 'buildx-inspect').stdout.decode()
        require(any(x.partition(':')[0].strip() == 'Driver' and x.partition(':')[2].strip() == 'docker'
                    for x in driver.splitlines()), 'BUILDX_DRIVER')
        endpoint = command(D + ['context', 'inspect', 'default', '--format', '{{.Endpoints.docker.Host}}'], 'default-context').stdout.decode().strip()
        require(endpoint == 'unix:///var/run/docker.sock', 'CONTEXT_ENDPOINT')
        source = R / 'source'
        source.mkdir(mode=0o755)
        safe_source(archive, manifest, source)
        (R / 'source.tar').write_bytes(archive)
        tools = R / 'tools'
        tools.mkdir(mode=0o700)
        tool = tools / 'trivy'
        tool.write_bytes(scanner)
        tool.chmod(0o500)
        base = D + ['build', '--platform', 'linux/amd64', '--label', 'io.zevyrn.source-commit=' + plan['commit']]
        require(not any(tag in snapshot()['tags'] for tag in plan['tags'].values()), 'PREBUILD_TAG_COLLISION')
        command(base + ['--target', 'build', '-t', plan['tags']['builder'], '.'], 'builder-build', source, timeout=1800)
        require(plan['tags']['runtime'] not in snapshot()['tags'], 'RUNTIME_TAG_COLLISION')
        command(base + ['-t', plan['tags']['runtime'], '.'], 'runtime-build', source, timeout=1800)
        identities = {}
        for role, tag in plan['tags'].items():
            image = json.loads(command(D + ['image', 'inspect', tag], role + '-inspect').stdout)[0]
            require(image['Os'] == 'linux' and image['Architecture'] == 'amd64', 'IMAGE_PLATFORM')
            identities[role] = {'tag': tag, 'imageID': image['Id'], 'platform': 'linux/amd64'}
            command(D + ['save', '-o', str(R / (role + '.tar')), tag], role + '-export', timeout=180)
            identities[role]['archiveSHA256'] = digest((R / (role + '.tar')).read_bytes())
            identities[role].update(image_archive_identity(R / (role + '.tar'), image))
        require(image['Config']['User'] == '10001:10001', 'RUNTIME_USER')
        save('image-identities.json', identities)
        builder = identities['builder']['imageID']
        runtime = identities['runtime']['imageID']
        apk = command(D + container_options('packages', 'none', '10001:10001') + ['--entrypoint', '/bin/cat', runtime, '/lib/apk/db/installed'], 'runtime-apk').stdout.decode()
        packages = {}
        for record in apk.split('\n\n'):
            fields = dict(line.split(':', 1) for line in record.splitlines() if ':' in line)
            if 'P' in fields and 'V' in fields:
                require(fields['P'] not in packages, 'DUPLICATE_APK_PACKAGE')
                packages[fields['P']] = fields['V']
        require(packages.get('brotli-libs') == '1.2.1-r0', 'RUNTIME_BROTLI_VERSION')
        require(not any(p in packages for p in ('nodejs', 'npm')), 'RUNTIME_BUILD_TOOL')
        save('runtime-packages.json', packages)
        for name, version in {'libexpat': '2.9.0-r0', 'zlib': '1.3.2-r1', 'libx11': '1.8.14-r0',
                              'curl': '8.23.0-r0', 'libcurl': '8.23.0-r0'}.items():
            require(packages.get(name) == version, 'RUNTIME_PIN:' + name)
        prior = {p['name']: p['version'] for p in references['originalRuntime']['packages']}
        save('runtime-package-differences.json', {'baselineArchiveSHA256': references['originalRuntime']['archiveSHA256'],
            'changes': [{'name': n, 'before': prior.get(n), 'after': packages.get(n)}
                        for n in sorted(set(prior) | set(packages)) if prior.get(n) != packages.get(n)]})
        asset_code = 'const fs=require("node:fs"),c=require("node:crypto");const walk=(p,r="")=>fs.readdirSync(p,{withFileTypes:true}).flatMap(x=>x.isDirectory()?walk(p+"/"+x.name,r+x.name+"/"):[{path:r+x.name,bytes:fs.statSync(p+"/"+x.name).size,sha256:c.createHash("sha256").update(fs.readFileSync(p+"/"+x.name)).digest("hex")}]);console.log(JSON.stringify(walk("/app/dist")));'
        assets = json.loads(command(D + container_options('asset-check', 'none') + ['--entrypoint', 'node', builder, '-e', asset_code], 'builder-assets').stdout)
        require(sorted(assets, key=lambda p: p['path']) == sorted(references['expectedAssets'], key=lambda p: p['path']), 'DEVELOPMENT_ASSET_IDENTITY')
        save('asset-comparison.json', {'matched': len(assets), 'expected': len(references['expectedAssets']), 'passed': True})
        runtime_tar = command(D + container_options('runtime-assets', 'none', '10001:10001') + [
            '--entrypoint', '/bin/tar', runtime, '-cf', '-', '-C', '/usr/share/nginx/html', '.'], 'runtime-assets').stdout
        runtime_assets = []
        extra_assets = []
        expected_names = {p['path'] for p in references['expectedAssets']}
        with tarfile.open(fileobj=io.BytesIO(runtime_tar), mode='r:') as tf:
            for member in tf:
                if member.isdir():
                    continue
                require(member.isfile(), 'RUNTIME_ASSET_TYPE')
                name = member.name[2:] if member.name.startswith('./') else member.name
                data = tf.extractfile(member).read()
                row = {'path': name, 'bytes': len(data), 'sha256': digest(data)}
                if name in expected_names:
                    require(member.uid == member.gid == 10001 and member.mode == 0o644, 'RUNTIME_ASSET_MODE_OWNER')
                    runtime_assets.append(row)
                else:
                    extra_assets.append({**row, 'uid': member.uid, 'gid': member.gid, 'mode': oct(member.mode)})
        require(sorted(runtime_assets, key=lambda p: p['path']) == sorted(references['expectedAssets'], key=lambda p: p['path']), 'RUNTIME_ASSET_IDENTITY')
        save('runtime-asset-comparison.json', {'matched': len(runtime_assets), 'modes': '0644', 'uid': 10001, 'gid': 10001,
            'additionalBaseFilesForReview': extra_assets, 'completeFilesystemQualification': False})
        versions = command(D + container_options('builder-versions', 'none') + ['--entrypoint', 'node', builder, '-e',
            'const fs=require("node:fs");console.log(JSON.stringify({node:process.version,npm:JSON.parse(fs.readFileSync("/usr/local/lib/node_modules/npm/package.json")).version,undici:JSON.parse(fs.readFileSync("/usr/local/lib/node_modules/npm/node_modules/undici/package.json")).version,builtinUndici:process.versions.undici}))'], 'builder-versions').stdout
        versions = json.loads(versions)
        require(versions['node'] == 'v24.22.1' and versions['npm'] == '11.21.1' and versions['undici'] == '6.29.0', 'BUILDER_DEPENDENCIES')
        save('builder-versions.json', versions)
        audit = command(D + container_options('audit') + ['--entrypoint', '/bin/sh', builder,
            '-ec', audit_shell()], 'npm-audit', allowed=(0, 1), timeout=300)
        (E / 'npm-audit.raw.json').write_bytes(audit.stdout)
        cache = R / 'trivy-cache'
        cache.mkdir(mode=0o700)
        (E / 'empty-config.yaml').write_text('{}\n')
        (E / 'empty.ignore').write_text('')
        trivy = [str(tool), '--config', str(E / 'empty-config.yaml'), '--cache-dir', str(cache)]
        version = json.loads(command(trivy + ['version', '--format', 'json'], 'scanner-version').stdout)
        require(version['Version'] == '0.76.0', 'SCANNER_VERSION')
        command(trivy + ['image', '--download-db-only', '--db-repository', plan['scanner']['databaseRepository'], '--skip-version-check'], 'database-download', timeout=600)
        start = database(cache)
        save('database-start.json', start)
        scan = ['--skip-db-update', '--skip-java-db-update', '--offline-scan', '--skip-version-check', '--ignorefile', str(E / 'empty.ignore')]
        # Collect both reports before the unchanged combined CI acceptance gate.
        for role in ('runtime', 'builder'):
            command(trivy + ['image', '--input', str(R / (role + '.tar')), '--scanners', 'vuln,secret',
                '--image-config-scanners', 'secret', '--list-all-pkgs', '--format', 'json',
                '--output', str(E / (role + '-raw.json')), *scan], role + '-scan', timeout=600)
        command(trivy + ['fs', '--scanners', 'secret', '--format', 'json', '--output', str(E / 'source-secrets.raw.json'), *scan, str(source)], 'source-secret-scan', timeout=300)
        command(trivy + ['image', '--input', str(R / 'runtime.tar'), '--format', 'cyclonedx', '--output', str(E / 'runtime-sbom.cdx.json'), *scan], 'sbom', timeout=300)
        end = database(cache)
        save('database-end.json', end)
        require(start['databaseSHA256'] == end['databaseSHA256'] and start['metadataSHA256'] == end['metadataSHA256'], 'DATABASE_CHANGED')
        for role in ('runtime', 'builder'):
            report = json.loads((E / (role + '-raw.json')).read_bytes())
            verify_scanner_identity(report, identities[role])
        validator = D + container_options('validator', 'none') + ['--mount', 'type=bind,src=' + str(E) + ',dst=/evidence', '--entrypoint', 'node', builder, 'scripts/ci-security.mjs']
        a = command(validator + ['npm', '/evidence/npm-audit.raw.json', '/evidence/npm-audit-summary.json'], 'audit-validator', allowed=(0, 1))
        v = command(validator + ['trivy', '/evidence/runtime-raw.json', '/evidence/runtime-summary.json', '/evidence/builder-raw.json', '/evidence/builder-summary.json'], 'image-validator', allowed=(0, 1))
        summaries = {n: json.loads((E / (n + '-summary.json')).read_bytes()) for n in ('npm-audit', 'runtime', 'builder')}
        require(all(type(s.get('blocked')) is bool for s in summaries.values()), 'MISSING_VALIDATOR_SUMMARY')
        require(a.returncode == int(summaries['npm-audit']['blocked']) and
                v.returncode == int(summaries['runtime']['blocked'] or summaries['builder']['blocked']), 'VALIDATOR_EXIT_MISMATCH')
        raw = json.loads((E / 'source-secrets.raw.json').read_bytes())
        require(raw.get('SchemaVersion') == 2 and raw.get('Trivy', {}).get('Version') == '0.76.0' and
                raw.get('ArtifactType') == 'filesystem' and raw.get('ArtifactName') == str(source), 'SOURCE_SCAN_FORMAT')
        require(not any(k in raw for k in ('error', 'Error', 'Errors')), 'SOURCE_SCAN_ERROR')
        results = raw.get('Results')
        require(results is None or isinstance(results, list), 'SOURCE_SCAN_RESULTS')
        secrets = 0
        for result in results or []:
            require(isinstance(result, dict) and (result.get('Secrets') is None or isinstance(result['Secrets'], list)), 'SOURCE_SECRET_RECORD')
            for secret in result.get('Secrets') or []:
                require(isinstance(secret, dict) and isinstance(secret.get('RuleID'), str) and secret['RuleID'], 'SOURCE_SECRET_IDENTITY')
                secrets += 1
        save('source-secret-summary.json', {'secretFindings': secrets, 'rawSHA256': digest((E / 'source-secrets.raw.json').read_bytes())})
        for row in manifest['files']:
            require(digest((source / row['path']).read_bytes()) == row['sha256'], 'SOURCE_CHANGED')
        if a.returncode or v.returncode or secrets:
            status = 'BLOCKED_SECURITY_GATE'
            raise RuntimeError('MANDATORY_SECURITY_GATE_BLOCKED')
        # Existing container health/security acceptance, only after all security gates pass.
        name = plan['resourcePrefix'] + '-runtime'
        args = D + ['run', '-d', '--name', name, '--label', 'io.zevyrn.validation-attempt=' + plan['attempt'],
            '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            '--pids-limit', '128', '--memory', '128m', '--cpus', '1', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m,mode=1777',
            '--network', 'none', runtime]
        cid = command(args, 'runtime-start').stdout.decode().strip()
        try:
            for _ in range(30):
                c = json.loads(command(D + ['inspect', cid], 'runtime-state').stdout)[0]
                if c['State'].get('Health', {}).get('Status') == 'healthy':
                    break
                time.sleep(1)
            require(c['State'].get('Health', {}).get('Status') == 'healthy', 'RUNTIME_HEALTH')
            health = command(D + ['exec', cid, 'wget', '-qO-', 'http://127.0.0.1:8080/healthz'], 'runtime-health').stdout
            require(health == b'ok\n' and c['HostConfig']['ReadonlyRootfs'] and c['HostConfig']['CapDrop'] == ['ALL'] and
                    'no-new-privileges:true' in c['HostConfig']['SecurityOpt'] and c['Config']['User'] == '10001:10001', 'RUNTIME_SECURITY')
            command(D + ['exec', cid, 'nginx', '-t'], 'nginx-configuration')
            for i, asset in enumerate(references['expectedAssets']):
                body = command(D + ['exec', cid, 'wget', '-qO-', 'http://127.0.0.1:8080/' + asset['path']], 'served-asset-' + str(i)).stdout
                require(len(body) == asset['bytes'] and digest(body) == asset['sha256'], 'SERVED_ASSET_IDENTITY')
            logs = command(D + ['logs', '--tail', '100', cid], 'runtime-logs')
            require(not any(x in (logs.stdout + logs.stderr).lower() for x in (b'[emerg]', b'[alert]', b'[crit]', b'[error]', b'permission denied')), 'RUNTIME_LOG_ERROR')
            save('runtime-acceptance.json', {'healthy': True, 'imageID': runtime, 'network': 'none', 'browserAcceptance': 'NOT_EXECUTED'})
        finally:
            owned = json.loads(bounded_output(D + ['inspect', cid]))[0]
            require(owned['Name'] == '/' + name and owned['Image'] == runtime and
                    owned['Config']['Labels'].get('io.zevyrn.validation-attempt') == plan['attempt'], 'CLEANUP_OWNERSHIP')
            command(D + ['stop', cid], 'runtime-stop')
            command(D + ['rm', cid], 'runtime-remove')
        status = 'PASS_DEVELOPMENT_CHECKS_NOT_RELEASE_QUALIFICATION'
    except Exception as error:
        primary_error = {'type': type(error).__name__, 'message': str(error)}
    finally:
        result = finalize(status, before, dispatch, primary_error)
    return result

def main():
    start_deadline(WORK_SECONDS)
    header = json.loads(sys.stdin.buffer.readline())
    def take(key, maximum):
        n = header[key]
        require(type(n) is int and 0 < n <= maximum, 'PAYLOAD_LENGTH')
        value = sys.stdin.buffer.read(n)
        require(len(value) == n, 'PAYLOAD_TRUNCATED')
        return value
    plan_bytes = take('plan', 100000)
    manifest_bytes = take('manifest', 1000000)
    plan = json.loads(plan_bytes)
    require(digest(manifest_bytes) == plan['sourceManifestSHA256'], 'MANIFEST_IDENTITY')
    references = take('references', 1000000)
    require(digest(references) == plan['referenceInputsSHA256'], 'REFERENCE_IDENTITY')
    dispatch = json.loads(take('dispatch', 20000))
    try:
        result = execute(plan, json.loads(manifest_bytes), take('source', 20000000),
            take('scanner', 200000000), take('preflight', 100000), json.loads(references), dispatch)
        return 0 if result['status'] == 'PASS_DEVELOPMENT_CHECKS_NOT_RELEASE_QUALIFICATION' else 1
    except Exception as error:
        print(json.dumps({'event': 'REJECTED', 'dispatchId': dispatch.get('dispatchId'),
            'errorType': type(error).__name__, 'message': str(error),
            'preflightReceipts': {n: json.loads(v) for n, v in PENDING.items() if n.endswith('.receipt.json')}}), flush=True)
        end_deadline()
        return 1

if __name__ == '__main__':
    sys.exit(main())
