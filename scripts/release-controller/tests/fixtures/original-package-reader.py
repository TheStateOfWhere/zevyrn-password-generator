"""Inert historical buggy-reader regression fixture; never a qualification entry."""
def write(name, data):
    with (R / name).open('x') as f:
        json.dump(data, f, indent=2)
        f.write('\n')

def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()

def packages(text):
    result = []
    for stanza in text.split('\n\n'):
        data = {}
        for line in stanza.splitlines():
            if len(line) > 2 and line[1] == ':':
                data.setdefault(line[0], line[2:])
        if 'P' in data:
            result.append({'name': data['P'], 'version': data.get('V'), 'origin': data.get('o'), 'architecture': data.get('A')})
    return result

def archive_inventory(kind, build):
    path = R / build['archive']
    assert digest(path) == build['archiveSHA256']
    apk = None
    names = set()
    checks = []
    with tarfile.open(path, 'r:') as archive:
        manifest = json.load(archive.extractfile('manifest.json'))
        assert len(manifest) == 1
        m = manifest[0]
        configBytes = archive.extractfile(m['Config']).read()
        assert 'sha256:' + hashlib.sha256(configBytes).hexdigest() == build['image']['id']
        config = json.loads(configBytes)
        assert config['os'] == 'linux' and config['architecture'] == 'amd64'
        assert len(m['Layers']) == len(config['rootfs']['diff_ids'])
        for member, expected in zip(m['Layers'], config['rootfs']['diff_ids']):
            raw = archive.extractfile(member)
            magic = raw.read(2)
            raw.seek(0)
            stream = gzip.GzipFile(fileobj=raw) if magic == b'\x1f\x8b' else raw
            h = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(block)
            assert 'sha256:' + h.hexdigest() == expected
            checks.append(expected)
            raw = archive.extractfile(member)
            additions = []
            deletions = []
            db = None
            with tarfile.open(fileobj=raw, mode='r:*') as layer:
                for item in layer:
                    name = item.name.removeprefix('./').lstrip('/')
                    if '/.wh.' in name or name.startswith('.wh.'):
                        parent = str(Path(name).parent)
                        base = Path(name).name
                        deletions.append((parent, base))
                    else:
                        additions.append(name)
                        if item.isfile() and name == 'lib/apk/db/installed':
                            db = layer.extractfile(item).read().decode()
            for parent, base in deletions:
                prefix = '' if parent == '.' else parent + '/'
                target = prefix + base.removeprefix('.wh.')
                if base == '.wh..wh..opq':
                    names = {n for n in names if not n.startswith(prefix)}
                else:
                    names = {n for n in names if n != target and (not n.startswith(target + '/'))}
                if target == 'lib/apk/db/installed':
                    apk = None
            names.update(additions)
            if db is not None:
                apk = db
    assert apk is not None
    inventory = packages(apk)
    assert inventory
    versions = {p['name']: p['version'] for p in inventory}
    required = {'nginx': '1.30.6-r1', 'libexpat': '2.9.0-r0', 'zlib': '1.3.2-r1', 'pcre2': '10.49-r0', 'tiff': '4.7.2-r0', 'libpng': '1.6.59-r0', 'nghttp2-libs': '1.70.0-r0'}
    if kind == 'runtime':
        for package, version in required.items():
            assert versions.get(package) == version, 'Runtime package mismatch: ' + package
        forbidden = ['usr/local/bin/node', 'usr/local/bin/npm', 'usr/local/lib/node_modules', 'app/node_modules']
        assert not any((n == p or n.startswith(p + '/') for n in names for p in forbidden)), 'Unexpected runtime build tooling'
    else:
        forbidden = []
    result = {'imageID': build['image']['id'], 'archiveSHA256': build['archiveSHA256'], 'platform': 'linux/amd64', 'allLayerDiffIDsVerified': checks, 'packages': inventory, 'requiredPackages': {p: {'installed': versions.get(p), 'requiredRuntimeVersion': v, 'scope': 'required in runtime; builder absence separately reported'} for p, v in required.items()}, 'unexpectedRuntimeBuildTools': False if kind == 'runtime' else None}
    write(kind + '-installed-packages.json', result)
    return versions
