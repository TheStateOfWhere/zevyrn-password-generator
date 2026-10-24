"""Individual builder HIGH dispositions. No network, commands or approval creation.

Trust starts in reviewed executable bytes, NEVER in the evidence directory.
The shipped candidate authority is empty. Test authority substitutions exist only
in isolated fixtures; there is no CLI/env/caller override for these anchors.
"""
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import stat

AUTHORITY_SHA256 = '3f299e6b290e1b612932a83d287aa818c0b6fc75ec8c24a6942567d73e2fdeeb'
HERE = Path(__file__).absolute().parent


def require(ok, reason):
    if not ok:
        raise ValueError('Builder applicability: ' + reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pairs(rows):
    out = {}
    for key, value in rows:
        require(key not in out, 'duplicate JSON key')
        out[key] = value
    return out


def parse(data):
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'nonfinite JSON'))


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'schema fields')


def hash_value(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'SHA256 format')
    return value


def plain(path):
    path = Path(path).absolute()
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'linked evidence')
    require(path.is_file(), 'missing evidence file')
    return path


def read_at(root, name, expected=None):
    require(type(name) is str and name and '\\' not in name and ':' not in name
            and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')),
            'unsafe evidence path')
    data = plain(Path(root) / name).read_bytes()
    if expected is not None:
        require(digest(data) == hash_value(expected), 'evidence hash: ' + name)
    return data


def timestamp(value):
    require(type(value) is str and value.endswith('Z'), 'UTC timestamp required')
    result = dt.datetime.fromisoformat(value[:-1] + '+00:00')
    require(result.utcoffset() == dt.timedelta(), 'UTC timestamp')
    return result


def authority():
    raw = read_at(HERE, 'builder-security-authority.json', AUTHORITY_SHA256)
    auth = parse(raw)
    keys(auth, ('schemaVersion', 'policySHA256', 'approvedReceipts'))
    require(type(auth['schemaVersion']) is int and auth['schemaVersion'] == 1, 'authority version')
    require(type(auth['approvedReceipts']) is list and len(auth['approvedReceipts']) == len(set(auth['approvedReceipts'])),
            'duplicate authority receipts')
    for h in auth['approvedReceipts']:
        hash_value(h)
    policy = parse(read_at(HERE, 'builder-security-policy.json', auth['policySHA256']))
    require(type(policy.get('schemaVersion')) is int and type(policy.get('maxApprovalSeconds')) is int
            and all(type(policy.get(k)) is bool for k in ('runtimeHighAllowed','criticalAllowed','secretsAllowed')), 'policy types')
    require(policy == {'schemaVersion': 1, 'maxApprovalSeconds': 604800,
                       'runtimeHighAllowed': False, 'criticalAllowed': False, 'secretsAllowed': False},
            'unsupported policy')
    return auth


def findings(raw):
    """Exact occurrence, never just CVE/name. Ambiguous scanner paths fail closed."""
    out = []
    for target in raw['Results']:
        for item in target.get('Vulnerabilities', []):
            if item['Severity'] != 'HIGH':
                continue
            path = item.get('PkgPath')
            require(type(path) is str and path and not path.startswith('/') and '\\' not in path
                    and ':' not in path and all(p not in ('', '.', '..') for p in path.split('/')),
                    'ambiguous HIGH occurrence path')
            row = {k: item.get(k) for k in ('VulnerabilityID', 'PkgName', 'InstalledVersion', 'PkgPath')}
            row.update(Target=target['Target'], Type=target['Type'], Class=target['Class'], Severity='HIGH')
            require(all(type(v) is str and v for v in row.values()), 'incomplete HIGH identity')
            require(re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', row['VulnerabilityID']), 'CVE identity')
            require(row not in out, 'duplicate HIGH occurrence')
            out.append(row)
    return out


def evaluate(raw_data, context, kind, root, now):
    """Called only after original scan identity/coverage/freshness validation.

    Also checks context/report bindings here so CI cannot provide an unchecked
    summary. A complete qualification still must validate its original graph.
    """
    require(kind in ('builder', 'runtime'), 'image role')
    require(now.tzinfo is not None, 'trusted clock timezone')
    raw = parse(raw_data)
    counts = {k: 0 for k in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')}
    secrets = 0
    require(type(raw.get('Results')) is list and raw['Results'], 'missing report')
    for target in raw['Results']:
        require(type(target) is dict and type(target.get('Vulnerabilities', [])) is list
                and type(target.get('Secrets', [])) is list, 'malformed findings')
        for item in target.get('Vulnerabilities', []):
            require(type(item) is dict and item.get('Severity') in counts, 'severity')
            counts[item['Severity']] += 1
        secrets += len(target.get('Secrets', []))
    require(counts['CRITICAL'] == 0 and secrets == 0, 'CRITICAL or secret')
    require(kind != 'runtime' or counts['HIGH'] == 0, 'runtime HIGH')
    if not counts['HIGH']:
        return {'status': 'PASS', 'rawCounts': counts, 'secrets': secrets,
                'approvedHighCount': 0, 'unapprovedHighCount': 0, 'approvals': []}
    auth = authority()
    require(bool(auth['approvedReceipts']), 'no operator-authorized receipts')
    require(root is not None, 'missing evidence root')
    observed = findings(raw)
    # The approved scope includes independently verified scan bindings and a
    # pinned context file describing source/config/commands/graph identities.
    scope = parse(read_at(root, 'builder-applicability/context.json'))
    keys(scope, ('schemaVersion', 'bindings', 'files'))
    require(type(scope['schemaVersion']) is int and scope['schemaVersion'] == 1, 'scope version')
    bindings = scope['bindings']
    required = ('imageID', 'archiveSHA256', 'sourceManifestSHA256', 'runID', 'dbSHA256',
                'scannerVersion', 'scannerBinarySHA256', 'scannerPolicySHA256', 'reportSHA256',
                'imageGraph', 'sourceIdentity', 'lockSHA256', 'packageSHA256', 'configSHA256',
                'commandsSHA256', 'recipeSHA256', 'helpersSHA256', 'moduleSHA256',
                'advisorySHA256', 'lifecycleSHA256', 'linuxEvidenceSHA256', 'modulePath', 'archivePath')
    keys(bindings, required)
    require(bindings['imageID'] == context['images']['builder']['imageID'] and
            bindings['archiveSHA256'] == context['images']['builder']['archiveSHA256'], 'image/archive scope')
    for key in ('sourceManifestSHA256', 'runID', 'dbSHA256', 'scannerVersion', 'scannerBinarySHA256', 'scannerPolicySHA256'):
        require(bindings[key] == context[key] and bool(bindings[key]), 'scan scope: ' + key)
    require(bindings['reportSHA256'] == digest(raw_data), 'report scope')
    require(bindings['imageGraph'] == context.get('exportIdentities', {}).get('builder')
            and type(bindings['imageGraph']) is dict and bool(bindings['imageGraph']), 'verified OCI graph missing')
    require(raw['Metadata']['ImageID'] in (bindings['imageID'], bindings['imageGraph'].get('configurationDigest')),
            'report image')
    require(type(scope['files']) is dict and bool(scope['files']), 'scope evidence files')
    # Every critical semantic identity must have actual pinned evidence bytes;
    # Linux provenance/lifecycle conclusions additionally require human review.
    evidence = {name: read_at(root, name, h) for name, h in scope['files'].items()}
    available_hashes = {digest(data) for data in evidence.values()}
    for key in ('lockSHA256', 'packageSHA256', 'configSHA256', 'commandsSHA256', 'recipeSHA256',
                'helpersSHA256', 'moduleSHA256', 'advisorySHA256', 'lifecycleSHA256', 'linuxEvidenceSHA256'):
        require(hash_value(bindings[key]) in available_hashes, 'unverified scope input: ' + key)
    source = bindings['sourceIdentity']
    keys(source, ('commit', 'sourceManifestSHA256', 'diffSHA256'))
    require(type(source['commit']) is str and re.fullmatch('[0-9a-f]{40}', source['commit'])
            and source['sourceManifestSHA256'] == context['sourceManifestSHA256']
            and hash_value(source['diffSHA256']) in available_hashes, 'source identity')
    require(hash_value(bindings['sourceManifestSHA256']) in available_hashes, 'source manifest evidence')
    # Compare against CURRENT selected inputs, not a stale duplicate conveniently
    # supplied in scope.files. These are fixed controller contracts, not commands
    # or paths selected by a waiver. Missing files block applicability.
    actual_paths = {'lockSHA256': 'source/package-lock.json', 'packageSHA256': 'source/package.json',
                    'recipeSHA256': 'source/Dockerfile', 'configSHA256': 'builder-execution-config.json',
                    'commandsSHA256': 'builder-execution-commands.json',
                    'helpersSHA256': 'builder-build-helpers.json',
                    'sourceManifestSHA256': 'source-manifest.json'}
    for key, name in actual_paths.items():
        require(digest(read_at(root, name)) == bindings[key], 'current execution input: ' + key)
    qualification = parse(read_at(root, 'qualification.json'))
    require(qualification.get('baselineHEAD') == source['commit']
            and qualification.get('sourceManifestSHA256') == bindings['sourceManifestSHA256']
            and qualification.get('runID') == bindings['runID'], 'selected source commit/run')
    source_rows = parse(read_at(root, 'source-manifest.json'))
    require(type(source_rows) is list and bool(source_rows), 'source manifest records')
    seen_source = set()
    for row in source_rows:
        keys(row, ('path', 'sha256', 'size', 'mode'))
        require(row['path'] not in seen_source, 'duplicate source record')
        seen_source.add(row['path'])
        data = read_at(root, 'source/' + row['path'], row['sha256'])
        require(type(row['size']) is int and len(data) == row['size'] and row['mode'] in ('0644', '0755'),
                'source size/mode policy')
    actual_source = set()
    for path in (Path(root) / 'source').rglob('*'):
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'linked source input')
        if path.is_file():
            actual_source.add(path.relative_to(Path(root) / 'source').as_posix())
        else:
            require(path.is_dir(), 'unsupported source input')
    require(actual_source == seen_source, 'unexpected or missing source input')
    helper_files = parse(read_at(root, 'builder-build-helpers.json'))
    require(type(helper_files) is dict and bool(helper_files), 'build helper inventory')
    for name, expected_hash in helper_files.items():
        read_at(root, name, expected_hash)
    # Reuse the existing layer/whiteout resolver to establish vulnerable module
    # bytes in the exact image. A copied module hash in a review is insufficient.
    image = image_filesystem(root, bindings)
    require(image['identityChain'] == bindings['imageGraph'], 'actual image graph')
    module = image['files'].get(bindings['modulePath'])
    require(module and module.get('type') == 'file' and module.get('sha256') == bindings['moduleSHA256'],
            'actual vulnerable module bytes')
    require(all(row['PkgPath'].endswith('/package.json')
                and bindings['modulePath'].startswith(row['PkgPath'][:-len('package.json')]) for row in observed),
            'module outside approved component')
    linux = parse(next(data for data in evidence.values() if digest(data) == bindings['linuxEvidenceSHA256']))
    keys(linux, ('platform', 'imageID', 'sourceManifestSHA256', 'commandsSHA256', 'lifecycleSHA256', 'records'))
    require(linux['platform'] == 'linux/amd64' and linux['imageID'] == bindings['imageID']
            and linux['sourceManifestSHA256'] == bindings['sourceManifestSHA256']
            and linux['commandsSHA256'] == bindings['commandsSHA256']
            and linux['lifecycleSHA256'] == bindings['lifecycleSHA256'], 'Linux execution identity')
    require(type(linux['records']) is dict and set(linux['records']) == {'install', 'test', 'audit', 'coverage'},
            'incomplete Linux execution')
    for row in linux['records'].values():
        keys(row, ('path', 'sha256', 'exitCode'))
        require(type(row['exitCode']) is int and row['exitCode'] == 0, 'Linux record status')
        record_data = read_at(root, row['path'], row['sha256'])
        require(digest(record_data) in available_hashes, 'Linux record integrity')
        record = parse(record_data)
        keys(record, ('executionID', 'phase', 'platform', 'imageID', 'sourceManifestSHA256',
                      'commandsSHA256', 'configSHA256', 'recipeSHA256', 'helpersSHA256',
                      'exitCode', 'error', 'stdoutPath', 'stdoutSHA256'))
        require(record['executionID'] == context['runID'] and record['phase'] in linux['records']
                and linux['records'][record['phase']] == row and record['platform'] == 'linux/amd64'
                and record['imageID'] == bindings['imageID']
                and record['sourceManifestSHA256'] == bindings['sourceManifestSHA256']
                and record['commandsSHA256'] == bindings['commandsSHA256']
                and all(record[k] == bindings[k] for k in ('configSHA256', 'recipeSHA256', 'helpersSHA256'))
                and type(record['exitCode']) is int and record['exitCode'] == 0 and record['error'] is None,
                'Linux execution receipt')
        require(digest(read_at(root, record['stdoutPath'], record['stdoutSHA256'])) in available_hashes,
                'Linux execution output')
    matches = []
    seen = []
    for h in auth['approvedReceipts']:
        receipt = parse(read_at(root, 'builder-applicability/receipts/' + h + '.json', h))
        keys(receipt, ('schemaVersion', 'operator', 'authorizationReference', 'assessmentSHA256',
                       'reviewSHA256', 'scopeSHA256', 'finding', 'approvedAt', 'expiresAt', 'status'))
        require(type(receipt['schemaVersion']) is int and receipt['schemaVersion'] == 1
                and receipt['status'] == 'APPROVED' and type(receipt['operator']) is str and bool(receipt['operator'])
                and type(receipt['authorizationReference']) is str and bool(receipt['authorizationReference']),
                'operator approval record')
        start, end = timestamp(receipt['approvedAt']), timestamp(receipt['expiresAt'])
        require(start <= now < end and 0 < (end - start).total_seconds() <= 604800, 'approval interval')
        require(receipt['scopeSHA256'] == digest(read_at(root, 'builder-applicability/context.json')), 'approved scope')
        for key in ('assessmentSHA256', 'reviewSHA256'):
            require(hash_value(receipt[key]) in available_hashes, 'missing reviewed evidence')
        require(receipt['finding'] in observed and receipt['finding'] not in seen, 'out-of-scope/conflicting approval')
        seen.append(receipt['finding'])
        matches.append({'finding': receipt['finding'], 'receiptSHA256': h, 'expiresAt': receipt['expiresAt']})
    require(len(seen) == len(observed), 'unapproved HIGH occurrence')
    return {'status': 'PASS_WITH_APPROVED_BUILDER_HIGH', 'rawCounts': counts, 'secrets': secrets,
            'approvedHighCount': len(seen), 'unapprovedHighCount': 0,
            'policySHA256': auth['policySHA256'], 'authoritySHA256': AUTHORITY_SHA256, 'approvals': matches}


def image_filesystem(root, bindings):
    # Code identities are frozen in the reviewed gate, not approval data.
    import types
    export_data = read_at(HERE, 'export_identity.py', '3db795c4cd5490e4088108e187b35d958a585b8776dbc5da07a1528f43f190d0')
    namespace = {'__name__': 'authenticated_export'}
    exec(compile(export_data, 'export_identity.py', 'exec'), namespace)
    fs_data = read_at(HERE, 'filesystem_equivalence.py', 'deecec7ac43d1bf395b46d82e2dbcf9fe24e0d360b411a709a995249532f0adf')
    # Supply the authenticated resolver directly; never import a same-name module
    # from the evidence root or Python search path.
    source = fs_data.decode().replace('from export_identity import resolve_export', '')
    fs = {'__name__': 'authenticated_filesystem', 'resolve_export': namespace['resolve_export']}
    exec(compile(source, 'filesystem_equivalence.py', 'exec'), fs)
    read_at(root, bindings['archivePath'], bindings['archiveSHA256'])
    return fs['filesystem'](Path(root) / bindings['archivePath'], bindings['imageID'], bindings['archiveSHA256'])
