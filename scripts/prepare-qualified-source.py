"""Prepare a NEW qualified-byte view; never normalize or overwrite a Git checkout.

Stdlib only. An independently pinned external bootstrap authenticates this module
before execution and supplies its private capability. Direct CLI use fails closed.
This prepares bytes, not qualification success or a vulnerability approval.
"""
from pathlib import Path, PurePosixPath
import hashlib, io, json, os, re, stat, tarfile

_BOOTSTRAP_CAPABILITY = None
REPOSITORY = Path(__file__).absolute().parents[1]
CONTRACT = 'zevyrn-v1.2.1-qualified-byte-preparation-v1'
PREFIX = 'qualification-dk02-20261019-02/source/'
MANIFEST_MEMBER = 'qualification-dk02-20261019-02/source-manifest.json'
MAX_FILE = 16 * 1024**2
MAX_TOTAL = 128 * 1024**2


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fields(value, names):
    require(type(value) is dict and set(value) == set(names), 'record_fields')


def decode(data):
    def pairs(rows):
        out = {}
        for key, value in rows:
            require(key not in out, 'duplicate_json_key')
            out[key] = value
        return out
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'nonfinite_json'))


def safe_name(name):
    require(type(name) is str and name and '\\' not in name and
            not PurePosixPath(name).is_absolute(), 'unsafe_path')
    parts = name.split('/')
    devices = {'CON', 'PRN', 'AUX', 'NUL', *('COM'+str(i) for i in range(1, 10)),
               *('LPT'+str(i) for i in range(1, 10))}
    require(all(p not in ('', '.', '..') and not p.endswith((' ', '.')) and
                not any(c in p for c in '<>:"|?*\x00') and
                p.split('.')[0].upper() not in devices for p in parts), 'unsafe_path')
    return name


def plain(path, directory=False):
    p = Path(path)
    require(p.is_absolute() and p.resolve() == p, 'noncanonical_path')
    for q in (*reversed(p.parents), p):
        s = q.lstat()
        require(not stat.S_ISLNK(s.st_mode) and
                not getattr(s, 'st_file_attributes', 0) & 0x400, 'linked_path')
    s = p.stat()
    require(stat.S_ISDIR(s.st_mode) if directory else
            stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'nonregular_input')
    return p


def read(path, limit=MAX_FILE):
    p = plain(path)
    before = p.stat()
    require(before.st_size <= limit, 'input_too_large')
    with p.open('rb') as f:
        opened = os.fstat(f.fileno())
        data = f.read(limit+1)
    after = p.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    require(identity(before) == identity(opened) == identity(after) and
            len(data) == before.st_size <= limit, 'input_changed_during_read')
    return data


def authenticated(record):
    fields(record, ('path', 'sha256'))
    require(type(record['sha256']) is str and
            re.fullmatch('[0-9a-f]{64}', record['sha256']), 'invalid_digest')
    data = read(record['path'])
    require(sha(data) == record['sha256'], 'evidence_hash')
    return data


def tree_hash(rows):
    root = {}
    for row in rows:
        parts = safe_name(row['path']).split('/')
        node = root
        for part in parts[:-1]:
            require(part not in node or type(node[part]) is dict, 'path_collision')
            node = node.setdefault(part, {})
        require(parts[-1] not in node, 'path_collision')
        node[parts[-1]] = (row['mode'], row['gitBlob'])
    def digest(node):
        data = b''
        for name, value in sorted(node.items(), key=lambda x:
                                  (x[0]+('/' if type(x[1]) is dict else '')).encode()):
            mode, value = ('40000', digest(value)) if type(value) is dict else value
            data += mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(value)
        return hashlib.sha1(b'tree '+str(len(data)).encode()+b'\0'+data).hexdigest()
    return digest(root)


def source_bytes(root, rows):
    plain(root, directory=True)
    require(type(rows) is list and bool(rows), 'source_inventory')
    require(all(type(r) is dict and type(r.get('bytes')) is int and
                0 <= r['bytes'] <= MAX_FILE for r in rows) and
            sum(r['bytes'] for r in rows) <= MAX_TOTAL, 'source_total_too_large')
    expected = {}
    folded = set()
    for row in rows:
        fields(row, ('path', 'mode', 'gitBlob', 'sha256', 'bytes'))
        name = safe_name(row['path'])
        require(name.casefold() not in folded, 'duplicate_source_path')
        folded.add(name.casefold())
        require(row['mode'] == '100644' and type(row['bytes']) is int and
                0 <= row['bytes'] <= MAX_FILE and
                re.fullmatch('[0-9a-f]{40}', row['gitBlob'] or '') and
                re.fullmatch('[0-9a-f]{64}', row['sha256'] or ''), 'source_identity')
        data = read(root/name)
        require(len(data) == row['bytes'] and sha(data) == row['sha256'] and
                hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() ==
                row['gitBlob'], 'source_bytes')
        expected[name] = data
    actual = set()
    directories = {PurePosixPath(n).parent.as_posix() for n in expected}
    directories |= {p.as_posix() for n in expected for p in PurePosixPath(n).parents}
    for p in root.rglob('*'):
        relative = p.relative_to(root).as_posix()
        if p.is_dir():
            plain(p, directory=True)
            require(relative in directories, 'unexpected_source_directory')
        else:
            plain(p)
            actual.add(safe_name(relative))
    require(actual == set(expected), 'unexpected_or_missing_source')
    require(sum(map(len, expected.values())) <= MAX_TOTAL, 'source_total_too_large')
    return expected


def new_leaf(path):
    require(safe_name(path.name) == path.name and '/' not in path.name,
            'unsafe_output_name')
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise ValueError('new_output_required')


def qualified_archive(evidence):
    fields(evidence, ('bundle', 'manifestSHA256', 'provenance'))
    archive = authenticated(evidence['bundle'])
    provenance = decode(authenticated(evidence['provenance']))
    require(provenance.get('status') == 'PASS_NORMALIZED_CONTENT_EQUIVALENCE' and
            provenance.get('rawHashEqualityClaimed') is False and
            type(provenance.get('records')) is list and len(provenance['records']) == 17,
            'provenance_scope')
    payloads = {}
    folded = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:*') as t:
        for count, member in enumerate(t, 1):
            require(count <= 1024, 'archive_member_limit')
            name = safe_name(member.name)
            require(member.isfile() and name.casefold() not in folded and
                    0 <= member.size <= MAX_FILE, 'archive_member')
            folded.add(name.casefold())
            total += member.size
            require(total <= MAX_TOTAL, 'archive_total_too_large')
            if name == MANIFEST_MEMBER or name.startswith(PREFIX):
                data = t.extractfile(member).read(MAX_FILE+1)
                require(len(data) == member.size, 'archive_length')
                payloads[name] = data
    require(MANIFEST_MEMBER in payloads and
            sha(payloads[MANIFEST_MEMBER]) == evidence['manifestSHA256'],
            'qualified_manifest_identity')
    manifest = decode(payloads.pop(MANIFEST_MEMBER))
    require(type(manifest) is list and len(manifest) == 97, 'qualified_manifest_scope')
    qualified = {}
    folded = set()
    for row in manifest:
        fields(row, ('path', 'sha256', 'size', 'mode'))
        name = safe_name(row['path'])
        require(name.casefold() not in folded and row['mode'] == '0644' and
                type(row['size']) is int and 0 <= row['size'] <= MAX_FILE,
                'qualified_manifest_record')
        folded.add(name.casefold())
        data = payloads.get(PREFIX+name)
        require(data is not None and len(data) == row['size'] and
                sha(data) == row['sha256'], 'qualified_source_identity')
        qualified[name] = data
    require(set(payloads) == {PREFIX+n for n in qualified}, 'qualified_source_coverage')
    return qualified, provenance


def prepare(authority_path, approved_sha256, capability):
    require(_BOOTSTRAP_CAPABILITY is not None and
            capability is _BOOTSTRAP_CAPABILITY, 'EXTERNAL_BOOTSTRAP_REQUIRED')
    authority_path = plain(authority_path)
    require(not authority_path.is_relative_to(REPOSITORY), 'repository_authority_rejected')
    authority_raw = read(authority_path)
    require(type(approved_sha256) is str and sha(authority_raw) == approved_sha256,
            'authority_identity')
    a = decode(authority_raw)
    fields(a, ('schemaVersion', 'contractID', 'preparer', 'sourceRoot', 'sourceCommit',
               'sourceTree', 'commitRecord', 'files', 'mappings', 'evidence',
               'workspaceRoot', 'outputRoot', 'receiptPath'))
    require(type(a['schemaVersion']) is int and a['schemaVersion'] == 1 and
            a['contractID'] == CONTRACT, 'authority_scope')
    require(Path(a['preparer']['path']) == Path(__file__).absolute() and
            authenticated(a['preparer']) == read(Path(__file__).absolute()),
            'preparer_identity')
    source = plain(a['sourceRoot'], directory=True)
    workspace = plain(a['workspaceRoot'], directory=True)
    output = Path(a['outputRoot'])
    receipt = Path(a['receiptPath'])
    require(output.is_absolute() and receipt.is_absolute() and
            output.absolute() == output and receipt.absolute() == receipt and
            output != receipt and
            output.parent == workspace and receipt.parent == workspace,
            'new_output_required')
    new_leaf(output)
    new_leaf(receipt)
    plain(output.parent, directory=True)
    plain(receipt.parent, directory=True)
    for protected in (source, REPOSITORY, authority_path.parent):
        require(not output.is_relative_to(protected) and not protected.is_relative_to(output),
                'output_overlap')
    require(not receipt.is_relative_to(source) and not receipt.is_relative_to(REPOSITORY) and
            not receipt.is_relative_to(output), 'receipt_overlap')
    require(not authority_path.is_relative_to(source), 'repository_authority_rejected')
    fields(a['evidence'], ('bundle', 'manifestSHA256', 'provenance'))
    for item in (a['commitRecord'], a['evidence']['bundle'], a['evidence']['provenance']):
        evidence_path = Path(item['path'])
        require(evidence_path.is_absolute() and not evidence_path.is_relative_to(source)
                and not evidence_path.is_relative_to(REPOSITORY),
                'repository_evidence_rejected')
    for protected in (source, REPOSITORY, authority_path.parent,
                      *(Path(item['path']).parent for item in
                        (a['commitRecord'], a['evidence']['bundle'], a['evidence']['provenance']))):
        require(not workspace.is_relative_to(protected) and
                not protected.is_relative_to(workspace), 'workspace_overlap')
    commit = authenticated(a['commitRecord'])
    require(type(a['sourceCommit']) is str and re.fullmatch('[0-9a-f]{40}', a['sourceCommit']) and
            hashlib.sha1(b'commit '+str(len(commit)).encode()+b'\0'+commit).hexdigest() ==
            a['sourceCommit'] and commit.splitlines()[0] == b'tree '+a['sourceTree'].encode(),
            'commit_tree_identity')
    raw = source_bytes(source, a['files'])
    require(tree_hash(a['files']) == a['sourceTree'], 'source_tree_identity')
    qualified, provenance = qualified_archive(a['evidence'])
    maps = a['mappings']
    require(type(maps) is list and len(maps) == 17, 'mapping_coverage')
    trusted = {}
    for row in provenance['records']:
        name = safe_name(row['path'])
        require(name.casefold() not in {p.casefold() for p in trusted}, 'duplicate_provenance')
        trusted[name] = row
    require(len(trusted) == 17, 'mapping_coverage')
    replacements = {}
    for row in maps:
        fields(row, ('path', 'gitSHA256', 'gitBytes', 'qualifiedSHA256', 'qualifiedBytes',
                     'sourceMember'))
        name = safe_name(row['path'])
        require(name.casefold() not in {p.casefold() for p in replacements} and
                name in trusted and name in raw and name in qualified,
                'mapping_path')
        original = qualified[name]
        require(type(row['gitBytes']) is int and type(row['qualifiedBytes']) is int and
                row['sourceMember'] == PREFIX+name and
                row['gitSHA256'] == trusted[name]['stagedBlobSHA256'] == sha(raw[name]) and
                row['qualifiedSHA256'] == trusted[name]['qualifiedWorkingSHA256'] == sha(original)
                and row['gitBytes'] == len(raw[name]) and row['qualifiedBytes'] == len(original),
                'mapping_identity')
        # Compare only to prove the reviewed pair; OUTPUT is copied original bytes.
        require(original != raw[name] and original.replace(b'\r\n', b'\n') == raw[name],
                'mapping_equivalence')
        replacements[name] = original
    require(set(replacements) == set(trusted), 'mapping_coverage')
    # All authority, source and evidence checks complete before any output creation.
    output.mkdir(mode=0o700)
    if os.name == 'posix':
        os.chmod(output, 0o700)
        require(stat.S_IMODE(output.stat().st_mode) == 0o700, 'output_root_mode')
    results = []
    for row in a['files']:
        name = row['path']
        data = replacements.get(name, raw[name])
        p = output/name
        p.parent.mkdir(parents=True, exist_ok=True)
        if os.name == 'posix':
            for parent in p.parents:
                if parent == output:
                    break
                os.chmod(parent, 0o755)
        with p.open('xb') as f:
            f.write(data)
        if os.name == 'posix':
            os.chmod(p, 0o644)
        require(read(p) == data, 'output_bytes')
        results.append({'path': name, 'sha256': sha(data), 'bytes': len(data),
                        'gitInputSHA256': row['sha256'], 'restored': name in replacements})
    require(source_bytes(source, a['files']) == raw, 'source_changed')
    prepared_rows = []
    for row in results:
        data = replacements.get(row['path'], raw[row['path']])
        prepared_rows.append({'path': row['path'], 'mode': '100644',
                              'gitBlob': hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),
                              'sha256': row['sha256'], 'bytes': row['bytes']})
    require(source_bytes(output, prepared_rows) == {**raw, **replacements},
            'final_output_identity')
    if os.name == 'posix':
        require(stat.S_IMODE(output.stat().st_mode) == 0o700 and
                all(stat.S_IMODE(p.stat().st_mode) == (0o755 if p.is_dir() else 0o644)
                    for p in output.rglob('*')), 'final_output_modes')
    result = {'schemaVersion': 1, 'status': 'QUALIFIED_BYTES_PREPARED',
              'authoritySHA256': approved_sha256, 'preparerSHA256': a['preparer']['sha256'],
              'sourceCommit': a['sourceCommit'], 'sourceTree': a['sourceTree'],
              'sourceRoot': str(source), 'outputRoot': str(output),
              'qualifiedSourceManifestSHA256': a['evidence']['manifestSHA256'],
              'qualificationBundleSHA256': a['evidence']['bundle']['sha256'],
              'mappingProvenanceSHA256': a['evidence']['provenance']['sha256'],
              'restoredFiles': 17, 'files': results,
              'qualificationExecuted': False, 'vulnerabilityApprovalGranted': False,
              'posixModesEnforced': os.name == 'posix'}
    with os.fdopen(os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                   'w', encoding='utf-8', newline='\n') as f:
        if os.name == 'posix':
            require(stat.S_IMODE(os.fstat(f.fileno()).st_mode) == 0o600, 'receipt_mode')
        json.dump(result, f, indent=2)
        f.write('\n')
    return result


if __name__ == '__main__':
    raise SystemExit('EXTERNAL_BOOTSTRAP_REQUIRED')
