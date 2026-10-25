"""Isolated, read-only clipboard evidence proposal. No phase execution or approval.

The pinned authority is review input, not an activated controller identity. A
successful assessment permits only a proposed clipboard-gate relationship.
It authenticates a supplemental browser relationship, never an original completion receipt.
"""
import datetime as dt
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from runtime_context import active,authority_document
from types import MappingProxyType

_HISTORICAL_BROWSER_TOOLS=MappingProxyType({})

def historical_browser_tools(document,authority_sha,anchors):
    """Relocate only byte-identical old browser executables, never their identities."""
    require(type(document) is dict and set(document)=={'scope','authoritySHA256','files'} and
            document['scope']=='historical-browser-tool-copies-v1' and type(document['files']) is list,
            'HISTORICAL_TOOL_COPY_SCOPE')
    require(document['authoritySHA256']==authority_sha,'HISTORICAL_TOOL_COPY_AUTHORITY')
    allowed={str(Path(r['path']).absolute()).casefold():r['sha256'] for r in anchors if Path(r['path']).name.lower() in ('node.exe','msedge.exe')}
    require(len(allowed)==2 and len(document['files'])==2,'HISTORICAL_TOOL_COPY_COVERAGE')
    result={};names=set()
    for row in document['files']:
        require(type(row) is dict and set(row)=={'originalPath','path','sha256'},'HISTORICAL_TOOL_COPY_RECORD')
        original=Path(row['originalPath']);copy=Path(row['path'])
        require(original.is_absolute() and copy.is_absolute() and original.name.lower() in ('node.exe','msedge.exe')
                and original.name.lower() not in names and HEX.fullmatch(row['sha256']), 'HISTORICAL_TOOL_COPY_IDENTITY')
        require(allowed.get(str(original.absolute()).casefold())==row['sha256'],'HISTORICAL_TOOL_COPY_ORIGINAL_BINDING')
        names.add(original.name.lower())
        data=no_links(copy).read_bytes()
        require(hashlib.sha256(data).hexdigest()==row['sha256'],'HISTORICAL_TOOL_COPY_HASH')
        result[(str(original.absolute()).casefold(),row['sha256'])]=copy
    return MappingProxyType(result)

AUTHORITY_SHA256 = 'd6db9ade8ca1a722609aef49f660624c50fb440e7b180414f355cffa61e54106'
HEX = re.compile(r'[0-9a-f]{64}\Z')


class EvidenceError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise EvidenceError(code)


def no_links(path):
    """Inspect the supplied spelling before canonicalization; reject reparse points."""
    path = Path(path).absolute()
    for component in [*reversed(path.parents), path]:
        info = component.lstat()  # inaccessible/missing components fail closed
        require(not stat.S_ISLNK(info.st_mode) and
                not getattr(info, 'st_file_attributes', 0) & 0x400,
                'LINKED_EVIDENCE_PATH')
    return path


def authenticated_bytes(path, expected):
    require(isinstance(expected, str) and HEX.fullmatch(expected), 'INVALID_HASH')
    path = _HISTORICAL_BROWSER_TOOLS.get((str(Path(path).absolute()).casefold(),expected),Path(path))
    path = no_links(path)
    require(path.is_file(), 'NOT_EVIDENCE_FILE')
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == expected, 'EVIDENCE_HASH_MISMATCH')
    return data


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def decode(data):
    return json.loads(data.decode('utf-8-sig'), object_pairs_hook=_pairs,
                      parse_constant=lambda _: require(False, 'NONFINITE_JSON'))


def read_json(path, expected):
    return decode(authenticated_bytes(path, expected))


def inventory(root, manifest, expected_count=None):
    rows = manifest['files']
    require(isinstance(rows, list) and rows, 'MISSING_INVENTORY')
    if expected_count is not None:
        require(len(rows) == expected_count, 'INVENTORY_COUNT')
    result, names = {}, set()
    for row in rows:
        name = row['path']
        require(isinstance(name, str) and name and '\\' not in name and ':' not in name,
                'UNSAFE_INVENTORY_PATH')
        parts = name.split('/')
        require(not PurePosixPath(name).is_absolute() and
                all(p not in ('', '.', '..') and not p.endswith((' ', '.')) for p in parts),
                'UNSAFE_INVENTORY_PATH')
        require(name.casefold() not in names, 'DUPLICATE_INVENTORY_PATH')
        names.add(name.casefold())
        data = authenticated_bytes(Path(root).joinpath(*parts), row['sha256'])
        if 'bytes' in row:
            require(type(row['bytes']) is int and len(data) == row['bytes'], 'EVIDENCE_SIZE')
        result[name] = data
    return result


def timestamp(value):
    stamp = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(stamp.tzinfo is not None and stamp.utcoffset() == dt.timedelta(0), 'UTC_REQUIRED')
    return stamp


def _claim(authority, document):
    require(isinstance(document, dict) and set(document) == {'claims'}, 'CLAIM_STRUCTURE')
    claims = document['claims']
    require(isinstance(claims, list) and len(claims) == 1, 'CONFLICTING_OR_MISSING_CLAIMS')
    expected = {
        'contractID': authority['contractID'], 'scope': 'CLIPBOARD_GATE_ONLY',
        'originalExecutionID': authority['originalExecutionID'],
        'qualificationRunID': authority['originalRunID'], 'gate': authority['gate'],
        'failureSHA256': authority['boundOriginal']['browser-testing-failed.json'],
        'retestExecutionID': authority['retest']['executionID'],
        'retestReceiptSHA256': authority['retest']['receiptSHA256'],
        'sourceManifestSHA256': authority['sourceManifestSHA256'], 'images': authority['images'],
        'consoleExecutionID': authority['completion']['browserExecutionID'],
        'consoleReceiptSHA256': '4a04dda72b2a777b63a280f20b9fb2aa3ec937e488c81f7d4dfa67ac55606a19',
        'cleanupReceiptSHA256': '09845d71aaf5bb3316db825a175e66fa59a56ab5fdf7e20410003017d061f22e'}
    require(claims[0] == expected, 'CLAIM_SCOPE_OR_IDENTITY_MISMATCH')
    return claims[0]


def _semantics(a, original, receipt, result, identity, process, matrix, now):
    """Only accepts objects already authenticated by assess(); unit-test boundary."""
    attempt = decode(original['browser-testing-attempt.json'])
    failure = decode(original['browser-testing-failed.json'])
    for record in (attempt, decode(original['browser-collection-completed.json'])):
        require(record['executionID'] == a['originalExecutionID'] and
                record['qualificationRunID'] == a['originalRunID'] and
                record['sourceManifestSHA256'] == a['sourceManifestSHA256'] and
                record['images'] == a['images'], 'ORIGINAL_IDENTITY')
    require(failure['executionID'] == a['originalExecutionID'] and
            failure['exception'] == 'ValueError' and
            failure['message'] == 'Browser acceptance process failed', 'WRONG_ORIGINAL_FAILURE')
    require(decode(original['browser-launcher-exit.json']) == {'exitCode': 1}, 'ORIGINAL_EXIT')
    # Exact authenticated traceback is checked without returning its sensitive assertion values.
    require(b'browser-acceptance.mjs:79:' in original['browser-launcher.stderr.log'],
            'FAILURE_LOCATION')
    for record in (receipt, result, identity):
        require(record['executionID'] == a['retest']['executionID'] and
                record['sourceManifestSHA256'] == a['sourceManifestSHA256'] and
                record['images'] == {k: a['images'][k] for k in ('builder', 'runtime')},
                'RETEST_IDENTITY')
    require(receipt['controllerActivationReceiptSHA256'] == a['activation']['sha256'] and
            result['controllerActivationReceiptSHA256'] == a['activation']['sha256'] and
            identity['controllerActivationReceipt'] == a['activation']['sha256'],
            'CONTROLLER_IDENTITY')
    require(receipt['status'] == result['status'] == 'PASS' and
            receipt['scope'] == result['scope'] == 'CLIPBOARD_ACCEPTANCE_ONLY' and
            receipt['settlementPerformed'] is False and result['qualificationSettled'] is False,
            'RETEST_SCOPE_OR_STATUS')
    require(type(process['processExitCode']) is int and process['processExitCode'] == 0 and
            type(result['processExitCode']) is int and result['processExitCode'] == 0,
            'RETEST_PROCESS_FAILED')
    require(result['matrix']['passed'] == matrix['passed'] == 59 and
            result['matrix']['failed'] == matrix['failed'] == 0 and
            result['matrix']['skipped'] == matrix['skipped'] == 0 and
            result['diagnosticControls'] == {'passed': 19, 'failed': 0, 'skipped': 0},
            'INCOMPLETE_RETEST_MATRIX')
    require(len(result['matrix']['cases']) == 59 and
            all(r['status'] == 'PASS' for r in result['matrix']['cases']), 'RETEST_CASE_FAILED')
    require(result['browserVersion'] == matrix['browserVersion'] == a['retest']['browserVersion'],
            'BROWSER_IDENTITY')
    session = result['session']
    require(session == matrix['session'] and session['interactive'] is True and
            session['sid'] == 'S-1-5-21-76887336-2434538660-3912857034-1602' and
            session['sessionId'] == 1 and session['station'] == 'WinSta0' and
            session['desktop'] == session['inputDesktop'] == 'Default' and
            session['apartment'] == 'STA' and session['state'] == session['protocol'] == 0,
            'SESSION_IDENTITY')
    required = {f'unchanged application {profile} count {count}'
                for profile in ('readable', 'strong-random', 'custom-policy') for count in (1, 5)}
    proofs = [p for p in result['positiveProofs'] if p['case'].startswith('unchanged application ')]
    require(len(proofs) == 6 and {p['case'] for p in proofs} == required, 'MISSING_CLIPBOARD_CASE')
    for p in proofs:
        mode = 'STRICT' if p['case'].endswith('1') else 'CRLF_TO_LF_OBSERVATION_ONLY'
        require(all(p[k] is True for k in ('nativeEquality', 'freshCopy', 'trustedKeyboardPaste')) and
                p['status'] == 'PASS' and p['comparisonMode'] == mode and 13 in p['formats'],
                'CLIPBOARD_PROOF_FAILED')
        # Sequence/owner observations remain authenticated diagnostics, not new
        # acceptance thresholds. Native equality and trusted paste stay mandatory.
    start, end = timestamp(result['startedUTC']), timestamp(result['finishedUTC'])
    require(timestamp(failure['utc']) < start <= end <= timestamp(receipt['UTC']) <= now,
            'EVIDENCE_CHRONOLOGY')
    require(0 <= (now - end).total_seconds() <= a['freshnessSeconds'], 'STALE_RETEST')
    require(matrix['startedUTC'] == result['startedUTC'] and
            timestamp(matrix['finishedUTC']) == end, 'EXECUTION_TIME_BINDING')


def assess(claim_path):
    """Read-only eligibility assessment. Never writes/dispatches qualification phases."""
    global _HISTORICAL_BROWSER_TOOLS
    ctx=active()
    _HISTORICAL_BROWSER_TOOLS=MappingProxyType({})
    descriptor=ctx.authority('supersession')
    a = read_json(Path(descriptor['path']), descriptor['sha256'])
    if 'historicalBrowserTools' in ctx.profile()['records']:
        _HISTORICAL_BROWSER_TOOLS=historical_browser_tools(authority_document('historicalBrowserTools'),descriptor['sha256'],a['completion']['anchors'])
    document = decode(no_links(claim_path).read_bytes())
    claim = _claim(a, document)
    for anchor in ('activation', 'controller', 'originalHarness'):
        authenticated_bytes(a[anchor]['path'], a[anchor]['sha256'])
    activation = read_json(a['activation']['path'], a['activation']['sha256'])
    require(str(Path(sys.executable)) == activation['runtime']['path'], 'INTERPRETER_PATH')
    authenticated_bytes(sys.executable, activation['runtime']['sha256'])
    require(len(activation['approvedArtifacts']) == 9, 'CONTROLLER_GRAPH_COUNT')
    for artifact in activation['approvedArtifacts']:
        authenticated_bytes(artifact['path'], artifact['sha256'])
    h = a['historicalManifest']
    historical = read_json(h['path'], h['sha256'])
    history = inventory(h['root'], historical, 2120)
    f = a['failureManifest']
    original = inventory(a['originalRoot'], read_json(f['path'], f['sha256']), f['records'])
    for name, digest in a['boundOriginal'].items():
        data = authenticated_bytes(Path(a['originalRoot']) / name, digest)
        if name not in original:
            key = 'before-browser/' + a['originalExecutionID'] + '/' + name
            require(key in history and history[key] == data, 'UNBOUND_ORIGINAL_RECORD')
        original[name] = data
    suites = []
    for suite in a['unaffectedSuites']:
        out = original['browser-workspace/' + suite + '.stdout.log']
        err = original['browser-workspace/' + suite + '.stderr.log']
        require(out.startswith(b'PASS:') and not err, 'INCOMPLETE_UNAFFECTED_SUITE')
        suites.append({'suite': suite, 'basis': 'authenticated sequential harness, later traceback and PASS log',
                       'originalCompletionReceiptCreated': False})
    r = a['retest']; root = Path(r['root'])
    records = inventory(root, read_json(root / 'final-evidence-inventory.json', r['inventorySHA256']))
    receipt = decode(records['ACCEPTANCE-RETEST-RECEIPT.json'])
    require(hashlib.sha256(records['ACCEPTANCE-RETEST-RECEIPT.json']).hexdigest() == r['receiptSHA256'],
            'RETEST_RECEIPT_HASH')
    for name, key in [('clipboard-acceptance-result.json', 'resultSHA256'),
                      ('execution-identity.json', 'executionIdentitySHA256')]:
        require(hashlib.sha256(records[name]).hexdigest() == receipt[key], 'RECEIPT_BINDING')
    require(receipt['reviewedRevision3InventorySHA256'] == r['harnessInventorySHA256'], 'HARNESS_AUTHORITY')
    result = decode(records['clipboard-acceptance-result.json'])
    prefix = 'exact-reviewed-harness/runs/acceptance-retest-01/'
    for name, key in [('clipboard-observations.jsonl', 'journal'), ('harness-test-results.json', 'results')]:
        require(hashlib.sha256(records[prefix + name]).hexdigest() == result['evidenceHashes'][key],
                'RETEST_EXECUTION_BINDING')
    _semantics(a, original, receipt, result, decode(records['execution-identity.json']),
               decode(records['retest-process-exit.json']), decode(records[prefix + 'harness-test-results.json']),
               dt.datetime.now(dt.timezone.utc))
    module = Path(__file__).with_name('browser_completion.py')
    data = authenticated_bytes(module, 'bd5a29cd41848ce89a7add5e62394ca105e96fa2f3e4fca1b2295a2e88b32877')
    scope = {'__file__': str(module), '__name__': 'authenticated_browser_completion'}
    exec(compile(data, str(module), 'exec'), scope)
    completion = scope['authenticate_and_evaluate'](globals(), a, dt.datetime.now(dt.timezone.utc), claim)
    return {'contractID': a['contractID'], 'status': 'PROPOSED_BROWSER_EVIDENCE_ELIGIBLE',
            'active': False, 'originalResult': 'FAILED_PRESERVED', 'gate': a['gate'],
            'failureSHA256': a['boundOriginal']['browser-testing-failed.json'],
            'retestReceiptSHA256': r['receiptSHA256'], 'sourceManifestSHA256': a['sourceManifestSHA256'],
            'images': a['images'], 'unaffectedSuiteAssessment': suites,
            'mandatoryConsoleCompletion': 'AUTHENTICATED_SEPARATE_EXECUTION_AND_LATER_CLEANUP',
            'completion': completion, 'browserEvidenceEligible': True,
            'browserPhaseComplete': False, 'settlementAllowed': False,
            'historicalRecordsWritten': 0, 'otherQualificationGatesSuperseded': [],
            'historicalToolCopiesAuthoritySHA256': ctx.authority('historicalBrowserTools')['sha256'] if _HISTORICAL_BROWSER_TOOLS else None,
            'historicalToolCopies': [{'originalPath':p,'preservedPath':str(v),'sha256':h,'authoritySHA256':descriptor['sha256']}
                                    for (p,h),v in _HISTORICAL_BROWSER_TOOLS.items()]}
