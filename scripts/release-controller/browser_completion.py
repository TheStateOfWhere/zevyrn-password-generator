"""Read-only, clipboard-specific completion relationship. No phase executor.

All documents supplied here must first be authenticated against the sealed
proposal authority. Semantic checks are separate to permit defensive unit tests.
"""
import datetime as dt
import hashlib
import re
from pathlib import Path


def evaluate(v, a, browser, cleanup, now):
    require, decode, stamp = v['require'], v['decode'], v['timestamp']
    b = decode(browser['BROWSER-CONSOLE-RESULTS.json'])
    receipt = decode(browser['EVIDENCE-EXECUTION-RECEIPT.json'])
    activation = decode(browser['NODE-BROWSER-ACTIVATION-RECEIPT.json'])
    c = decode(cleanup['CLEANUP-COMPLETION-RECEIPT.json'])
    proof = decode(cleanup['CLEANUP-VERIFICATION-RESULT.json'])
    spec = a['completion']
    images = {k: a['images'][k] for k in ('builder', 'runtime')}
    expected_failure = {'stage': 'synthetic-clipboard-hygiene', 'name': 'Error',
                        'code': 'NATIVE_PROCESS_FAILED'}
    for doc in (b, receipt):
        require(doc['executionID'] == spec['browserExecutionID'] and
                doc['scope'] == 'SIX_CASE_CONSOLE_PAGEERROR_EVIDENCE_ONLY', 'CONSOLE_SCOPE')
    for doc in (b, receipt, activation, c, proof):
        require(doc['sourceManifestSHA256'] == a['sourceManifestSHA256'] and
                doc['images'] == images, 'COMPLETION_SOURCE_IMAGE')
    for doc in (b, receipt):
        require(doc['activationReceiptSHA256'] == spec['nodeActivationSHA256'], 'NODE_ACTIVATION')
    require(b['controllerReceiptSHA256'] == activation['activeRevision2ControllerReceiptSHA256'] ==
            a['activation']['sha256'], 'COMPLETION_CONTROLLER')
    require(activation['status'] == 'ACTIVE_SELECTION_FOR_AUTHORIZED_BROWSER_EVIDENCE' and
            activation['executionID'] == spec['browserExecutionID'] and
            activation['runtime'] == b['runtime'] == c['runtime'] == proof['runtime'] == spec['runtime'],
            'COMPLETION_RUNTIME')
    require(b['authoritySHA256'] == c['authoritySHA256'] == proof['authoritySHA256'] ==
            activation['authority']['sha256'] == spec['authoritySHA256'] and
            b['runtimeGuardSHA256'] == activation['runtimeGuard']['sha256'] == spec['guardSHA256'],
            'COMPLETION_BROWSER_AUTHORITY')
    require(b['browserVersion'] == a['retest']['browserVersion'], 'COMPLETION_BROWSER_VERSION')
    require(b['priorClipboardReceiptSHA256'] == a['retest']['receiptSHA256'], 'COMPLETION_CLIPBOARD_LINK')
    require(b['session'] == proof['session'] == spec['session'], 'COMPLETION_SESSION')
    for doc in (b, receipt):
        require(doc['clipboardAcceptanceRerun'] is False and doc['supersessionActivated'] is False and
                doc['qualificationSettled'] is False, 'COMPLETION_SCOPE_EXPANSION')
    require(b['status'] == 'BLOCKED' and b['cleanupFailure'] == receipt['cleanupFailure'] == expected_failure and
            receipt['status'] == 'BLOCKED_CLEANUP_VERIFICATION' and receipt['cleanupVerified'] is False and
            type(receipt['actualProcessExitCode']) is int and receipt['actualProcessExitCode'] == 1 and
            decode(browser['EXECUTION-EXIT.json'])['exitCode'] == 1, 'HISTORICAL_FAILURE_PRESERVED')
    require(b['cleanup'] == {'browserClosed': True, 'serverClosed': True, 'ownedContexts': 6} and
            receipt['ownedBrowserResourcesClosed'] is True, 'BROWSER_RESOURCE_CLEANUP')
    require(b['passed'] == 6 and b['failed'] == b['notExecuted'] == 0 and receipt['sixCaseAssertions'] ==
            {'failed': 0, 'passed': 6, 'consoleErrors': 0, 'notExecuted': 0,
             'allFinalAssertionsCompleted': True, 'pageErrors': 0}, 'CONSOLE_CASE_COUNTS')
    for name, key in [('BROWSER-CONSOLE-RESULTS.json', 'resultSHA256'),
                      ('browser-events.jsonl', 'journalSHA256'), ('EXECUTION-EXIT.json', 'exitSHA256')]:
        require(hashlib.sha256(browser[name]).hexdigest() == receipt[key], 'CONSOLE_RECEIPT_BINDING')
    require(receipt['collectorSHA256'] == hashlib.sha256(browser['collect-browser-console-evidence.mjs']).hexdigest(),
            'CONSOLE_COLLECTOR_BINDING')
    rows = [decode(line) for line in browser['browser-events.jsonl'].splitlines()]
    identity = {'executionID': spec['browserExecutionID'], 'sourceManifestSHA256': a['sourceManifestSHA256'],
                'images': images}
    require(len(rows) == 40 and all(r['sequence'] == i and r['identity'] == identity
                                   for i, r in enumerate(rows)), 'CONSOLE_JOURNAL_IDENTITY')
    require(rows[0]['stage'] == 'start' and rows[0]['outcome'] == 'IN_PROGRESS' and
            rows[1]['kind'] == 'session-authenticated' and rows[1]['session'] == spec['session'] and
            rows[2]['kind'] == 'headed-browser-launched' and rows[2]['version'] == b['browserVersion'],
            'CONSOLE_START_RECORDS')
    required = [(p, n) for p in ('readable', 'strong-random', 'custom-policy') for n in (1, 5)]
    require(len(b['cases']) == 6 and [(r['profile'], r['count']) for r in b['cases']] == required,
            'CONSOLE_CASE_COVERAGE')
    previous = stamp(b['startedUTC'])
    for i, case in enumerate(b['cases']):
        case_id = f'{required[i][0]}-{required[i][1]}'
        base = 3 + i * 6
        events = rows[base:base+6]
        require(case['id'] == case_id and case['status'] == 'PASS' and
                all(case[k] is True for k in ('finalAssertionsCompleted', 'loadSucceeded', 'profileVerified',
                    'countSettingVerified', 'generationVerified', 'copyInteractionCompleted',
                    'listenersStillRegisteredAtFinal', 'consoleProbeDelivered')) and
                case['consoleErrors'] == case['pageErrors'] == 0, 'CONSOLE_CASE_ASSERTIONS')
        require([r['kind'] for r in events] == ['listeners-registered', 'console-probe-delivered',
                'navigation-start', 'interactions-complete', 'final-assertions-complete', 'case-complete'] and
                all(r['caseID'] == case_id for r in events) and
                case['listenerRegistrationSequence'] == base and case['navigationStartSequence'] == base+2 and
                case['finalAssertionSequence'] == base+4, 'CONSOLE_LISTENER_ORDER')
        require(events[0]['console'] is True and events[0]['pageerror'] is True and
                events[3]['generation'] is True and events[3]['copyAction'] is True and
                events[3]['clipboardGateRetested'] is False and
                events[4]['consoleErrors'] == events[4]['pageErrors'] == 0 and
                events[4]['listenersStillRegistered'] is True and events[4]['consoleProbeDelivered'] is True and
                events[5]['status'] == 'PASS' and events[5]['lateErrorsChecked'] is True, 'CONSOLE_EVENT_ASSERTIONS')
        times = [stamp(r['UTC']) for r in events]
        require(previous <= stamp(case['startedUTC']) <= times[0] and times == sorted(times) and
                times[-1] == stamp(case['finishedUTC']), 'CONSOLE_CASE_CHRONOLOGY')
        previous = stamp(case['finishedUTC'])
    require(rows[-1]['kind'] == 'execution-complete' and rows[-1]['status'] == 'BLOCKED' and
            rows[-1]['passed'] == 6 and rows[-1]['failed'] == rows[-1]['notExecuted'] == 0 and
            stamp(rows[-1]['UTC']) == stamp(b['finishedUTC']), 'CONSOLE_FINAL_RECORD')
    require(c['schemaVersion'] == 1 and c['scope'] == 'SUBSEQUENT_CLIPBOARD_HYGIENE_COMPLETION_ONLY' and
            c['status'] == 'CLEANUP_VERIFIED_LATER_NOT_INTEGRATED' and
            c['originalExecutionID'] == proof['originalExecutionID'] == spec['browserExecutionID'] and
            c['cleanupExecutionID'] == proof['cleanupExecutionID'] == spec['cleanupExecutionID'] and
            c['receiptID'] == spec['cleanupReceiptID'], 'CLEANUP_EXECUTION_LINK')
    for field, name in [('originalExecutionReceiptSHA256', 'EVIDENCE-EXECUTION-RECEIPT.json'),
                        ('originalResultSHA256', 'BROWSER-CONSOLE-RESULTS.json'),
                        ('originalJournalSHA256', 'browser-events.jsonl'), ('originalExitSHA256', 'EXECUTION-EXIT.json')]:
        require(c[field] == hashlib.sha256(browser[name]).hexdigest(), 'CLEANUP_ORIGINAL_BINDING')
    require(c['originalFailureSelector'] == 'cleanupFailure.stage=synthetic-clipboard-hygiene' and
            c['originalFailureCode'] == expected_failure['code'] and c['originalStatusRemains'] == 'BLOCKED' and
            c['originalExitRemains'] == proof['originalExitCode'] == 1 and
            c['historicalCleanupSuccessClaimed'] is False and c['historicalClipboardStateReconstructed'] is False and
            c['freshnessAnchorsReset'] is False and c['wholeQualificationPassClaimed'] is False and
            c['qualificationSettled'] is False and c['supersessionActivated'] is False and
            c['contractIntegrationRequiresSeparateApproval'] is True and
            c['sixBrowserCases'] == {'resultsModified': False, 'rerun': 0, 'authenticatedPassed': 6},
            'CLEANUP_SCOPE_EXPANSION')
    require(c['nativeCleanupNowVerified'] is True and c['singleFreshSentinelWrite'] is True and
            proof['status'] == 'CLEANUP_VERIFIED_LATER' and proof['processExitCode'] == 0 and
            decode(cleanup['EXECUTION-EXIT.json'])['exitCode'] == 0 and
            all(proof[k] is True for k in ('cleanupVerifiedNow', 'freshReplacementVerifiedByWriter',
                'separateNativeReadVerified', 'independentWindowsReadVerified', 'independentReaderRejectsMismatch')) and
            proof['originalHistoricalCleanupSuccess'] is False and proof['originalClipboardStateReconstructed'] is False and
            proof['browserCasesRerun'] == 0 and proof['qualificationSettled'] is False, 'CLEANUP_NOT_VERIFIED')
    for key, name in [('cleanupResultSHA256', 'CLEANUP-VERIFICATION-RESULT.json'),
                      ('cleanupExitSHA256', 'EXECUTION-EXIT.json'), ('cleanupDriverSHA256', 'verify-native-cleanup.mjs'),
                      ('independentReaderSHA256', 'independent-native-read.ps1')]:
        require(c[key] == hashlib.sha256(cleanup[name]).hexdigest(), 'CLEANUP_RECEIPT_BINDING')
    for key, name in [('seed', 'fresh-seed.stdout.json'), ('nativeRead', 'separate-native-read.stdout.json'),
                      ('independentWindowsRead', 'independent-positive-read.stdout.json')]:
        require(c['proofs'][key] == hashlib.sha256(cleanup[name]).hexdigest(), 'CLEANUP_PROOF_BINDING')
        p = decode(cleanup[name])
        require(p['passed'] is True and p['expectedSHA256'] == c['sentinelSHA256'], 'CLEANUP_EQUALITY')
        if key != 'independentWindowsRead':
            require(p['rawExact'] is True and p['matches'] is True and p['mode'] == 'STRICT' and
                    p['observedSHA256'] == c['sentinelSHA256'] and p['session'] == spec['session'] and
                    13 in p['diagnostics']['formats'] and p['operations'] and
                    all(op['succeeded'] is True and op['win32Error'] == 0 for op in p['operations']), 'CLEANUP_NATIVE_PROOF')
        else:
            require(p['exactMatch'] is True and p['contentsLogged'] is False and p['commandType'] == 'Cmdlet',
                    'CLEANUP_INDEPENDENT_PROOF')
    require(proof['activationReceiptSHA256'] == spec['nodeActivationSHA256'] and
            proof['nativeHelperSHA256'] == c['nativeHelperSHA256'] == spec['nativeHelperSHA256'], 'CLEANUP_HELPER')
    require(proof['originalResultSHA256'] == c['originalResultSHA256'] and
            proof['originalExitSHA256'] == c['originalExitSHA256'], 'CLEANUP_RESULT_BINDING')
    require(previous <= stamp(b['finishedUTC']) <= stamp(receipt['UTC']) < stamp(proof['startedUTC']) <=
            stamp(proof['finishedUTC']) == stamp(c['verifiedCleanupCompletedUTC']) <= now,
            'COMPLETION_CHRONOLOGY')
    for end in (b['finishedUTC'], proof['finishedUTC']):
        require(0 <= (now-stamp(end)).total_seconds() <= a['freshnessSeconds'], 'STALE_COMPLETION')
    return {'consoleCasesAuthenticated': 6, 'laterCleanupAuthenticated': True,
            'originalBrowserExecutionStatus': 'BLOCKED', 'originalBrowserExitCode': 1,
            'historicalCleanupSuccessClaimed': False, 'consoleExecutionID': spec['browserExecutionID'],
            'cleanupExecutionID': spec['cleanupExecutionID'], 'freshnessAnchorsReset': False}


def authenticate_and_evaluate(v, a, now, claim):
    """All runtime/reader/controller files are authenticated before any code load."""
    spec = a['completion']
    phases = {'preflight','scan','scan-acceptance','reuse','audit','acceptance',
              'runtime-creation','runtime-collection','runtime-removal',
              'browser-creation','browser-collection','browser-removal'}
    records = spec['controllerRecords']
    v['require'](type(records) is dict and set(records) == phases,
                 'CONTROLLER_RECORD_COVERAGE')
    for phase, pins in records.items():
        v['require'](type(pins) is dict and set(pins) ==
                     {phase+'-attempt.json',phase+'-completed.json'} and
                     all(type(h) is str and re.fullmatch('[0-9a-f]{64}', h)
                         for h in pins.values()), 'CONTROLLER_RECORD_IDENTITY')
    bundles = {}
    for key in ('browser', 'cleanup'):
        s = spec[key]
        manifest = v['read_json'](Path(s['root']) / 'final-evidence-inventory.json', s['inventorySHA256'])
        rows = manifest.get('files', manifest.get('records'))
        bundles[key] = v['inventory'](s['root'], {'files': rows}, s['records'])
    for key, name, field in (
            ('browser', 'EVIDENCE-EXECUTION-RECEIPT.json', 'consoleReceiptSHA256'),
            ('cleanup', 'CLEANUP-COMPLETION-RECEIPT.json', 'cleanupReceiptSHA256')):
        v['require'](hashlib.sha256(bundles[key][name]).hexdigest() == claim[field],
                     'COMPLETION_RECEIPT_CLAIM_BINDING')
    for anchor in spec['anchors']:
        v['authenticated_bytes'](anchor['path'], anchor['sha256'])
    result = evaluate(v, a, bundles['browser'], bundles['cleanup'], now)
    # Reuse the existing controller's exact completion verifier, never dispatch a
    # handler or import its qualification dependencies. These are genuine original
    # predecessor/removal records, not synthetic browser-testing completion.
    scope = {'__file__': a['controller']['path'], '__name__': 'authenticated_completion_reader'}
    data = v['authenticated_bytes'](a['controller']['path'], a['controller']['sha256'])
    exec(compile(data, a['controller']['path'], 'exec'), scope)
    v['require']({p.name for p in Path(a['originalRoot']).glob('*-failed.json')} ==
                 {'browser-testing-failed.json'}, 'UNRELATED_QUALIFICATION_FAILURE')
    for phase, pins in spec['controllerRecords'].items():
        for name, digest in pins.items():
            v['authenticated_bytes'](Path(a['originalRoot']) / name, digest)
        scope['completed'](Path(a['originalRoot']), phase)
    result['mandatoryControllerRecordsVerified'] = list(spec['controllerRecords'])
    return result
