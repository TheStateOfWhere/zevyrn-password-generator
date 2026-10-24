"""Offline defensive tests; no browser, qualification handler, subprocess or Docker."""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).parent
V = runpy.run_path(str(HERE / 'clipboard_supersession.py'))
Error = V['EvidenceError']


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = V['read_json'](HERE / 'supersession-authority.PROPOSED.json', V['AUTHORITY_SHA256'])
        cls.claim = json.loads((HERE / 'clipboard-claim.PROPOSED.json').read_text(encoding='utf-8-sig'))
        cls.assessment = V['assess'](HERE / 'clipboard-claim.PROPOSED.json')
        a = cls.a
        root = Path(a['originalRoot'])
        original = {n: V['authenticated_bytes'](root / n, h) for n, h in a['boundOriginal'].items()}
        retest = Path(a['retest']['root'])
        inv = V['read_json'](retest / 'final-evidence-inventory.json', a['retest']['inventorySHA256'])
        records = V['inventory'](retest, inv)
        cls.objects = [a, original, V['decode'](records['ACCEPTANCE-RETEST-RECEIPT.json']),
                       V['decode'](records['clipboard-acceptance-result.json']),
                       V['decode'](records['execution-identity.json']),
                       V['decode'](records['retest-process-exit.json']),
                       V['decode'](records['exact-reviewed-harness/runs/acceptance-retest-01/harness-test-results.json']),
                       dt.datetime.now(dt.timezone.utc)]

    def test_actual_link_eligible_only(self):
        self.assertEqual(self.assessment['status'], 'PROPOSED_BROWSER_EVIDENCE_ELIGIBLE')
        self.assertFalse(self.assessment['active'])
        self.assertFalse(self.assessment['settlementAllowed'])
        self.assertFalse(self.assessment['browserPhaseComplete'])

    def test_historical_failure_visible(self):
        self.assertEqual(self.assessment['originalResult'], 'FAILED_PRESERVED')
        self.assertEqual(self.assessment['historicalRecordsWritten'], 0)

    def test_nine_suites_derived_not_fabricated(self):
        suites = self.assessment['unaffectedSuiteAssessment']
        self.assertEqual([x['suite'] for x in suites], self.a['unaffectedSuites'])
        self.assertTrue(all(x['originalCompletionReceiptCreated'] is False for x in suites))

    def test_no_unrelated_supersession(self):
        self.assertEqual(self.assessment['otherQualificationGatesSuperseded'], [])
        self.assertEqual(self.assessment['gate'], 'browser-testing.realClipboardPasteBack')

    def test_browser_boundary_does_not_grant_full_settlement(self):
        adapter = runpy.run_path(str(HERE / 'settlement_supersession.py'))
        result = adapter['require_settlement'](HERE / 'clipboard-claim.PROPOSED.json')
        self.assertTrue(result['browserEvidenceEligible'])
        self.assertFalse(result['settlementAllowed'])
        self.assertFalse(result['browserPhaseComplete'])

    def test_actual_semantics(self):
        V['_semantics'](*copy.deepcopy(self.objects))

    def test_claim_exact(self):
        V['_claim'](self.a, self.claim)

    def test_nonfinite_json(self):
        with self.assertRaisesRegex(Error, '^NONFINITE_JSON$'):
            V['decode'](b'{"x":NaN}')

    def test_duplicate_json_key(self):
        with self.assertRaisesRegex(Error, '^DUPLICATE_JSON_KEY$'):
            V['decode'](b'{"claims":[],"claims":[]}')

    def test_missing_manifest_data(self):
        with self.assertRaises(KeyError):
            V['inventory'](HERE, {})

    def test_empty_inventory(self):
        with self.assertRaisesRegex(Error, '^MISSING_INVENTORY$'):
            V['inventory'](HERE, {'files': []})

    def test_file_authentication_positive_and_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'ordinary-evidence.json'
            data = b'{"fixture":"nonexecutable"}'
            file.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            self.assertEqual(V['authenticated_bytes'](file, digest), data)
            file.write_bytes(data + b' ')
            with self.assertRaisesRegex(Error, '^EVIDENCE_HASH_MISMATCH$'):
                V['authenticated_bytes'](file, digest)

    def test_missing_historical_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                V['authenticated_bytes'](Path(tmp) / 'absent', '0' * 64)

    def test_size_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'record'; p.write_bytes(b'{}')
            row = {'path': 'record', 'sha256': hashlib.sha256(b'{}').hexdigest(), 'bytes': 3}
            with self.assertRaisesRegex(Error, '^EVIDENCE_SIZE$'):
                V['inventory'](tmp, {'files': [row]})

    def test_duplicate_inventory_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'record'; p.write_bytes(b'{}')
            row = {'path': 'record', 'sha256': hashlib.sha256(b'{}').hexdigest()}
            with self.assertRaisesRegex(Error, '^DUPLICATE_INVENTORY_PATH$'):
                V['inventory'](tmp, {'files': [row, row]})

    def test_completion_requires_separate_authenticated_execution(self):
        self.assertEqual(self.assessment['mandatoryConsoleCompletion'], 'AUTHENTICATED_SEPARATE_EXECUTION_AND_LATER_CLEANUP')
        self.assertEqual(self.assessment['completion']['consoleCasesAuthenticated'], 6)

    def test_public_entry_rejects_wrong_gate_before_evidence_assessment(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'claim.json'
            document = copy.deepcopy(self.claim)
            document['claims'][0]['gate'] = 'security-scans'
            p.write_text(json.dumps(document), encoding='utf-8')
            with self.assertRaisesRegex(Error, '^CLAIM_SCOPE_OR_IDENTITY_MISMATCH$'):
                V['assess'](p)

    def test_invalid_hash_cannot_be_authority(self):
        with self.assertRaisesRegex(Error, '^INVALID_HASH$'):
            V['authenticated_bytes'](HERE / 'clipboard-claim.PROPOSED.json', None)

    def test_inventory_count_mismatch(self):
        with self.assertRaisesRegex(Error, '^INVENTORY_COUNT$'):
            V['inventory'](HERE, {'files':[{}]}, 114)


def claim_negative(name, mutate, code='CLAIM_SCOPE_OR_IDENTITY_MISMATCH'):
    def test(self):
        document = copy.deepcopy(self.claim)
        mutate(document)
        with self.assertRaisesRegex(Error, '^' + code + '$'):
            V['_claim'](self.a, document)
    setattr(ContractTests, 'test_claim_' + name, test)


for name, field, value in [
    ('wrong_gate', 'gate', 'security-scans'), ('wrong_source', 'sourceManifestSHA256', '0'*64),
    ('wrong_attempt', 'originalExecutionID', 'other'), ('wrong_run', 'qualificationRunID', 'other'),
    ('wrong_failure', 'failureSHA256', '0'*64), ('wrong_retest', 'retestExecutionID', 'other'),
    ('forged_receipt', 'retestReceiptSHA256', '0'*64), ('whole_browser_scope', 'scope', 'BROWSER_SUITE'),
    ('wrong_contract', 'contractID', 'other')]:
    claim_negative(name, lambda d, f=field, v=value: d['claims'][0].__setitem__(f, v))
claim_negative('wrong_image', lambda d: d['claims'][0]['images'].__setitem__('runtime', 'sha256:'+'0'*64))
claim_negative('extra_override', lambda d: d['claims'][0].__setitem__('override', True))
claim_negative('duplicate', lambda d: d['claims'].append(copy.deepcopy(d['claims'][0])), 'CONFLICTING_OR_MISSING_CLAIMS')
claim_negative('conflicting', lambda d: d['claims'].append({'gate':'security'}), 'CONFLICTING_OR_MISSING_CLAIMS')
claim_negative('missing', lambda d: d.__setitem__('claims', []), 'CONFLICTING_OR_MISSING_CLAIMS')


def semantic_negative(name, mutate, code):
    def test(self):
        objects = copy.deepcopy(self.objects)
        mutate(objects)
        with self.assertRaisesRegex(Error, '^' + code + '$'):
            V['_semantics'](*objects)
    setattr(ContractTests, 'test_semantic_' + name, test)


for name, idx, field, value, code in [
    ('wrong_source', 3, 'sourceManifestSHA256', '0'*64, 'RETEST_IDENTITY'),
    ('wrong_controller', 3, 'controllerActivationReceiptSHA256', '0'*64, 'CONTROLLER_IDENTITY'),
    ('failed_receipt', 2, 'status', 'FAIL', 'RETEST_SCOPE_OR_STATUS'),
    ('wrong_scope', 2, 'scope', 'ALL_BROWSER', 'RETEST_SCOPE_OR_STATUS'),
    ('already_settled', 3, 'qualificationSettled', True, 'RETEST_SCOPE_OR_STATUS'),
    ('process_failed', 5, 'processExitCode', 1, 'RETEST_PROCESS_FAILED'),
    ('browser_substituted', 3, 'browserVersion', 'other', 'BROWSER_IDENTITY')]:
    semantic_negative(name, lambda o,i=idx,f=field,v=value:o[i].__setitem__(f,v), code)
semantic_negative('failed_matrix', lambda o:o[3]['matrix'].__setitem__('failed',1), 'INCOMPLETE_RETEST_MATRIX')
semantic_negative('skipped_matrix', lambda o:o[3]['matrix'].__setitem__('skipped',1), 'INCOMPLETE_RETEST_MATRIX')
semantic_negative('missing_case', lambda o:o[3]['matrix']['cases'].pop(), 'RETEST_CASE_FAILED')
semantic_negative('failed_case', lambda o:o[3]['matrix']['cases'][0].__setitem__('status','FAIL'), 'RETEST_CASE_FAILED')
semantic_negative('wrong_session', lambda o:o[3]['session'].__setitem__('sid','other'), 'SESSION_IDENTITY')
semantic_negative('missing_clipboard_case', lambda o:o[3]['positiveProofs'].pop(), 'MISSING_CLIPBOARD_CASE')
for name, key, value in [('no_native_equality','nativeEquality',False),('no_keyboard_paste','trustedKeyboardPaste',False),
                         ('stale_copy','freshCopy',False),('missing_native_text','formats',[]),
                         ('broad_normalization','comparisonMode','TRIM')]:
    semantic_negative(name, lambda o,k=key,v=value:o[3]['positiveProofs'][3].__setitem__(k,v), 'CLIPBOARD_PROOF_FAILED')
semantic_negative('stale_retest', lambda o:o.__setitem__(7,V['timestamp'](o[3]['finishedUTC'])+dt.timedelta(days=2)), 'STALE_RETEST')
semantic_negative('future_retest', lambda o:o.__setitem__(7,V['timestamp'](o[3]['startedUTC'])-dt.timedelta(seconds=1)), 'EVIDENCE_CHRONOLOGY')
semantic_negative('time_substitution', lambda o:o[6].__setitem__('startedUTC','2026-10-22T06:39:31Z'), 'EXECUTION_TIME_BINDING')
semantic_negative('wrong_failure_location', lambda o:o[1].__setitem__('browser-launcher.stderr.log', b'other failure'), 'FAILURE_LOCATION')
semantic_negative('wrong_original_exit', lambda o:o[1].__setitem__('browser-launcher-exit.json', b'{"exitCode":0}'), 'ORIGINAL_EXIT')

for name, data in [('empty', b''), ('truncated', b'{"claims":['), ('malformed', b'notice\n{}')]:
    def invalid_json_test(self, data=data):
        with self.assertRaises(json.JSONDecodeError):
            V['decode'](data)
    setattr(ContractTests, 'test_json_' + name, invalid_json_test)

for index, name in enumerate(['../outside','/absolute','a//b','a/./b','a\\b','C:/absolute','a./b']):
    def unsafe_test(self, path=name):
        with self.assertRaisesRegex(Error, '^UNSAFE_INVENTORY_PATH$'):
            V['inventory'](HERE, {'files':[{'path':path,'sha256':'0'*64}]})
    setattr(ContractTests, f'test_unsafe_inventory_path_{index}', unsafe_test)


if __name__ == '__main__':
    unittest.main(verbosity=2)
