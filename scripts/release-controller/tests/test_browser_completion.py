"""Offline authenticated-record and ordinary fixture controls; no browser calls."""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
V = runpy.run_path(str(HERE/'clipboard_supersession.py'))
C = runpy.run_path(str(HERE/'browser_completion.py'))
Error = V['EvidenceError']


class CompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = V['read_json'](HERE/'supersession-authority.PROPOSED.json', V['AUTHORITY_SHA256'])
        cls.bundles = []
        for key in ('browser','cleanup'):
            spec = cls.a['completion'][key]
            manifest = V['read_json'](Path(spec['root'])/'final-evidence-inventory.json',spec['inventorySHA256'])
            cls.bundles.append(V['inventory'](spec['root'],{'files':manifest.get('files',manifest.get('records'))},spec['records']))

    def evaluate(self, a=None, b=None, c=None, now=None):
        return C['evaluate'](V,a or self.a,b or self.bundles[0],c or self.bundles[1],
                             now or dt.datetime.now(dt.timezone.utc))

    def test_actual_authenticated_completion(self):
        result = C['authenticate_and_evaluate'](V,self.a,dt.datetime.now(dt.timezone.utc))
        self.assertEqual(result['consoleCasesAuthenticated'],6)
        self.assertEqual(len(result['mandatoryControllerRecordsVerified']),12)
        self.assertTrue(result['laterCleanupAuthenticated'])
        self.assertEqual(result['originalBrowserExecutionStatus'],'BLOCKED')
        self.assertEqual(result['originalBrowserExitCode'],1)
        self.assertFalse(result['historicalCleanupSuccessClaimed'])

    def test_no_successful_historical_run_fabricated(self):
        result = self.evaluate()
        self.assertFalse(result['freshnessAnchorsReset'])
        self.assertEqual(result['originalBrowserExitCode'],1)

    def test_missing_cleanup_receipt(self):
        c = copy.deepcopy(self.bundles[1]); del c['CLEANUP-COMPLETION-RECEIPT.json']
        with self.assertRaises(KeyError): self.evaluate(c=c)

    def test_missing_console_journal(self):
        b = copy.deepcopy(self.bundles[0]); del b['browser-events.jsonl']
        with self.assertRaises(KeyError): self.evaluate(b=b)

    def test_changed_authenticated_file_blocks_public_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'result.json'; path.write_bytes(b'{}')
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            path.write_bytes(b'{"altered":true}')
            with self.assertRaisesRegex(Error,'^EVIDENCE_HASH_MISMATCH$'):
                V['authenticated_bytes'](path,digest)

    def test_missing_controller_record_fails_before_completion_reader(self):
        a=copy.deepcopy(self.a)
        a['completion']['controllerRecords']['audit']={'absent-completion.json':'0'*64}
        with self.assertRaises(FileNotFoundError):
            C['authenticate_and_evaluate'](V,a,dt.datetime.now(dt.timezone.utc))

    def test_altered_controller_record_fails(self):
        a=copy.deepcopy(self.a)
        a['completion']['controllerRecords']['audit']['audit-completed.json']='0'*64
        with self.assertRaisesRegex(Error,'^EVIDENCE_HASH_MISMATCH$'):
            C['authenticate_and_evaluate'](V,a,dt.datetime.now(dt.timezone.utc))

    def test_invalid_inventory_identity_fails(self):
        a=copy.deepcopy(self.a); a['completion']['cleanup']['inventorySHA256']='0'*64
        with self.assertRaisesRegex(Error,'^EVIDENCE_HASH_MISMATCH$'):
            C['authenticate_and_evaluate'](V,a,dt.datetime.now(dt.timezone.utc))

    def test_altered_external_helper_fails(self):
        a=copy.deepcopy(self.a); a['completion']['anchors'][0]['sha256']='0'*64
        with self.assertRaisesRegex(Error,'^EVIDENCE_HASH_MISMATCH$'):
            C['authenticate_and_evaluate'](V,a,dt.datetime.now(dt.timezone.utc))

    def test_unrelated_failure_blocks_public_completion_reader(self):
        original = Path.glob
        root = Path(self.a['originalRoot'])
        def glob(path, pattern):
            if path == root and pattern == '*-failed.json':
                return iter([root/'browser-testing-failed.json',root/'scan-failed.json'])
            return original(path,pattern)
        with patch.object(Path,'glob',glob):
            with self.assertRaisesRegex(Error,'^UNRELATED_QUALIFICATION_FAILURE$'):
                C['authenticate_and_evaluate'](V,self.a,dt.datetime.now(dt.timezone.utc))

    def test_claim_requires_exact_console_cleanup_relationship(self):
        claim = V['decode']((HERE/'clipboard-claim.PROPOSED.json').read_bytes())
        for key in ('consoleExecutionID','consoleReceiptSHA256','cleanupReceiptSHA256'):
            with self.subTest(field=key):
                changed=copy.deepcopy(claim); changed['claims'][0][key]='unrelated'
                with self.assertRaisesRegex(Error,'^CLAIM_SCOPE_OR_IDENTITY_MISMATCH$'):
                    V['_claim'](self.a,changed)


def negative(name, bundle_index, filename, mutate, code, refresh=False):
    def test(self):
        b,c=copy.deepcopy(self.bundles)
        target=(b,c)[bundle_index]
        value=V['decode'](target[filename]); mutate(value)
        target[filename]=json.dumps(value).encode()
        if refresh:
            # Semantic unit boundary: independently test inner checks after hash
            # authentication. Public code never rewrites or refreshes receipts.
            if bundle_index==0:
                rec=V['decode'](b['EVIDENCE-EXECUTION-RECEIPT.json'])
                keys={'BROWSER-CONSOLE-RESULTS.json':'resultSHA256','browser-events.jsonl':'journalSHA256',
                      'EXECUTION-EXIT.json':'exitSHA256'}
                rec[keys[filename]]=hashlib.sha256(b[filename]).hexdigest()
                b['EVIDENCE-EXECUTION-RECEIPT.json']=json.dumps(rec).encode()
        with self.assertRaisesRegex(Error,'^'+code+'$'):
            self.evaluate(b=b,c=c)
    setattr(CompletionTests,'test_reject_'+name,test)


for name,file,field,value,code in [
    ('wrong_execution','BROWSER-CONSOLE-RESULTS.json','executionID','other','CONSOLE_SCOPE'),
    ('wrong_scope','BROWSER-CONSOLE-RESULTS.json','scope','ALL_QUALIFICATION','CONSOLE_SCOPE'),
    ('wrong_source','BROWSER-CONSOLE-RESULTS.json','sourceManifestSHA256','0'*64,'COMPLETION_SOURCE_IMAGE'),
    ('wrong_controller','BROWSER-CONSOLE-RESULTS.json','controllerReceiptSHA256','0'*64,'COMPLETION_CONTROLLER'),
    ('wrong_node_activation','BROWSER-CONSOLE-RESULTS.json','activationReceiptSHA256','0'*64,'NODE_ACTIVATION'),
    ('wrong_browser','BROWSER-CONSOLE-RESULTS.json','browserVersion','other','COMPLETION_BROWSER_VERSION'),
    ('wrong_clipboard_retest','BROWSER-CONSOLE-RESULTS.json','priorClipboardReceiptSHA256','0'*64,'COMPLETION_CLIPBOARD_LINK'),
    ('rerun_clipboard','BROWSER-CONSOLE-RESULTS.json','clipboardAcceptanceRerun',True,'COMPLETION_SCOPE_EXPANSION'),
    ('rewritten_browser_pass','BROWSER-CONSOLE-RESULTS.json','status','PASS','HISTORICAL_FAILURE_PRESERVED'),
    ('missing_browser_cleanup','BROWSER-CONSOLE-RESULTS.json','cleanup',{},'BROWSER_RESOURCE_CLEANUP'),
    ('wrong_counts','BROWSER-CONSOLE-RESULTS.json','passed',5,'CONSOLE_CASE_COUNTS'),
    ('missing_native_cleanup','CLEANUP-COMPLETION-RECEIPT.json','nativeCleanupNowVerified',False,'CLEANUP_NOT_VERIFIED'),
    ('unrelated_cleanup_execution','CLEANUP-COMPLETION-RECEIPT.json','originalExecutionID','other','CLEANUP_EXECUTION_LINK'),
    ('conflicting_cleanup_receipt','CLEANUP-COMPLETION-RECEIPT.json','receiptID','other','CLEANUP_EXECUTION_LINK'),
    ('wrong_cleanup_scope','CLEANUP-COMPLETION-RECEIPT.json','scope','ALL_FAILURES','CLEANUP_EXECUTION_LINK'),
    ('wrong_failure_selector','CLEANUP-COMPLETION-RECEIPT.json','originalFailureSelector','security-scan','CLEANUP_SCOPE_EXPANSION'),
    ('historical_success_claim','CLEANUP-COMPLETION-RECEIPT.json','historicalCleanupSuccessClaimed',True,'CLEANUP_SCOPE_EXPANSION'),
    ('freshness_reset','CLEANUP-COMPLETION-RECEIPT.json','freshnessAnchorsReset',True,'CLEANUP_SCOPE_EXPANSION'),
    ('wrong_original_result','CLEANUP-COMPLETION-RECEIPT.json','originalResultSHA256','0'*64,'CLEANUP_ORIGINAL_BINDING'),
    ('wrong_original_exit','CLEANUP-COMPLETION-RECEIPT.json','originalExitSHA256','0'*64,'CLEANUP_ORIGINAL_BINDING'),
    ('wrong_original_journal','CLEANUP-COMPLETION-RECEIPT.json','originalJournalSHA256','0'*64,'CLEANUP_ORIGINAL_BINDING'),
    ('wrong_cleanup_result','CLEANUP-COMPLETION-RECEIPT.json','cleanupResultSHA256','0'*64,'CLEANUP_RECEIPT_BINDING'),
    ('wrong_cleanup_exit','CLEANUP-COMPLETION-RECEIPT.json','cleanupExitSHA256','0'*64,'CLEANUP_RECEIPT_BINDING'),
    ('cleanup_driver_substitution','CLEANUP-COMPLETION-RECEIPT.json','cleanupDriverSHA256','0'*64,'CLEANUP_RECEIPT_BINDING'),
]:
    bi=1 if file.startswith('CLEANUP') else 0
    negative(name,bi,file,lambda d,k=field,v=value:d.__setitem__(k,v),code)
for name,mutate,code in [
    ('missing_case',lambda d:d['cases'].pop(),'CONSOLE_CASE_COVERAGE'),
    ('duplicate_case',lambda d:d['cases'].__setitem__(1,copy.deepcopy(d['cases'][0])),'CONSOLE_CASE_COVERAGE'),
    ('missing_final_assertion',lambda d:d['cases'][0].__setitem__('finalAssertionsCompleted',False),'CONSOLE_CASE_ASSERTIONS'),
    ('console_errors',lambda d:d['cases'][0].__setitem__('consoleErrors',1),'CONSOLE_CASE_ASSERTIONS'),
    ('page_errors',lambda d:d['cases'][0].__setitem__('pageErrors',1),'CONSOLE_CASE_ASSERTIONS'),
    ('listener_after_navigation',lambda d:d['cases'][0].__setitem__('listenerRegistrationSequence',6),'CONSOLE_LISTENER_ORDER'),
    ('wrong_application_image',lambda d:d['images'].__setitem__('runtime','sha256:'+'0'*64),'COMPLETION_SOURCE_IMAGE'),
]:
    negative(name,0,'BROWSER-CONSOLE-RESULTS.json',mutate,code,True)


def journal_negative(name, mutate, code):
    def test(self):
        b,c=copy.deepcopy(self.bundles)
        rows=[V['decode'](r) for r in b['browser-events.jsonl'].splitlines()]; mutate(rows)
        b['browser-events.jsonl']=b'\n'.join(json.dumps(r).encode() for r in rows)+b'\n'
        rec=V['decode'](b['EVIDENCE-EXECUTION-RECEIPT.json'])
        rec['journalSHA256']=hashlib.sha256(b['browser-events.jsonl']).hexdigest()
        b['EVIDENCE-EXECUTION-RECEIPT.json']=json.dumps(rec).encode()
        with self.assertRaisesRegex(Error,'^'+code+'$'): self.evaluate(b=b,c=c)
    setattr(CompletionTests,'test_journal_'+name,test)

journal_negative('missing_listener',lambda r:r.pop(3),'CONSOLE_JOURNAL_IDENTITY')
journal_negative('wrong_identity',lambda r:r[3]['identity'].__setitem__('executionID','other'),'CONSOLE_JOURNAL_IDENTITY')
journal_negative('wrong_listener_order',lambda r:r[3].__setitem__('kind','navigation-start'),'CONSOLE_LISTENER_ORDER')
journal_negative('missing_pageerror_listener',lambda r:r[3].__setitem__('pageerror',False),'CONSOLE_EVENT_ASSERTIONS')
journal_negative('missing_console_probe',lambda r:r[7].__setitem__('consoleProbeDelivered',False),'CONSOLE_EVENT_ASSERTIONS')
journal_negative('missing_late_error_check',lambda r:r[8].__setitem__('lateErrorsChecked',False),'CONSOLE_EVENT_ASSERTIONS')


def stale_test(self):
    with self.assertRaisesRegex(Error,'^STALE_COMPLETION$'):
        self.evaluate(now=V['timestamp']('2026-10-24T18:12:07.501Z'))
CompletionTests.test_completion_cannot_reset_freshness=stale_test

if __name__=='__main__': unittest.main(verbosity=2)
