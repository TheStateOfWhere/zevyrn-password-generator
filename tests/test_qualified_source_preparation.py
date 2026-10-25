"""Synthetic, non-approval tests of the real external bootstrap/preparer path.

Run with an explicitly supplied empty-pin external bootstrap template in
QUALIFIED_PREPARATION_TEST_TEMPLATE. Test copies alone receive synthetic pins.
No production authority, Git checkout, historical evidence or network is used.
"""
from pathlib import Path
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(kind, data):
    return hashlib.sha1(kind.encode()+b' '+str(len(data)).encode()+b'\0'+data).hexdigest()


class QualifiedPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='qualified-preparation-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repo = self.root/'code'
        self.script = self.repo/'scripts/prepare-qualified-source.py'
        self.script.parent.mkdir(parents=True)
        self.script.write_bytes((Path(__file__).resolve().parents[1]/'scripts/prepare-qualified-source.py').read_bytes())
        self.template = Path(os.environ['QUALIFIED_PREPARATION_TEST_TEMPLATE']).read_text()
        self.assertIn('APPROVED_AUTHORITY_SHA256 = frozenset()', self.template)
        self.source = self.root/'source'
        self.source.mkdir()
        self.operator = self.root/'operator'
        self.operator.mkdir()
        self.workspace = self.root/'workspace'
        self.workspace.mkdir()
        self.authority = self.operator/'authority.json'
        self.boot = self.root/'bootstrap.TEST-ONLY.py'
        self.files, self.maps, manifest, records = [], [], [], []
        members = {}
        for i in range(97):
            name = 'file%02d.txt' % i
            raw = ('value %02d  \n\nlast\n' % i).encode()
            original = raw.replace(b'\n', b'\r\n') if i < 17 else raw
            (self.source/name).write_bytes(raw)
            self.files.append(dict(path=name, mode='100644', gitBlob=git('blob', raw), sha256=sha(raw), bytes=len(raw)))
            manifest.append(dict(path=name, mode='0644', sha256=sha(original), size=len(original)))
            member = 'qualification-dk02-20261019-02/source/'+name
            members[member] = original
            if i < 17:
                self.maps.append(dict(path=name, gitSHA256=sha(raw), gitBytes=len(raw), qualifiedSHA256=sha(original), qualifiedBytes=len(original), sourceMember=member))
                records.append(dict(path=name, stagedBlobSHA256=sha(raw), qualifiedWorkingSHA256=sha(original)))
        manifest_raw = json.dumps(manifest).encode()
        members['qualification-dk02-20261019-02/source-manifest.json'] = manifest_raw
        bundle = self.operator/'bundle.tar.gz'
        with tarfile.open(bundle, 'w:gz') as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        provenance = self.operator/'provenance.json'
        provenance.write_text(json.dumps(dict(status='PASS_NORMALIZED_CONTENT_EQUIVALENCE', rawHashEqualityClaimed=False, records=records)))
        tree_payload = b''.join(b'100644 '+r['path'].encode()+b'\0'+bytes.fromhex(r['gitBlob']) for r in self.files)
        tree = git('tree', tree_payload)
        commit = self.operator/'commit'
        commit.write_bytes(b'tree '+tree.encode()+b'\nauthor Synthetic <test@example.invalid> 0 +0000\ncommitter Synthetic <test@example.invalid> 0 +0000\n\nSynthetic fixture\n')
        self.doc = dict(schemaVersion=1, contractID='zevyrn-v1.2.1-qualified-byte-preparation-v1', preparer=dict(path=str(self.script), sha256=sha(self.script.read_bytes())), sourceRoot=str(self.source), sourceCommit=git('commit', commit.read_bytes()), sourceTree=tree, commitRecord=dict(path=str(commit), sha256=sha(commit.read_bytes())), files=self.files, mappings=self.maps, evidence=dict(bundle=dict(path=str(bundle), sha256=sha(bundle.read_bytes())), manifestSHA256=sha(manifest_raw), provenance=dict(path=str(provenance), sha256=sha(provenance.read_bytes()))), workspaceRoot=str(self.workspace), outputRoot=str(self.workspace/'prepared'), receiptPath=str(self.workspace/'receipt.json'))

    def seal(self, approved=True):
        self.authority.write_text(json.dumps(self.doc))
        pin = "frozenset(['"+sha(self.authority.read_bytes())+"'])" if approved else 'frozenset()'
        self.boot.write_text(self.template.replace('APPROVED_AUTHORITY_SHA256 = frozenset()', 'APPROVED_AUTHORITY_SHA256 = '+pin))

    def execute(self, flags=None):
        return subprocess.run([sys.executable, *(flags or ['-I', '-S', '-B']), str(self.boot), str(self.authority)], capture_output=True, timeout=30)

    def rejected(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout.decode(errors='replace'))
        self.assertFalse(Path(self.doc['outputRoot']).exists())
        self.assertFalse(Path(self.doc['receiptPath']).exists())

    def test_exact_original_bytes_and_unchanged_inputs(self):
        self.seal()
        self.assertEqual(self.execute().returncode, 0)
        receipt = json.loads(Path(self.doc['receiptPath']).read_bytes())
        self.assertEqual(receipt['restoredFiles'], 17)
        self.assertFalse(receipt['qualificationExecuted'])
        self.assertFalse(receipt['vulnerabilityApprovalGranted'])
        for i, row in enumerate(self.files):
            raw = (self.source/row['path']).read_bytes()
            self.assertEqual(sha(raw), row['sha256'])
            prepared = (Path(self.doc['outputRoot'])/row['path']).read_bytes()
            expected = raw.replace(b'\n', b'\r\n') if i < 17 else raw
            self.assertEqual(prepared, expected)
            self.assertIn(b'  ', prepared)
        if os.name == 'posix':
            self.assertEqual(Path(self.doc['outputRoot']).stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o644 for p in Path(self.doc['outputRoot']).iterdir()))

    def test_empty_external_pins_reject(self):
        self.seal(approved=False)
        self.rejected(self.execute())

    def test_tampered_authority_rejects_without_renewed_external_pin(self):
        self.seal()
        self.authority.write_bytes(self.authority.read_bytes()+b' ')
        self.rejected(self.execute())

    def test_modified_helper_rejected_before_import(self):
        self.seal()
        marker = self.root/'executed'
        self.script.write_text("from pathlib import Path\nPath("+repr(str(marker))+").touch()\n")
        self.rejected(self.execute())
        self.assertFalse(marker.exists())

    def test_direct_cli_rejected(self):
        result = subprocess.run([sys.executable, '-I', '-S', '-B', str(self.script)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'EXTERNAL_BOOTSTRAP_REQUIRED', result.stderr)

    def test_optimized_execution_rejected(self):
        self.seal()
        self.rejected(self.execute(['-I', '-S', '-B', '-O']))

    def test_missing_isolation_rejected(self):
        self.seal()
        self.rejected(self.execute(['-S', '-B']))

    def test_site_enabled_rejected(self):
        self.seal()
        self.rejected(self.execute(['-I', '-B']))

    def test_duplicate_authority_json_key_rejected(self):
        self.seal()
        raw = self.authority.read_text()
        self.authority.write_text(raw[:-1]+',"schemaVersion":1}')
        self.boot.write_text(self.template.replace('APPROVED_AUTHORITY_SHA256 = frozenset()', "APPROVED_AUTHORITY_SHA256 = frozenset(['"+sha(self.authority.read_bytes())+"'])"))
        self.rejected(self.execute())

    def test_duplicate_provenance_rejected_even_if_document_hash_approved(self):
        p = Path(self.doc['evidence']['provenance']['path'])
        record = json.loads(p.read_bytes())
        record['records'][1] = record['records'][0]
        p.write_text(json.dumps(record))
        self.doc['evidence']['provenance']['sha256'] = sha(p.read_bytes())
        self.seal()
        self.rejected(self.execute())

    def test_qualified_payload_mismatch_rejected_inside_reauthenticated_bundle(self):
        p = Path(self.doc['evidence']['bundle']['path'])
        with tarfile.open(p, 'r:gz') as source:
            members = [(i, source.extractfile(i).read()) for i in source.getmembers()]
        with tarfile.open(p, 'w:gz') as destination:
            for i, data in members:
                if i.name == self.maps[0]['sourceMember']:
                    data = b'altered qualified content'
                    i.size = len(data)
                destination.addfile(i, io.BytesIO(data))
        self.doc['evidence']['bundle']['sha256'] = sha(p.read_bytes())
        self.seal()
        self.rejected(self.execute())

    def test_duplicate_archive_member_rejected_inside_reauthenticated_bundle(self):
        p = Path(self.doc['evidence']['bundle']['path'])
        with tarfile.open(p, 'r:gz') as source:
            members = [(i, source.extractfile(i).read()) for i in source.getmembers()]
        with tarfile.open(p, 'w:gz') as destination:
            for i, data in members+[members[0]]:
                destination.addfile(i, io.BytesIO(data))
        self.doc['evidence']['bundle']['sha256'] = sha(p.read_bytes())
        self.seal()
        self.rejected(self.execute())

    def test_archive_member_limit_is_enforced_during_iteration(self):
        p = Path(self.doc['evidence']['bundle']['path'])
        with tarfile.open(p, 'r:gz') as source:
            members = [(i, source.extractfile(i).read()) for i in source.getmembers()]
        with tarfile.open(p, 'w:gz') as destination:
            for i, data in members:
                destination.addfile(i, io.BytesIO(data))
            for number in range(1025-len(members)):
                destination.addfile(tarfile.TarInfo('extra%04d' % number), io.BytesIO(b''))
        self.doc['evidence']['bundle']['sha256'] = sha(p.read_bytes())
        self.seal()
        result = self.execute()
        self.rejected(result)
        self.assertIn(b'archive_member_limit', result.stderr)

    def test_hardlinked_source_rejected(self):
        os.link(self.source/'file00.txt', self.root/'linked-source')
        self.seal()
        self.rejected(self.execute())

    def test_hardlinked_authority_rejected(self):
        self.seal()
        os.link(self.authority, self.root/'linked-authority')
        self.rejected(self.execute())

    def test_changed_output_before_final_sweep_has_no_success_receipt(self):
        self.seal()
        injection = " original=m.source_bytes\n def checked(root,rows):\n  if root==Path(doc['outputRoot']):(root/'file00.txt').write_bytes(b'changed')\n  return original(root,rows)\n m.source_bytes=checked\n result=m.prepare(authority,digest,capability)"
        self.boot.write_text(self.boot.read_text().replace(' result=m.prepare(authority,digest,capability)', injection))
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'source_bytes', result.stderr)
        self.assertTrue(Path(self.doc['outputRoot']).is_dir())
        self.assertFalse(Path(self.doc['receiptPath']).exists())

    def test_extra_output_before_final_sweep_has_no_success_receipt(self):
        self.seal()
        injection = " original=m.source_bytes\n def checked(root,rows):\n  if root==Path(doc['outputRoot']):(root/'extra.txt').write_bytes(b'unexpected')\n  return original(root,rows)\n m.source_bytes=checked\n result=m.prepare(authority,digest,capability)"
        self.boot.write_text(self.boot.read_text().replace(' result=m.prepare(authority,digest,capability)', injection))
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'unexpected_or_missing_source', result.stderr)
        self.assertFalse(Path(self.doc['receiptPath']).exists())

    def test_repository_authority_cannot_approve_itself(self):
        self.authority = self.repo/'authority.json'
        self.seal()
        self.rejected(self.execute())

    def test_existing_output_refused(self):
        self.seal()
        Path(self.doc['outputRoot']).mkdir()
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(Path(self.doc['outputRoot']).iterdir()), [])
        self.assertFalse(Path(self.doc['receiptPath']).exists())

    def test_existing_receipt_refused(self):
        self.seal()
        p = Path(self.doc['receiptPath'])
        p.write_bytes(b'protected')
        self.assertNotEqual(self.execute().returncode, 0)
        self.assertEqual(p.read_bytes(), b'protected')
        self.assertFalse(Path(self.doc['outputRoot']).exists())


def negative(method):
    def test(self):
        method(self)
        self.seal()
        self.rejected(self.execute())
    return test


CASES = {
    'missing_source': lambda s: (s.source/'file00.txt').unlink(),
    'modified_source': lambda s: (s.source/'file00.txt').write_bytes(b'altered'),
    'unexpected_source': lambda s: (s.source/'extra.txt').write_bytes(b'extra'),
    'duplicate_source': lambda s: s.files.append(copy.deepcopy(s.files[0])),
    'missing_mapping': lambda s: s.maps.pop(),
    'duplicate_mapping': lambda s: s.maps.__setitem__(1, copy.deepcopy(s.maps[0])),
    'wrong_mapping_path': lambda s: s.maps[0].update(path='file80.txt'),
    'wrong_mapping_length': lambda s: s.maps[0].update(qualifiedBytes=1),
    'wrong_git_length': lambda s: s.maps[0].update(gitBytes=1),
    'wrong_qualified_hash': lambda s: s.maps[0].update(qualifiedSHA256='0'*64),
    'wrong_git_hash': lambda s: s.maps[0].update(gitSHA256='0'*64),
    'wrong_member': lambda s: s.maps[0].update(sourceMember='wrong/file00.txt'),
    'wrong_source_tree': lambda s: s.doc.update(sourceTree='0'*40),
    'wrong_source_commit': lambda s: s.doc.update(sourceCommit='0'*40),
    'wrong_git_blob': lambda s: s.files[0].update(gitBlob='0'*40),
    'wrong_mode': lambda s: s.files[0].update(mode='100755'),
    'unsafe_path': lambda s: s.maps[0].update(path='../escape'),
    'wrong_contract': lambda s: s.doc.update(contractID='another-contract'),
    'wrong_schema': lambda s: s.doc.update(schemaVersion=True),
    'unsafe_output_leaf': lambda s: s.doc.update(outputRoot=str(s.workspace/'CON')),
    'unsafe_receipt_leaf': lambda s: s.doc.update(receiptPath=str(s.workspace/'existing.txt:receipt')),
    'oversized_declared_total': lambda s: [r.update(bytes=16*1024**2) for r in s.files],
    'missing_bundle': lambda s: Path(s.doc['evidence']['bundle']['path']).unlink(),
    'modified_bundle': lambda s: Path(s.doc['evidence']['bundle']['path']).write_bytes(b'altered'),
    'missing_provenance': lambda s: Path(s.doc['evidence']['provenance']['path']).unlink(),
    'modified_provenance': lambda s: Path(s.doc['evidence']['provenance']['path']).write_bytes(b'{}'),
    'substituted_bundle': lambda s: s.doc['evidence']['bundle'].update(path=str(s.source/'file00.txt')),
    'substituted_manifest': lambda s: s.doc['evidence'].update(manifestSHA256='0'*64),
    'missing_commit': lambda s: Path(s.doc['commitRecord']['path']).unlink(),
    'extra_authority_field': lambda s: s.doc.update(approveVulnerabilities=True),
    'source_workspace_overlap': lambda s: s.doc.update(workspaceRoot=str(s.source), outputRoot=str(s.source/'prepared'), receiptPath=str(s.source/'receipt')),
}
for name, mutation in CASES.items():
    setattr(QualifiedPreparationTests, 'test_reject_'+name, negative(mutation))


if __name__ == '__main__':
    unittest.main()
