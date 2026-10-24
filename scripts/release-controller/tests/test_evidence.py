import copy
import datetime as dt
import json
import unittest
import subprocess
import sys
from pathlib import Path
from qualification_evidence import *
from test_whiteouts import load_helper


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 10, 17, 20, 0, tzinfo=dt.timezone.utc)
        self.time = lambda minutes: (self.now + dt.timedelta(minutes=minutes)).isoformat()
        self.archive = b'current-runtime-export'; self.database = b'current-verified-database'
        self.packages = {'libexpat': '2.9.0-r0', 'zlib': '1.3.2-r1'}
        self.context = {'runID': 'test-new-run', 'sourceManifestSHA256': 'a' * 64, 'startedUTC': self.time(-10),
                        'scannerVersion': '0.76.0', 'scannerBinarySHA256': 'b' * 64, 'dbSHA256': sha(self.database), 'scannerPolicySHA256': SCANNER_POLICY_SHA256,
                        'images': {k: {'imageID': 'sha256:' + ('c' if k == 'runtime' else 'd') * 64,
                                       'archiveSHA256': sha(self.archive)} for k in ('runtime', 'builder')}}
        self.db = {'Version': 2, 'UpdatedAt': self.time(-60), 'DownloadedAt': self.time(-9), 'NextUpdate': self.time(60)}
        self.report = {'SchemaVersion': 2, 'ArtifactType': 'container_image', 'CreatedAt': self.time(-3),
                       'Metadata': {'ImageID': self.context['images']['runtime']['imageID']},
                       'Results': [{'Target': 'runtime.tar (alpine)', 'Class': 'os-pkgs', 'Type': 'alpine',
                                    'Packages': [{'Name': n, 'Version': v} for n, v in self.packages.items()]}]}
        self.bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                    'metadata': {'timestamp': self.time(-3), 'tools': {'components': [{'type': 'application', 'name': 'trivy', 'version': '0.76.0'}]},
                                 'component': {'type': 'container', 'name': 'runtime.tar', 'properties': [
                                     {'name': 'aquasecurity:trivy:ImageID', 'value': self.context['images']['runtime']['imageID']}]}},
                    'components': [{'type': 'library', 'name': n, 'version': v,
                                    'purl': 'pkg:apk/alpine/' + n + '@' + v + '?arch=x86_64'} for n, v in self.packages.items()]}

    def receipt(self, data, field='reportSHA256', kind='runtime'):
        return {**{key: self.context[key] for key in ('runID', 'sourceManifestSHA256', 'scannerVersion', 'scannerBinarySHA256', 'dbSHA256', 'scannerPolicySHA256')},
                **self.context['images'][kind], field: sha(data), 'startedUTC': self.time(-4), 'finishedUTC': self.time(-2)}

    def scan(self, *, receipt_change=None, data_change=None, kind='runtime'):
        report = copy.deepcopy(self.report)
        if kind == 'builder':
            from test_js_compiler import CompilerTests
            CompilerTests.setUpClass()
            self.archive,image_id,archive_hash=CompilerTests.fixture()
            self.context['images']['builder']={'imageID':image_id,'archiveSHA256':archive_hash}
            report['Metadata']['ImageID'] = self.context['images']['builder']['imageID']
            report['Results'].append({'Target': 'Node.js', 'Class': 'lang-pkgs', 'Type': 'node-pkg',
                                      'Packages': [{'Name': n, 'Version': v, 'FilePath': 'app/node_modules/' + p + '/package.json'} for n, v,p in [('@typescript/typescript6','6.0.2','@typescript/typescript6'),('typescript','6.0.3','@typescript/old'),('playwright', '1.62.1','playwright'), ('playwright-core', '1.62.1','playwright-core')]]})
        if data_change:
            data_change(report)
        data = encoded(report); receipt = self.receipt(data, kind=kind)
        if receipt_change:
            receipt_change(receipt)
        return validate_scan(data, receipt, self.context, kind, self.packages, self.db, self.database, self.archive, self.now)

    def sbom(self, *, receipt_change=None, data_change=None):
        bom = copy.deepcopy(self.bom)
        if data_change:
            data_change(bom)
        data = encoded(bom); receipt = self.receipt(data, 'sbomSHA256')
        if receipt_change:
            receipt_change(receipt)
        return validate_sbom(data, receipt, self.context, self.packages, self.archive, self.now)

    def test_valid_runtime_report(self):
        self.assertTrue(self.scan()['passed'])

    def test_unapproved_scanner_policy(self):
        self.context['scannerPolicySHA256']='0'*64
        with self.assertRaisesRegex(EvidenceError,'Unapproved scanner policy'):
            self.scan()

    def test_sbom_uses_official_spdx_reference(self):
        self.assertTrue(self.sbom(data_change=lambda b:b['components'][0].update(licenses=[{'license':{'id':'MIT'}}]))['passed'])

    def test_valid_builder_report(self):
        self.assertTrue(self.scan(kind='builder')['passed'])

    def test_wrong_report_image(self):
        with self.assertRaisesRegex(EvidenceError, 'Wrong scanner image identity'):
            self.scan(data_change=lambda r: r['Metadata'].update(ImageID='sha256:' + 'e' * 64))

    def test_wrong_receipt_image(self):
        with self.assertRaisesRegex(EvidenceError, 'image/archive mismatch'):
            self.scan(receipt_change=lambda r: r.update(imageID='sha256:' + 'e' * 64))

    def test_wrong_archive_receipt(self):
        with self.assertRaisesRegex(EvidenceError, 'image/archive mismatch'):
            self.scan(receipt_change=lambda r: r.update(archiveSHA256='0' * 64))

    def test_actual_archive_substituted(self):
        self.archive = b'different export'
        with self.assertRaisesRegex(EvidenceError, 'Exported archive hash mismatch'):
            self.scan()

    def test_stale_database(self):
        self.db['UpdatedAt'] = self.time(-1500)
        with self.assertRaisesRegex(EvidenceError, 'Stale vulnerability database'):
            self.scan()

    def test_missing_database(self):
        self.database = b''
        with self.assertRaisesRegex(EvidenceError, 'Missing or substituted vulnerability database'):
            self.scan()

    def test_substituted_database(self):
        self.database = b'other-db'
        with self.assertRaisesRegex(EvidenceError, 'Missing or substituted vulnerability database'):
            self.scan()

    def test_prior_run_database_download(self):
        self.db['DownloadedAt'] = self.time(-20)
        with self.assertRaisesRegex(EvidenceError, 'not downloaded in current run'):
            self.scan()

    def test_expired_database(self):
        self.db['NextUpdate'] = self.time(-1)
        with self.assertRaisesRegex(EvidenceError, 'Expired vulnerability database'):
            self.scan()

    def test_missing_package_coverage(self):
        with self.assertRaisesRegex(EvidenceError, 'Missing package coverage'):
            self.scan(data_change=lambda r: r['Results'][0].update(Packages=[]))

    def test_partial_package_coverage(self):
        with self.assertRaisesRegex(EvidenceError, 'Trivy OS package inventory mismatch'):
            self.scan(data_change=lambda r: r['Results'][0]['Packages'].pop())

    def test_additional_package(self):
        with self.assertRaisesRegex(EvidenceError, 'Trivy OS package inventory mismatch'):
            self.scan(data_change=lambda r: r['Results'][0]['Packages'].append({'Name': 'extra', 'Version': '1-r0'}))

    def test_duplicate_package(self):
        with self.assertRaisesRegex(EvidenceError, 'Duplicate or conflicting package inventory'):
            self.scan(data_change=lambda r: r['Results'][0]['Packages'].append(r['Results'][0]['Packages'][0]))

    def test_version_mismatch(self):
        with self.assertRaisesRegex(EvidenceError, 'Trivy OS package inventory mismatch'):
            self.scan(data_change=lambda r: r['Results'][0]['Packages'][0].update(Version='0-r0'))

    def test_npm_does_not_satisfy_os_coverage(self):
        with self.assertRaisesRegex(EvidenceError, 'Missing package coverage'):
            self.scan(data_change=lambda r: r['Results'][0].update(Class='lang-pkgs', Type='npm'))

    def test_missing_application_dependency(self):
        with self.assertRaisesRegex(EvidenceError, 'Missing application dependency coverage'):
            self.scan(kind='builder', data_change=lambda r: r['Results'][1]['Packages'].pop())

    def test_runtime_application_dependencies_fail(self):
        def change(r):
            r['Results'].append({'Target': 'app/package-lock.json', 'Class': 'lang-pkgs', 'Type': 'npm', 'Packages': [{'Name': 'typescript', 'Version': '7.0.2'}]})
        with self.assertRaisesRegex(EvidenceError, 'Unexpected runtime application dependencies'):
            self.scan(data_change=change)

    def test_high_and_critical_fail(self):
        for severity in ('HIGH', 'CRITICAL'):
            with self.subTest(severity=severity):
                with self.assertRaisesRegex(EvidenceError, 'Critical/high vulnerability or secret gate failed'):
                    self.scan(data_change=lambda r: r['Results'][0].update(Vulnerabilities=[{'VulnerabilityID': 'CVE-synthetic', 'Severity': severity}]))

    def test_secrets_fail(self):
        with self.assertRaisesRegex(EvidenceError, 'Critical/high vulnerability or secret gate failed'):
            self.scan(data_change=lambda r: r['Results'][0].update(Secrets=[{'RuleID': 'synthetic-no-secret-content'}]))

    def test_missing_severity_fails(self):
        with self.assertRaisesRegex(EvidenceError, 'Missing or invalid vulnerability severity/identity'):
            self.scan(data_change=lambda r: r['Results'][0].update(Vulnerabilities=[{'VulnerabilityID': 'CVE-synthetic'}]))

    def test_malformed_findings_fail(self):
        with self.assertRaisesRegex(EvidenceError, 'Malformed scanner findings'):
            self.scan(data_change=lambda r: r['Results'][0].update(Vulnerabilities=None))

    def test_report_substitution_fails(self):
        with self.assertRaisesRegex(EvidenceError, 'Substituted evidence content'):
            self.scan(receipt_change=lambda r: r.update(reportSHA256='0' * 64))

    def test_old_run_fails(self):
        with self.assertRaisesRegex(EvidenceError, 'context mismatch: runID'):
            self.scan(receipt_change=lambda r: r.update(runID='prior-run'))

    def test_wrong_source_manifest(self):
        with self.assertRaisesRegex(EvidenceError, 'context mismatch: sourceManifestSHA256'):
            self.scan(receipt_change=lambda r: r.update(sourceManifestSHA256='0' * 64))

    def test_wrong_scanner_version(self):
        with self.assertRaisesRegex(EvidenceError, 'context mismatch: scannerVersion'):
            self.scan(receipt_change=lambda r: r.update(scannerVersion='unverified'))

    def test_wrong_scanner_binary(self):
        with self.assertRaisesRegex(EvidenceError, 'context mismatch: scannerBinarySHA256'):
            self.scan(receipt_change=lambda r: r.update(scannerBinarySHA256='0' * 64))

    def test_old_report_timestamp(self):
        with self.assertRaisesRegex(EvidenceError, 'Stale scanner report'):
            self.scan(data_change=lambda r: r.update(CreatedAt=self.time(-30)))

    def test_valid_sbom(self):
        self.assertTrue(self.sbom()['passed'])

    def test_valid_sbom_17(self):
        self.assertTrue(self.sbom(data_change=lambda b: b.update(specVersion='1.7'))['passed'])

    def test_invalid_sbom_schema(self):
        with self.assertRaisesRegex(EvidenceError, 'Invalid CycloneDX schema'):
            self.sbom(data_change=lambda b: b.update(bomFormat='other'))

    def test_wrong_sbom_image(self):
        with self.assertRaisesRegex(EvidenceError, 'Wrong or missing SBOM image binding'):
            self.sbom(data_change=lambda b: b['metadata']['component']['properties'][0].update(value='sha256:' + 'f' * 64))

    def test_missing_sbom_image(self):
        with self.assertRaisesRegex(EvidenceError, 'Wrong or missing SBOM image binding'):
            self.sbom(data_change=lambda b: b['metadata']['component'].pop('properties'))

    def test_substituted_sbom(self):
        with self.assertRaisesRegex(EvidenceError, 'Substituted evidence content'):
            self.sbom(receipt_change=lambda r: r.update(sbomSHA256='0' * 64))

    def test_wrong_sbom_archive_binding(self):
        with self.assertRaisesRegex(EvidenceError, 'image/archive mismatch'):
            self.sbom(receipt_change=lambda r: r.update(archiveSHA256='0' * 64))

    def test_sbom_missing_packages(self):
        with self.assertRaisesRegex(EvidenceError, 'SBOM OS package inventory mismatch'):
            self.sbom(data_change=lambda b: b['components'].pop())

    def test_sbom_duplicates(self):
        with self.assertRaisesRegex(EvidenceError, 'Invalid CycloneDX schema|Duplicate or conflicting package inventory'):
            self.sbom(data_change=lambda b: b['components'].append(copy.deepcopy(b['components'][0])))

    def test_sbom_inconsistent_purl(self):
        with self.assertRaisesRegex(EvidenceError, 'Inconsistent APK component identity'):
            self.sbom(data_change=lambda b: b['components'][0].update(version='bad'))

    def test_sbom_wrong_scanner(self):
        with self.assertRaisesRegex(EvidenceError, 'Missing SBOM scanner identity'):
            self.sbom(data_change=lambda b: b['metadata']['tools']['components'][0].update(version='old'))

    def test_sbom_old_timestamp(self):
        with self.assertRaisesRegex(EvidenceError, 'Stale SBOM'):
            self.sbom(data_change=lambda b: b['metadata'].update(timestamp=self.time(-60)))

    def test_scanner_environment_isolation(self):
        result = isolated_scanner_environment(HERE, {'PATH': '/bin', 'TRIVY_SEVERITY': 'LOW', 'TRIVY_IGNORE_UNFIXED': 'true', 'HOME': '/other', 'LD_PRELOAD': 'bad'})
        self.assertNotIn('TRIVY_SEVERITY', result); self.assertNotIn('TRIVY_IGNORE_UNFIXED', result)
        self.assertNotIn('LD_PRELOAD', result); self.assertNotEqual(result['HOME'], '/other')

    def test_linux_scan_import_has_no_schema_dependency(self):
        code="""import sys,importlib.abc
class Block(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname.split('.')[0] in ('jsonschema','referencing','rpds'):raise ImportError('schema package deliberately unavailable')
sys.meta_path.insert(0,Block())
import qualification_evidence
assert callable(qualification_evidence.validate_scan)
"""
        result=subprocess.run([sys.executable,'-B','-c',code],cwd=HERE,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)


class PackageRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parse = staticmethod(load_helper(HERE / 'scan-images.py', HERE)['packages'])

    def test_valid_packages_and_metadata(self):
        result = self.parse('P:libc6-compat\nV:1.2.3_alpha1-r0\nA:x86_64\no:musl\nF:lib\nR:a\nR:b\n\nP:libstdc++\nV:14.2.0_git20241001-r1\nA:x86_64\n')
        self.assertEqual(len(result), 2); self.assertEqual(result[0]['origin'], 'musl')

    def test_missing_version(self):
        with self.assertRaisesRegex(ValueError, 'Missing or malformed APK package version'):
            self.parse('P:libexpat\nA:x86_64\n')

    def test_empty_version(self):
        with self.assertRaisesRegex(ValueError, 'Missing or malformed APK package version'):
            self.parse('P:libexpat\nV:\n')

    def test_missing_name(self):
        with self.assertRaisesRegex(ValueError, 'Invalid APK package name'):
            self.parse('V:1.0-r0\n')

    def test_malformed_record(self):
        with self.assertRaisesRegex(ValueError, 'Malformed APK record field'):
            self.parse('P:libexpat\nV:1-r0\nbroken line\n')

    def test_duplicate_and_conflicting_records(self):
        for version in ('1-r0', '2-r0'):
            with self.assertRaisesRegex(ValueError, 'Duplicate or conflicting APK package identity'):
                self.parse('P:libexpat\nV:1-r0\n\nP:libexpat\nV:' + version + '\n')

    def test_duplicate_identity_fields(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate APK identity field'):
            self.parse('P:libexpat\nV:1-r0\nV:2-r0\n')

    def test_unsafe_names_and_versions(self):
        for name in ('../bad', 'bad name', ''):
            with self.assertRaisesRegex(ValueError, 'Invalid APK package name'):
                self.parse('P:' + name + '\nV:1-r0\n')
        with self.assertRaisesRegex(ValueError, 'Missing or malformed APK package version'):
            self.parse('P:valid\nV:unknown\n')


if __name__ == '__main__':
    unittest.main()
