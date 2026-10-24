"""Synthetic approvals only. NO Undici approval, live qualification or host calls.

Only fixture executable trust anchors are recompiled to model external operator
approval. The actual candidate's authority stays empty. All evidence is retained.
"""
import ast
import copy
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import shutil
import os
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

C = Path(__file__).absolute().parents[1]
E = C.parents[2].with_name(C.parents[2].name+'-completion') / 'validation'
NOW = dt.datetime(2026, 10, 24, 12, tzinfo=dt.timezone.utc)
H = lambda b: hashlib.sha256(b).hexdigest()
J = lambda x: json.dumps(x, sort_keys=True).encode()
UTC = lambda x: x.isoformat().replace('+00:00', 'Z')


def module(path, name):
    scope = types.ModuleType(name)
    scope.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), scope.__dict__)
    return scope


def tar(rows):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as t:
        for name, data in rows.items():
            info = tarfile.TarInfo(name); info.size = len(data); info.mode = 0o644
            t.addfile(info, io.BytesIO(data))
    return out.getvalue()


class Fixture:
    def __init__(self):
        parent = E / 'test-fixtures'; parent.mkdir(parents=True,exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='synthetic-', dir=parent))
        self.code = self.root / 'code'; self.code.mkdir()
        for p in C.iterdir():
            if p.is_file(): shutil.copyfile(p, self.code / p.name)
        self.data = self.root / 'data'; self.data.mkdir()
        self.now = NOW
        self.module_path = 'usr/local/lib/node_modules/npm/node_modules/example/lib/fetch.js'
        module_bytes = b'Synthetic module bytes. Not executable payload.'
        layer = tar({self.module_path: module_bytes})
        config = J({'architecture': 'amd64', 'os': 'linux', 'config': {},
                    'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + H(layer)]}})
        self.image = 'sha256:' + H(config)
        archive = tar({'manifest.json': J([{'Config': 'config.json', 'Layers': ['0/layer.tar']}]),
                       'config.json': config, '0/layer.tar': layer})
        self.write('builder.tar', archive)
        self.write('source/package.json', b'{"name":"synthetic"}')
        self.write('source/package-lock.json', b'{"lockfileVersion":3}')
        self.write('source/Dockerfile', b'FROM synthetic-fixture-only')
        source_rows=[{'path':p.relative_to(self.data/'source').as_posix(),'sha256':H(p.read_bytes()),'size':p.stat().st_size,'mode':'0644'}
                     for p in (self.data/'source').rglob('*') if p.is_file()]
        self.write('source-manifest.json', J(source_rows))
        self.write('builder-execution-config.json', J({'registry': 'fixture://not-network', 'nativeHooks': False}))
        self.write('builder-execution-commands.json', J(['npm ci', 'npm test', 'npm audit']))
        self.write('build-helper.txt', b'Frozen synthetic build helper input')
        self.write('builder-build-helpers.json', J({'build-helper.txt': H((self.data/'build-helper.txt').read_bytes())}))
        self.write('inputs/module.txt', module_bytes)
        self.write('inputs/advisory.txt', b'CVE-2099-12345 synthetic HIGH advisory')
        self.write('inputs/lifecycle.txt', b'No native hooks in synthetic graph')
        self.write('inputs/diff.txt', b'Frozen synthetic source diff')
        self.write('inputs/assessment.txt', b'TEST ONLY NOT OPERATOR AUTHORIZATION')
        self.write('inputs/review.txt', b'Synthetic independent review fixture')
        self.database = b'synthetic-database'
        self.archive = archive
        self.context = {'runID': 'synthetic-execution', 'sourceManifestSHA256': H((self.data/'source-manifest.json').read_bytes()),
                        'startedUTC': UTC(NOW-dt.timedelta(minutes=10)), 'scannerVersion': '0.76.0',
                        'scannerBinarySHA256': H(b'scanner'), 'dbSHA256': H(self.database),
                        'scannerPolicySHA256': module(self.code/'qualification_evidence.py','fixture_qe').SCANNER_POLICY_SHA256,
                        'images': {k: {'imageID': self.image, 'archiveSHA256': H(archive)} for k in ('builder','runtime')}}
        gate = module(self.code/'builder_security.py', 'fixture_gate')
        image = gate.image_filesystem(self.data, {'archivePath':'builder.tar','archiveSHA256':H(archive),'imageID':self.image})
        self.context['exportIdentities'] = {'builder': image['identityChain'], 'runtime': image['identityChain']}
        self.write('qualification.json', J({'runID':self.context['runID'],'baselineHEAD':'a'*40,
                                          'sourceManifestSHA256':self.context['sourceManifestSHA256']}))
        self.report = {'SchemaVersion':2, 'ArtifactType':'container_image', 'CreatedAt':UTC(NOW-dt.timedelta(minutes=3)),
                       'Metadata':{'ImageID':self.image}, 'Results':[
                           {'Target':'builder.tar (alpine)', 'Class':'os-pkgs', 'Type':'alpine',
                            'Packages':[{'Name':'libexpat','Version':'2.9.0-r0'}]},
                           {'Target':'Node.js','Class':'lang-pkgs','Type':'node-pkg', 'Packages':[
                               {'Name':n,'Version':v,'FilePath':p} for n,v,p in (
                                   ('@typescript/typescript6','6.0.2','app/node_modules/@typescript/typescript6/package.json'),
                                   ('typescript','6.0.3','app/node_modules/@typescript/old/package.json'),
                                   ('playwright','1.62.1','app/node_modules/playwright/package.json'),
                                   ('playwright-core','1.62.1','app/node_modules/playwright-core/package.json'))],
                            'Vulnerabilities':[{'VulnerabilityID':'CVE-2099-12345','PkgName':'example','InstalledVersion':'1.0.0',
                                                'PkgPath':'usr/local/lib/node_modules/npm/node_modules/example/package.json','Severity':'HIGH'}]}]}
        self.bindings = {k:self.context[k] for k in ('sourceManifestSHA256','runID','dbSHA256','scannerVersion','scannerBinarySHA256','scannerPolicySHA256')}
        self.bindings.update(self.context['images']['builder'])
        self.bindings.update(imageGraph=image['identityChain'], archivePath='builder.tar', modulePath=self.module_path,
                             reportSHA256=H(J(self.report)), moduleSHA256=H(module_bytes))
        mapping = {'lockSHA256':'source/package-lock.json','packageSHA256':'source/package.json','recipeSHA256':'source/Dockerfile',
                   'configSHA256':'builder-execution-config.json','commandsSHA256':'builder-execution-commands.json',
                   'helpersSHA256':'builder-build-helpers.json','advisorySHA256':'inputs/advisory.txt','lifecycleSHA256':'inputs/lifecycle.txt'}
        self.bindings.update({k:H((self.data/v).read_bytes()) for k,v in mapping.items()})
        self.bindings['sourceIdentity'] = {'commit':'a'*40,'sourceManifestSHA256':self.context['sourceManifestSHA256'], 'diffSHA256':H((self.data/'inputs/diff.txt').read_bytes())}
        linux = {'platform':'linux/amd64','imageID':self.image,'sourceManifestSHA256':self.context['sourceManifestSHA256'],
                 'commandsSHA256':self.bindings['commandsSHA256'],'lifecycleSHA256':self.bindings['lifecycleSHA256'],'records':{}}
        for phase in ('install','test','audit','coverage'):
            output='linux/'+phase+'.stdout'; self.write(output, b'SYNTHETIC NONSECRET OUTPUT')
            record={'executionID':self.context['runID'],'phase':phase,'platform':'linux/amd64','imageID':self.image,
                    'sourceManifestSHA256':self.context['sourceManifestSHA256'],'commandsSHA256':self.bindings['commandsSHA256'],
                    **{k:self.bindings[k] for k in ('configSHA256','recipeSHA256','helpersSHA256')},
                    'exitCode':0,'error':None,'stdoutPath':output,'stdoutSHA256':H((self.data/output).read_bytes())}
            name='linux/'+phase+'.json';self.write(name,J(record))
            linux['records'][phase]={'path':name,'sha256':H(J(record)),'exitCode':0}
        self.write('inputs/linux.json',J(linux)); self.bindings['linuxEvidenceSHA256']=H(J(linux))
        self.scope={'schemaVersion':1,'bindings':self.bindings,'files':{}}
        self.receipts=[]

    def write(self,name,data):
        path=self.data/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)

    def seal_scope(self):
        self.scope['bindings']['reportSHA256']=H(J(self.report))
        self.scope['files']={p.relative_to(self.data).as_posix():H(p.read_bytes()) for p in self.data.rglob('*')
                             if p.is_file() and not p.relative_to(self.data).as_posix().startswith('builder-applicability/')}
        self.write('builder-applicability/context.json',J(self.scope))

    def approval(self, change=None, scope_change=None):
        self.seal_scope()
        if scope_change:
            scope_change(self.scope)
            self.write('builder-applicability/context.json',J(self.scope))
        gate=module(self.code/'builder_security.py','fixture_gate')
        rows=gate.findings(self.report)
        self.receipts=[]
        for finding in rows:
            receipt={'schemaVersion':1,'operator':'SYNTHETIC_TEST_OPERATOR','authorizationReference':'test-fixture-only',
                     'assessmentSHA256':H((self.data/'inputs/assessment.txt').read_bytes()),'reviewSHA256':H((self.data/'inputs/review.txt').read_bytes()),
                     'scopeSHA256':H(J(self.scope)),'finding':finding,'approvedAt':UTC(NOW-dt.timedelta(hours=1)),
                     'expiresAt':UTC(NOW+dt.timedelta(hours=1)),'status':'APPROVED'}
            if change: change(receipt)
            raw=J(receipt);h=H(raw); self.write('builder-applicability/receipts/'+h+'.json',raw);self.receipts.append(h)
        self.pin(self.receipts)

    def pin(self, hashes):
        # This models an external authorized executable graph, NOT a supported
        # production approval API. Only copies beneath test-fixtures change.
        auth={'schemaVersion':1,'policySHA256':H((self.code/'builder-security-policy.json').read_bytes()),'approvedReceipts':hashes}
        (self.code/'builder-security-authority.json').write_bytes(J(auth))
        src=(C/'builder_security.py').read_text(); original=module(C/'builder_security.py','original_gate').AUTHORITY_SHA256
        src=src.replace(original,H(J(auth))); (self.code/'builder_security.py').write_text(src)
        q=(C/'qualification_evidence.py').read_text().replace(H((C/'builder_security.py').read_bytes()),H((self.code/'builder_security.py').read_bytes()))
        (self.code/'qualification_evidence.py').write_text(q)

    def direct(self, kind='builder', now=None):
        gate=module(self.code/'builder_security.py','fixture_gate')
        return gate.evaluate(J(self.report),self.context,kind,self.data,now or self.now)

    def scan(self,kind='builder',now=None,qe_override=None):
        qe=qe_override or module(self.code/'qualification_evidence.py','fixture_qe')
        data=J(self.report)
        receipt={k:self.context[k] for k in ('runID','sourceManifestSHA256','scannerVersion','scannerBinarySHA256','dbSHA256','scannerPolicySHA256')}
        receipt.update(self.context['images'][kind]);receipt.update(reportSHA256=H(data),startedUTC=UTC(NOW-dt.timedelta(minutes=4)),finishedUTC=UTC(NOW-dt.timedelta(minutes=2)))
        db={'Version':2,'UpdatedAt':UTC(NOW-dt.timedelta(hours=1)), 'DownloadedAt':UTC(NOW-dt.timedelta(minutes=9)), 'NextUpdate':UTC(NOW+dt.timedelta(hours=4))}
        # Original compiler archive checks are separately regression tested;
        # this small fixture supplies its already-verified compiler inventory.
        compiler=types.ModuleType('compiler_inventory');compiler.authenticate_compiler=lambda *args:{'app/node_modules/@typescript/old/package.json':{'name':'typescript','version':'6.0.3'}}
        with patch.dict(sys.modules,{'compiler_inventory':compiler}):
            return qe.validate_scan(data,receipt,self.context,kind,{'libexpat':'2.9.0-r0'},db,self.database,self.archive,now or self.now,evidence_root=self.data)

    def controller(self):
        """Actual readiness function; host/legacy catalog are fixture boundaries."""
        ctl=module(self.code/'continuation.py','fixture_controller')
        ctl.RUN=self.context['runID'];ctl.SOURCE=self.context['sourceManifestSHA256']
        ctl.IMAGES={k:self.image for k in ('builder','runtime')}
        ctl.authenticate_helpers=lambda root: None  # No active graph or remote host is used.
        class Clock(dt.datetime):
            @classmethod
            def now(cls,tz=None):return self.now
        ctl.datetime=types.SimpleNamespace(datetime=Clock,timezone=dt.timezone)
        self.context['attemptID']=self.root.name
        def save(path,obj):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(J(obj))
        save(self.root/'scan-attempt.json',{'startedUTC':self.context['startedUTC']})
        save(self.data/'evidence-context.json',self.context)
        save(self.root/'scan-driver-exit.json',{'exitCode':0,'error':None,'executionID':self.root.name})
        save(self.data/'scan-status.json',{'phase':'READY_FOR_LOCAL_SCHEMA_VALIDATION'})
        builds={}
        for kind in ('builder','runtime'):
            report=copy.deepcopy(self.report)
            if kind=='runtime':report['Results']=report['Results'][:1]
            data=J(report);self.write(kind+'-raw-scan.json',data)
            receipt={k:self.context[k] for k in ('runID','sourceManifestSHA256','scannerVersion','scannerBinarySHA256','dbSHA256','scannerPolicySHA256')}
            receipt.update(self.context['images'][kind]);receipt.update(attemptID=self.root.name,reportSHA256=H(data),startedUTC=UTC(NOW-dt.timedelta(minutes=4)),finishedUTC=UTC(NOW-dt.timedelta(minutes=2)))
            save(self.data/(kind+'-scan-receipt.json'),receipt)
            builds[kind]={'archive':'builder.tar','archiveSHA256':H(self.archive)}
            save(self.data/(kind+'-installed-packages.json'),{'packages':[{'name':'libexpat','version':'2.9.0-r0'}]})
        self.write('runtime-sbom.cdx.json',b'SYNTHETIC SBOM BOUNDARY')
        r=json.loads((self.data/'runtime-scan-receipt.json').read_bytes());r.pop('reportSHA256');r['sbomSHA256']=H(b'SYNTHETIC SBOM BOUNDARY');save(self.data/'runtime-sbom-receipt.json',r)
        save(self.data/'builds.json',builds)
        self.write('trivy-cache/db/trivy.db',self.database)
        db={'Version':2,'UpdatedAt':UTC(NOW-dt.timedelta(hours=1)),'DownloadedAt':UTC(NOW-dt.timedelta(minutes=9)),'NextUpdate':UTC(NOW+dt.timedelta(hours=4))}
        for point in ('start','end'):save(self.data/('scanner-db-'+point+'.json'),{'metadata':db})
        for name in ctl.SCAN_LOGS:
            self.write(name,b'SYNTHETIC SCANNER PROCESS OUTPUT');self.write(name+'.stderr',b'')
            save(self.data/(name+'.exit.json'),{'attemptID':self.root.name,'runID':ctl.RUN,'sourceManifestSHA256':ctl.SOURCE,'exitCode':0,'error':None,'stdoutSHA256':H((self.data/name).read_bytes()),'stderrSHA256':H(b'')})
        return ctl

    def readiness(self,ctl):
        qe=module(self.code/'qualification_evidence.py','qualification_evidence')
        compiler=types.ModuleType('compiler_inventory');compiler.authenticate_compiler=lambda *args:{'app/node_modules/@typescript/old/package.json':{'name':'typescript','version':'6.0.3'}}
        with patch.dict(sys.modules,{'qualification_evidence':qe,'compiler_inventory':compiler}):
            return ctl.strict_scans(self.root)

    def refresh(self,ctl):
        """Actual security_refresh.validate; external historical graph is synthetic.

        Its inventory, receipt binding, freshness and applicability checks run
        unchanged. w.verify_acceptance calls real scan validators; full SBOM and
        browser/host predicates are not requalified by this local test.
        """
        self.context['attemptID']='synthetic-refresh';self.write('evidence-context.json',J(self.context))
        original_q=json.loads((self.data/'qualification.json').read_bytes())
        self.write('qualification.json',J({**original_q,'attemptID':'synthetic-refresh','parentExecutionID':self.root.name}))
        original=self.root/'original-data';original.mkdir(exist_ok=True);(original/'qualification.json').write_bytes(J(original_q))
        for kind in ('builder','runtime'):
            name=kind+'-scan-receipt.json';r=json.loads((self.data/name).read_bytes());r['attemptID']='synthetic-refresh';self.write(name,J(r))
        r=json.loads((self.data/'runtime-sbom-receipt.json').read_bytes());r['attemptID']='synthetic-refresh';self.write('runtime-sbom-receipt.json',J(r))
        for name in ctl.SCAN_LOGS:
            r=json.loads((self.data/(name+'.exit.json')).read_bytes());r['attemptID']='synthetic-refresh';self.write(name+'.exit.json',J(r))
        # Refresh lineage is a scope change: simulate NEW external approval of
        # this refreshed fixture, never silently reuse readiness authority.
        self.approval()
        for name in ('qualification_evidence.py','builder_security.py','builder-security-policy.json','builder-security-authority.json','export_identity.py','filesystem_equivalence.py'):
            self.write(name,(self.code/name).read_bytes())
        self.write('accepted.json',J({'synthetic':True}))
        self.write('refresh-driver-exit.json',J({'exitCode':0}))
        self.write('refresh-import-receipt.json',J({'parentExecutionID':self.root.name,'executionID':'synthetic-refresh','sourceManifestSHA256':ctl.SOURCE,'originalEvidenceModified':False,'importedUnchangedFiles':{}}))
        (self.root/'fresh-inputs.json').write_bytes(J({}))
        manifest={'root':str(self.data),'files':[{'path':p.relative_to(self.data).as_posix(),'bytes':p.stat().st_size,'sha256':H(p.read_bytes())} for p in self.data.rglob('*') if p.is_file()]}
        mp=self.root/'refresh-manifest.json';mp.write_bytes(J(manifest));fm=self.root/'fresh-manifest.json';fm.write_bytes(J({'executionID':'synthetic-refresh','exitCode':0,'files':[]}))
        authority={'schemaVersion':1,'scope':'settlement-security-freshness-only','originalRoot':str(self.root),'parentExecutionID':self.root.name,
                   'runID':ctl.RUN,'sourceManifestSHA256':ctl.SOURCE,'images':ctl.IMAGES,'historicalReceipts':{},
                   'freshManifest':{'path':str(fm),'sha256':H(fm.read_bytes())},'viewRoot':str(self.data),'viewManifest':{'path':str(mp),'sha256':H(mp.read_bytes())},
                   'refreshExecutionID':'synthetic-refresh','acceptedSHA256':H((self.data/'accepted.json').read_bytes())}
        ap=self.code/'security-refresh-authority.PROPOSED.json';ap.write_bytes(J(authority))
        source=(C/'security_refresh.py').read_text();source=source.replace("descriptor=active().authority('securityRefresh')","descriptor="+repr({'path':str(ap),'sha256':H(J(authority))}))
        (self.code/'security_refresh.py').write_text(source)
        refresh=module(self.code/'security_refresh.py','fixture_refresh')
        # Explicit unit boundary for the independently pinned canonical helper.
        # Complete-bootstrap tests exercise the actual context loader separately.
        refresh.active=lambda:types.SimpleNamespace(code_hash=lambda name:H((self.code/name).read_bytes()))
        qe=module(self.code/'qualification_evidence.py','qualification_evidence')
        realread=ctl.read
        def read(p):
            if p==self.data/'qualification.json':return original_q
            return realread(p)
        env={**ctl.__dict__,'read':read,'completed':lambda root,name:None}
        w=types.SimpleNamespace(inputs=lambda root:json.loads((root/'qualification.json').read_bytes()),schema_environment=lambda:None)
        def verify(root):
            result=self.scan(qe_override=qe)
            return {'databaseSHA256':self.context['dbSHA256'],'results':{'builder':result,'runtime':{'passed':True}}}
        w.verify_acceptance=verify
        def run(now=None):
            with patch.dict(sys.modules,{'qualification_evidence':qe}):
                # root/data points to the retained view for normal controller
                # layout; original q is supplied as the authenticated predecessor.
                return refresh.validate(env,self.root,w,now or self.now)
        return run

    def final_contract(self,ctl,run,missing=None):
        """Real completeness inventory; historical browser/host contracts are
        independent fixture boundaries. No successful security decision mocked.
        """
        out=self.root/'settlement-output';out.mkdir()
        def save(path,doc):
            if path.name!=missing:path.write_bytes(J(doc))
        proof={'syntheticBrowserBoundary':True}
        ctl.settlement_link=lambda:{'context':lambda C,root:{'output':out,'proof':proof},
                                    'completed':lambda C,ctx,name:None}
        ctl.container_contract=lambda *args:None
        ctl.browser_contract=lambda *args:None
        ctl.refreshed_security=lambda root:run()
        for phase in ('audit','acceptance','runtime-collection','browser-collection'):
            save(self.root/(phase+'-completed.json'),{'executionID':self.root.name,'qualificationRunID':ctl.RUN})
        for kind in ('runtime','browser'):
            save(self.root/(kind+'-inspect.json'),{'Id':kind+'-synthetic-id'})
            save(self.root/(kind+'-checks.json'),{'executionID':self.root.name,'containerID':kind+'-synthetic-id','imageID':self.image,'healthExitCode':0})
            for suffix in ('health-stdout','health-stderr','packages-stdout','packages-stderr','container-stdout','container-stderr'):
                if kind+'-'+suffix+'.log'!=missing:(self.root/(kind+'-'+suffix+'.log')).write_bytes(b'Synthetic external boundary')
        save(self.root/'execution-workloads-before.json',[]);save(self.root/'execution-resources-before.json',[])
        save(out/'browser-evidence-integration.json',proof)
        save(out/'security-evidence-integration.json',run()['proof'])
        save(out/'settled.json',{'executionID':self.root.name,'qualificationRunID':ctl.RUN,'workloads':[],'resources':[]})
        for n in ('settlement-attempt.json','settlement-completed.json'):save(out/n,{'synthetic':True})


class GateTests(unittest.TestCase):
    def setUp(self): self.f=Fixture()
    def test_valid_approved_occurrence_real_scan_validator(self):
        self.f.approval(); r=self.f.scan();self.assertEqual(r['counts']['HIGH'],1);self.assertEqual(r['builderApplicability']['status'],'PASS_WITH_APPROVED_BUILDER_HIGH')
    def test_clean_builder_original_strict_default(self):
        self.f.report['Results'][1].pop('Vulnerabilities');self.assertEqual(self.f.scan()['builderApplicability']['status'],'PASS')
    def test_clean_runtime(self):
        self.f.report['Results']=self.f.report['Results'][:1];self.assertTrue(self.f.scan('runtime')['passed'])
    def test_missing_approval(self):
        self.f.seal_scope()
        with self.assertRaisesRegex(ValueError,'no operator'):self.f.scan()
    def test_unapproved_receipt_cannot_self_authorize(self):
        self.f.approval();self.f.pin([])
        with self.assertRaisesRegex(ValueError,'no operator'):self.f.scan()
    def test_changed_authority_rejected_before_receipt(self):
        self.f.approval();p=self.f.code/'builder-security-authority.json';p.write_text('{"approved":true}')
        with self.assertRaisesRegex(ValueError,'evidence hash'):self.f.scan()
    def test_two_findings_one_approved(self):
        self.f.approval();self.f.report['Results'][1]['Vulnerabilities'].append({**self.f.report['Results'][1]['Vulnerabilities'][0],'VulnerabilityID':'CVE-2099-22222'})
        with self.assertRaises(ValueError):self.f.scan()
    def test_two_individually_approved(self):
        self.f.report['Results'][1]['Vulnerabilities'].append({**self.f.report['Results'][1]['Vulnerabilities'][0],'VulnerabilityID':'CVE-2099-22222'})
        self.f.approval();self.assertEqual(self.f.scan()['builderApplicability']['approvedHighCount'],2)
    def test_builder_critical(self):
        self.f.approval();self.f.report['Results'][1]['Vulnerabilities'][0]['Severity']='CRITICAL'
        with self.assertRaisesRegex(ValueError,'CRITICAL'):self.f.scan()
    def test_builder_secret(self):
        self.f.approval();self.f.report['Results'][0]['Secrets']=[{'RuleID':'synthetic'}]
        with self.assertRaisesRegex(ValueError,'secret'):self.f.scan()
    def test_runtime_high_cannot_use_builder_approval(self):
        self.f.approval()
        high=self.f.report['Results'][1]['Vulnerabilities']
        self.f.report['Results']=self.f.report['Results'][:1]
        self.f.report['Results'][0]['Vulnerabilities']=high
        with self.assertRaisesRegex(ValueError,'runtime HIGH'):self.f.scan('runtime')
    def test_expired(self):
        self.f.approval(lambda r:r.update(expiresAt=UTC(NOW)))
        with self.assertRaisesRegex(ValueError,'interval'):self.f.scan()
    def test_longer_than_seven_days(self):
        self.f.approval(lambda r:r.update(expiresAt=UTC(NOW+dt.timedelta(days=7))))
        with self.assertRaisesRegex(ValueError,'interval'):self.f.scan()
    def test_future_approval(self):
        self.f.approval(lambda r:r.update(approvedAt=UTC(NOW+dt.timedelta(minutes=1))))
        with self.assertRaisesRegex(ValueError,'interval'):self.f.scan()
    def test_exact_seven_days(self):
        self.f.approval(lambda r:r.update(approvedAt=UTC(NOW),expiresAt=UTC(NOW+dt.timedelta(days=7))))
        self.assertTrue(self.f.scan()['passed'])
    def test_duplicate_authority(self):
        self.f.approval();self.f.pin(self.f.receipts*2)
        with self.assertRaisesRegex(ValueError,'duplicate'):self.f.scan()
    def test_conflicting_receipts(self):
        self.f.approval();old=self.f.receipts[0]; raw=json.loads((self.f.data/('builder-applicability/receipts/'+old+'.json')).read_bytes());raw['operator']='OTHER_TEST_OPERATOR';h=H(J(raw));self.f.write('builder-applicability/receipts/'+h+'.json',J(raw));self.f.pin([old,h])
        with self.assertRaisesRegex(ValueError,'conflicting'):self.f.scan()
    def test_altered_receipt(self):
        self.f.approval();self.f.write('builder-applicability/receipts/'+self.f.receipts[0]+'.json',b'{}')
        with self.assertRaisesRegex(ValueError,'evidence hash'):self.f.scan()
    def test_missing_review(self):
        self.f.approval(lambda r:r.update(reviewSHA256='f'*64))
        with self.assertRaisesRegex(ValueError,'reviewed evidence'):self.f.scan()
    def test_missing_assessment(self):
        self.f.approval(lambda r:r.update(assessmentSHA256='f'*64))
        with self.assertRaisesRegex(ValueError,'reviewed evidence'):self.f.scan()
    def test_not_approved_status(self):
        self.f.approval(lambda r:r.update(status='NOT_APPROVED'))
        with self.assertRaisesRegex(ValueError,'operator approval'):self.f.scan()
    def test_unknown_receipt_field(self):
        self.f.approval(lambda r:r.update(approved=True))
        with self.assertRaisesRegex(ValueError,'schema'):self.f.scan()
    def test_unknown_policy_version(self):
        self.f.approval();p=self.f.code/'builder-security-policy.json';doc=json.loads(p.read_bytes());doc['schemaVersion']=2;p.write_bytes(J(doc));self.f.pin(self.f.receipts)
        with self.assertRaisesRegex(ValueError,'policy'):self.f.scan()
    def test_linked_scope_rejected(self):
        self.f.approval(); # Native symlink behavior separately tested when Windows permits.
        gate=module(self.f.code/'builder_security.py','fixture_gate')
        with self.assertRaisesRegex(ValueError,'unsafe'):gate.read_at(self.f.data,'../outside')
    def test_duplicate_json_key(self):
        self.f.approval();self.f.write('builder-applicability/context.json',b'{"schemaVersion":1,"schemaVersion":1}')
        with self.assertRaisesRegex(ValueError,'duplicate'):self.f.scan()
    def test_stale_database_parent_gate(self):
        self.f.approval()
        with self.assertRaisesRegex(ValueError,'Stale vulnerability database'):self.f.scan(now=NOW+dt.timedelta(days=2))
    def test_no_undici_approval_in_candidate(self):
        auth=json.loads((C/'builder-security-authority.json').read_bytes());self.assertEqual(auth['approvedReceipts'],[])

    def test_stale_duplicate_config_does_not_match_current_input(self):
        old=(self.f.data/'builder-execution-config.json').read_bytes();self.f.write('inputs/old-config-copy.json',old)
        self.f.approval(scope_change=lambda s:s['files'].pop('builder-execution-config.json'))
        self.f.write('builder-execution-config.json',b'NEW ACTUAL CONFIG')
        with self.assertRaisesRegex(ValueError,'current execution input'):self.f.scan()

    def test_stale_duplicate_helper_inventory_does_not_match_current(self):
        old=(self.f.data/'builder-build-helpers.json').read_bytes();self.f.write('inputs/old-helpers-copy.json',old)
        self.f.approval(scope_change=lambda s:s['files'].pop('builder-build-helpers.json'))
        self.f.write('builder-build-helpers.json',J({'different-helper':'0'*64}))
        with self.assertRaisesRegex(ValueError,'current execution input'):self.f.scan()

    def test_readiness_actual_entrypoint_accepts(self):
        ctl=self.f.controller();self.f.approval()
        self.assertEqual(self.f.readiness(ctl)['builder']['builderApplicability']['rawCounts']['HIGH'],1)

    def test_readiness_actual_entrypoint_rejects_unapproved(self):
        ctl=self.f.controller();self.f.seal_scope()
        with self.assertRaisesRegex(ValueError,'no operator'):self.f.readiness(ctl)

    def test_settlement_refresh_actual_entrypoint_accepts(self):
        ctl=self.f.controller();self.f.approval();run=self.f.refresh(ctl)
        self.assertEqual(run()['proof']['builderApplicability']['status'],'PASS_WITH_APPROVED_BUILDER_HIGH')

    def test_accepted_readiness_expired_settlement(self):
        ctl=self.f.controller();self.f.approval();self.assertTrue(self.f.readiness(ctl))
        run=self.f.refresh(ctl);self.f.now=NOW+dt.timedelta(hours=2)
        with self.assertRaisesRegex(ValueError,'interval'):run()

    def test_final_completeness_rechecks_before_other_evidence(self):
        ctl=self.f.controller();self.f.approval();run=self.f.refresh(ctl)
        ctl.refreshed_security=lambda root:run()
        self.f.now=NOW+dt.timedelta(hours=2)
        with self.assertRaisesRegex(ValueError,'interval'):ctl.complete_contract(self.f.root)

    def test_report_changed_with_new_valid_scan_receipt(self):
        self.f.approval();self.f.report['CreatedAt']=UTC(NOW-dt.timedelta(minutes=2))
        with self.assertRaisesRegex(ValueError,'report scope'):self.f.scan()

    def test_wrong_finding_version(self):
        self.f.approval(lambda r:r['finding'].update(InstalledVersion='99.0.0'))
        with self.assertRaisesRegex(ValueError,'out-of-scope'):self.f.scan()

    def test_wrong_finding_cve(self):
        self.f.approval(lambda r:r['finding'].update(VulnerabilityID='CVE-2099-99999'))
        with self.assertRaisesRegex(ValueError,'out-of-scope'):self.f.scan()

    def test_wrong_finding_path(self):
        self.f.approval(lambda r:r['finding'].update(PkgPath='other/package.json'))
        with self.assertRaisesRegex(ValueError,'out-of-scope'):self.f.scan()

    def test_ambiguous_missing_package_path(self):
        self.f.report['Results'][1]['Vulnerabilities'][0].pop('PkgPath');self.f.seal_scope()
        # Use a synthetically authorized unrelated receipt to reach occurrence
        # parsing; never infer the missing path from a package name.
        self.f.pin(['a'*64])
        with self.assertRaisesRegex(ValueError,'ambiguous'):self.f.scan()

    def test_unknown_severity(self):
        self.f.report['Results'][1]['Vulnerabilities'][0]['Severity']='UNCLASSIFIED'
        with self.assertRaises(ValueError):self.f.scan()

    def test_changed_source_file_behind_original_manifest(self):
        self.f.write('source/src.txt',b'original');rows=json.loads((self.f.data/'source-manifest.json').read_bytes());rows.append({'path':'src.txt','sha256':H(b'original'),'size':8,'mode':'0644'});self.f.write('source-manifest.json',J(rows))
        self.f.context['sourceManifestSHA256']=H(J(rows));self.f.bindings['sourceManifestSHA256']=H(J(rows));self.f.bindings['sourceIdentity']['sourceManifestSHA256']=H(J(rows))
        q=json.loads((self.f.data/'qualification.json').read_bytes());q['sourceManifestSHA256']=H(J(rows));self.f.write('qualification.json',J(q))
        # Other Linux source binding remains intentionally old: either that or
        # the changed actual source must reject; neither may be accepted.
        self.f.approval(scope_change=lambda s:s['files'].pop('source/src.txt'));self.f.write('source/src.txt',b'changed!')
        with self.assertRaises(ValueError):self.f.scan()

    def test_wrong_source_commit_even_when_scope_reapproved(self):
        self.f.bindings['sourceIdentity']['commit']='b'*40;self.f.approval()
        with self.assertRaisesRegex(ValueError,'selected source commit'):self.f.scan()

    def test_windows_evidence_not_linux(self):
        doc=json.loads((self.f.data/'inputs/linux.json').read_bytes());doc['platform']='windows/amd64';self.f.write('inputs/linux.json',J(doc));self.f.bindings['linuxEvidenceSHA256']=H(J(doc));self.f.approval()
        with self.assertRaisesRegex(ValueError,'Linux execution identity'):self.f.scan()

    def test_missing_linux_record(self):
        doc=json.loads((self.f.data/'inputs/linux.json').read_bytes());doc['records'].pop('coverage');self.f.write('inputs/linux.json',J(doc));self.f.bindings['linuxEvidenceSHA256']=H(J(doc));self.f.approval()
        with self.assertRaisesRegex(ValueError,'incomplete Linux'):self.f.scan()

    def test_fabricated_unbound_linux_exit_record(self):
        record=json.loads((self.f.data/'linux/install.json').read_bytes());record['commandsSHA256']='f'*64;self.f.write('linux/install.json',J(record))
        doc=json.loads((self.f.data/'inputs/linux.json').read_bytes());doc['records']['install']['sha256']=H(J(record));self.f.write('inputs/linux.json',J(doc));self.f.bindings['linuxEvidenceSHA256']=H(J(doc));self.f.approval()
        with self.assertRaisesRegex(ValueError,'Linux execution receipt'):self.f.scan()

    def test_module_hash_does_not_match_image_bytes(self):
        self.f.write('inputs/other-module.txt',b'not image code');self.f.bindings['moduleSHA256']=H(b'not image code');self.f.approval()
        with self.assertRaisesRegex(ValueError,'actual vulnerable module bytes'):self.f.scan()

    def test_other_component_not_authorized_by_one_module(self):
        self.f.report['Results'][1]['Vulnerabilities'][0]['PkgPath']='other/package.json';self.f.approval()
        with self.assertRaisesRegex(ValueError,'module outside'):self.f.scan()

    def test_reversed_approval_interval(self):
        self.f.approval(lambda r:r.update(expiresAt=UTC(NOW-dt.timedelta(hours=2))))
        with self.assertRaisesRegex(ValueError,'interval'):self.f.scan()

    def test_malformed_approval_timestamp(self):
        self.f.approval(lambda r:r.update(expiresAt='not-time'))
        with self.assertRaises(ValueError):self.f.scan()

    def test_naive_approval_timestamp(self):
        self.f.approval(lambda r:r.update(expiresAt='2026-10-25T00:00:00'))
        with self.assertRaises(ValueError):self.f.scan()

    def test_gate_code_tampered_rejected_before_execution(self):
        self.f.approval();p=self.f.code/'builder_security.py';p.write_bytes(p.read_bytes()+b'\n# altered fixture code\n')
        with self.assertRaisesRegex(ValueError,'helper identity'):self.f.scan()

    def test_no_policy_path_or_authority_cli_override(self):
        tree=ast.parse((C/'builder_security.py').read_bytes());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='evaluate')
        self.assertEqual([a.arg for a in fn.args.args],['raw_data','context','kind','root','now'])
        self.assertNotIn('getenv',(C/'builder_security.py').read_text())

    def test_native_linked_ancestor_is_rejected(self):
        target=self.f.root/'plain-target';target.mkdir();(target/'file.txt').write_bytes(b'nonsecret')
        link=self.f.root/'linked-target'
        if os.name=='nt':
            r=subprocess.run(['cmd','/c','mklink','/J',str(link),str(target)],capture_output=True)
            if r.returncode:self.skipTest('Windows junction fixture unavailable')
        else:
            link.symlink_to(target,target_is_directory=True)
        gate=module(self.f.code/'builder_security.py','fixture_gate')
        with self.assertRaisesRegex(ValueError,'linked evidence'):gate.plain(link/'file.txt')

    def test_unlisted_source_input_blocks(self):
        self.f.approval();self.f.write('source/new-unapproved.txt',b'new input')
        with self.assertRaisesRegex(ValueError,'unexpected or missing source input'):self.f.scan()

    def test_final_completeness_positive_and_historical_failure_preserved(self):
        ctl=self.f.controller();self.f.approval();run=self.f.refresh(ctl)
        failure=self.f.root/'browser-testing-failed.json';failure.write_bytes(J({'exitCode':1,'historical':'unchanged'}));before=H(failure.read_bytes())
        self.f.final_contract(ctl,run);result=ctl.complete_contract(self.f.root)
        self.assertEqual(len(result['supplemental']),5);self.assertEqual(H(failure.read_bytes()),before)

    def test_final_missing_mandatory_completion_record(self):
        ctl=self.f.controller();self.f.approval();run=self.f.refresh(ctl)
        self.f.final_contract(ctl,run,missing='audit-completed.json')
        with self.assertRaisesRegex(ValueError,'Incomplete final evidence binding'):ctl.complete_contract(self.f.root)

    def test_final_missing_inventory_resource(self):
        ctl=self.f.controller();self.f.approval();run=self.f.refresh(ctl)
        self.f.final_contract(ctl,run,missing='runtime-health-stdout.log')
        with self.assertRaisesRegex(ValueError,'Incomplete final evidence binding'):ctl.complete_contract(self.f.root)


def controller_negative_test(name):
    def test(self):
        ctl=self.f.controller();self.f.approval()
        if name=='expired':self.f.now=NOW+dt.timedelta(hours=2)
        elif name=='source':self.f.write('source/package-lock.json',b'changed lock')
        elif name=='database':self.f.write('trivy-cache/db/trivy.db',b'changed database')
        elif name=='report':
            r=json.loads((self.f.data/'builder-raw-scan.json').read_bytes());r['Results'][1]['Vulnerabilities'].append({**r['Results'][1]['Vulnerabilities'][0],'VulnerabilityID':'CVE-2099-22222'});self.f.write('builder-raw-scan.json',J(r))
        elif name=='scope':self.f.write('builder-applicability/context.json',b'{}')
        elif name=='driver':(self.f.root/'scan-driver-exit.json').write_bytes(J({'exitCode':1}))
        with self.assertRaises((ValueError,KeyError)):self.f.readiness(ctl)
    return test


for name in ('expired','source','database','report','scope','driver'):
    setattr(GateTests,'test_readiness_path_rejects_'+name,controller_negative_test(name))


def settlement_negative_test(name):
    def test(self):
        ctl=self.f.controller();self.f.approval();run=self.f.refresh(ctl)
        if name=='expired':self.f.now=NOW+dt.timedelta(hours=2)
        elif name=='source':self.f.write('source/package-lock.json',b'changed lock')
        elif name=='database':self.f.write('trivy-cache/db/trivy.db',b'changed database')
        elif name=='report':self.f.write('builder-raw-scan.json',b'{}')
        elif name=='scope':self.f.write('builder-applicability/context.json',b'{}')
        elif name=='record':self.f.write('linux/install.json',b'{}')
        with self.assertRaises((ValueError,KeyError)):run()
    return test


for name in ('expired','source','database','report','scope','record'):
    setattr(GateTests,'test_settlement_path_rejects_'+name,settlement_negative_test(name))


def mismatch_test(key):
    def test(self):
        self.f.approval()
        if key in ('imageID','archiveSHA256'): self.f.context['images']['builder'][key]='sha256:'+'0'*64 if key=='imageID' else '0'*64
        else:self.f.context[key]='0'*64
        with self.assertRaises(ValueError):self.f.scan()
    return test


for key in ('imageID','archiveSHA256','sourceManifestSHA256','runID','dbSHA256','scannerVersion','scannerBinarySHA256','scannerPolicySHA256'):
    setattr(GateTests,'test_observed_'+key+'_mismatch',mismatch_test(key))


def current_input_test(path):
    def test(self):
        self.f.approval();self.f.write(path,b'Changed actual execution input, approved copied evidence untouched')
        with self.assertRaises(ValueError):self.f.scan()
    return test


for name,path in {'lock':'source/package-lock.json','package':'source/package.json','config':'builder-execution-config.json',
                  'command':'builder-execution-commands.json','recipe':'source/Dockerfile','helper':'build-helper.txt',
                  'advisory':'inputs/advisory.txt','linux':'inputs/linux.json','lifecycle':'inputs/lifecycle.txt',
                  'linux_output':'linux/install.stdout','source_manifest':'source-manifest.json','archive':'builder.tar'}.items():
    setattr(GateTests,'test_actual_'+name+'_changed',current_input_test(path))


if __name__=='__main__': unittest.main(verbosity=2)
