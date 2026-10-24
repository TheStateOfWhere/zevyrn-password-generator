import base64,copy,hashlib,importlib.util,io,json,os,pathlib,stat,sys,tarfile,tempfile,unittest
from unittest import mock
HERE=pathlib.Path(__file__).absolute().parents[1]
spec=importlib.util.spec_from_file_location('reviewed_stage_source',HERE/'stage_source.py');s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
def sha(b):return hashlib.sha256(b).hexdigest()
class StageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='zevyrn-stage-fixture-');self.root=pathlib.Path(self.temp.name)/'new-attempt'
        self.contents={'nginx.conf':b'synthetic static configuration\n','public/index.html':b'<p>synthetic test</p>\n'}
        self.policy={'schemaVersion':1,'attemptRootMode':0o700,'directoryMode':0o755,'files':{p:0o644 for p in self.contents}}
        self.manifest={'source':[{'path':p,'sha256':sha(b),'bytes':len(b),'mode':0o644} for p,b in self.contents.items()]}
    def tearDown(self):self.temp.cleanup()
    def archive(self,entries=None,mode=0o666):
        out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w',format=tarfile.PAX_FORMAT) as archive:
            for name,data,kind,pax in (entries or [(p,b,tarfile.REGTYPE,{}) for p,b in self.contents.items()]):
                m=tarfile.TarInfo(name);m.mode=mode;m.type=kind;m.pax_headers=pax
                if kind==tarfile.REGTYPE:m.size=len(data)
                else:m.linkname='nginx.conf'
                archive.addfile(m,io.BytesIO(data) if kind==tarfile.REGTYPE else None)
        return out.getvalue()
    def stage(self,data=None,manifest=None,policy=None):return s.stage_source(self.root,data if data is not None else self.archive(),manifest or self.manifest,policy or self.policy)
    def rejected(self,data=None,manifest=None,policy=None):
        with self.assertRaises((ValueError,tarfile.TarError)):self.stage(data,manifest,policy)
        self.assertFalse(self.root.exists(),'invalid evidence must fail before workspace creation')
    def test_windows_archive_0666_cannot_override_approved_0644(self):
        calls=[]
        with mock.patch.object(s,'apply_mode',side_effect=lambda p,m:calls.append((str(p),m))):result=self.stage()
        self.assertEqual(result['status'],'STAGED_WITH_APPROVED_MODES')
        for name,b in self.contents.items():
            self.assertEqual((self.root/'source'/name).read_bytes(),b);self.assertIn((str(self.root/'source'/name),0o644),calls)
        self.assertIn((str(self.root),0o700),calls);self.assertIn((str(self.root/'source/public'),0o755),calls)
    def test_archive_0000_still_uses_approved_modes(self):
        with mock.patch.object(s,'apply_mode') as apply:self.stage(self.archive(mode=0))
        self.assertIn(mock.call(self.root/'source/nginx.conf',0o644),apply.call_args_list)
    def test_unapproved_group_write_rejected(self):
        m=copy.deepcopy(self.manifest);m['source'][0]['mode']=0o664;self.rejected(manifest=m)
    def test_unapproved_executable_rejected(self):
        m=copy.deepcopy(self.manifest);m['source'][0]['mode']=0o755;self.rejected(manifest=m)
    def test_setuid_mode_rejected(self):
        m=copy.deepcopy(self.manifest);m['source'][0]['mode']=0o4644;self.rejected(manifest=m)
    def test_modified_password_or_configuration_bytes_rejected(self):
        entries=[(p,b+b'altered',tarfile.REGTYPE,{}) for p,b in self.contents.items()];self.rejected(self.archive(entries))
    def test_missing_member_rejected(self):self.rejected(self.archive([('nginx.conf',self.contents['nginx.conf'],tarfile.REGTYPE,{})]))
    def test_extra_member_rejected(self):self.rejected(self.archive([(p,b,tarfile.REGTYPE,{}) for p,b in self.contents.items()]+[('extra',b'x',tarfile.REGTYPE,{})]))
    def test_duplicate_member_rejected(self):self.rejected(self.archive([(p,b,tarfile.REGTYPE,{}) for p,b in self.contents.items()]+[('nginx.conf',b'x',tarfile.REGTYPE,{})]))
    def test_duplicate_manifest_rejected(self):
        m=copy.deepcopy(self.manifest);m['source'].append(m['source'][0]);self.rejected(manifest=m)
    def test_symbolic_link_member_rejected(self):self.rejected(self.archive([('nginx.conf',b'',tarfile.SYMTYPE,{})]+[(p,b,tarfile.REGTYPE,{}) for p,b in self.contents.items() if p!='nginx.conf']))
    def test_hard_link_member_rejected(self):self.rejected(self.archive([('nginx.conf',b'',tarfile.LNKTYPE,{})]+[(p,b,tarfile.REGTYPE,{}) for p,b in self.contents.items() if p!='nginx.conf']))
    def test_permission_overriding_pax_rejected(self):self.rejected(self.archive([(p,b,tarfile.REGTYPE,{'SCHILY.mode':'0666'}) for p,b in self.contents.items()]))
    def test_empty_archive_rejected(self):self.rejected(b'')
    def test_truncated_archive_rejected(self):self.rejected(self.archive()[:600])
    def test_existing_workspace_rejected(self):
        self.root.mkdir()
        with self.assertRaisesRegex(ValueError,'new and absolute'):self.stage()
    def test_unsafe_path_rejected_before_write(self):
        m=copy.deepcopy(self.manifest);m['source'][0]['path']='../outside';self.rejected(manifest=m)
    def test_incomplete_mode_policy_rejected(self):
        p=copy.deepcopy(self.policy);p['files'].pop('nginx.conf');self.rejected(policy=p)
    def test_permission_failure_cannot_report_success(self):
        with mock.patch.object(s,'apply_mode',side_effect=PermissionError('controlled mode failure')):
            with self.assertRaises(PermissionError):self.stage()
        self.assertFalse((self.root/'candidate-source-manifest.json').exists())
    def request(self):
        p=json.dumps(self.policy);m=json.dumps(self.manifest);data=self.archive()
        return {'policyJSON':p,'manifestJSON':m,'archiveBase64':base64.b64encode(data).decode()},[str(self.root),sha(p.encode()),sha(m.encode()),sha(data)]
    def call_main(self,request,args,free=8*1024**3):
        with mock.patch.object(s.sys,'platform','linux'),mock.patch.object(s.os,'getuid',return_value=1000,create=True),mock.patch.object(s.shutil,'disk_usage',return_value=type('Disk',(),{'free':free})()),mock.patch.object(s,'stage_source',return_value={'controlled':'handler'}) as handler:
            result=s.main(request,*args)
            handler.assert_called_once();return result
    def test_main_validates_before_staging_dispatch(self):
        r,a=self.request();self.assertEqual(self.call_main(r,a),{'controlled':'handler'})
    def test_main_wrong_policy_rejected_before_dispatch(self):
        r,a=self.request();a[1]='0'*64
        with self.assertRaisesRegex(ValueError,'authority identity'):self.call_main(r,a)
    def test_main_wrong_manifest_rejected_before_dispatch(self):
        r,a=self.request();a[2]='0'*64
        with self.assertRaisesRegex(ValueError,'authority identity'):self.call_main(r,a)
    def test_main_wrong_archive_rejected_before_dispatch(self):
        r,a=self.request();a[3]='0'*64
        with self.assertRaisesRegex(ValueError,'Transfer identity'):self.call_main(r,a)
    def test_main_insufficient_capacity_rejected_before_dispatch(self):
        r,a=self.request()
        with self.assertRaisesRegex(ValueError,'8 GiB'):self.call_main(r,a,8*1024**3-1)
    def test_wrong_platform_rejected_before_dispatch(self):
        r,a=self.request()
        with mock.patch.object(s.sys,'platform','win32'),self.assertRaisesRegex(ValueError,'Linux UID1000'):s.main(r,*a)
    def test_prepared_archive_has_exact_approved_modes(self):
        # Generate the actual frozen 100-file source archive as ordinary data;
        # do not import a historical generated archive into repository source.
        repository=HERE.parents[1];evidence=repository.parent
        approved=json.loads((evidence/'application-baseline.json').read_bytes())['files']
        encoded=io.BytesIO()
        with tarfile.open(fileobj=encoded,mode='w',format=tarfile.USTAR_FORMAT) as prepared:
            for row in approved:
                data=(repository/row['path']).read_bytes();self.assertEqual(sha(data),row['sha256'])
                member=tarfile.TarInfo(row['path']);member.mode=0o644;member.size=len(data)
                prepared.addfile(member,io.BytesIO(data))
        encoded.seek(0)
        with tarfile.open(fileobj=encoded,mode='r:') as archive:
            members=archive.getmembers();self.assertEqual(len(members),100)
            self.assertTrue(all(m.mode==0o644 and m.isfile() for m in members))
    @unittest.skipUnless(os.name=='posix','Windows does not enforce POSIX chmod bits; no local Linux environment installed')
    def test_native_umask_0002_cannot_add_group_write(self):
        old=os.umask(0o002)
        try:self.stage()
        finally:os.umask(old)
        self.assertEqual(stat.S_IMODE((self.root/'source/nginx.conf').stat().st_mode),0o644)
        self.assertEqual(stat.S_IMODE((self.root/'source/public').stat().st_mode),0o755)
    @unittest.skipUnless(os.name=='posix','Windows does not enforce POSIX chmod bits; no local Linux environment installed')
    def test_native_umask_0077_cannot_remove_approved_read_bits(self):
        old=os.umask(0o077)
        try:self.stage()
        finally:os.umask(old)
        self.assertEqual(stat.S_IMODE((self.root/'source/public/index.html').stat().st_mode),0o644)
    @unittest.skipUnless(os.name=='posix','Windows does not enforce POSIX chmod bits; no local Linux environment installed')
    def test_native_private_root_and_manifest(self):
        self.stage();self.assertEqual(stat.S_IMODE(self.root.stat().st_mode),0o700)
        self.assertEqual(stat.S_IMODE((self.root/'candidate-source-manifest.json').stat().st_mode),0o600)
if __name__=='__main__':unittest.main(verbosity=2)
