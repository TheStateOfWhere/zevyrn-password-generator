"""Defensive CLI path tests: ordinary files/directories and mocked dispatch only."""
from pathlib import Path
from contextlib import ExitStack,redirect_stdout
import importlib.util,io,json,os,sys,tempfile,unittest
from unittest.mock import Mock,patch
from restored_support import P as HERE, load_controller, fixture, bind_unit_context, OLD
c=load_controller(__name__)
EXEC=c.RUN+'-attempt-20261020-01'
HANDLERS=('verify','readiness','preflight','scan','scan_accept','reuse','audit','accept','create','collect_runtime','browser','supplemental_browser_producer','remove_owned','settled','final')
PHASES=('verify','readiness','preflight','scan','scan-acceptance','reuse','audit','accept','runtime-create','browser-create','runtime-collect','browser-collect','browser-test','browser-console','clipboard-cleanup','remove-runtime','remove-browser','settled','final')

class CliPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name);self.root=self.base/EXEC;self.root.mkdir()
        self.stack=ExitStack();self.stack.enter_context(bind_unit_context(c,self.root));self.handlers={n:self.stack.enter_context(patch.object(c,n,Mock(return_value={'testOnly':True}))) for n in HANDLERS}
    def tearDown(self):self.stack.close();self.tmp.cleanup()
    def main(self,path=None,phase='verify'):
        with patch.object(sys,'argv',['continuation.py',phase,str(path if path is not None else self.root),'--execute-approved']),redirect_stdout(io.StringIO()):c.main()
    def no_dispatch(self):
        for handler in self.handlers.values():handler.assert_not_called()
    def test_ordinary_directory_canonicalized_then_dispatched(self):
        self.main();self.handlers['verify'].assert_called_once_with(self.root.resolve())
    def test_relative_directory_checked_and_canonicalized(self):
        relative=Path(os.path.relpath(self.root,os.getcwd()));self.main(relative)
        self.handlers['verify'].assert_called_once_with(self.root.resolve())
    def test_lexical_checks_precede_resolve_and_dispatch(self):
        events=[];plain=c.plain_entry;resolve=Path.resolve
        def checked(path):events.append(('checked',path));return plain(path)
        def resolved(path,*args,**kwargs):events.append(('resolved',path));return resolve(path,*args,**kwargs)
        with patch.object(c,'plain_entry',checked),patch.object(Path,'resolve',resolved):self.main()
        checks=[i for i,event in enumerate(events) if event[0]=='checked'];resolves=[i for i,event in enumerate(events) if event[0]=='resolved']
        self.assertEqual([events[i][1] for i in checks],[self.root.absolute(),*self.root.absolute().parents])
        self.assertTrue(checks and resolves);self.assertLess(max(checks),min(resolves))
    def test_linked_root_rejected_through_main(self):
        with patch.object(Path,'is_symlink',lambda p:p==self.root),self.assertRaisesRegex(ValueError,'Linked helper boundary entry'):self.main()
        self.no_dispatch()
    def test_linked_ancestor_rejected_through_main(self):
        with patch.object(Path,'is_symlink',lambda p:p==self.base),self.assertRaisesRegex(ValueError,'Linked helper boundary entry'):self.main()
        self.no_dispatch()
    def test_junction_root_rejected_through_main(self):
        with patch.object(Path,'is_junction',lambda p:p==self.root,create=True),self.assertRaisesRegex(ValueError,'Linked helper boundary entry'):self.main()
        self.no_dispatch()
    def test_all_cli_phases_reject_before_dispatch(self):
        for phase in PHASES:
            with self.subTest(phase=phase),patch.object(Path,'is_symlink',lambda p:p==self.root),self.assertRaisesRegex(ValueError,'Linked helper boundary entry'):self.main(phase=phase)
        self.no_dispatch()
    def test_all_cli_phases_use_canonical_path(self):
        seen=[]
        for handler in self.handlers.values():handler.side_effect=lambda root,*args,**kwargs:seen.append(root) or {'testOnly':True}
        for phase in PHASES:self.main(phase=phase)
        self.assertEqual(seen,[self.root.resolve()]*len(PHASES))
    def test_missing_directory_rejected(self):
        with self.assertRaises(FileNotFoundError):self.main(self.base/'missing')
        self.no_dispatch()
    def test_file_path_rejected_before_resolve(self):
        file=self.base/'ordinary.txt';file.write_text('ordinary fixture')
        with patch.object(Path,'resolve',side_effect=AssertionError('canonicalization must not occur')),self.assertRaisesRegex(ValueError,'Execution path must be an existing directory'):self.main(file)
        self.no_dispatch()
    def test_invalid_path_rejected(self):
        with self.assertRaises((ValueError,OSError)):self.main(str(self.root)+'\x00')
        self.no_dispatch()
    def test_inaccessible_path_fails_closed(self):
        with patch.object(c,'plain_entry',side_effect=PermissionError('controlled access denial')),self.assertRaisesRegex(PermissionError,'controlled access denial'):self.main()
        self.no_dispatch()
    def test_direct_verify_retains_original_root_check(self):
        self.stack.close() # Exercise the real direct-verification function.
        with patch.object(Path,'is_symlink',lambda p:p==self.root),patch.object(c,'read') as read,self.assertRaisesRegex(ValueError,'Linked helper boundary entry'):c.verify(self.root)
        read.assert_not_called()
    def test_direct_verify_checks_ancestor(self):
        self.stack.close()
        with patch.object(Path,'is_symlink',lambda p:p==self.base),patch.object(c,'read') as read,self.assertRaisesRegex(ValueError,'Linked helper boundary entry'):c.verify(self.root)
        read.assert_not_called()
    def test_existing_approved_preparation_verifies(self):
        self.stack.close()
        with bind_unit_context(c,fixture(c)):c.verify(fixture(c))
    def test_native_symlink_root(self):
        parent=self.base/'alias-parent';parent.mkdir();link=parent/EXEC
        try:os.symlink(self.root,link,target_is_directory=True)
        except OSError as e:self.skipTest('Native symlink creation unavailable: '+str(e))
        try:
            with self.assertRaisesRegex(ValueError,'Linked helper boundary entry'):self.main(link)
            self.no_dispatch()
        finally:link.unlink()
    def test_native_symlink_ancestor(self):
        parent=self.base/'real-parent';parent.mkdir();(parent/EXEC).mkdir();link=self.base/'alias-parent'
        try:os.symlink(parent,link,target_is_directory=True)
        except OSError as e:self.skipTest('Native symlink creation unavailable: '+str(e))
        try:
            with self.assertRaisesRegex(ValueError,'Linked helper boundary entry'):self.main(link/EXEC)
            self.no_dispatch()
        finally:link.unlink()
    def junction(self,target,link):
        if sys.platform!='win32':self.skipTest('Windows junction test only')
        import _winapi
        if not hasattr(_winapi,'CreateJunction'):self.skipTest('Native junction API unavailable')
        try:_winapi.CreateJunction(str(target),str(link))
        except OSError as e:self.skipTest('Native junction creation unavailable: '+str(e))
    def test_native_junction_root(self):
        parent=self.base/'junction-parent';parent.mkdir();link=parent/EXEC;self.junction(self.root,link)
        try:
            self.assertTrue(link.is_junction())
            with self.assertRaisesRegex(ValueError,'Linked helper boundary entry'):self.main(link)
            self.no_dispatch()
        finally:os.rmdir(link)
    def test_native_junction_ancestor(self):
        parent=self.base/'real-parent';parent.mkdir();(parent/EXEC).mkdir();link=self.base/'junction-parent';self.junction(parent,link)
        try:
            self.assertTrue(link.is_junction())
            with self.assertRaisesRegex(ValueError,'Linked helper boundary entry'):self.main(link/EXEC)
            self.no_dispatch()
        finally:os.rmdir(link)

if __name__=='__main__':unittest.main(verbosity=2)
