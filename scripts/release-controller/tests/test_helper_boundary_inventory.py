"""Offline authentication and inventory controls; no qualification execution."""
from pathlib import Path
import ast,copy,hashlib,importlib.util,json,os,py_compile,shutil,struct,subprocess,sys,tempfile,types,unicodedata,unittest
from unittest.mock import patch
from restored_support import P as HERE, load_controller, fixture, bind_unit_context, OLD
c=load_controller(__name__)
EXEC=c.RUN+'-attempt-20261020-01'
from evidence_inventory import inventory_files as inventory

def write(p,value):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value),encoding='utf-8')
def inject_cache(source,cache,sentinel):
    # Inert cache negative: the loader must never be reached. No payload generator.
    cache.parent.mkdir(exist_ok=True)
    cache.write_bytes(importlib.util.MAGIC_NUMBER+b'\x00'*4+struct.pack('<II',int(source.stat().st_mtime)&0xffffffff,source.stat().st_size&0xffffffff)+b'inert-not-code')

class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.controller=Path(self.tmp.name)/'repository/scripts/release-controller';self.controller.mkdir(parents=True);self.root=self.controller/EXEC;self.data=self.root/'data';self.data.mkdir(parents=True)
        shutil.copyfile(HERE/'workflow.py',self.controller/'workflow.py')
        self.helper=self.data/'qualification_evidence.py';self.helper.write_text('PROBE="approved"\n')
        write(self.root/'fresh-inputs.json',{'qualification_evidence.py':c.sha(self.helper)})
        write(self.root/'python-execution-boundary.json',{'controllerFiles':{'workflow.py':c.sha(self.controller/'workflow.py')},'controllerDirectories':[EXEC]})
        write(self.root/'preparation-seal.json',{n:c.sha(self.root/n) for n in ('fresh-inputs.json','python-execution-boundary.json')})
        self.override=patch.object(c,'HERE',self.controller);self.override.start();self.binding=bind_unit_context(c,self.root,controller=self.controller);self.binding.__enter__()
    def tearDown(self):self.binding.__exit__(None,None,None);self.override.stop();self.tmp.cleanup()
    def test_approved_tree_succeeds(self):c.authenticate_helpers(self.root)
    def test_controller_workflow_import_after_authentication_succeeds(self):self.assertEqual(c.workflow().DAEMON,'a69a1524-fcf8-41b9-8371-9a17d84affdc')
    def test_unlisted_bytecode_rejected(self):
        (self.data/'unexpected.pyc').write_bytes(b'not code')
        with self.assertRaisesRegex(ValueError,'Unexpected Python bytecode/cache'):c.authenticate_helpers(self.root)
    def test_empty_cache_directory_rejected(self):
        (self.data/'__pycache__').mkdir()
        with self.assertRaisesRegex(ValueError,'Unexpected Python bytecode/cache'):c.authenticate_helpers(self.root)
    def test_module_rejected(self):
        (self.data/'unexpected.py').write_text('# Inert unexpected import candidate')
        with self.assertRaisesRegex(ValueError,'Unexpected active helper payload'):c.authenticate_helpers(self.root)
    def test_package_rejected_before_init(self):
        p=self.data/'qualification_evidence';p.mkdir();(p/'__init__.py').write_text('# Inert unexpected import candidate')
        with self.assertRaisesRegex(ValueError,'Unexpected active helper payload'):c.authenticate_helpers(self.root)
    def test_empty_namespace_package_rejected(self):
        (self.data/'unlisted_package').mkdir()
        with self.assertRaisesRegex(ValueError,'Unexpected active helper payload'):c.authenticate_helpers(self.root)
    def test_changed_approved_source_rejected(self):
        self.helper.write_text('PROBE="substituted"\n')
        with self.assertRaisesRegex(ValueError,'Approved helper input missing or changed'):c.authenticate_helpers(self.root)
    def test_missing_approved_source_rejected(self):
        self.helper.unlink()
        with self.assertRaises(FileNotFoundError):c.authenticate_helpers(self.root)
    def test_changed_boundary_manifest_rejected(self):
        write(self.root/'python-execution-boundary.json',{})
        with self.assertRaisesRegex(ValueError,'Python boundary identity mismatch'):c.authenticate_helpers(self.root)
    def test_changed_input_catalog_rejected(self):
        write(self.root/'fresh-inputs.json',{})
        with self.assertRaisesRegex(ValueError,'Helper input catalog changed'):c.authenticate_helpers(self.root)
    def test_controller_unlisted_module_rejected(self):
        (self.controller/'unlisted.py').write_text('# Inert unexpected import candidate')
        with self.assertRaisesRegex(ValueError,'Unexpected controller executable/importable'):c.workflow()
    def test_controller_unlisted_package_rejected(self):
        (self.controller/'unlisted_package').mkdir()
        with self.assertRaisesRegex(ValueError,'Unexpected controller directory'):c.workflow()
    def test_controller_missing_workflow_rejected(self):
        (self.controller/'workflow.py').unlink()
        with self.assertRaises(FileNotFoundError):c.workflow()
    def test_cached_workflow_cannot_execute(self):
        source=self.controller/'workflow.py';sentinel=self.controller/'sentinel'
        inject_cache(source,Path(importlib.util.cache_from_source(str(source))),sentinel)
        with self.assertRaisesRegex(ValueError,'Unexpected controller directory'):c.workflow()
        self.assertFalse(sentinel.exists())
    def test_injected_data_cache_rejected_before_import(self):
        sentinel=self.controller/'sentinel';inject_cache(self.helper,Path(importlib.util.cache_from_source(str(self.helper))),sentinel)
        original=c.sha(self.helper)
        with patch.object(importlib.util,'spec_from_file_location') as loader,self.assertRaisesRegex(ValueError,'Unexpected Python bytecode/cache'):c.authenticate_helpers(self.root)
        loader.assert_not_called();self.assertEqual(c.sha(self.helper),original);self.assertFalse(sentinel.exists())
    def test_link_guard_fails_before_hash_or_import(self):
        with patch.object(Path,'is_symlink',lambda p:p==self.helper),self.assertRaisesRegex(ValueError,'Linked helper boundary entry'):c.authenticate_helpers(self.root)
    def test_linked_attempt_root_rejected_before_seal_read(self):
        with patch.object(Path,'is_symlink',lambda p:p==self.root),self.assertRaisesRegex(ValueError,'Linked helper boundary entry'):c.verify(self.root)
    def test_real_symlink_escape(self):
        outside=self.controller/'outside.txt';outside.write_text('not approved')
        self.helper.unlink()
        try:os.symlink(outside,self.helper)
        except OSError as e:self.skipTest('Native symlink creation unavailable: '+str(e))
        with self.assertRaisesRegex(ValueError,'Linked helper boundary entry'):c.authenticate_helpers(self.root)

class InventoryTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def test_nested_same_basename_included(self):
        for n in ('final-evidence-inventory.json','final-evidence-inventory.sha256','history/final-evidence-inventory.json','before/final-evidence-inventory.json','history/final-evidence-inventory.sha256'):
            p=self.root/n;p.parent.mkdir(exist_ok=True);p.write_text(n)
        rows=inventory(self.root)
        self.assertEqual({r['path'] for r in rows},{'history/final-evidence-inventory.json','before/final-evidence-inventory.json','history/final-evidence-inventory.sha256'})
    def test_hashes_sizes_and_order(self):
        for n in ('z','a','m'):(self.root/n).write_bytes(n.encode()*3)
        rows=inventory(self.root);self.assertEqual([r['path'] for r in rows],['a','m','z'])
        for r in rows:self.assertEqual(r['sha256'],c.sha(self.root/r['path']));self.assertEqual(r['bytes'],3)
    def test_duplicate_path_rejected(self):
        p=self.root/'a';p.write_text('a')
        with self.assertRaisesRegex(ValueError,'Duplicate normalized inventory path'):inventory(self.root,[p,p])
    def test_case_normalized_collision_rejected(self):
        a=self.root/'a';b=self.root/'A';a.write_text('a');b.write_text('b')
        with self.assertRaisesRegex(ValueError,'Duplicate normalized inventory path'):inventory(self.root,[a,b])
    def test_unicode_normalized_collision_rejected(self):
        a=self.root/'\u00e9';b=self.root/'e\u0301';a.write_text('a');b.write_text('b')
        with self.assertRaisesRegex(ValueError,'Duplicate normalized inventory path'):inventory(self.root,[a,b])
    def test_traversal_rejected(self):
        p=self.root/'x/../file'
        with self.assertRaisesRegex(ValueError,'Unsafe inventory path'):inventory(self.root,[p])
    def test_outside_path_rejected(self):
        with self.assertRaisesRegex(ValueError,'Escaping inventory path'):inventory(self.root,[self.root.parent/'outside'])
    def test_symlink_guard_rejected(self):
        p=self.root/'link';p.write_text('x')
        with patch.object(Path,'is_symlink',lambda q:q==p),self.assertRaisesRegex(ValueError,'Linked inventory path'):inventory(self.root)
    def test_linked_root_ancestor_rejected(self):
        with patch.object(Path,'is_symlink',lambda q:q==self.root.parent),self.assertRaisesRegex(ValueError,'Linked inventory root'):inventory(self.root)
    def test_real_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as other:
            outside=Path(other)/'outside';outside.write_text('x')
            try:os.symlink(outside,self.root/'link')
            except OSError as e:self.skipTest('Native symlink creation unavailable: '+str(e))
            with self.assertRaisesRegex(ValueError,'Linked inventory path'):inventory(self.root)
    def test_historical_receipt_bytes_preserved(self):
        p=self.root/'history/receipt.json';p.parent.mkdir();p.write_bytes(b'{"failed":true}\n');before=p.read_bytes()
        rows=inventory(self.root);self.assertEqual(p.read_bytes(),before);self.assertEqual(rows[0]['sha256'],hashlib.sha256(before).hexdigest())
    def test_missing_file_not_silently_excluded(self):
        with self.assertRaisesRegex(ValueError,'Nonregular inventory entry'):inventory(self.root,[self.root/'missing'])

if __name__=='__main__':unittest.main(verbosity=2)
