"""Deterministic synthetic Docker-save archives; no daemon, network or scanner."""
from pathlib import Path
import ast
import gzip
import hashlib
import io
import json
import tarfile
import unittest

E = Path(__file__).resolve().parents[1]
DB = 'lib/apk/db/installed'
V1 = b'P:synthetic-package\nV:1.0-r0\nA:x86_64\n\n'
V2 = V1.replace(b'1.0-r0', b'2.0-r0')


def load_helper(path, work):
    tree = ast.parse(path.read_text())
    names = {'digest', 'write', 'packages', 'archive_name', 'archive_inventory'}
    definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = {'Path': Path, 'hashlib': hashlib, 'json': json, 'tarfile': tarfile, 'gzip': gzip, 'R': work}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


def entry(name, data=b'', kind=tarfile.REGTYPE, link=''):
    return (name, data, kind, link)


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for name, data, kind, link in entries:
            item = tarfile.TarInfo(name); item.type = kind; item.linkname = link
            item.size = len(data) if kind == tarfile.REGTYPE else 0
            archive.addfile(item, io.BytesIO(data) if item.isfile() else None)
    return output.getvalue()


class WhiteoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent = E.parents[2].with_name(E.parents[2].name+'-completion') / 'whiteout-fixtures'
        parent.parent.mkdir(parents=True,exist_ok=True)
        parent.mkdir(exist_ok=True)
        for attempt in range(1, 1000):
            cls.root = parent / ('run-' + str(attempt).zfill(3))
            try:
                cls.root.mkdir(exist_ok=False)
                break
            except FileExistsError:
                continue
        else:
            raise RuntimeError('No unused synthetic test directory')

    def setUp(self):
        self.work = self.root / self._testMethodName
        self.work.mkdir()
        self.helper = load_helper(E / 'scan-images.py', self.work)
        self.counter = 0

    def image(self, layers, *, compress=False, config_ref='config.json', layer_ref=None,
              extra_outer=(), config_edit=None, image_id=None, bad_diff=False):
        self.counter += 1
        blobs = [tar_bytes(items) for items in layers]
        config = {'os': 'linux', 'architecture': 'amd64', 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(b).hexdigest() for b in blobs]}}
        if bad_diff and blobs:
            config['rootfs']['diff_ids'][0] = 'sha256:' + 'f' * 64
        if config_edit:
            config_edit(config)
        config_bytes = json.dumps(config, sort_keys=True).encode()
        refs = [layer_ref if i == 0 and layer_ref is not None else str(i) + '/layer.tar' for i in range(len(blobs))]
        manifest = [{'Config': config_ref, 'Layers': refs}]
        outer = [entry('manifest.json', json.dumps(manifest).encode()), entry(config_ref, config_bytes)]
        outer += [entry(ref, gzip.compress(blob, mtime=0) if compress else blob) for ref, blob in zip(refs, blobs)]
        outer += list(extra_outer)
        path = self.work / ('image-' + str(self.counter) + '.tar')
        path.write_bytes(tar_bytes(outer))
        return {'archive': path.name, 'archiveSHA256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'image': {'id': image_id or 'sha256:' + hashlib.sha256(config_bytes).hexdigest()}}

    def inventory(self, layers, **kwargs):
        build = self.image(layers, **kwargs)
        result = self.helper['archive_inventory']('case-' + str(self.counter), build)
        return result

    def missing(self, layers):
        with self.assertRaisesRegex(ValueError, 'Incomplete package inventory: effective APK database missing'):
            self.inventory(layers)
        self.assertFalse((self.work / ('case-' + str(self.counter) + '-installed-packages.json')).exists())

    def test_base_database(self):
        self.assertEqual(self.inventory([[entry(DB, V1)]]), {'synthetic-package': '1.0-r0'})

    def test_ordinary_database_whiteout(self):
        self.missing([[entry(DB, V1)], [entry('lib/apk/db/.wh.installed')]])

    def test_opaque_database_directory(self):
        self.missing([[entry(DB, V1)], [entry('lib/apk/db/.wh..wh..opq')]])

    def test_parent_removed(self):
        for marker in ['.wh.lib', 'lib/.wh.apk', 'lib/apk/.wh.db']:
            with self.subTest(marker=marker):
                self.missing([[entry(DB, V1)], [entry(marker)]])

    def test_opaque_ancestors(self):
        for marker in ['.wh..wh..opq', 'lib/.wh..wh..opq', 'lib/apk/.wh..wh..opq']:
            with self.subTest(marker=marker):
                self.missing([[entry(DB, V1)], [entry(marker)]])

    def test_later_database_recreation(self):
        self.assertEqual(self.inventory([[entry(DB, V1)], [entry('lib/.wh.apk')], [entry(DB, V2)]]), {'synthetic-package': '2.0-r0'})

    def test_same_layer_recreation_order_independent(self):
        for marker in ['lib/apk/db/.wh.installed', 'lib/apk/db/.wh..wh..opq', '.wh.lib']:
            for additions_first in (False, True):
                with self.subTest(marker=marker, additions_first=additions_first):
                    items = [entry(marker), entry(DB, V2)]
                    if additions_first:
                        items.reverse()
                    self.assertEqual(self.inventory([[entry(DB, V1)], items]), {'synthetic-package': '2.0-r0'})

    def test_new_database_survives_same_layer_whiteout_without_base(self):
        self.assertEqual(self.inventory([[entry(DB, V2), entry('lib/apk/db/.wh..wh..opq')]]), {'synthetic-package': '2.0-r0'})

    def test_unrelated_whiteouts(self):
        for marker in ['etc/.wh.unrelated', 'lib/apk/db/.wh.installed-backup', 'lib/apk/db/elsewhere/.wh..wh..opq', 'lib/apk2/.wh..wh..opq']:
            with self.subTest(marker=marker):
                self.assertEqual(self.inventory([[entry(DB, V1)], [entry(marker)]]), {'synthetic-package': '1.0-r0'})

    def test_multiple_layers_conflicting_operations(self):
        layers = [[entry(DB, V1)], [entry('lib/.wh.apk')], [entry(DB, V2)], [entry('lib/apk/db/.wh..wh..opq')], [entry(DB, V1)]]
        self.assertEqual(self.inventory(layers), {'synthetic-package': '1.0-r0'})
        self.missing(layers + [[entry('.wh.lib')]])

    def test_layer_order_changes_result(self):
        self.missing([[entry(DB, V1)], [entry('lib/apk/db/.wh.installed')]])
        self.assertEqual(self.inventory([[entry('lib/apk/db/.wh.installed')], [entry(DB, V1)]]), {'synthetic-package': '1.0-r0'})

    def test_malformed_whiteout_types(self):
        for kind in (tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError, 'Malformed whiteout entry'):
                    self.inventory([[entry(DB, V1)], [entry('lib/apk/db/.wh.installed', kind=kind, link=DB)]])

    def test_nonempty_whiteout(self):
        with self.assertRaisesRegex(ValueError, 'Malformed whiteout entry'):
            self.inventory([[entry(DB, V1)], [entry('lib/apk/db/.wh..wh..opq', b'bad')]])

    def test_malformed_whiteout_names(self):
        for name in ['lib/.wh.', 'lib/.wh..', 'lib/.wh...', 'lib/.wh..wh.other', 'lib/.wh.bad/child']:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, 'Malformed whiteout'):
                    self.inventory([[entry(DB, V1)], [entry(name)]])

    def test_unsafe_layer_member_names(self):
        for name in ['../escape', '/absolute', 'lib/../../escape', 'lib/../apk/db/installed', 'lib//apk/db/installed', 'C:/escape', r'lib\apk\db\installed']:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, 'Unsafe archive member name'):
                    self.inventory([[entry(DB, V1), entry(name)]])

    def test_unsafe_outer_names_and_references(self):
        for name in ['../config.json', '/config.json', 'C:/config.json']:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, 'Unsafe archive member name'):
                    self.inventory([[entry(DB, V1)]], config_ref=name)
        with self.assertRaisesRegex(ValueError, 'Unsafe archive member name'):
            self.inventory([[entry(DB, V1)]], layer_ref='../layer.tar')
        with self.assertRaisesRegex(ValueError, 'Unsafe archive member name'):
            self.inventory([[entry(DB, V1)]], extra_outer=[entry('../unused', b'bad')])

    def test_unsafe_name_direct_nul_and_empty(self):
        for name in ['bad\x00name', '', './bad/./file']:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, 'Unsafe archive member name'):
                    self.helper['archive_name'](name)

    def test_missing_database(self):
        self.missing([[entry('etc/unrelated', b'no database')]])

    def test_zero_layers_missing_database(self):
        self.missing([])

    def test_empty_database(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete package inventory: effective APK database empty'):
            self.inventory([[entry(DB)]])
        self.assertFalse(list(self.work.glob('*-installed-packages.json')))

    def test_duplicate_layer_members(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate layer member'):
            self.inventory([[entry(DB, V1), entry(DB, V2)]])

    def test_duplicate_outer_members(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported or duplicate outer archive member'):
            self.inventory([[entry(DB, V1)]], extra_outer=[entry('config.json', b'duplicate')])

    def test_package_database_link_or_directory_is_incomplete(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError, 'Incomplete package inventory: database is not a regular file'):
                    self.inventory([[entry(DB, V1)], [entry(DB, kind=kind, link='elsewhere')]])

    def test_database_ancestor_replacement_is_incomplete(self):
        for kind in (tarfile.REGTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError, 'Incomplete package inventory: unsupported database ancestor replacement'):
                    self.inventory([[entry(DB, V1)], [entry('lib/apk/db', kind=kind, link='elsewhere')]])

    def test_database_ancestor_directory_metadata_preserves_database(self):
        self.assertEqual(self.inventory([[entry(DB, V1)], [entry('lib/apk/db', kind=tarfile.DIRTYPE)]]), {'synthetic-package': '1.0-r0'})

    def test_gzip_layers(self):
        self.assertEqual(self.inventory([[entry(DB, V1)], [entry('lib/apk/db/.wh..wh..opq'), entry(DB, V2)]], compress=True), {'synthetic-package': '2.0-r0'})

    def test_dot_prefixed_members_and_root_directory(self):
        self.assertEqual(self.inventory([[entry('./', kind=tarfile.DIRTYPE), entry('./' + DB, V1)], [entry('./lib/apk/db/.wh..wh..opq'), entry('./' + DB, V2)]]), {'synthetic-package': '2.0-r0'})

    def test_image_identity_tampering_still_fails(self):
        with self.assertRaises(AssertionError):
            self.inventory([[entry(DB, V1)]], image_id='sha256:' + '0' * 64)

    def test_layer_diff_id_tampering_still_fails(self):
        with self.assertRaises(AssertionError):
            self.inventory([[entry(DB, V1)]], bad_diff=True)

    def test_archive_hash_tampering_still_fails(self):
        build = self.image([[entry(DB, V1)]]); build['archiveSHA256'] = '0' * 64
        with self.assertRaises(AssertionError):
            self.helper['archive_inventory']('bad-archive', build)

    def test_platform_tampering_still_fails(self):
        with self.assertRaises(AssertionError):
            self.inventory([[entry(DB, V1)]], config_edit=lambda config: config.update(architecture='arm64'))

    def test_runtime_package_pins_still_enforced(self):
        build = self.image([[entry(DB, V1)]])
        with self.assertRaisesRegex(AssertionError, 'Runtime package mismatch: nginx'):
            self.helper['archive_inventory']('runtime', build)

    def test_retained_original_bug_is_detected(self):
        original = load_helper(E / 'tests/fixtures/original-package-reader.py', self.work)
        build = self.image([[entry(DB, V1)], [entry('lib/apk/db/.wh..wh..opq')]])
        self.assertEqual(original['archive_inventory']('original-negative-control', build), {'synthetic-package': '1.0-r0'})
        with self.assertRaisesRegex(ValueError, 'Incomplete package inventory'):
            self.helper['archive_inventory']('corrected-negative-control', build)


if __name__ == '__main__':
    unittest.main()
