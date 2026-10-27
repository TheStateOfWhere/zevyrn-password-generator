"""Synthetic archive tests only: no Docker, SSH, scanner, or network execution."""
import ast
import base64
import copy
import gzip
import hashlib
import io
import json
import pathlib
import runpy
import tarfile
import tempfile
import unittest

HERE = pathlib.Path(__file__).parent
NS = runpy.run_path(str(HERE / 'remote-driver.py'), run_name='identity_tests')
INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
EMPTY = 'application/vnd.oci.empty.v1+json'
LAYER = 'application/vnd.oci.image.layer.v1.tar'

def sha(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()

class Fixture:
    def __init__(self, change=None, compressed=False):
        self.files = {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}'}
        def blob(value, kind):
            data = value if isinstance(value, bytes) else json.dumps(value, separators=(',', ':')).encode()
            desc = {'mediaType': kind, 'digest': sha(data), 'size': len(data)}
            self.files['blobs/sha256/' + desc['digest'][7:]] = data
            return desc
        self.diffids = [sha(b'first layer'), sha(b'second layer')]
        self.config = {'os': 'linux', 'architecture': 'amd64', 'rootfs': {'type': 'layers', 'diff_ids': self.diffids.copy()}}
        self.layers = [blob(gzip.compress(x) if compressed else x, LAYER + ('+gzip' if compressed else '')) for x in [b'first layer', b'second layer']]
        if change:
            change(self)
        self.c = blob(self.config, CONFIG)
        manifest = {'schemaVersion': 2, 'mediaType': MANIFEST, 'config': self.c, 'layers': self.layers}
        self.m = blob(manifest, MANIFEST)
        self.m['platform'] = {'os': 'linux', 'architecture': 'amd64'}
        index = {'schemaVersion': 2, 'mediaType': INDEX, 'manifests': [self.m]}
        self.i = blob(index, INDEX)
        self.files['index.json'] = json.dumps({'schemaVersion': 2, 'mediaType': INDEX, 'manifests': [self.i]}).encode()
        self.inspect = {'Id': self.i['digest'], 'Descriptor': self.i.copy(), 'Os': 'linux', 'Architecture': 'amd64',
                        'RootFS': {'Type': 'layers', 'Layers': self.diffids.copy()}}
        self.report = {'Metadata': {'ImageID': self.c['digest'], 'DiffIDs': self.diffids.copy(), 'ImageConfig': copy.deepcopy(self.config)}}

    def object(self, desc, transform):
        key = 'blobs/sha256/' + desc['digest'][7:]
        value = json.loads(self.files.pop(key))
        transform(value)
        data = json.dumps(value).encode()
        desc.update(digest=sha(data), size=len(data))
        self.files['blobs/sha256/' + desc['digest'][7:]] = data

    def replace_index(self, transform):
        self.object(self.i, transform)
        self.inspect.update(Id=self.i['digest'], Descriptor=self.i.copy())
        self.files['index.json'] = json.dumps({'schemaVersion': 2, 'mediaType': INDEX, 'manifests': [self.i]}).encode()

    def empty_attestation(self, config_edit=None, descriptor_edit=None, payload=b'{}'):
        # Actual observed descriptor: empty.v1+json, two bytes, embedded Base64.
        config = {'mediaType': EMPTY, 'digest': sha(payload), 'size': len(payload),
                  'data': base64.b64encode(payload).decode('ascii')}
        self.files['blobs/sha256/' + config['digest'][7:]] = payload
        if config_edit: config_edit(config)
        statement = b'synthetic attestation; not execution evidence'
        layer = {'mediaType': 'application/vnd.in-toto+json', 'digest': sha(statement), 'size': len(statement)}
        self.files['blobs/sha256/' + layer['digest'][7:]] = statement
        raw = json.dumps({'schemaVersion': 2, 'mediaType': MANIFEST, 'config': config, 'layers': [layer]}).encode()
        attestation = {'mediaType': MANIFEST, 'digest': sha(raw), 'size': len(raw),
                       'platform': {'os': 'unknown', 'architecture': 'unknown'},
                       'annotations': {'vnd.docker.reference.type': 'attestation-manifest',
                                       'vnd.docker.reference.digest': self.m['digest']}}
        self.files['blobs/sha256/' + attestation['digest'][7:]] = raw
        if descriptor_edit: descriptor_edit(attestation)
        self.replace_index(lambda value: value['manifests'].append(attestation))
        return config

    def check(self, extra=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'image.tar'
            with tarfile.open(path, 'w') as t:
                for name, data in self.files.items():
                    member = tarfile.TarInfo(name); member.size = len(data)
                    t.addfile(member, io.BytesIO(data))
                if extra:
                    member, data = extra
                    t.addfile(member, io.BytesIO(data))
            identity = NS['image_archive_identity'](path, self.inspect)
            NS['verify_scanner_identity'](self.report, identity)
            return identity

class IdentityTests(unittest.TestCase):
    def test_index_manifest_config_are_distinct_and_verified(self):
        f = Fixture(); d = f.check()
        self.assertIn(f.i['digest'], d['indexDigests'])
        self.assertEqual(d['manifestDigest'], f.m['digest'])
        self.assertEqual(d['configurationDigest'], f.c['digest'])
        self.assertEqual(len({f.i['digest'], f.m['digest'], f.c['digest']}), 3)

    def test_gzip_layer_diffids(self):
        Fixture(compressed=True).check()

    def test_direct_manifest_descriptor(self):
        f = Fixture(); f.inspect.update(Id=f.m['digest'], Descriptor=f.m.copy()); f.check()

    def test_classic_configuration_id(self):
        f = Fixture(); f.inspect.pop('Descriptor'); f.inspect['Id'] = f.c['digest']; f.check()

    def test_attestation_is_verified_but_not_selected(self):
        f = Fixture()
        cfg = b'{"os":"unknown","architecture":"unknown"}'
        c = {'mediaType': CONFIG, 'digest': sha(cfg), 'size': len(cfg)}
        f.files['blobs/sha256/' + c['digest'][7:]] = cfg
        raw = json.dumps({'schemaVersion': 2, 'mediaType': MANIFEST, 'config': c, 'layers': f.layers}).encode()
        a = {'mediaType': MANIFEST, 'digest': sha(raw), 'size': len(raw),
             'platform': {'os': 'unknown', 'architecture': 'unknown'},
             'annotations': {'vnd.docker.reference.type': 'attestation-manifest',
                             'vnd.docker.reference.digest': f.m['digest']}}
        f.files['blobs/sha256/' + a['digest'][7:]] = raw
        f.replace_index(lambda v: v['manifests'].append(a)); f.check()

    def test_actual_empty_configuration_attestation(self):
        f = Fixture(); c = f.empty_attestation()
        self.assertEqual(c['digest'], 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a')
        self.assertEqual(c['size'], 2)
        identity = f.check()
        self.assertEqual(identity['manifestDigest'], f.m['digest'])
        self.assertEqual(identity['configurationDigest'], f.c['digest'])

    def test_empty_attestation_config_without_embedded_data(self):
        f = Fixture(); f.empty_attestation(config_edit=lambda c: c.pop('data')); f.check()

    def test_valid_embedded_runnable_configuration_is_verified(self):
        f = Fixture(); data = f.files['blobs/sha256/' + f.c['digest'][7:]]
        f.object(f.m, lambda m: m['config'].update(data=base64.b64encode(data).decode('ascii')))
        f.replace_index(lambda i: i.update(manifests=[f.m])); f.check()

    def test_embedded_encoding_type_and_bounds_fail_closed(self):
        for value in ['not base64!', 'AA==extra', 'é', None, 4, 'A'*87385]:
            with self.subTest(valueType=type(value).__name__):
                f = Fixture(); f.empty_attestation(config_edit=lambda c: c.update(data=value))
                with self.assertRaises(RuntimeError): f.check()

    def test_embedded_size_and_digest_mismatches(self):
        for edit in [lambda c: c.update(size=3), lambda c: c.update(digest='sha256:'+'0'*64),
                     lambda c: c.update(data=base64.b64encode(b'xx').decode('ascii')),
                     lambda c: c.update(data=base64.b64encode(b'').decode('ascii'))]:
            f = Fixture(); f.empty_attestation(config_edit=edit)
            with self.assertRaises(RuntimeError): f.check()

    def test_embedded_data_does_not_replace_missing_or_conflicting_archive_blob(self):
        for absent in [True,False]:
            f = Fixture(); c = f.empty_attestation(); key = 'blobs/sha256/'+c['digest'][7:]
            if absent: del f.files[key]
            else: f.files[key] = b'xx'
            with self.assertRaises(RuntimeError): f.check()

    def test_empty_config_requires_exact_empty_payload(self):
        for payload in [b'[]', b'{ }', b'{"os":"unknown","architecture":"unknown"}']:
            f = Fixture(); f.empty_attestation(payload=payload)
            with self.assertRaisesRegex(RuntimeError,'OCI_ATTESTATION_EMPTY_CONFIG'): f.check()

    def test_empty_config_cannot_be_runnable(self):
        f=Fixture(); c=f.empty_attestation()
        f.object(f.m,lambda m:m.update(config=c))
        f.replace_index(lambda i:i.update(manifests=[f.m]))
        with self.assertRaisesRegex(RuntimeError,'OCI_CONFIG_TYPE'):f.check()

    def test_attestation_reference_and_platform_are_bound_to_selected_image(self):
        for edit in [lambda a:a['annotations'].pop('vnd.docker.reference.digest'),
                     lambda a:a['annotations'].update({'vnd.docker.reference.digest':'sha256:'+'0'*64}),
                     lambda a:a.update(platform={'os':'linux','architecture':'amd64'}),
                     lambda a:a.update(platform={'os':'unknown','architecture':'amd64'}),
                     lambda a:a['platform'].update(variant='v1')]:
            f=Fixture();f.empty_attestation(descriptor_edit=edit)
            with self.assertRaises(RuntimeError):f.check()

    def test_missing_or_corrupt_each_chain_blob(self):
        for field in ['i', 'm', 'c']:
            for mode in ['missing', 'modified', 'size']:
                with self.subTest(field=field, mode=mode):
                    f = Fixture(); key = 'blobs/sha256/' + getattr(f, field)['digest'][7:]
                    if mode == 'missing': del f.files[key]
                    elif mode == 'modified': f.files[key] = b'X' * len(f.files[key])
                    else: f.files[key] += b' '
                    with self.assertRaises(RuntimeError): f.check()

    def test_wrong_config_platform_and_diffid_order(self):
        for change in [lambda f: f.config.update(os='windows'),
                       lambda f: f.config.update(architecture='arm64'),
                       lambda f: f.config['rootfs']['diff_ids'].reverse(),
                       lambda f: f.layers.reverse(),
                       lambda f: f.config['rootfs'].update(type='other')]:
            with self.subTest(change=change), self.assertRaises(RuntimeError): Fixture(change).check()

    def test_ambiguous_runnable_and_duplicate_descriptor(self):
        for duplicate in [True, False]:
            f = Fixture(); other = copy.deepcopy(f.m)
            if not duplicate:
                f.object(other, lambda v: v.update(annotations={'different': 'manifest'}))
            f.replace_index(lambda v: v['manifests'].append(other))
            with self.subTest(duplicate=duplicate), self.assertRaises(RuntimeError): f.check()

    def test_missing_wrong_or_forged_platform(self):
        for transform in [lambda d: d.pop('platform'), lambda d: d.update(platform={'os': 'linux', 'architecture': 'arm64'}),
                          lambda d: d.update(annotations={'vnd.docker.reference.type': 'attestation-manifest'})]:
            f = Fixture(); f.replace_index(lambda v: transform(v['manifests'][0]))
            with self.assertRaises(RuntimeError): f.check()

    def test_docker_platform_layers_and_descriptor_mismatch(self):
        for change in [lambda d: d.update(Os='windows'), lambda d: d.update(Architecture='arm64'),
                       lambda d: d['RootFS']['Layers'].reverse(), lambda d: d.update(Id='sha256:'+'0'*64),
                       lambda d: d['Descriptor'].update(size=1), lambda d: d['Descriptor'].update(mediaType=CONFIG)]:
            f = Fixture(); change(f.inspect)
            with self.assertRaises(RuntimeError): f.check()

    def test_scanner_identity_os_architecture_and_order_mismatch(self):
        for change in [lambda d: d.update(ImageID='sha256:'+'0'*64), lambda d: d['DiffIDs'].reverse(),
                       lambda d: d['ImageConfig'].update(os='windows'), lambda d: d['ImageConfig'].update(architecture='arm64'),
                       lambda d: d['ImageConfig']['rootfs']['diff_ids'].reverse(), lambda d: d.pop('ImageConfig')]:
            f = Fixture(); change(f.report['Metadata'])
            with self.assertRaises(RuntimeError): f.check()

    def test_malformed_json_and_duplicate_keys(self):
        for raw in [b'{', b'[]', b'{"imageLayoutVersion":"1.0.0","imageLayoutVersion":"1.0.0"}']:
            f = Fixture(); f.files['oci-layout'] = raw
            with self.assertRaises((RuntimeError, ValueError)): f.check()

    def test_archive_paths_duplicates_links_and_missing_layout(self):
        for name, kind in [('index.json', tarfile.REGTYPE), ('../escape', tarfile.REGTYPE),
                           ('blobs/sha256/'+'0'*64, tarfile.SYMTYPE), ('blobs/sha256/'+'0'*64, tarfile.LNKTYPE)]:
            f = Fixture(); member = tarfile.TarInfo(name); member.type = kind; member.size = 0
            with self.assertRaises(RuntimeError): f.check((member, b''))
        f = Fixture(); del f.files['oci-layout']
        with self.assertRaises(RuntimeError): f.check()

    def test_layer_missing_corruption_and_unsupported_format(self):
        for mode in ['missing', 'corrupt', 'unsupported']:
            f = Fixture()
            if mode == 'unsupported':
                f = Fixture(lambda x: x.layers[0].update(mediaType=LAYER+'+zstd'))
            else:
                key = 'blobs/sha256/' + f.layers[0]['digest'][7:]
                if mode == 'missing': del f.files[key]
                else: f.files[key] = b'X'*len(f.files[key])
            with self.assertRaises(RuntimeError): f.check()

    def test_external_descriptor_and_zero_runnable_rejected(self):
        for transform in [lambda v: v['manifests'][0].update(urls=['https://example.invalid/blob']),
                          lambda v: v.update(manifests=[])]:
            f = Fixture(); f.replace_index(transform)
            with self.assertRaises(RuntimeError): f.check()

    def test_production_binding_block_prevents_validator_execution(self):
        # Execute the actual production statements from binding through first validator.
        module = ast.parse((HERE/'remote-driver.py').read_text())
        execute = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'execute')
        body = next(n for n in execute.body if isinstance(n, ast.Try)).body
        start = next(i for i,n in enumerate(body) if isinstance(n, ast.For) and any(isinstance(c,ast.Name) and c.id=='verify_scanner_identity' for c in ast.walk(n)))
        stop = next(i for i,n in enumerate(body[start:],start) if isinstance(n,ast.Assign) and any(isinstance(c,ast.Name) and c.id=='a' for c in n.targets))
        block = compile(ast.fix_missing_locations(ast.Module(body=body[start:stop+1],type_ignores=[])), '<production-binding>', 'exec')
        for good in [True,False]:
            f=Fixture(); identity=f.check()
            report=copy.deepcopy(f.report)
            if not good: report['Metadata']['ImageID']='sha256:'+'0'*64
            with tempfile.TemporaryDirectory() as tmp:
                e=pathlib.Path(tmp)
                for role in ['builder','runtime']: (e/(role+'-raw.json')).write_text(json.dumps(report))
                calls=[]
                env={**NS,'E':e,'identities':{'builder':identity,'runtime':identity},'D':['docker'],
                     'builder':'candidate','container_options':lambda *a: [],'command':lambda *a,**k: calls.append(a)}
                if good: exec(block,env)
                else:
                    with self.assertRaises(RuntimeError): exec(block,env)
                self.assertEqual(len(calls),int(good))

if __name__ == '__main__':
    unittest.main()
