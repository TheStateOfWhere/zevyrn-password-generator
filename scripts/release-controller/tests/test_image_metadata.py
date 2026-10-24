import copy
import json
import unittest
from image_metadata import normalize_image


def fixture(runtime=False):
    result = {'Id': 'sha256:' + 'a' * 64, 'Os': 'linux', 'Architecture': 'amd64', 'Size': 123, 'Config': {}}
    if runtime:
        result['Config'] = {
            'User': '10001:10001', 'Entrypoint': ['nginx'], 'Cmd': ['-g', 'daemon off;'],
            'Healthcheck': {'Test': ['CMD-SHELL', 'wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1'], 'Interval': 30000000000},
            'ExposedPorts': {'8080/tcp': {}}, 'Labels': {'org.opencontainers.image.version': '1.2.1'},
        }
    return result


class ImageMetadataTests(unittest.TestCase):
    def test_builder_omitted_user(self):
        result = normalize_image(fixture(), 'builder')
        self.assertIsNone(result['user'])
        self.assertEqual(result['presence']['User'], 'omitted')
        self.assertEqual(result['effectiveUser'], '0 (Docker default)')

    def test_builder_explicit_user(self):
        value = fixture(); value['Config']['User'] = 'node'
        self.assertEqual(normalize_image(value, 'builder')['effectiveUser'], 'node')

    def test_builder_optional_fields_omitted(self):
        result = normalize_image(fixture(), 'builder')
        for key in ('healthcheck', 'exposedPorts', 'repoDigests', 'entrypoint', 'cmd'):
            self.assertIsNone(result[key])

    def test_null_distinct_from_missing_and_malformed(self):
        value = fixture(); value['Config']['Healthcheck'] = None
        self.assertEqual(normalize_image(value, 'builder')['presence']['Healthcheck'], 'null')
        value['Config']['User'] = None
        with self.assertRaisesRegex(ValueError, 'Malformed optional image field: User'):
            normalize_image(value, 'builder')

    def test_runtime_valid(self):
        self.assertEqual(normalize_image(json.dumps(fixture(True)), 'runtime')['user'], '10001:10001')

    def test_runtime_missing_user(self):
        value = fixture(True); del value['Config']['User']
        with self.assertRaisesRegex(ValueError, 'explicit non-root user'):
            normalize_image(value, 'runtime')

    def test_runtime_root_user(self):
        value = fixture(True); value['Config']['User'] = '0:0'
        with self.assertRaisesRegex(ValueError, 'explicit non-root user'):
            normalize_image(value, 'runtime')

    def test_runtime_missing_health(self):
        value = fixture(True); del value['Config']['Healthcheck']
        with self.assertRaisesRegex(ValueError, 'approved health check'):
            normalize_image(value, 'runtime')

    def test_runtime_disabled_health(self):
        value = fixture(True); value['Config']['Healthcheck'] = {'Test': ['NONE']}
        with self.assertRaisesRegex(ValueError, 'approved health check'):
            normalize_image(value, 'runtime')

    def test_runtime_missing_port(self):
        value = fixture(True); del value['Config']['ExposedPorts']
        with self.assertRaisesRegex(ValueError, 'exposed port 8080'):
            normalize_image(value, 'runtime')

    def test_runtime_extra_port(self):
        value = fixture(True); value['Config']['ExposedPorts']['80/tcp'] = {}
        with self.assertRaisesRegex(ValueError, 'only exposed port'):
            normalize_image(value, 'runtime')

    def test_malformed_json(self):
        with self.assertRaisesRegex(ValueError, 'Malformed inspection JSON'):
            normalize_image('{', 'builder')

    def test_missing_identity_fields(self):
        for key in ('Id', 'Os', 'Architecture', 'Size', 'Config'):
            with self.subTest(key=key):
                value = fixture(); del value[key]
                with self.assertRaisesRegex(ValueError, 'Invalid or missing image field: ' + key):
                    normalize_image(value, 'builder')

    def test_malformed_optional_values(self):
        for key, malformed in [('User', 0), ('Healthcheck', []), ('ExposedPorts', []), ('Env', 'TOKEN=secret'), ('Entrypoint', [1])]:
            with self.subTest(key=key):
                value = fixture(); value['Config'][key] = malformed
                with self.assertRaisesRegex(ValueError, 'Malformed'):
                    normalize_image(value, 'builder')

    def test_runtime_privileges_fail(self):
        for key, val in [('Privileged', True), ('CapAdd', ['ALL']), ('HostConfig', {})]:
            value = fixture(True); value['Config'][key] = val
            with self.assertRaisesRegex(ValueError, 'Unexpected image privilege'):
                normalize_image(value, 'runtime')

    def test_environment_values_never_recorded(self):
        value = fixture(); value['Config']['Env'] = ['PATH=/bin', 'TOKEN=never-print-this-value']
        result = normalize_image(value, 'builder')
        self.assertEqual(result['environment']['names'], ['PATH', 'TOKEN'])
        self.assertNotIn('never-print-this-value', json.dumps(result))

    def test_available_metadata_preserved(self):
        value = fixture(True)
        value['RepoDigests'] = ['example@sha256:' + 'b' * 64]
        result = normalize_image(value, 'runtime')
        self.assertEqual(result['repoDigests'], value['RepoDigests'])
        self.assertEqual(result['healthcheck'], value['Config']['Healthcheck'])
        self.assertEqual(result['exposedPorts'], value['Config']['ExposedPorts'])


if __name__ == '__main__':
    unittest.main()
