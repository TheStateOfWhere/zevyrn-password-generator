"""Local acceptance entry point. Revalidate every file; never trust passed alone.

Usage: python -B accept-evidence.py EVIDENCE_DIR [--write]
No Docker, SSH, subprocess or network operations. --write is exclusive creation.
Expected qualification.json and builds.json must come from the reviewed live
controller/administrator preflight, not from an untrusted evidence provider.
"""
from pathlib import Path
import ast
import datetime as dt
import json
import sys
from qualification_evidence import *
from image_metadata import normalize_image


def file_at(root, name):
    root = root.resolve(); result = root / name
    require(not result.is_symlink() and result.resolve().is_relative_to(root) and result.is_file(), 'Missing or unsafe evidence file: ' + name)
    return result


def load(root, name):
    return json.loads(file_at(root, name).read_bytes())


def validate_bundle(root, now=None):
    root = Path(root); now = now or dt.datetime.now(dt.timezone.utc)
    q, builds, context = [load(root, name) for name in ('qualification.json', 'builds.json', 'evidence-context.json')]
    require(context['runID'] == q['runID'] and context['sourceManifestSHA256'] == q['sourceManifestSHA256'], 'Wrong acceptance run/source')
    require(sha(file_at(root, 'source-manifest.json').read_bytes()) == q['sourceManifestSHA256'], 'Source manifest file mismatch')
    require(context['scannerVersion'] == '0.76.0', 'Unapproved scanner version')
    provenance = load(root, 'scanner-provenance.json')
    require(provenance.get('releaseArchiveSHA256') == 'e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7', 'Unverified scanner provenance')
    require(sha(file_at(root, 'tools/trivy').read_bytes()) == provenance.get('binarySHA256') == context['scannerBinarySHA256'], 'Scanner binary mismatch')
    require(load(root, 'scanner-version.json').get('Version') == context['scannerVersion'], 'Scanner version record mismatch')
    start_db, end_db = load(root, 'scanner-db-start.json'), load(root, 'scanner-db-end.json')
    require(start_db['databaseSHA256'] == end_db['databaseSHA256'] == context['dbSHA256'], 'Database changed during evidence generation')
    database = file_at(root, 'trivy-cache/db/trivy.db').read_bytes()
    database_valid(start_db['metadata'], database, context, now)
    database_valid(end_db['metadata'], database, context, now)
    results = {}; bound_files = {}
    # Recompute installed-package inventory from each hash-verified export,
    # using ONLY archive functions from the corrected helper.
    tree = ast.parse((HERE / 'scan-images.py').read_text())
    funcs = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in ('digest','packages','archive_name','archive_inventory')]
    import tarfile, gzip
    captured = {}
    namespace = {'Path': Path, 'R': root, 'hashlib': hashlib, 'json': json, 'tarfile': tarfile, 'gzip': gzip,
                 'write': lambda name, data: captured.update({name: data})}
    exec(compile(ast.Module(body=funcs, type_ignores=[]), 'reviewed archive validation', 'exec'), namespace)
    for kind in ('builder', 'runtime'):
        build = builds[kind]
        require(context['images'][kind] == {'imageID': build['image']['id'], 'archiveSHA256': build['archiveSHA256']}, 'Build/context identity mismatch')
        archive = file_at(root, build['archive'])
        expected = namespace['archive_inventory'](kind, build)
        # Validate the immutable export's actual config, not just a user field
        # copied into builds.json. archive_inventory already verified its ID.
        with tarfile.open(archive, 'r:') as exported:
            reference=captured[kind+'-installed-packages.json']['identityChain']['configurationReference']
            config = json.load(exported.extractfile(reference))
        metadata = normalize_image({'Id':build['image']['id'], 'Os':config['os'],
                                    'Architecture':config['architecture'], 'Size':archive.stat().st_size,
                                    'Config':config['config']}, kind)
        require(metadata['labels'] and metadata['labels'].get('io.zevyrn.source-manifest-sha256') == context['sourceManifestSHA256'], 'Export source association mismatch')
        inventory = load(root, kind + '-installed-packages.json')
        require(inventory == captured[kind + '-installed-packages.json'], 'Substituted installed-package evidence')
        chain=captured[kind+'-installed-packages.json']['identityChain']
        supplied=context.get('exportIdentities',{}).get(kind)
        require(supplied==chain or (supplied is None and chain['format']=='docker-save-config-id'),'Missing or substituted export identity chain')
        data = file_at(root, kind + '-raw-scan.json').read_bytes()
        receipt = load(root, kind + '-scan-receipt.json')
        results[kind] = validate_scan(data, receipt, context, kind, expected, end_db['metadata'], database, archive.read_bytes(), now, evidence_root=root)
        bound_files[kind + '-raw-scan.json'] = sha(data)
    sbom_data = file_at(root, 'runtime-sbom.cdx.json').read_bytes()
    sbom_receipt = load(root, 'runtime-sbom-receipt.json')
    require(sbom_receipt.get('sourceReportSHA256') == bound_files['runtime-raw-scan.json'], 'SBOM derived from different scan')
    results['sbom'] = validate_sbom(sbom_data, sbom_receipt, context, results['runtime']['packages'], file_at(root, builds['runtime']['archive']).read_bytes(), now)
    bound_files['runtime-sbom.cdx.json'] = sha(sbom_data)
    # Bind all acceptance inputs; a controller must re-run validate_bundle just
    # before issuing the runtime gate, not reuse a previous passed JSON file.
    for name in ('qualification.json','builds.json','evidence-context.json','source-manifest.json',
                 'builder-scan-receipt.json','runtime-scan-receipt.json','runtime-sbom-receipt.json',
                 'builder-installed-packages.json','runtime-installed-packages.json',
                 'scanner-db-start.json','scanner-db-end.json','scanner-version.json','scanner-provenance.json'):
        bound_files[name] = sha(file_at(root, name).read_bytes())
    for decision in results['builder']['builderApplicability'].get('approvals', []):
        h = decision['receiptSHA256']
        bound_files['builder-applicability/receipts/' + h + '.json'] = sha(file_at(root, 'builder-applicability/receipts/' + h + '.json').read_bytes())
    if results['builder']['builderApplicability'].get('approvals'):
        scope_data = file_at(root, 'builder-applicability/context.json').read_bytes()
        bound_files['builder-applicability/context.json'] = sha(scope_data)
        for name, expected_hash in json.loads(scope_data)['files'].items():
            require(sha(file_at(root, name).read_bytes()) == expected_hash, 'Applicability input changed')
            bound_files[name] = expected_hash
    return {'passed': True, 'runID': q['runID'], 'sourceManifestSHA256': q['sourceManifestSHA256'],
            'runtimeImageID': context['images']['runtime']['imageID'], 'images': context['images'],
            'scannerVersion': context['scannerVersion'], 'databaseSHA256': context['dbSHA256'],
            'boundFiles': bound_files, 'results': results, 'checkedUTC': now.isoformat()}


if __name__ == '__main__':
    result = validate_bundle(Path(sys.argv[1]))
    if '--write' in sys.argv[2:]:
        with (Path(sys.argv[1]) / 'scan-and-sbom-acceptance.json').open('x') as stream:
            json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps({'passed': True, 'runtimeImageID': result['runtimeImageID'], 'runID': result['runID']}))
