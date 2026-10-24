"""Fail-closed local evidence validation. No Docker, network, or privilege calls."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import re
import sys
from urllib.parse import unquote, urlsplit

HERE = Path(__file__).resolve().parent


class EvidenceError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise EvidenceError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


SCANNER_POLICY = {'scanners':['vuln','secret'], 'imageConfigScanners':['secret'],
                  'severities':['UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'],
                  'includeDevDependencies':True, 'listAllPackages':True,
                  'isolatedEnvironment':True, 'emptyIgnoreFile':True,
                  'emptyConfig':True, 'skipDatabaseUpdateDuringScan':True}
SCANNER_POLICY_SHA256 = sha(json.dumps(SCANNER_POLICY, sort_keys=True).encode())


def timestamp(value):
    try:
        result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(result.tzinfo is not None, 'Timestamp lacks timezone')
        return result
    except (TypeError, AttributeError, ValueError) as error:
        raise EvidenceError('Invalid evidence timestamp') from error


def isolated_scanner_environment(root, inherited=None):
    # An allowlist excludes TRIVY_*, proxy injection, loader and home config.
    inherited = os.environ if inherited is None else inherited
    env = {k: inherited[k] for k in ('PATH', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP') if k in inherited}
    root = Path(root)
    env.update(HOME=str(root / 'scanner-policy'), XDG_CONFIG_HOME=str(root / 'scanner-policy'),
               TRIVY_DISABLE_TELEMETRY='true', TRIVY_CACHE_DIR=str(root / 'trivy-cache'))
    return env


def database_valid(metadata, database, context, now):
    require(bool(database) and sha(database) == context['dbSHA256'], 'Missing or substituted vulnerability database')
    require(metadata.get('Version') == 2, 'Unsupported or missing database version')
    updated, downloaded = timestamp(metadata.get('UpdatedAt')), timestamp(metadata.get('DownloadedAt'))
    start = timestamp(context['startedUTC'])
    require(-300 <= (now - updated).total_seconds() <= 86400, 'Stale vulnerability database')
    require(start - dt.timedelta(seconds=5) <= downloaded <= now + dt.timedelta(seconds=5), 'Database not downloaded in current run')
    require(timestamp(metadata.get('NextUpdate')) > now, 'Expired vulnerability database')


def bind_receipt(data, receipt, context, kind, field, now):
    expected = context['images'][kind]
    require(context.get('scannerPolicySHA256') == SCANNER_POLICY_SHA256, 'Unapproved scanner policy')
    for key in ('runID', 'sourceManifestSHA256', 'scannerVersion', 'scannerBinarySHA256', 'dbSHA256', 'scannerPolicySHA256'):
        require(receipt.get(key) == context.get(key) and bool(receipt.get(key)), 'Evidence context mismatch: ' + key)
    for key in ('imageID', 'archiveSHA256'):
        require(receipt.get(key) == expected.get(key), 'Evidence image/archive mismatch: ' + key)
    require(receipt.get(field) == sha(data), 'Substituted evidence content: ' + field)
    start, end = timestamp(receipt.get('startedUTC')), timestamp(receipt.get('finishedUTC'))
    require(timestamp(context['startedUTC']) <= start <= end <= now + dt.timedelta(seconds=5), 'Stale or invalid evidence interval')
    require((now - end).total_seconds() <= 86400, 'Stale evidence')
    return start, end


def package_set(rows, name='Name', version='Version'):
    require(isinstance(rows, list) and bool(rows), 'Missing package coverage')
    result = {}
    for row in rows:
        require(isinstance(row, dict), 'Malformed package inventory')
        n, v = row.get(name), row.get(version)
        require(isinstance(n, str) and bool(n) and isinstance(v, str) and bool(v.strip()), 'Incomplete package identity/version')
        require(n not in result, 'Duplicate or conflicting package inventory')
        result[n] = v
    return result


def reconcile(actual, expected, label):
    require(bool(expected) and all(isinstance(n, str) and isinstance(v, str) and v for n, v in expected.items()), 'Incomplete expected package inventory')
    require(actual == expected, label + ' package inventory mismatch')


def report_identity(context, kind, actual):
    root=context['images'][kind]['imageID']
    chain=context.get('exportIdentities',{}).get(kind)
    if chain is None:
        require(actual==root,'Wrong scanner image identity')
        return 'legacy-image-id'
    require(chain.get('imageID')==root,'Export identity context mismatch')
    config=chain.get('configurationDigest')
    require(isinstance(config,str) and re.fullmatch(r'sha256:[0-9a-f]{64}',config),'Invalid configuration identity binding')
    require(actual in (root,config),'Wrong scanner image identity')
    return 'root-image-id' if actual==root else 'verified-configuration-digest'


def application_node_packages(target, verified_vendors=None):
    # Installed-image results aggregate under Target "Node.js". Only the
    # per-package image path establishes application dependency provenance.
    require(target.get('Class') == 'lang-pkgs' and target.get('Type') == 'node-pkg', 'Unexpected Node.js result ecosystem')
    rows = target.get('Packages')
    require(isinstance(rows, list), 'Missing Node.js package coverage')
    result = []
    module = r'(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*'
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get('Name'), str) and bool(row['Name'])
                and isinstance(row.get('Version'), str) and bool(row['Version'].strip()), 'Incomplete Node.js package identity/version')
        path = row.get('FilePath')
        require(isinstance(path, str) and bool(path) and len(path) <= 4096, 'Missing or malformed Node.js FilePath')
        require(not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in path)
                and not any(c in path for c in ('\\', ':', '%')), 'Unsafe Node.js FilePath')
        if path.startswith('./'):
            path = path[2:]
        elif path.startswith('/'):
            path = path[1:]
        require(all(part not in ('', '.', '..') for part in path.split('/')), 'Unsafe Node.js FilePath')
        if not path.startswith('app/node_modules/'):
            continue  # Still scanned for findings; cannot prove app coverage.
        match = re.fullmatch(r'app/node_modules/(?:' + module + r'/node_modules/)*(?P<package>' + module + r')/package\.json', path)
        if path in (verified_vendors or {}) or match is None:
            vendor = (verified_vendors or {}).get(path)
            require(vendor is not None and vendor['name'] == row['Name'] and vendor['version'] == row['Version'],
                    'Unexpected application package FilePath')
        else:
            require(match['package'] == row['Name'], 'Unexpected application package FilePath')
        result.append(row)
    return result



BUILDER_GATE_ROOT = Path(__file__).absolute().parent

def builder_applicability(data, context, kind, root, now):
    # Authenticate code before execution/import; no evidence-controlled anchors.
    import stat
    path = BUILDER_GATE_ROOT / 'builder_security.py'
    for part in [*reversed(path.absolute().parents), path.absolute()]:
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'Linked builder security helper')
    code = path.read_bytes()
    require(sha(code) == '8de308f81a5a05a9eb7c0a308cd3a65985aaacf92606b568fc7f1b2723870dbb', 'Builder security helper identity')
    scope = {'__file__': str(path), '__name__': 'authenticated_builder_security'}
    exec(compile(code, str(path), 'exec'), scope)
    try:
        return scope['evaluate'](data, context, kind, root, now)
    except ValueError as error:
        # Retain the established controller diagnostic while adding the exact
        # disposition failure; callers must still receive EvidenceError.
        raise EvidenceError('Critical/high vulnerability or secret gate failed; ' + str(error)) from error

def validate_scan(data, receipt, context, kind, expected, db_metadata, database, archive, now, evidence_root=None):
    database_valid(db_metadata, database, context, now)
    start, end = bind_receipt(data, receipt, context, kind, 'reportSHA256', now)
    require(sha(archive) == context['images'][kind]['archiveSHA256'], 'Exported archive hash mismatch')
    raw = json.loads(data)
    require(type(raw.get('SchemaVersion')) is int and raw['SchemaVersion'] >= 2 and raw.get('ArtifactType') == 'container_image', 'Invalid scanner report')
    identity_role=report_identity(context,kind,raw.get('Metadata',{}).get('ImageID'))
    require(start - dt.timedelta(seconds=5) <= timestamp(raw.get('CreatedAt')) <= end + dt.timedelta(seconds=5), 'Stale scanner report')
    results = raw.get('Results')
    require(isinstance(results, list), 'Missing scanner results')
    verified_vendors = {}
    # The bound export determines required coverage, independently of what
    # the scanner chose to report. An omitted row must never disable this gate.
    if kind == 'builder':
        from compiler_inventory import authenticate_compiler
        verified_vendors = authenticate_compiler(archive, context['images'][kind]['imageID'],
            context['images'][kind]['archiveSHA256'], context['sourceManifestSHA256'])
    covered_paths = set()
    os_rows, npm_rows, app_rows, provenance = [], [], [], []
    counts = {k: 0 for k in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')}
    secrets = 0
    for target in results:
        require(isinstance(target, dict) and isinstance(target.get('Target'), str), 'Malformed scanner target')
        # A second row under a different ecosystem cannot contradict or
        # impersonate the authenticated vendor's Node.js discovery evidence.
        if isinstance(target.get('Packages'), list):
            for row in target['Packages']:
                path = row.get('FilePath') if isinstance(row, dict) else None
                if isinstance(path, str):
                    canonical = path[2:] if path.startswith('./') else path[1:] if path.startswith('/') else path
                    if canonical in verified_vendors:
                        require(target.get('Class') == 'lang-pkgs' and target.get('Type') == 'node-pkg',
                                'Unexpected vendored scanner ecosystem')
        if target.get('Class') == 'os-pkgs' and target.get('Type') == 'alpine':
            os_rows.extend(target.get('Packages') or [])
            provenance.append({'target': target['Target'], 'class': target['Class'], 'type': target['Type']})
        if target.get('Class') == 'lang-pkgs' and target.get('Type') in ('npm', 'node-pkg'):
            npm_rows.extend(target.get('Packages') or [])
            if target['Type'] == 'node-pkg':
                for row in application_node_packages(target, verified_vendors):
                    path = row['FilePath']
                    canonical = path[2:] if path.startswith('./') else path[1:] if path.startswith('/') else path
                    require(canonical not in covered_paths, 'Duplicate or conflicting application coverage')
                    covered_paths.add(canonical)
                    app_rows.append(row)
        for key in ('Vulnerabilities', 'Secrets'):
            require(key not in target or isinstance(target[key], list), 'Malformed scanner findings')
        for finding in target.get('Vulnerabilities', []):
            severity = finding.get('Severity') if isinstance(finding, dict) else None
            require(severity in counts and isinstance(finding.get('VulnerabilityID'), str), 'Missing or invalid vulnerability severity/identity')
            counts[severity] += 1
        secrets += len(target.get('Secrets', []))
    if kind == 'builder':
        require(not any(t.get('Type') == 'gobinary' for t in results), 'Unexpected native compiler or Go coverage')
    reconcile(package_set(os_rows), expected, 'Trivy OS')
    if kind == 'builder':
        require(bool(npm_rows), 'Missing application dependency coverage')
        npm = {(p.get('Name'), p.get('Version')) for p in app_rows}
        require(all(p in npm for p in [('@typescript/typescript6', '6.0.2'), ('typescript', '6.0.3'), ('playwright', '1.62.1'), ('playwright-core', '1.62.1')]), 'Missing application dependency coverage')
        require(all(path in covered_paths for path in verified_vendors), 'Missing authenticated vendored dependency coverage')
    else:
        require(not npm_rows, 'Unexpected runtime application dependencies')
    applicability = builder_applicability(data, context, kind, evidence_root, now)
    require(applicability['rawCounts'] == counts and applicability['secrets'] == secrets, 'Disposition/count mismatch')
    return {'passed': True, 'counts': counts, 'secrets': secrets, 'builderApplicability': applicability, 'packages': expected,
            'provenance': provenance, 'imageID': context['images'][kind]['imageID'], 'reportedImageID':raw['Metadata']['ImageID'], 'reportedIdentityRole':identity_role, 'reportSHA256': sha(data)}


SCHEMA_HASHES = {
 '1.6': {'bom-1.6.schema.json':'3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93', 'spdx.schema.json':'baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e','jsf-0.82.schema.json':'8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae'},
 '1.7': {'bom-1.7.schema.json':'df472ef4aaf593904c479293723a1a5c191d6672715c93b3c0b5c318f3914221','spdx.schema.json':'54a6288292bc6c90b0d3952f5f939f17436fa76704ffe68a46e5b78539c7cc1b','jsf-0.82.schema.json':'8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae'}
}


def validate_schema(bom):
    # Schema validation runs on the Windows controller with its retained,
    # pinned validator dependencies. Linux scanning needs only stdlib imports.
    # External bootstrap authenticates/imports the existing dependency environment.
    from jsonschema import Draft7Validator, FormatChecker
    from referencing import Registry, Resource
    version = bom.get('specVersion')
    require(version in SCHEMA_HASHES, 'Unsupported CycloneDX schema version')
    registry = Registry()  # No network retrieval fallback.
    documents = {}
    for name, expected in SCHEMA_HASHES[version].items():
        data = (HERE / 'schemas' / version / name).read_bytes()
        require(sha(data) == expected, 'Official schema hash mismatch')
        doc = json.loads(data); documents[name] = doc
        resource = Resource.from_contents(doc)
        for base in ('http://cyclonedx.org/schema/', 'https://cyclonedx.org/schema/'):
            registry = registry.with_resource(base + name, resource)
        if '$id' in doc:
            registry = registry.with_resource(doc['$id'], resource)
    schema = documents['bom-' + version + '.schema.json']
    errors = list(Draft7Validator(schema, registry=registry, format_checker=FormatChecker()).iter_errors(bom))
    require(not errors, 'Invalid CycloneDX schema')


def validate_sbom(data, receipt, context, expected, archive, now):
    start, end = bind_receipt(data, receipt, context, 'runtime', 'sbomSHA256', now)
    require(sha(archive) == context['images']['runtime']['archiveSHA256'], 'SBOM archive hash mismatch')
    bom = json.loads(data); validate_schema(bom)
    meta = bom.get('metadata', {}); component = meta.get('component', {})
    require(component.get('type') == 'container', 'Missing SBOM container metadata')
    props = component.get('properties', [])
    identities = [p.get('value') for p in props if p.get('name') == 'aquasecurity:trivy:ImageID']
    require(len(identities)==1,'Wrong or missing SBOM image binding')
    try:identity_role=report_identity(context,'runtime',identities[0])
    except EvidenceError as error:raise EvidenceError('Wrong or missing SBOM image binding') from error
    require(start - dt.timedelta(seconds=5) <= timestamp(meta.get('timestamp')) <= end + dt.timedelta(seconds=5), 'Stale SBOM')
    tools = meta.get('tools', {}).get('components', [])
    require(any(t.get('name') == 'trivy' and t.get('version') == context['scannerVersion'] for t in tools), 'Missing SBOM scanner identity')
    packages = []
    for item in bom.get('components', []):
        purl = item.get('purl', '')
        if not purl.startswith('pkg:apk/'):
            continue
        path = purl.split('?', 1)[0].split('#', 1)[0]
        require('@' in path, 'Malformed APK component purl')
        package_path, version = path.rsplit('@', 1)
        name = unquote(package_path.rsplit('/', 1)[-1]); version = unquote(version)
        require(item.get('name') == name and item.get('version') == version and item.get('type') == 'library', 'Inconsistent APK component identity')
        packages.append({'Name': name, 'Version': version})
    reconcile(package_set(packages), expected, 'SBOM OS')
    return {'passed': True, 'schemaVersion': bom['specVersion'], 'sbomSHA256': sha(data),
            'imageID': context['images']['runtime']['imageID'], 'reportedImageID':identities[0],'reportedIdentityRole':identity_role,'packages': expected}
