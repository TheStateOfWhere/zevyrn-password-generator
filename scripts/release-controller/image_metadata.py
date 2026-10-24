"""Validate Docker image inspection in memory; never retain environment values."""
import json
import re


def normalize_image(payload, stage):
    if stage not in ('builder', 'runtime'):
        raise ValueError('Unknown image stage')
    try:
        value = json.loads(payload) if isinstance(payload, (str, bytes)) else payload
    except (ValueError, UnicodeError) as error:
        raise ValueError('Malformed inspection JSON') from error
    if not isinstance(value, dict):
        raise ValueError('Inspection must be an object')

    def required(obj, key, kind):
        if key not in obj or type(obj[key]) is not kind:
            raise ValueError('Invalid or missing image field: ' + key)
        return obj[key]

    identity = required(value, 'Id', str)
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', identity):
        raise ValueError('Invalid image identity')
    platform = required(value, 'Os', str)
    architecture = required(value, 'Architecture', str)
    if (platform, architecture) != ('linux', 'amd64'):
        raise ValueError('Unexpected image platform')
    size = required(value, 'Size', int)
    if size < 0:
        raise ValueError('Invalid image size')
    config = required(value, 'Config', dict)
    presence = {}

    def optional(obj, key, kind, nullable=False):
        presence[key] = 'omitted' if key not in obj else 'null' if obj[key] is None else 'present'
        if key not in obj:
            return None
        result = obj[key]
        if result is None and nullable:
            return None
        if type(result) is not kind:
            raise ValueError('Malformed optional image field: ' + key)
        return result

    user = optional(config, 'User', str)
    labels = optional(config, 'Labels', dict, True)
    if labels is not None and not all(isinstance(k, str) and isinstance(v, str) for k, v in labels.items()):
        raise ValueError('Malformed Labels')
    sequences = {}
    for obj, key in [(config, 'Entrypoint'), (config, 'Cmd'), (config, 'Env'), (value, 'RepoTags'), (value, 'RepoDigests')]:
        sequence = optional(obj, key, list, True)
        if sequence is not None and not all(type(x) is str for x in sequence):
            raise ValueError('Malformed optional image sequence: ' + key)
        sequences[key] = sequence
    for digest in sequences['RepoDigests'] or []:
        if not re.fullmatch(r'.+@sha256:[0-9a-f]{64}', digest):
            raise ValueError('Malformed repository digest')
    health = optional(config, 'Healthcheck', dict, True)
    if health is not None:
        test = required(health, 'Test', list)
        if not test or not all(type(x) is str for x in test) or test[0] not in ('NONE', 'CMD', 'CMD-SHELL'):
            raise ValueError('Malformed health-check Test')
        for key in ('Interval', 'Timeout', 'StartPeriod', 'StartInterval', 'Retries'):
            if key in health and (type(health[key]) is not int or health[key] < 0):
                raise ValueError('Malformed health-check timing: ' + key)
        if set(health) - {'Test', 'Interval', 'Timeout', 'StartPeriod', 'StartInterval', 'Retries'}:
            raise ValueError('Unexpected health-check fields')
    ports = optional(config, 'ExposedPorts', dict, True)
    if ports is not None:
        for port, details in ports.items():
            if not re.fullmatch(r'[0-9]+/(tcp|udp|sctp)', port) or not 1 <= int(port.split('/')[0]) <= 65535 or details != {}:
                raise ValueError('Malformed exposed port')
    volumes = optional(config, 'Volumes', dict, True)
    if volumes is not None and not all(type(k) is str and v == {} for k, v in volumes.items()):
        raise ValueError('Malformed image volumes')
    onbuild = optional(config, 'OnBuild', list, True)
    if onbuild is not None and not all(type(x) is str for x in onbuild):
        raise ValueError('Malformed OnBuild')
    # Image config normally has no host privileges. Reject unexpected security
    # properties rather than interpreting them as a safe runtime default.
    for obj in (value, config):
        if any(key in obj for key in ('Privileged', 'CapAdd', 'SecurityOpt', 'HostConfig')):
            raise ValueError('Unexpected image privilege configuration')
    if stage == 'runtime':
        if user != '10001:10001':
            raise ValueError('Runtime requires explicit non-root user 10001:10001')
        if not health or health['Test'] != ['CMD-SHELL', 'wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1']:
            raise ValueError('Runtime requires approved health check')
        if not ports or set(ports) != {'8080/tcp'}:
            raise ValueError('Runtime requires only exposed port 8080/tcp')
        if sequences['Entrypoint'] != ['nginx'] or sequences['Cmd'] != ['-g', 'daemon off;']:
            raise ValueError('Unexpected runtime entrypoint or command')
        if volumes or onbuild:
            raise ValueError('Unexpected runtime volumes or build triggers')
        if not labels or labels.get('org.opencontainers.image.version') != '1.2.1':
            raise ValueError('Unexpected runtime version')
    environment = sequences['Env']
    if environment is not None and any('=' not in x or not x.split('=', 1)[0] for x in environment):
        raise ValueError('Malformed environment metadata')
    return {
        'id': identity, 'os': platform, 'architecture': architecture, 'size': size,
        'user': user, 'effectiveUser': user or '0 (Docker default)',
        'labels': labels, 'entrypoint': sequences['Entrypoint'], 'cmd': sequences['Cmd'],
        'environment': {'count': len(environment) if environment is not None else None,
                        'names': [x.split('=', 1)[0] for x in environment] if environment is not None else None,
                        'valuesRecorded': False},
        'healthcheck': health, 'exposedPorts': ports, 'volumes': volumes, 'onBuild': onbuild,
        'repoTags': sequences['RepoTags'], 'repoDigests': sequences['RepoDigests'], 'presence': presence,
    }
