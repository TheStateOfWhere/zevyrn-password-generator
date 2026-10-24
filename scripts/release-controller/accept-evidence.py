"""Local-only CLI wrapper; never authorizes a Docker phase."""
from pathlib import Path
import json
import sys
raise SystemExit('BLOCKED: external bootstrap required before acceptance imports')
from acceptance_gate import validate_bundle

result = validate_bundle(Path(sys.argv[1]))
if '--write' in sys.argv[2:]:
    with (Path(sys.argv[1]) / 'scan-and-sbom-acceptance.json').open('x') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
print(json.dumps({'passed': True, 'runtimeImageID': result['runtimeImageID'], 'runID': result['runID']}))
