"""Proposed read-only browser boundary, not a qualification phase executor.

The normal controller must still enforce fresh scans, SBOM, runtime, cleanup,
phase records and final completeness. This module neither writes an original
completion receipt nor authorizes final qualification or changes active selection.
"""
import hashlib
from pathlib import Path

MODULE_SHA256 = 'd94f734a856e730c316bf1e9765cdc9eaf0d4e5dea07a5c98a3661ce996963bb'


def _validator():
    p = Path(__file__).with_name('clipboard_supersession.py')
    # Check lexical paths before trusting any code, matching the reviewed loader.
    import stat
    for component in [*reversed(p.absolute().parents), p.absolute()]:
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('LINKED_SUPERSESSION_MODULE')
    data = p.read_bytes()
    if hashlib.sha256(data).hexdigest() != MODULE_SHA256:
        raise ValueError('SUPERSESSION_VALIDATOR_IDENTITY')
    scope = {'__file__': str(p), '__name__': 'reviewed_supersession_proposal'}
    exec(compile(data, str(p), 'exec'), scope)
    return scope


def inspect_proposal(claim_path):
    return _validator()['assess'](claim_path)


def require_settlement(claim_path):
    """Validate the supplemental browser prerequisite only. No settlement occurs."""
    result = inspect_proposal(claim_path)
    if result.get('browserEvidenceEligible') is not True:
        raise ValueError('MISSING_AUTHENTICATED_BROWSER_COMPLETION')
    return result


if __name__ == '__main__':
    import argparse
    import json
    parser = argparse.ArgumentParser(description='Read-only evidence contract; no settlement')
    parser.add_argument('claim', type=Path)
    print(json.dumps(require_settlement(parser.parse_args().claim), indent=2))
