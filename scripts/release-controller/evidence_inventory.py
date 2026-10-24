"""Deterministic ordinary-file inventory, no execution or side effects."""
from pathlib import Path
import hashlib,unicodedata
def sha(p):
 with Path(p).open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def inventory_files(root, paths=None):
    """Deterministic complete inventory, with only exact root outputs excluded."""
    root = Path(root).absolute()
    excluded = {'final-evidence-inventory.json', 'final-evidence-inventory.sha256'}
    for q in (root, *root.parents):
        if q.is_symlink() or getattr(q, 'is_junction', lambda: False)() or (q.exists() and getattr(q.lstat(), 'st_file_attributes', 0) & 1024):
            raise ValueError('Linked inventory root')
    entries = list(root.rglob('*')) if paths is None else [Path(p) for p in paths]
    rows = []
    seen = set()
    for p in entries:
        try:
            relative = p.relative_to(root)
        except ValueError as e:
            raise ValueError('Escaping inventory path') from e
        if any((x in ('', '.', '..') for x in relative.parts)):
            raise ValueError('Unsafe inventory path')
        for q in (p, *p.parents):
            if q.is_symlink() or getattr(q, 'is_junction', lambda: False)() or (q.exists() and getattr(q.lstat(), 'st_file_attributes', 0) & 1024):
                raise ValueError('Linked inventory path')
            if q == root:
                break
        if not p.resolve().is_relative_to(root.resolve()):
            raise ValueError('Escaping inventory path')
        if p.is_dir():
            continue
        if not p.is_file():
            raise ValueError('Nonregular inventory entry')
        name = relative.as_posix()
        if '\\' in name or ':' in name:
            raise ValueError('Unsafe inventory path')
        normalized = unicodedata.normalize('NFC', name).casefold()
        if normalized in seen:
            raise ValueError('Duplicate normalized inventory path')
        seen.add(normalized)
        if name not in excluded:
            rows.append({'path': name, 'sha256': sha(p), 'bytes': p.stat().st_size})
    return sorted(rows, key=lambda r: r['path'])
