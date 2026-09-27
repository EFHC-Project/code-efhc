from __future__ import annotations
import os, tempfile
from contextlib import contextmanager
from pathlib import Path
from .security import validate_path, validate_total

@contextmanager
def materialize(files):
    pairs=[(validate_path(f.path), f.content) for f in files]
    validate_total(pairs)
    with tempfile.TemporaryDirectory(prefix='code-efhc-') as td:
        root=Path(td)
        for rel,content in pairs:
            dst=root/rel
            dst.parent.mkdir(parents=True,exist_ok=True)
            dst.write_text(content,encoding='utf-8')
            os.chmod(dst,0o444)
        yield root
