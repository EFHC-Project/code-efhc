from __future__ import annotations
from pathlib import PurePosixPath

MAX_TOTAL_BYTES = 10_000_000
BLOCKED_NAMES = {".env", ".git", ".ssh", "id_rsa", "id_ed25519"}

class InputRejected(ValueError):
    pass

def validate_path(path: str) -> str:
    p = PurePosixPath(path.replace('\\','/'))
    if p.is_absolute() or '..' in p.parts or not p.parts:
        raise InputRejected(f"unsafe path: {path}")
    if any(part in BLOCKED_NAMES for part in p.parts):
        raise InputRejected(f"blocked path: {path}")
    if p.suffix and p.suffix.lower() not in {'.py','.pyi','.toml','.ini','.cfg','.txt'}:
        raise InputRejected(f"unsupported file type: {path}")
    return str(p)

def validate_total(files: list[tuple[str,str]]) -> None:
    total = sum(len(c.encode('utf-8')) for _,c in files)
    if total > MAX_TOTAL_BYTES:
        raise InputRejected("input too large")
