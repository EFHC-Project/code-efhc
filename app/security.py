from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import PurePosixPath
from urllib.parse import urlsplit

MAX_INLINE_TOTAL_BYTES = 10_000_000
MAX_DOWNLOAD_BYTES = 30_000_000
MAX_EXTRACTED_BYTES = 80_000_000
MAX_ARCHIVE_ENTRIES = 5_000
MAX_RELEVANT_FILE_BYTES = 3_000_000

BLOCKED_NAMES = {".env", ".git", ".ssh", "id_rsa", "id_ed25519", "credentials", "credentials.json"}
ALLOWED_SUFFIXES = {".py", ".pyi", ".toml", ".ini", ".cfg", ".txt", ".yaml", ".yml", ".json", ".lock"}
ALLOWED_NAMES = {
    ".flake8",
    ".bandit",
    "pyproject.toml",
    "ruff.toml",
    ".ruff.toml",
    "mypy.ini",
    ".mypy.ini",
    "setup.cfg",
    "tox.ini",
    "requirements.txt",
    "requirements-dev.txt",
}
EXACT_PIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}==[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}$")
GITHUB_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class InputRejected(ValueError):
    pass


class DependencyRejected(InputRejected):
    pass


def _pure_path(path: str) -> PurePosixPath:
    if not isinstance(path, str) or not path.strip():
        raise InputRejected("empty path")
    p = PurePosixPath(path.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise InputRejected(f"unsafe path: {path}")
    return p


def is_blocked_path(path: str) -> bool:
    p = _pure_path(path)
    return any(part.lower() in BLOCKED_NAMES for part in p.parts)


def validate_path(path: str, require_relevant_type: bool = True) -> str:
    p = _pure_path(path)
    if is_blocked_path(str(p)):
        raise InputRejected(f"blocked path: {path}")
    if require_relevant_type and not is_relevant_file(str(p)):
        raise InputRejected(f"unsupported file type: {path}")
    return str(p)


def is_relevant_file(path: str) -> bool:
    p = _pure_path(path)
    name = p.name.lower()
    return name in ALLOWED_NAMES or p.suffix.lower() in ALLOWED_SUFFIXES


def validate_total(files: list[tuple[str, str]]) -> None:
    total = sum(len(c.encode("utf-8")) for _, c in files)
    if total > MAX_INLINE_TOTAL_BYTES:
        raise InputRejected("inline input too large")


def validate_dependencies(mode: str, dependencies: list[str], authorized: bool) -> list[str]:
    if mode == "none":
        if dependencies:
            raise DependencyRejected("dependencies supplied while dependency_mode=none")
        return []
    if mode != "isolated":
        raise DependencyRejected("unsupported dependency mode")
    if not authorized:
        raise DependencyRejected("isolated dependency mode requires explicit authorization")
    if not dependencies:
        raise DependencyRejected("isolated dependency mode requires exact pinned dependencies")
    if len(dependencies) > 10:
        raise DependencyRejected("too many dependencies")
    normalized = []
    for spec in dependencies:
        spec = spec.strip()
        if not EXACT_PIN_RE.fullmatch(spec):
            raise DependencyRejected(f"dependency must be exact name==version pin: {spec}")
        normalized.append(spec)
    return normalized


def validate_github_ref(owner: str, repo: str, commit_sha: str) -> tuple[str, str, str]:
    if not GITHUB_NAME_RE.fullmatch(owner) or not GITHUB_NAME_RE.fullmatch(repo):
        raise InputRejected("invalid GitHub owner/repository")
    if not COMMIT_SHA_RE.fullmatch(commit_sha):
        raise InputRejected("GitHub intake requires an exact 40-character commit SHA")
    return owner, repo, commit_sha.lower()


def validate_https_public_url(url: str, allowed_hosts: set[str] | None = None) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise InputRejected("download URL must use https")
    if parts.username or parts.password:
        raise InputRejected("download URL credentials are not allowed")
    if parts.port not in (None, 443):
        raise InputRejected("download URL must use port 443")
    host = parts.hostname.lower().rstrip(".")
    if allowed_hosts is not None and host not in allowed_hosts:
        raise InputRejected(f"download host not allowed: {host}")
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise InputRejected(f"download host cannot be resolved: {host}") from exc
    if not infos:
        raise InputRejected(f"download host cannot be resolved: {host}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise InputRejected("download URL resolves to a non-public address")
    return url
