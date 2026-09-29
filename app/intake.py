from __future__ import annotations

import hashlib
import io
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urljoin, urlsplit

import httpx

from .models import (
    FileEvidence,
    FileInput,
    GitHubCheckRequest,
    IntakeReport,
    UploadedCheckRequest,
)
from .security import (
    MAX_ARCHIVE_ENTRIES,
    MAX_DOWNLOAD_BYTES,
    MAX_EXTRACTED_BYTES,
    MAX_RELEVANT_FILE_BYTES,
    InputRejected,
    is_blocked_path,
    is_relevant_file,
    validate_dependencies,
    validate_github_ref,
    validate_https_public_url,
    validate_path,
    validate_total,
)


@dataclass
class PreparedWorkspace:
    root: Path
    intake: IntakeReport
    mypy_path: str | None = None
    targets: list[str] | None = None
    unknown_mode_paths: set[str] | None = None


CONFIG_NAMES = {
    ".bandit",
    ".flake8",
    ".mypy.ini",
    ".ruff.toml",
    "mypy.ini",
    "pyproject.toml",
    "ruff.toml",
    "setup.cfg",
    "tox.ini",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _role_for_path(rel: str, targets: set[str]) -> str:
    name = PurePosixPath(rel).name.lower()
    if name in CONFIG_NAMES:
        return "config"
    if rel in targets:
        return "target"
    return "context"


def _config_identity(files: list[FileEvidence]) -> str | None:
    rows = [
        f"{item.path}\0{item.sha256}"
        for item in files
        if item.role == "config"
    ]
    if not rows:
        return None
    return hashlib.sha256(
        "\n".join(sorted(rows)).encode("utf-8")
    ).hexdigest()


def _readonly_mode(mode: int | None) -> int:
    return 0o444 | ((mode or 0) & 0o111)


def _download_limited(url: str, allowed_hosts: set[str] | None = None) -> bytes:
    current = validate_https_public_url(url, allowed_hosts=allowed_hosts)
    with httpx.Client(timeout=20.0, follow_redirects=False, trust_env=False, headers={"User-Agent": "CODE-EFHC/0.2"}) as client:
        for _ in range(4):
            validate_https_public_url(current, allowed_hosts=allowed_hosts)
            with client.stream("GET", current) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        raise InputRejected("redirect without location")
                    current = urljoin(current, location)
                    continue
                try:
                    response.raise_for_status()
                except httpx.HTTPError as exc:
                    raise InputRejected(f"download failed with HTTP {response.status_code}") from exc
                length = response.headers.get("content-length")
                if length and int(length) > MAX_DOWNLOAD_BYTES:
                    raise InputRejected("download exceeds compressed/input size limit")
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes(65536):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise InputRejected("download exceeds compressed/input size limit")
                    chunks.append(chunk)
                return b"".join(chunks)
    raise InputRejected("too many redirects")


def _member_path(name: str) -> str:
    p = PurePosixPath(name.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise InputRejected(f"unsafe archive member: {name}")
    return str(p)


def _write_relevant(destination: Path, rel: str, data: bytes) -> tuple[int, int]:
    rel = _member_path(rel)
    if is_blocked_path(rel) or not is_relevant_file(rel):
        return 0, 1
    if len(data) > MAX_RELEVANT_FILE_BYTES:
        raise InputRejected(f"relevant file too large: {rel}")
    dst = destination / rel
    if dst.exists():
        raise InputRejected(f"duplicate input path: {rel}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)
    os.chmod(dst, 0o444)
    return len(data), 0


def _extract_zip(data: bytes, destination: Path) -> tuple[int, int, int]:
    count = relevant_total = skipped = archive_total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise InputRejected("archive contains too many entries")
        for info in infos:
            rel = _member_path(info.filename)
            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode == stat.S_IFLNK:
                raise InputRejected(f"archive symlink rejected: {rel}")
            if info.is_dir():
                continue
            archive_total += info.file_size
            if archive_total > MAX_EXTRACTED_BYTES:
                raise InputRejected("archive extracted-size limit exceeded")
            if is_blocked_path(rel) or not is_relevant_file(rel):
                skipped += 1
                continue
            if info.file_size > MAX_RELEVANT_FILE_BYTES:
                raise InputRejected(f"relevant file too large: {rel}")
            raw = zf.read(info)
            written, was_skipped = _write_relevant(destination, rel, raw)
            if written:
                count += 1
                relevant_total += written
            skipped += was_skipped
    return count, relevant_total, skipped


def _extract_tar(data: bytes, destination: Path) -> tuple[int, int, int]:
    count = relevant_total = skipped = archive_total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        members = tf.getmembers()
        if len(members) > MAX_ARCHIVE_ENTRIES:
            raise InputRejected("archive contains too many entries")
        for member in members:
            rel = _member_path(member.name)
            if member.issym() or member.islnk() or member.isdev():
                raise InputRejected(f"archive link/device rejected: {rel}")
            if not member.isfile():
                continue
            archive_total += member.size
            if archive_total > MAX_EXTRACTED_BYTES:
                raise InputRejected("archive extracted-size limit exceeded")
            if is_blocked_path(rel) or not is_relevant_file(rel):
                skipped += 1
                continue
            if member.size > MAX_RELEVANT_FILE_BYTES:
                raise InputRejected(f"relevant file too large: {rel}")
            source = tf.extractfile(member)
            if source is None:
                continue
            raw = source.read(MAX_RELEVANT_FILE_BYTES + 1)
            if len(raw) > MAX_RELEVANT_FILE_BYTES:
                raise InputRejected(f"relevant file too large: {rel}")
            written, was_skipped = _write_relevant(destination, rel, raw)
            if written:
                count += 1
                relevant_total += written
            skipped += was_skipped
    return count, relevant_total, skipped


ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz",
    ".tbz2",
    ".tar.xz",
    ".txz",
)
ARCHIVE_MIME_TYPES = {
    "application/zip",
    "application/x-zip-compressed",
    "application/x-tar",
    "application/gzip",
    "application/x-gzip",
    "application/x-bzip2",
    "application/x-xz",
}


def _looks_like_zip(data: bytes, name: str | None = None) -> bool:
    del name
    return zipfile.is_zipfile(io.BytesIO(data))


def _looks_like_tar(data: bytes, name: str | None = None) -> bool:
    del name
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*"):
            return True
    except (tarfile.TarError, OSError, EOFError):
        return False


def _has_archive_hint(name: str | None, mime_type: str | None) -> bool:
    lower_name = (name or "").lower()
    lower_mime = (mime_type or "").lower()
    return (
        lower_name.endswith(ARCHIVE_SUFFIXES)
        or lower_mime in ARCHIVE_MIME_TYPES
    )


def _project_root(project_dir: Path) -> Path:
    visible = [p for p in project_dir.iterdir() if p.name not in {".code-efhc-deps"}]
    if len(visible) == 1 and visible[0].is_dir():
        return visible[0]
    return project_dir


def _prepare_dependencies(base: Path, mode: str, dependencies: list[str], authorized: bool) -> tuple[str | None, list[str]]:
    pins = validate_dependencies(mode, dependencies, authorized)
    if not pins:
        return None, []
    target = base / "deps"
    target.mkdir(mode=0o700)
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--target",
        str(target),
        "--only-binary=:all:",
        "--no-deps",
        "--disable-pip-version-check",
        "--no-input",
        *pins,
    ]
    env = os.environ.copy()
    env.update({
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_NO_CACHE_DIR": "1",
        "PIP_DEFAULT_TIMEOUT": "15",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=120, env=env)
    except subprocess.TimeoutExpired as exc:
        raise InputRejected("isolated dependency bootstrap timed out") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout)[-1200:].replace("\n", " ")
        raise InputRejected(f"isolated dependency bootstrap failed: {detail}")
    return str(target), pins


def _select_inline_targets(
    pairs: list[tuple[str, str]],
    targets: list[str] | None,
) -> list[str]:
    available = {rel for rel, _ in pairs}
    requested = targets or [
        rel
        for rel, _ in pairs
        if PurePosixPath(rel).suffix.lower() in {".py", ".pyi"}
    ]
    selected: list[str] = []
    for raw in requested:
        rel = validate_path(raw)
        if PurePosixPath(rel).suffix.lower() not in {".py", ".pyi"}:
            raise InputRejected(f"quality-gate target is not Python: {rel}")
        if rel not in available:
            raise InputRejected(f"quality-gate target was not supplied: {rel}")
        if rel not in selected:
            selected.append(rel)
    if not selected:
        raise InputRejected("no Python targets selected")
    return selected


@contextmanager
def inline_workspace(
    files: list[FileInput],
    mode: str = "none",
    dependencies: list[str] | None = None,
    authorized: bool = False,
    targets: list[str] | None = None,
):
    pairs = [(validate_path(f.path), f.content) for f in files]
    validate_total(pairs)
    selected_targets = _select_inline_targets(pairs, targets)
    selected_set = set(selected_targets)
    with tempfile.TemporaryDirectory(prefix="code-efhc-") as td:
        base = Path(td)
        project = base / "project"
        project.mkdir()
        total = 0
        evidence: list[FileEvidence] = []
        unknown_mode_paths: set[str] = set()
        by_path = {validate_path(f.path): f for f in files}
        for rel, content in pairs:
            source = by_path[rel]
            data = content.encode("utf-8")
            dst = project / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
            os.chmod(dst, _readonly_mode(source.mode))
            total += len(data)
            if source.mode is None:
                unknown_mode_paths.add(rel)
            evidence.append(
                FileEvidence(
                    path=rel,
                    sha256=_sha256(data),
                    role=_role_for_path(rel, selected_set),
                    mode=source.mode,
                    mode_provenance=(
                        "supplied"
                        if source.mode is not None
                        else "unknown"
                    ),
                )
            )
        mypy_path, pins = _prepare_dependencies(
            base,
            mode,
            dependencies or [],
            authorized,
        )
        yield PreparedWorkspace(
            root=project,
            intake=IntakeReport(
                source_kind="inline",
                source_identity="inline",
                file_count=len(pairs),
                total_bytes=total,
                dependency_mode=mode,
                dependencies=pins,
                targets=selected_targets,
                config_identity=_config_identity(evidence),
                files=evidence,
            ),
            mypy_path=mypy_path,
            targets=selected_targets,
            unknown_mode_paths=unknown_mode_paths,
        )


@contextmanager
def uploaded_workspace(req: UploadedCheckRequest):
    with tempfile.TemporaryDirectory(prefix="code-efhc-") as td:
        base = Path(td)
        project = base / "project"
        project.mkdir()
        count = total = skipped = 0
        identities: list[str] = []
        for index, file_ref in enumerate(req.files, start=1):
            identity = file_ref.file_id.strip()
            if not identity:
                raise InputRejected(
                    "uploaded file reference requires a non-empty host id"
                )
            data = _download_limited(file_ref.download_url)
            name = (
                file_ref.file_name
                or PurePosixPath(
                    urlsplit(file_ref.download_url).path
                ).name
                or f"input_{index}"
            )
            identities.append(identity)
            try:
                if _looks_like_zip(data, name):
                    c, b, s = _extract_zip(data, project)
                elif _looks_like_tar(data, name):
                    c, b, s = _extract_tar(data, project)
                elif _has_archive_hint(name, file_ref.mime_type):
                    raise InputRejected(
                        "invalid or unsupported archive"
                    )
                else:
                    if not file_ref.file_name and not (
                        file_ref.mime_type
                        and "python" in file_ref.mime_type.lower()
                    ):
                        raise InputRejected(
                            "non-archive uploaded file requires "
                            "file_name or Python mime type"
                        )
                    if not file_ref.file_name:
                        name = f"input_{index}.py"
                    written, s = _write_relevant(
                        project,
                        validate_path(name),
                        data,
                    )
                    c, b = (1 if written else 0), written
            except InputRejected:
                raise
            except (
                zipfile.BadZipFile,
                tarfile.TarError,
                RuntimeError,
                OSError,
                EOFError,
            ) as exc:
                raise InputRejected(
                    "invalid or unsupported archive"
                ) from exc
            count += c
            total += b
            skipped += s
        if count == 0:
            raise InputRejected("no relevant Python/config files found")
        mypy_path, pins = _prepare_dependencies(base, req.dependency_mode, req.dependencies, req.dependency_authorized)
        yield PreparedWorkspace(
            root=_project_root(project),
            intake=IntakeReport(
                source_kind="uploaded",
                source_identity=",".join(identities),
                file_count=count,
                total_bytes=total,
                skipped_files=skipped,
                dependency_mode=req.dependency_mode,
                dependencies=pins,
            ),
            mypy_path=mypy_path,
        )


@contextmanager
def github_workspace(req: GitHubCheckRequest):
    owner, repo, sha = validate_github_ref(req.owner, req.repo, req.commit_sha)
    url = f"https://codeload.github.com/{owner}/{repo}/zip/{sha}"
    data = _download_limited(url, allowed_hosts={"codeload.github.com"})
    with tempfile.TemporaryDirectory(prefix="code-efhc-") as td:
        base = Path(td)
        project = base / "project"
        project.mkdir()
        count, total, skipped = _extract_zip(data, project)
        if count == 0:
            raise InputRejected("no relevant Python/config files found in GitHub revision")
        root = _project_root(project)
        if req.subpath:
            rel = validate_path(req.subpath, require_relevant_type=False)
            candidate = root / rel
            if not candidate.is_dir():
                raise InputRejected("GitHub subpath is not a directory in the selected revision")
            root = candidate
        mypy_path, pins = _prepare_dependencies(base, req.dependency_mode, req.dependencies, req.dependency_authorized)
        yield PreparedWorkspace(
            root=root,
            intake=IntakeReport(
                source_kind="github",
                source_identity=f"github.com/{owner}/{repo}",
                source_commit=sha,
                file_count=count,
                total_bytes=total,
                skipped_files=skipped,
                dependency_mode=req.dependency_mode,
                dependencies=pins,
            ),
            mypy_path=mypy_path,
        )
