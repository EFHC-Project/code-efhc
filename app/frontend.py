from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from .models import (
    FileEvidence,
    FileInput,
    FileRole,
    FrontendCheckRequest,
    FrontendFinding,
    FrontendIntakeReport,
    FrontendToolResult,
)
from .security import InputRejected, is_blocked_path, validate_total

FrontendStatus = Literal[
    "PASS",
    "FINDINGS",
    "CONFIG_ERROR",
    "TOOL_UNAVAILABLE",
    "NOT_APPLICABLE",
]

FRONTEND_SUFFIXES = {
    ".cjs",
    ".js",
    ".jsx",
    ".json",
    ".mjs",
    ".ts",
    ".tsx",
}
FRONTEND_CONFIG_NAMES = {
    "package-lock.json",
    "package.json",
    "tsconfig.json",
}
TSC = "/opt/efhc-frontend/node_modules/.bin/tsc"
ESLINT = "/opt/efhc-frontend/node_modules/.bin/eslint"
ESLINT_CONFIG = "/app/guard/eslint.config.mjs"
NODE = "/usr/local/bin/node"
TIMEOUT = 60


@dataclass
class FrontendWorkspace:
    root: Path
    intake: FrontendIntakeReport
    targets: list[str]


def _frontend_path(path: str) -> str:
    if not isinstance(path, str) or not path.strip():
        raise InputRejected("empty frontend path")
    parsed = PurePosixPath(path.replace("\\", "/"))
    if parsed.is_absolute() or ".." in parsed.parts or not parsed.parts:
        raise InputRejected(f"unsafe frontend path: {path}")
    rel = parsed.as_posix()
    if is_blocked_path(rel):
        raise InputRejected(f"blocked frontend path: {path}")
    name = parsed.name.lower()
    suffix = parsed.suffix.lower()
    if (
        suffix not in FRONTEND_SUFFIXES
        and name not in FRONTEND_CONFIG_NAMES
        and not name.startswith("tsconfig.")
    ):
        raise InputRejected(f"unsupported frontend file type: {path}")
    return rel


def _target_path(path: str) -> str:
    rel = _frontend_path(path)
    suffix = PurePosixPath(rel).suffix.lower()
    if suffix not in {".cjs", ".js", ".jsx", ".mjs", ".ts", ".tsx"}:
        raise InputRejected(
            f"frontend target is not source code: {rel}"
        )
    return rel


def _role(path: str, targets: set[str]) -> FileRole:
    name = PurePosixPath(path).name.lower()
    if name in FRONTEND_CONFIG_NAMES or name.startswith("tsconfig."):
        return "config"
    if path in targets:
        return "target"
    return "context"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _config_identity(files: list[FileEvidence]) -> str | None:
    rows = [
        f"{item.path}\0{item.sha256}"
        for item in files
        if item.role == "config"
    ]
    if not rows:
        return None
    payload = "\n".join(sorted(rows)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@contextmanager
def frontend_workspace(
    files: list[FileInput],
    targets: list[str],
):
    pairs = [
        (_frontend_path(item.path), item.content)
        for item in files
    ]
    validate_total(pairs)
    available = {path for path, _ in pairs}
    selected: list[str] = []
    for raw in targets:
        rel = _target_path(raw)
        if rel not in available:
            raise InputRejected(
                f"frontend target was not supplied: {rel}"
            )
        if rel not in selected:
            selected.append(rel)
    if not selected:
        raise InputRejected("no frontend targets selected")
    target_set = set(selected)

    with tempfile.TemporaryDirectory(
        prefix="code-efhc-front-"
    ) as td:
        root = Path(td) / "project"
        root.mkdir()
        evidence: list[FileEvidence] = []
        total = 0
        by_path = {
            _frontend_path(item.path): item
            for item in files
        }
        for rel, text in pairs:
            source = by_path[rel]
            data = text.encode("utf-8")
            dst = root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
            os.chmod(dst, 0o444)
            total += len(data)
            evidence.append(
                FileEvidence(
                    path=rel,
                    sha256=_sha256(data),
                    role=_role(rel, target_set),
                    mode=source.mode,
                    mode_provenance=(
                        "supplied"
                        if source.mode is not None
                        else "unknown"
                    ),
                )
            )
        yield FrontendWorkspace(
            root=root,
            intake=FrontendIntakeReport(
                source_kind="inline",
                source_identity="inline",
                file_count=len(pairs),
                total_bytes=total,
                targets=selected,
                config_identity=_config_identity(evidence),
                files=evidence,
            ),
            targets=selected,
        )


def _offline_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "CODE_EFHC_BLOCK_NETWORK": "1",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "",
        "npm_config_offline": "true",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
    })
    return env


def _version(cmd: list[str]) -> str | None:
    try:
        proc = subprocess.run(  # nosec B603
            cmd,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
            env=_offline_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (proc.stdout or proc.stderr).strip()
    return text.splitlines()[0][:200] if text else None


def _timeout_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _run(
    cmd: list[str],
    root: Path,
) -> subprocess.CompletedProcess[str] | None:
    if not Path(cmd[0]).is_file() and shutil.which(cmd[0]) is None:
        return None
    try:
        return subprocess.run(  # nosec B603
            cmd,
            cwd=root,
            text=True,
            capture_output=True,
            timeout=TIMEOUT,
            check=False,
            env=_offline_env(),
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            cmd,
            124,
            _timeout_text(exc.stdout),
            _timeout_text(exc.stderr) or "timeout",
        )


def _normalized_exit(
    status: FrontendStatus,
    raw: int | None,
) -> int | None:
    if status in {"PASS", "NOT_APPLICABLE"}:
        return 0
    return raw


def _ts_config(root: Path, targets: list[str]) -> Path:
    generated = root / ".code-efhc-tsconfig.json"
    config: dict[str, object] = {
        "files": targets,
        "include": [],
        "compilerOptions": {
            "allowJs": False,
            "esModuleInterop": True,
            "jsx": "react-jsx",
            "module": "ESNext",
            "moduleResolution": "Bundler",
            "noEmit": True,
            "resolveJsonModule": True,
            "skipLibCheck": True,
            "target": "ES2022",
        },
    }
    if (root / "tsconfig.json").is_file():
        config["extends"] = "./tsconfig.json"
        config["compilerOptions"] = {"noEmit": True}
    generated.write_text(
        json.dumps(config, sort_keys=True),
        encoding="utf-8",
    )
    os.chmod(generated, 0o444)
    return generated


def run_typescript(
    root: Path,
    targets: list[str],
) -> FrontendToolResult:
    applicable = [
        item
        for item in targets
        if PurePosixPath(item).suffix.lower() in {".ts", ".tsx"}
    ]
    if not applicable:
        return FrontendToolResult(
            tool="typescript",
            status="NOT_APPLICABLE",
            exit_code=0,
            raw_exit_code=0,
        )
    config = _ts_config(root, applicable)
    proc = _run(
        [TSC, "--pretty", "false", "--project", str(config)],
        root,
    )
    if proc is None:
        return FrontendToolResult(
            tool="typescript",
            status="TOOL_UNAVAILABLE",
        )
    findings: list[FrontendFinding] = []
    pattern = re.compile(
        r"^(.*)\((\d+),(\d+)\): error (TS\d+): (.*)$"
    )
    for line in proc.stdout.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        path = Path(match[1])
        try:
            rel = (
                path.resolve()
                .relative_to(root.resolve())
                .as_posix()
            )
        except (OSError, ValueError):
            rel = path.as_posix()
        findings.append(
            FrontendFinding(
                tool="typescript",
                path=rel,
                line=int(match[2]),
                column=int(match[3]),
                code=match[4],
                message=match[5],
            )
        )
    status: FrontendStatus
    if findings:
        status = "FINDINGS"
    elif proc.returncode == 0:
        status = "PASS"
    else:
        status = "CONFIG_ERROR"
    return FrontendToolResult(
        tool="typescript",
        status=status,
        exit_code=_normalized_exit(status, proc.returncode),
        raw_exit_code=proc.returncode,
        version=_version([TSC, "--version"]),
        findings=findings,
        stderr=proc.stderr[-4000:],
    )


def run_eslint(
    root: Path,
    targets: list[str],
) -> FrontendToolResult:
    applicable = [
        item
        for item in targets
        if PurePosixPath(item).suffix.lower()
        in {".cjs", ".js", ".jsx", ".mjs"}
    ]
    if not applicable:
        return FrontendToolResult(
            tool="eslint",
            status="NOT_APPLICABLE",
            exit_code=0,
            raw_exit_code=0,
            notes=[
                (
                    "Trusted ESLint verification applies to "
                    "JavaScript-family targets. TypeScript targets "
                    "are verified by the TypeScript compiler."
                )
            ],
        )
    proc = _run(
        [
            ESLINT,
            "--config",
            ESLINT_CONFIG,
            "--no-config-lookup",
            "--format",
            "json",
            *applicable,
        ],
        root,
    )
    if proc is None:
        return FrontendToolResult(
            tool="eslint",
            status="TOOL_UNAVAILABLE",
        )
    findings: list[FrontendFinding] = []
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        data = []
    for file_result in data:
        raw_path = file_result.get("filePath", "")
        path = Path(raw_path)
        try:
            rel = (
                path.resolve()
                .relative_to(root.resolve())
                .as_posix()
            )
        except (OSError, ValueError):
            rel = path.as_posix()
        for item in file_result.get("messages", []):
            findings.append(
                FrontendFinding(
                    tool="eslint",
                    path=rel,
                    line=item.get("line"),
                    column=item.get("column"),
                    code=item.get("ruleId") or "ESLINT",
                    message=item.get("message", ""),
                    severity=str(item.get("severity", "")),
                )
            )
    status: FrontendStatus
    if findings:
        status = "FINDINGS"
    elif proc.returncode == 0:
        status = "PASS"
    else:
        status = "CONFIG_ERROR"
    return FrontendToolResult(
        tool="eslint",
        status=status,
        exit_code=_normalized_exit(status, proc.returncode),
        raw_exit_code=proc.returncode,
        version=_version([ESLINT, "--version"]),
        findings=findings,
        notes=[
            (
                "Uses CODE EFHC trusted JavaScript ESLint "
                "configuration; project executable ESLint config "
                "is not loaded."
            )
        ],
        stderr=proc.stderr[-4000:],
    )


def run_node_check(
    root: Path,
    targets: list[str],
) -> FrontendToolResult:
    applicable = [
        item
        for item in targets
        if PurePosixPath(item).suffix.lower()
        in {".cjs", ".js", ".mjs"}
    ]
    if not applicable:
        return FrontendToolResult(
            tool="node-check",
            status="NOT_APPLICABLE",
            exit_code=0,
            raw_exit_code=0,
        )
    findings: list[FrontendFinding] = []
    raw_exit = 0
    stderr_parts: list[str] = []
    for rel in applicable:
        proc = _run([NODE, "--check", rel], root)
        if proc is None:
            return FrontendToolResult(
                tool="node-check",
                status="TOOL_UNAVAILABLE",
            )
        raw_exit = max(raw_exit, proc.returncode)
        if proc.returncode != 0:
            findings.append(
                FrontendFinding(
                    tool="node-check",
                    path=rel,
                    code="NODE_SYNTAX",
                    message=(
                        proc.stderr or proc.stdout
                    ).strip()[:1000],
                )
            )
        if proc.stderr:
            stderr_parts.append(proc.stderr)
    status: FrontendStatus = (
        "FINDINGS"
        if findings
        else "PASS"
    )
    return FrontendToolResult(
        tool="node-check",
        status=status,
        exit_code=_normalized_exit(status, raw_exit),
        raw_exit_code=raw_exit,
        version=_version([NODE, "--version"]),
        findings=findings,
        stderr="\n".join(stderr_parts)[-4000:],
    )


FRONTEND_RUNNERS = {
    "typescript": run_typescript,
    "eslint": run_eslint,
    "node-check": run_node_check,
}


def execute_frontend_gate(
    req: FrontendCheckRequest,
) -> tuple[FrontendWorkspace, list[FrontendToolResult]]:
    with frontend_workspace(req.files, req.targets) as prepared:
        results = [
            FRONTEND_RUNNERS[tool](
                prepared.root,
                prepared.targets,
            )
            for tool in req.tools
        ]
        return prepared, results
