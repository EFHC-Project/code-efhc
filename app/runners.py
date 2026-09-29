from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from .models import Finding, ToolResult

TIMEOUT = 60
CONFIG_LIMIT = 300_000


def _version(cmd):
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=10)
        return (p.stdout or p.stderr).strip().splitlines()[0][:200]
    except Exception:
        return None


def _read_config(path: Path) -> str:
    try:
        if path.stat().st_size > CONFIG_LIMIT:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _unsafe_config(root: Path, tool: str) -> str | None:
    if tool == "mypy":
        for name in ("mypy.ini", ".mypy.ini", "setup.cfg", "pyproject.toml"):
            path = root / name
            if not path.is_file():
                continue
            text = _read_config(path)
            if re.search(r"(?im)^\s*plugins\s*=", text):
                return f"blocked executable mypy plugin configuration in {name}"
            if re.search(r"(?im)^\s*python_executable\s*=", text):
                return f"blocked mypy python_executable override in {name}"
    if tool == "flake8":
        for name in (".flake8", "setup.cfg", "tox.ini"):
            path = root / name
            if path.is_file() and re.search(
                r"(?im)^\s*\[flake8:local-plugins\]\s*$",
                _read_config(path),
            ):
                return (
                    "blocked Flake8 local-plugins configuration "
                    f"in {name}"
                )
    return None


def _offline_env(mypy_path: str | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "CODE_EFHC_BLOCK_NETWORK": "1",
        "PYTHONPATH": "/app/guard",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_NO_INDEX": "1",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "",
    })
    if mypy_path:
        env["MYPYPATH"] = mypy_path
    else:
        env.pop("MYPYPATH", None)
    return env


def _run(
    tool: str,
    cmd: list[str],
    root: Path,
    mypy_path: str | None = None,
):
    unsafe = _unsafe_config(root, tool)
    if unsafe:
        return ToolResult(tool=tool, status="CONFIG_ERROR", stderr=unsafe)
    exe = shutil.which(cmd[0])
    if not exe:
        return None
    try:
        return subprocess.run(
            cmd,
            cwd=root,
            text=True,
            capture_output=True,
            timeout=TIMEOUT,
            env=_offline_env(mypy_path),
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            cmd,
            124,
            exc.stdout or "",
            exc.stderr or "timeout",
        )


def _scan_targets(targets: list[str] | None) -> list[str]:
    return targets or ["."]


def _evidence_path(root: Path, raw: str) -> str:
    if not raw:
        return ""
    path = Path(raw)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            return path.as_posix()
    normalized = path.as_posix()
    if normalized.startswith("./"):
        return normalized[2:]
    return normalized


def run_flake8(
    root: Path,
    mypy_path: str | None = None,
    targets: list[str] | None = None,
):
    p = _run(
        "flake8",
        ["flake8", *_scan_targets(targets)],
        root,
        mypy_path,
    )
    if isinstance(p, ToolResult):
        return p
    if p is None:
        return ToolResult(tool="flake8", status="TOOL_UNAVAILABLE")
    finds = []
    rx = re.compile(
        r"^(.*?):(\d+):(\d+):\s+([A-Z]\d+)\s+(.*)$"
    )
    for line in p.stdout.splitlines():
        m = rx.match(line)
        if m:
            finds.append(
                Finding(
                    tool="flake8",
                    path=_evidence_path(root, m[1]),
                    line=int(m[2]),
                    column=int(m[3]),
                    code=m[4],
                    message=m[5],
                )
            )
    status = (
        "PASS"
        if p.returncode == 0
        else ("FINDINGS" if finds else "CONFIG_ERROR")
    )
    return ToolResult(
        tool="flake8",
        status=status,
        exit_code=p.returncode,
        version=_version(["flake8", "--version"]),
        findings=finds,
        stderr=p.stderr[-4000:],
    )


def run_ruff(
    root: Path,
    mypy_path: str | None = None,
    targets: list[str] | None = None,
):
    p = _run(
        "ruff",
        [
            "ruff",
            "check",
            "--output-format",
            "json",
            "--no-cache",
            *_scan_targets(targets),
        ],
        root,
        mypy_path,
    )
    if isinstance(p, ToolResult):
        return p
    if p is None:
        return ToolResult(tool="ruff", status="TOOL_UNAVAILABLE")
    finds = []
    try:
        data = json.loads(p.stdout or "[]")
        for item in data:
            loc = item.get("location") or {}
            finds.append(
                Finding(
                    tool="ruff",
                    path=_evidence_path(
                        root,
                        item.get("filename", ""),
                    ),
                    line=loc.get("row"),
                    column=loc.get("column"),
                    code=item.get("code"),
                    message=item.get("message", ""),
                )
            )
    except Exception:
        data = []
    status = (
        "PASS"
        if p.returncode == 0
        else ("FINDINGS" if finds else "CONFIG_ERROR")
    )
    return ToolResult(
        tool="ruff",
        status=status,
        exit_code=p.returncode,
        version=_version(["ruff", "--version"]),
        findings=finds,
        stderr=p.stderr[-4000:],
    )


def run_mypy(
    root: Path,
    mypy_path: str | None = None,
    targets: list[str] | None = None,
):
    p = _run(
        "mypy",
        [
            "mypy",
            "--show-column-numbers",
            "--show-error-codes",
            "--no-error-summary",
            "--no-incremental",
            *_scan_targets(targets),
        ],
        root,
        mypy_path,
    )
    if isinstance(p, ToolResult):
        return p
    if p is None:
        return ToolResult(tool="mypy", status="TOOL_UNAVAILABLE")
    finds = []
    rx = re.compile(
        r"^(.*?):(\d+):(\d+):\s+error:\s+(.*?)\s+\[([^\]]+)\]$"
    )
    for line in p.stdout.splitlines():
        m = rx.match(line)
        if m:
            finds.append(
                Finding(
                    tool="mypy",
                    path=_evidence_path(root, m[1]),
                    line=int(m[2]),
                    column=int(m[3]),
                    code=m[5],
                    message=m[4],
                )
            )
    status = (
        "PASS"
        if p.returncode == 0
        else ("FINDINGS" if finds else "CONFIG_ERROR")
    )
    return ToolResult(
        tool="mypy",
        status=status,
        exit_code=p.returncode,
        version=_version(["mypy", "--version"]),
        findings=finds,
        stderr=p.stderr[-4000:],
    )


def run_bandit(
    root: Path,
    mypy_path: str | None = None,
    targets: list[str] | None = None,
):
    scan = _scan_targets(targets)
    cmd = (
        ["bandit", "-r", ".", "-f", "json", "-q"]
        if targets is None
        else ["bandit", "-f", "json", "-q", *scan]
    )
    p = _run("bandit", cmd, root, mypy_path)
    if isinstance(p, ToolResult):
        return p
    if p is None:
        return ToolResult(tool="bandit", status="TOOL_UNAVAILABLE")
    finds = []
    try:
        data = json.loads(p.stdout or "{}")
        for item in data.get("results", []):
            finds.append(
                Finding(
                    tool="bandit",
                    path=_evidence_path(
                        root,
                        item.get("filename", ""),
                    ),
                    line=item.get("line_number"),
                    column=item.get("col_offset"),
                    code=item.get("test_id"),
                    message=item.get("issue_text", ""),
                    severity=item.get("issue_severity"),
                    confidence=item.get("issue_confidence"),
                )
            )
    except Exception:
        data = {}
    status = (
        "PASS"
        if p.returncode == 0
        else ("FINDINGS" if finds else "CONFIG_ERROR")
    )
    return ToolResult(
        tool="bandit",
        status=status,
        exit_code=p.returncode,
        version=_version(["bandit", "--version"]),
        findings=finds,
        stderr=p.stderr[-4000:],
    )


RUNNERS = {
    "flake8": run_flake8,
    "ruff": run_ruff,
    "mypy": run_mypy,
    "bandit": run_bandit,
}
