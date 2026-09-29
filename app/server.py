from __future__ import annotations

import os
from collections import Counter
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ValidationError

from .frontend import execute_frontend_gate
from .intake import (
    PreparedWorkspace,
    github_workspace,
    inline_workspace,
    uploaded_workspace,
)
from .models import (
    CheckRequest,
    CompareCheckRequest,
    CompareQualityGateResponse,
    Finding,
    FrontendCheckRequest,
    FrontendQualityGateResponse,
    GateEvidence,
    GitHubCheckRequest,
    QualityGateResponse,
    RegressionFinding,
    RegressionSummary,
    ToolEvidence,
    ToolName,
    UploadedCheckRequest,
)
from .runners import RUNNERS
from .security import InputRejected

RUNTIME_VERSION = "0.2.4"

app = FastAPI(title="CODE EFHC Runtime", version=RUNTIME_VERSION)

OPENAI_FILE_SCHEMA = {
    "type": "object",
    "properties": {
        "download_url": {"type": "string"},
        "file_id": {"type": "string"},
        "mime_type": {"type": "string"},
        "file_name": {"type": "string"},
    },
    "required": ["download_url", "file_id"],
    "additionalProperties": False,
}
INLINE_FILE_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string"},
        "content": {"type": "string"},
        "mode": {
            "type": "integer",
            "minimum": 0,
            "maximum": 511,
            "description": (
                "Original POSIX permission bits (0..511). "
                "Omit when mode provenance is unavailable."
            ),
        },
    },
    "required": ["path", "content"],
    "additionalProperties": False,
}
TOOLS_SCHEMA = {
    "type": "array",
    "items": {
        "type": "string",
        "enum": ["flake8", "ruff", "mypy", "bandit"],
    },
    "minItems": 1,
    "maxItems": 4,
}
FRONTEND_TOOLS_SCHEMA = {
    "type": "array",
    "items": {
        "type": "string",
        "enum": ["typescript", "eslint", "node-check"],
    },
    "minItems": 1,
    "maxItems": 3,
}

DEPENDENCY_PROPERTIES = {
    "dependency_mode": {
        "type": "string",
        "enum": ["none", "isolated"],
        "default": "none",
    },
    "dependencies": {
        "type": "array",
        "items": {"type": "string"},
        "maxItems": 10,
    },
    "dependency_authorized": {"type": "boolean", "default": False},
}

GUARDIAN_INSTRUCTIONS = (
    "CODE EFHC is a read-only Coding / Project Guardian verification layer. "
    "ChatGPT performs authorized code changes; CODE EFHC independently "
    "verifies selected Python code. Work from the current explicit OWNER "
    "task, physical project authority and project-native rules. "
    "For routine work, prefer run_python_quality_gate_inline with only "
    "changed Python files and/or a small justified suspicious Python slice. "
    "The files array is the ephemeral workspace: selected targets plus "
    "minimal import/context/config files. The targets array is the scanner "
    "scope. Context/config files must not become scanner targets merely "
    "because they were supplied. Preserve file mode when known; when mode "
    "provenance is unavailable, EXE001 is not valid evidence. "
    "When a real comparable baseline and candidate are available, "
    "compare_python_quality_gate provides native INTRODUCED/RESOLVED/"
    "PRE_EXISTING classification and returns a compact summary by default. "
    "For TypeScript/JavaScript use run_frontend_quality_gate_inline with "
    "explicit targets and minimal context; it performs trusted static "
    "TypeScript, ESLint and Node syntax verification without running project "
    "test/build scripts. Do not invent a baseline. Do not send a full project "
    "archive by "
    "default. Never weaken checks, run auto-fix, or install dependencies "
    "without explicit authorization for exact pins. Runtime checks are "
    "not remote CI."
)


def _inline_files_property():
    return {
        "type": "array",
        "items": INLINE_FILE_SCHEMA,
        "minItems": 1,
        "maxItems": 200,
    }


def _targets_property():
    return {
        "type": "array",
        "items": {"type": "string"},
        "minItems": 1,
        "maxItems": 200,
    }


def _tool_descriptors():
    return [
        {
            "name": "run_python_quality_gate",
            "title": "Check uploaded Python project files",
            "description": (
                "Fallback/manual route for explicit uploaded Python/config "
                "files or ZIP/TAR archive audits. Routine verification "
                "should use the targeted inline route."
            ),
            "inputSchema": {
                "type": "object",
                "$defs": {"OpenAIFile": OPENAI_FILE_SCHEMA},
                "properties": {
                    "files": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/OpenAIFile"},
                        "minItems": 1,
                        "maxItems": 10,
                    },
                    "tools": TOOLS_SCHEMA,
                    **DEPENDENCY_PROPERTIES,
                },
                "required": ["files"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
            "_meta": {"openai/fileParams": ["files"]},
        },
        {
            "name": "run_python_quality_gate_from_github",
            "title": "Check an exact public GitHub revision",
            "description": (
                "Fetch a public GitHub repository at an exact 40-character "
                "commit SHA and run the read-only quality gate. Moving "
                "branch names are rejected."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "commit_sha": {
                        "type": "string",
                        "pattern": "^[0-9a-fA-F]{40}$",
                    },
                    "subpath": {"type": "string"},
                    "tools": TOOLS_SCHEMA,
                    **DEPENDENCY_PROPERTIES,
                },
                "required": ["owner", "repo", "commit_sha"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": True,
                "idempotentHint": True,
            },
        },
        {
            "name": "run_python_quality_gate_inline",
            "title": "Check selected Python targets",
            "description": (
                "Preferred routine route. files contains target, context and "
                "checker-config workspace files. targets identifies only "
                "Python files Flake8/Ruff/mypy/Bandit should scan. "
                "Context/config files remain available for imports and "
                "project-owned configuration. Optional mode preserves POSIX "
                "executable semantics. Returns SHA-256/provenance evidence."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "files": _inline_files_property(),
                    "targets": _targets_property(),
                    "tools": TOOLS_SCHEMA,
                    **DEPENDENCY_PROPERTIES,
                },
                "required": ["files", "targets"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "run_frontend_quality_gate_inline",
            "title": "Check selected TypeScript and JavaScript targets",
            "description": (
                "Targeted read-only static frontend verification. files "
                "contains selected targets plus minimal source/type/config "
                "context. targets is the scanner scope. Runs trusted "
                "TypeScript, ESLint and Node syntax checks. Project test/build "
                "scripts are intentionally not executed by this static gate."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "files": _inline_files_property(),
                    "targets": _targets_property(),
                    "tools": FRONTEND_TOOLS_SCHEMA,
                },
                "required": ["files", "targets"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "compare_python_quality_gate",
            "title": "Compare baseline and candidate Python quality",
            "description": (
                "Run the same targeted gate on comparable baseline and "
                "candidate workspaces and classify finding multiplicities as "
                "INTRODUCED, RESOLVED or PRE_EXISTING. The default response "
                "is compact: counts, provenance and tool evidence without "
                "the full historical finding list."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "baseline_files": _inline_files_property(),
                    "candidate_files": _inline_files_property(),
                    "baseline_targets": _targets_property(),
                    "candidate_targets": _targets_property(),
                    "include_findings": {
                        "type": "boolean",
                        "default": False,
                    },
                    "tools": TOOLS_SCHEMA,
                    **DEPENDENCY_PROPERTIES,
                },
                "required": [
                    "baseline_files",
                    "candidate_files",
                    "baseline_targets",
                    "candidate_targets",
                ],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
    ]


@app.get("/health")
def health():
    return {"status": "ok", "runtime": RUNTIME_VERSION}


def _runtime_commit() -> str | None:
    return os.getenv("RAILWAY_GIT_COMMIT_SHA") or os.getenv("GIT_COMMIT_SHA")


def _execute(
    prepared: PreparedWorkspace,
    tools: list[ToolName],
) -> QualityGateResponse:
    results = [
        RUNNERS[t](
            prepared.root,
            prepared.mypy_path,
            prepared.targets,
            prepared.unknown_mode_paths,
        )
        for t in tools
    ]
    findings = [f for result in results for f in result.findings]
    statuses = {result.status for result in results}
    status: Literal[
        "PASS",
        "FAIL_FINDINGS",
        "FAIL_CONFIG",
        "PARTIAL",
        "ERROR",
    ]
    if "CONFIG_ERROR" in statuses:
        status = "FAIL_CONFIG"
    elif findings:
        status = "FAIL_FINDINGS"
    elif statuses <= {"PASS"}:
        status = "PASS"
    elif "ERROR" in statuses:
        status = "ERROR"
    else:
        status = "PARTIAL"
    return QualityGateResponse(
        status=status,
        runtime_version=RUNTIME_VERSION,
        runtime_commit=_runtime_commit(),
        results=results,
        findings=findings,
        intake=prepared.intake,
    )


def _execute_frontend(
    req: FrontendCheckRequest,
) -> FrontendQualityGateResponse:
    prepared, results = execute_frontend_gate(req)
    findings = [
        finding
        for result in results
        for finding in result.findings
    ]
    statuses = {result.status for result in results}
    status: Literal[
        "PASS",
        "FAIL_FINDINGS",
        "FAIL_CONFIG",
        "PARTIAL",
    ]
    if "CONFIG_ERROR" in statuses:
        status = "FAIL_CONFIG"
    elif findings:
        status = "FAIL_FINDINGS"
    elif statuses <= {"PASS", "NOT_APPLICABLE"}:
        status = "PASS"
    else:
        status = "PARTIAL"
    return FrontendQualityGateResponse(
        status=status,
        runtime_version=RUNTIME_VERSION,
        runtime_commit=_runtime_commit(),
        results=results,
        findings=findings,
        intake=prepared.intake,
    )


def _compact_gate(out: QualityGateResponse) -> GateEvidence:
    return GateEvidence(
        status=out.status,
        runtime_version=out.runtime_version,
        runtime_commit=out.runtime_commit,
        finding_count=len(out.findings),
        results=[
            ToolEvidence(
                tool=result.tool,
                status=result.status,
                exit_code=result.exit_code,
                raw_exit_code=result.raw_exit_code,
                version=result.version,
                finding_count=len(result.findings),
                suppressed_findings=result.suppressed_findings,
                notes=result.notes,
            )
            for result in out.results
        ],
        intake=out.intake,
    )


def _fingerprint(finding: Finding) -> tuple[str, ...]:
    return (
        finding.tool,
        finding.code or "",
        finding.path,
        finding.message,
        finding.severity or "",
        finding.confidence or "",
    )


def _compare_outputs(
    baseline: QualityGateResponse,
    candidate: QualityGateResponse,
    include_findings: bool,
) -> CompareQualityGateResponse:
    base_counts = Counter(_fingerprint(item) for item in baseline.findings)
    cand_counts = Counter(_fingerprint(item) for item in candidate.findings)
    base_by_fp = {_fingerprint(item): item for item in baseline.findings}
    cand_by_fp = {_fingerprint(item): item for item in candidate.findings}

    all_keys = set(base_counts) | set(cand_counts)
    introduced = sum(
        max(cand_counts[key] - base_counts[key], 0)
        for key in all_keys
    )
    resolved = sum(
        max(base_counts[key] - cand_counts[key], 0)
        for key in all_keys
    )
    pre_existing = sum(
        min(base_counts[key], cand_counts[key])
        for key in all_keys
    )

    details: list[RegressionFinding] = []
    if include_findings:
        for key in sorted(all_keys):
            pre_count = min(base_counts[key], cand_counts[key])
            if pre_count:
                details.append(
                    RegressionFinding(
                        classification="PRE_EXISTING",
                        finding=cand_by_fp.get(key, base_by_fp[key]),
                        count=pre_count,
                    )
                )
            intro_count = max(cand_counts[key] - base_counts[key], 0)
            if intro_count:
                details.append(
                    RegressionFinding(
                        classification="INTRODUCED",
                        finding=cand_by_fp[key],
                        count=intro_count,
                    )
                )
            resolved_count = max(base_counts[key] - cand_counts[key], 0)
            if resolved_count:
                details.append(
                    RegressionFinding(
                        classification="RESOLVED",
                        finding=base_by_fp[key],
                        count=resolved_count,
                    )
                )

    statuses = {baseline.status, candidate.status}
    status: Literal[
        "PASS",
        "FAIL_INTRODUCED",
        "FAIL_CONFIG",
        "PARTIAL",
        "ERROR",
    ]
    if "FAIL_CONFIG" in statuses:
        status = "FAIL_CONFIG"
    elif "ERROR" in statuses:
        status = "ERROR"
    elif "PARTIAL" in statuses:
        status = "PARTIAL"
    elif introduced:
        status = "FAIL_INTRODUCED"
    else:
        status = "PASS"

    return CompareQualityGateResponse(
        status=status,
        summary=RegressionSummary(
            baseline=len(baseline.findings),
            candidate=len(candidate.findings),
            introduced=introduced,
            resolved=resolved,
            pre_existing=pre_existing,
        ),
        baseline=_compact_gate(baseline),
        candidate=_compact_gate(candidate),
        findings=details,
    )


def _compare(req: CompareCheckRequest) -> CompareQualityGateResponse:
    with inline_workspace(
        req.baseline_files,
        req.dependency_mode,
        req.dependencies,
        req.dependency_authorized,
        req.baseline_targets,
    ) as prepared:
        baseline = _execute(prepared, req.tools)
    with inline_workspace(
        req.candidate_files,
        req.dependency_mode,
        req.dependencies,
        req.dependency_authorized,
        req.candidate_targets,
    ) as prepared:
        candidate = _execute(prepared, req.tools)
    return _compare_outputs(
        baseline,
        candidate,
        req.include_findings,
    )


@app.post("/v1/quality-gate", response_model=QualityGateResponse)
def quality_gate(req: CheckRequest):
    try:
        with inline_workspace(
            req.files,
            req.dependency_mode,
            req.dependencies,
            req.dependency_authorized,
            req.targets,
        ) as prepared:
            return _execute(prepared, req.tools)
    except InputRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post(
    "/v1/frontend-quality-gate",
    response_model=FrontendQualityGateResponse,
)
def frontend_quality_gate(req: FrontendCheckRequest):
    try:
        return _execute_frontend(req)
    except InputRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post(
    "/v1/quality-gate/compare",
    response_model=CompareQualityGateResponse,
)
def quality_gate_compare(req: CompareCheckRequest):
    try:
        return _compare(req)
    except InputRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/v1/quality-gate/github", response_model=QualityGateResponse)
def quality_gate_github(req: GitHubCheckRequest):
    try:
        with github_workspace(req) as prepared:
            return _execute(prepared, req.tools)
    except InputRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _mcp_success(rid, out: BaseModel):
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "result": {
            "content": [
                {"type": "text", "text": out.model_dump_json()}
            ],
            "structuredContent": out.model_dump(),
        },
    }


def _mcp_error(rid, code: int, message: str):
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "error": {"code": code, "message": message},
    }


@app.post("/mcp")
async def mcp(request: Request):
    body = await request.json()
    method = body.get("method")
    rid = body.get("id")
    if method == "notifications/initialized":
        return Response(status_code=202)
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {
                "name": "code-efhc",
                "version": RUNTIME_VERSION,
            },
            "instructions": GUARDIAN_INSTRUCTIONS,
        }
        return {"jsonrpc": "2.0", "id": rid, "result": result}
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {"tools": _tool_descriptors()},
        }
    if method != "tools/call":
        return _mcp_error(rid, -32601, "Method not found")

    params = body.get("params") or {}
    name = params.get("name")
    args = params.get("arguments") or {}
    try:
        if name == "run_python_quality_gate":
            uploaded_req = UploadedCheckRequest.model_validate(args)
            with uploaded_workspace(uploaded_req) as prepared:
                return _mcp_success(
                    rid,
                    _execute(prepared, uploaded_req.tools),
                )
        if name == "run_python_quality_gate_from_github":
            github_req = GitHubCheckRequest.model_validate(args)
            with github_workspace(github_req) as prepared:
                return _mcp_success(
                    rid,
                    _execute(prepared, github_req.tools),
                )
        if name == "run_python_quality_gate_inline":
            inline_req = CheckRequest.model_validate(args)
            with inline_workspace(
                inline_req.files,
                inline_req.dependency_mode,
                inline_req.dependencies,
                inline_req.dependency_authorized,
                inline_req.targets,
            ) as prepared:
                return _mcp_success(
                    rid,
                    _execute(prepared, inline_req.tools),
                )
        if name == "run_frontend_quality_gate_inline":
            frontend_req = FrontendCheckRequest.model_validate(args)
            return _mcp_success(
                rid,
                _execute_frontend(frontend_req),
            )
        if name == "compare_python_quality_gate":
            compare_req = CompareCheckRequest.model_validate(args)
            return _mcp_success(rid, _compare(compare_req))
        return _mcp_error(rid, -32601, "Unknown tool")
    except (ValidationError, InputRejected) as exc:
        return _mcp_error(rid, -32602, str(exc)[:2000])
