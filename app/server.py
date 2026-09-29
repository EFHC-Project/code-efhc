from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import ValidationError

from .intake import PreparedWorkspace, github_workspace, inline_workspace, uploaded_workspace
from .models import CheckRequest, GitHubCheckRequest, QualityGateResponse, UploadedCheckRequest
from .runners import RUNNERS
from .security import InputRejected

app = FastAPI(title="CODE EFHC Runtime", version="0.2.2")

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
TOOLS_SCHEMA = {"type": "array", "items": {"type": "string", "enum": ["flake8", "ruff", "mypy", "bandit"]}, "minItems": 1, "maxItems": 4}
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
    "task, physical project HEAD, active SSOT/CANON/NORM, project profile "
    "and locks/freezes. ChatGPT Memory is navigation only, never authority. "
    "For routine work, prefer run_python_quality_gate_inline with only the "
    "changed Python files and/or a small task-relevant suspicious Python "
    "selection. Add only the minimal local Python/import/config context "
    "needed for correct analysis, and set targets to the files that should "
    "actually be scanned. Do not send a full project archive by default. "
    "run_python_quality_gate remains a fallback for explicit uploaded "
    "Python/config files or a manual archive audit. "
    "run_python_quality_gate_from_github requires an exact 40-character "
    "public GitHub commit SHA. Never weaken checks to obtain PASS. Never "
    "run auto-fix. Never enable isolated dependencies without explicit "
    "user authorization for exact name==version pins. Local/runtime checks "
    "are not remote CI; never claim CI GREEN without direct evidence."
)


def _tool_descriptors():
    return [
        {
            "name": "run_python_quality_gate",
            "title": "Check uploaded Python project files",
            "description": "Fallback/manual route for explicit uploaded Python/config files or ZIP/TAR archive audits. Routine verification should use the targeted inline route instead of sending an entire project archive. Archives are safely extracted into an ephemeral workspace. Isolated dependency bootstrap is available only with explicit authorization and exact name==version pins.",
            "inputSchema": {
                "type": "object",
                "$defs": {"OpenAIFile": OPENAI_FILE_SCHEMA},
                "properties": {
                    "files": {"type": "array", "items": {"$ref": "#/$defs/OpenAIFile"}, "minItems": 1, "maxItems": 10},
                    "tools": TOOLS_SCHEMA,
                    **DEPENDENCY_PROPERTIES,
                },
                "required": ["files"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False, "idempotentHint": True},
            "_meta": {"openai/fileParams": ["files"]},
        },
        {
            "name": "run_python_quality_gate_from_github",
            "title": "Check an exact public GitHub revision",
            "description": "Fetch a public GitHub repository at an exact 40-character commit SHA, safely extract relevant Python/config files, then run the read-only quality gate. Moving branch names are not accepted.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "commit_sha": {"type": "string", "pattern": "^[0-9a-fA-F]{40}$"},
                    "subpath": {"type": "string"},
                    "tools": TOOLS_SCHEMA,
                    **DEPENDENCY_PROPERTIES,
                },
                "required": ["owner", "repo", "commit_sha"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True, "idempotentHint": True},
        },
        {
            "name": "run_python_quality_gate_inline",
            "title": "Check selected Python targets",
            "description": "Preferred route for routine verification. Send only changed and/or task-relevant suspicious Python files plus minimal local Python/import/config context. Use targets to identify the files Flake8, Ruff, mypy and Bandit should actually scan; context files remain available for import/type resolution.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "files": {
                        "type": "array",
                        "items": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"], "additionalProperties": False},
                        "minItems": 1,
                        "maxItems": 200,
                    },
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 200,
                    },
                    "tools": TOOLS_SCHEMA,
                    **DEPENDENCY_PROPERTIES,
                },
                "required": ["files"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False, "idempotentHint": True},
        },
    ]


@app.get("/health")
def health():
    return {"status": "ok", "runtime": "0.2.2"}


def _execute(prepared: PreparedWorkspace, tools: list[str]) -> QualityGateResponse:
    results = [
        RUNNERS[t](prepared.root, prepared.mypy_path, prepared.targets)
        for t in tools
    ]
    findings = [f for r in results for f in r.findings]
    statuses = {r.status for r in results}
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
    return QualityGateResponse(status=status, results=results, findings=findings, intake=prepared.intake)


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
    except InputRejected as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/quality-gate/github", response_model=QualityGateResponse)
def quality_gate_github(req: GitHubCheckRequest):
    try:
        with github_workspace(req) as prepared:
            return _execute(prepared, req.tools)
    except InputRejected as e:
        raise HTTPException(status_code=400, detail=str(e))


def _mcp_success(rid, out: QualityGateResponse):
    return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": out.model_dump_json()}], "structuredContent": out.model_dump()}}


def _mcp_error(rid, code: int, message: str):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


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
            "serverInfo": {"name": "code-efhc", "version": "0.2.2"},
            "instructions": GUARDIAN_INSTRUCTIONS,
        }
        return {"jsonrpc": "2.0", "id": rid, "result": result}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": _tool_descriptors()}}
    if method != "tools/call":
        return _mcp_error(rid, -32601, "Method not found")

    params = body.get("params") or {}
    name = params.get("name")
    args = params.get("arguments") or {}
    try:
        if name == "run_python_quality_gate":
            req = UploadedCheckRequest.model_validate(args)
            with uploaded_workspace(req) as prepared:
                return _mcp_success(rid, _execute(prepared, req.tools))
        if name == "run_python_quality_gate_from_github":
            req = GitHubCheckRequest.model_validate(args)
            with github_workspace(req) as prepared:
                return _mcp_success(rid, _execute(prepared, req.tools))
        if name == "run_python_quality_gate_inline":
            req = CheckRequest.model_validate(args)
            with inline_workspace(
                req.files,
                req.dependency_mode,
                req.dependencies,
                req.dependency_authorized,
                req.targets,
            ) as prepared:
                return _mcp_success(rid, _execute(prepared, req.tools))
        return _mcp_error(rid, -32601, "Unknown tool")
    except (ValidationError, InputRejected) as exc:
        return _mcp_error(rid, -32602, str(exc)[:2000])
