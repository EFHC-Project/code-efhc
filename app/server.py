from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import ValidationError

from .intake import PreparedWorkspace, github_workspace, inline_workspace, uploaded_workspace
from .models import CheckRequest, GitHubCheckRequest, QualityGateResponse, UploadedCheckRequest
from .runners import RUNNERS
from .security import InputRejected

app = FastAPI(title="CODE EFHC Quality Gate Runtime", version="0.2.0")

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
    "dependency_mode": {"type": "string", "enum": ["none", "isolated"], "default": "none"},
    "dependencies": {"type": "array", "items": {"type": "string"}, "maxItems": 10},
    "dependency_authorized": {"type": "boolean", "default": False},
}


def _tool_descriptors():
    return [
        {
            "name": "run_python_quality_gate",
            "title": "Check uploaded Python project files",
            "description": "Run read-only Flake8, Ruff, mypy and Bandit on uploaded Python files or ZIP/TAR archives. Archives are safely extracted into an ephemeral workspace. Isolated dependency bootstrap is available only with explicit authorization and exact name==version pins.",
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
            "title": "Check inline Python files",
            "description": "Run the same read-only quality gate on small inline text files. Use the uploaded-file tool for user files and archives.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "files": {
                        "type": "array",
                        "items": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"], "additionalProperties": False},
                        "minItems": 1,
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
    return {"status": "ok", "runtime": "0.2.0"}


def _execute(prepared: PreparedWorkspace, tools: list[str]) -> QualityGateResponse:
    results = [RUNNERS[t](prepared.root, prepared.mypy_path) for t in tools]
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
        with inline_workspace(req.files, req.dependency_mode, req.dependencies, req.dependency_authorized) as prepared:
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
            "serverInfo": {"name": "code-efhc-quality-gate", "version": "0.2.0"},
            "instructions": "Use run_python_quality_gate for uploaded files/archives, run_python_quality_gate_from_github only with an exact public GitHub commit SHA, and run_python_quality_gate_inline for small inline code. Never enable isolated dependencies without explicit user authorization for the exact pins.",
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
            with inline_workspace(req.files, req.dependency_mode, req.dependencies, req.dependency_authorized) as prepared:
                return _mcp_success(rid, _execute(prepared, req.tools))
        return _mcp_error(rid, -32601, "Unknown tool")
    except (ValidationError, InputRejected) as exc:
        return _mcp_error(rid, -32602, str(exc)[:2000])
