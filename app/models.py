from __future__ import annotations
from typing import Literal
from pydantic import BaseModel, Field

ToolName = Literal["flake8", "ruff", "mypy", "bandit"]

class FileInput(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    content: str = Field(max_length=2_000_000)

class CheckRequest(BaseModel):
    files: list[FileInput] = Field(min_length=1, max_length=200)
    tools: list[ToolName] = Field(default_factory=lambda: ["flake8","ruff","mypy","bandit"])
    target_python: str | None = None

class Finding(BaseModel):
    tool: ToolName
    code: str | None = None
    path: str
    line: int | None = None
    column: int | None = None
    message: str
    severity: str | None = None
    confidence: str | None = None

class ToolResult(BaseModel):
    tool: ToolName
    status: Literal["PASS","FINDINGS","CONFIG_ERROR","TOOL_UNAVAILABLE","ERROR"]
    exit_code: int | None = None
    version: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    stderr: str = ""

class QualityGateResponse(BaseModel):
    status: Literal["PASS","FAIL_FINDINGS","FAIL_CONFIG","PARTIAL","ERROR"]
    results: list[ToolResult]
    findings: list[Finding]
