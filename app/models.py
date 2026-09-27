from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ToolName = Literal["flake8", "ruff", "mypy", "bandit"]
DependencyMode = Literal["none", "isolated"]


class FileInput(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    content: str = Field(max_length=2_000_000)


class OpenAIFileRef(BaseModel):
    download_url: str = Field(min_length=1, max_length=4096)
    file_id: str = Field(min_length=1, max_length=512)
    mime_type: str | None = Field(default=None, max_length=255)
    file_name: str | None = Field(default=None, max_length=500)


class GateOptions(BaseModel):
    tools: list[ToolName] = Field(default_factory=lambda: ["flake8", "ruff", "mypy", "bandit"], min_length=1, max_length=4)
    dependency_mode: DependencyMode = "none"
    dependencies: list[str] = Field(default_factory=list, max_length=10)
    dependency_authorized: bool = False


class CheckRequest(GateOptions):
    files: list[FileInput] = Field(min_length=1, max_length=200)
    target_python: str | None = None


class UploadedCheckRequest(GateOptions):
    files: list[OpenAIFileRef] = Field(min_length=1, max_length=10)


class GitHubCheckRequest(GateOptions):
    owner: str = Field(min_length=1, max_length=100)
    repo: str = Field(min_length=1, max_length=100)
    commit_sha: str = Field(min_length=40, max_length=40)
    subpath: str | None = Field(default=None, max_length=500)


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
    status: Literal["PASS", "FINDINGS", "CONFIG_ERROR", "TOOL_UNAVAILABLE", "ERROR"]
    exit_code: int | None = None
    version: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    stderr: str = ""


class IntakeReport(BaseModel):
    source_kind: Literal["inline", "uploaded", "github"]
    source_identity: str
    source_commit: str | None = None
    file_count: int = 0
    total_bytes: int = 0
    skipped_files: int = 0
    dependency_mode: DependencyMode = "none"
    dependencies: list[str] = Field(default_factory=list)


class QualityGateResponse(BaseModel):
    status: Literal["PASS", "FAIL_FINDINGS", "FAIL_CONFIG", "PARTIAL", "ERROR"]
    results: list[ToolResult]
    findings: list[Finding]
    intake: IntakeReport | None = None
