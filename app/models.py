from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ToolName = Literal["flake8", "ruff", "mypy", "bandit"]
DependencyMode = Literal["none", "isolated"]


def _default_tools() -> list[ToolName]:
    return ["flake8", "ruff", "mypy", "bandit"]


FileRole = Literal["target", "context", "config"]
ModeProvenance = Literal["supplied", "archive", "unknown"]
RegressionClass = Literal["INTRODUCED", "RESOLVED", "PRE_EXISTING"]


class FileInput(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    content: str = Field(max_length=2_000_000)
    mode: int | None = Field(default=None, ge=0, le=0o777)


class OpenAIFileRef(BaseModel):
    download_url: str = Field(min_length=1, max_length=4096)
    file_id: str = Field(min_length=1, max_length=512)
    mime_type: str | None = Field(default=None, max_length=255)
    file_name: str | None = Field(default=None, max_length=500)


class GateOptions(BaseModel):
    tools: list[ToolName] = Field(
        default_factory=_default_tools,
        min_length=1,
        max_length=4,
    )
    dependency_mode: DependencyMode = "none"
    dependencies: list[str] = Field(default_factory=list, max_length=10)
    dependency_authorized: bool = False


class CheckRequest(GateOptions):
    files: list[FileInput] = Field(min_length=1, max_length=200)
    targets: list[str] = Field(default_factory=list, max_length=200)


class CompareCheckRequest(GateOptions):
    baseline_files: list[FileInput] = Field(min_length=1, max_length=200)
    candidate_files: list[FileInput] = Field(min_length=1, max_length=200)
    baseline_targets: list[str] = Field(default_factory=list, max_length=200)
    candidate_targets: list[str] = Field(default_factory=list, max_length=200)
    include_findings: bool = False


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
    status: Literal[
        "PASS",
        "FINDINGS",
        "CONFIG_ERROR",
        "TOOL_UNAVAILABLE",
        "ERROR",
    ]
    exit_code: int | None = None
    version: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    suppressed_findings: int = 0
    notes: list[str] = Field(default_factory=list)
    stderr: str = ""


class FileEvidence(BaseModel):
    path: str
    sha256: str
    role: FileRole
    mode: int | None = None
    mode_provenance: ModeProvenance = "unknown"


class IntakeReport(BaseModel):
    source_kind: Literal["inline", "uploaded", "github"]
    source_identity: str
    source_commit: str | None = None
    file_count: int = 0
    total_bytes: int = 0
    skipped_files: int = 0
    dependency_mode: DependencyMode = "none"
    dependencies: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    config_identity: str | None = None
    files: list[FileEvidence] = Field(default_factory=list)


class QualityGateResponse(BaseModel):
    status: Literal[
        "PASS",
        "FAIL_FINDINGS",
        "FAIL_CONFIG",
        "PARTIAL",
        "ERROR",
    ]
    runtime_version: str
    runtime_commit: str | None = None
    results: list[ToolResult]
    findings: list[Finding]
    intake: IntakeReport | None = None


class ToolEvidence(BaseModel):
    tool: ToolName
    status: Literal[
        "PASS",
        "FINDINGS",
        "CONFIG_ERROR",
        "TOOL_UNAVAILABLE",
        "ERROR",
    ]
    exit_code: int | None = None
    version: str | None = None
    finding_count: int = 0
    suppressed_findings: int = 0
    notes: list[str] = Field(default_factory=list)


class GateEvidence(BaseModel):
    status: Literal[
        "PASS",
        "FAIL_FINDINGS",
        "FAIL_CONFIG",
        "PARTIAL",
        "ERROR",
    ]
    runtime_version: str
    runtime_commit: str | None = None
    finding_count: int
    results: list[ToolEvidence]
    intake: IntakeReport | None = None


class RegressionSummary(BaseModel):
    baseline: int
    candidate: int
    introduced: int
    resolved: int
    pre_existing: int


class RegressionFinding(BaseModel):
    classification: RegressionClass
    finding: Finding
    count: int = 1


class CompareQualityGateResponse(BaseModel):
    status: Literal[
        "PASS",
        "FAIL_INTRODUCED",
        "FAIL_CONFIG",
        "PARTIAL",
        "ERROR",
    ]
    summary: RegressionSummary
    baseline: GateEvidence
    candidate: GateEvidence
    findings: list[RegressionFinding] = Field(default_factory=list)
