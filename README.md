# CODE EFHC Quality Gate Runtime

Controlled read-only MCP/runtime service for targeted CODE EFHC Python verification.

## Endpoints

- `GET /health`
- `POST /v1/quality-gate`
- `POST /mcp`

## Preferred operating mode

Routine verification is intentionally narrow.

ChatGPT / the EFHC CODE Skill selects:
- changed Python files; and/or
- a small task-relevant suspicious Python slice;
- minimal local Python/import context needed by mypy;
- checker config only when it materially affects the selected targets.

The preferred MCP route is `run_python_quality_gate_inline`.

The `files` array may contain context files, while `targets` identifies the Python files that Flake8, Ruff, mypy and Bandit must actually scan. This keeps ordinary verification in the kilobyte range and avoids sending full project archives through the checker runtime.

The uploaded-file/archive and exact-GitHub routes remain available as explicit/manual verification routes, but full-project archive scanning is not the default workflow.

## Checkers

Pinned runtime toolchain:
- Flake8 7.4.1
- Ruff 0.16.9
- mypy 1.18.2
- Bandit 1.8.6

The project-native checker configuration remains authoritative when supplied.

## Security

- ephemeral per-request workspace;
- only bounded text/source/config inputs are accepted;
- context files are available for type/import resolution but are not scanned when excluded from `targets`;
- path traversal and secret-like paths are rejected;
- supplied project files are read-only;
- no shell command is constructed from user input;
- no Ruff auto-fix;
- no automatic dependency installation;
- no arbitrary project code execution by the service.

Runtime deployment configuration: Railway Dockerfile builder, healthcheck `/health`.
