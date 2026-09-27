# CODE EFHC Quality Gate Runtime

Controlled read-only MCP/runtime service for CODE EFHC Python verification.

## Endpoints

- `GET /health`
- `POST /v1/quality-gate`
- `POST /mcp`

## Checkers

Pinned runtime toolchain:
- Flake8 7.4.1
- Ruff 0.16.9
- mypy 1.18.2
- Bandit 1.8.6

The project-native checker configuration remains authoritative when supplied.

## Security

- ephemeral per-request workspace;
- accepted inputs are bounded text/source/config files only;
- path traversal and secret-like paths are rejected;
- supplied project files are read-only;
- no shell command is constructed from user input;
- no Ruff auto-fix;
- no dependency installation during a scan;
- no arbitrary project code execution by the service.
