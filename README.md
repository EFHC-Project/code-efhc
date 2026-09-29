# CODE EFHC Quality Gate Runtime

Controlled read-only MCP/runtime service for targeted CODE EFHC Python verification.

## Endpoints

- `GET /health`
- `POST /v1/quality-gate`
- `POST /v1/quality-gate/compare`
- `POST /v1/quality-gate/github`
- `POST /v1/frontend-quality-gate`
- `POST /mcp`

## Preferred operating mode

Routine verification remains intentionally narrow.

ChatGPT / the EFHC CODE Skill selects:
- changed Python files; and/or
- a small task-relevant suspicious Python slice;
- minimal local Python/import context needed by mypy;
- project checker config only when it materially affects the selected targets.

The preferred single-state route is `run_python_quality_gate_inline`.

The `files` array is the ephemeral workspace. It may contain target, context and checker-configuration files. The `targets` array is the scanner scope: only those Python files are passed to Flake8, Ruff, mypy and Bandit. Context and config files remain available for import resolution and project-owned checker configuration without automatically becoming scanner targets.

Optional `mode` preserves original POSIX permission bits. When mode provenance is unavailable, Ruff `EXE001` is suppressed rather than reported as physical-project evidence.

Each inline result includes:
- SHA-256 for supplied files;
- role = `target|context|config`;
- mode + provenance;
- selected targets;
- aggregate checker-config identity;
- runtime identity;
- checker versions and status;
- normalized `exit_code` plus `raw_exit_code` when suppression/normalization
  changes the raw subprocess result.

## Native baseline → candidate comparison

When a real comparable baseline and candidate exist, use `compare_python_quality_gate`.

It runs the same selected checker set on both targeted workspaces and compares finding multiplicities using stable fingerprints. Findings are classified as:
- `INTRODUCED`;
- `RESOLVED`;
- `PRE_EXISTING`.

The default response is regression-oriented and compact:

```text
baseline N
candidate N
introduced N
resolved N
pre_existing N
```

Full classified findings are returned only when `include_findings=true`.

A baseline must be physically comparable and actually available. The runtime does not invent historical state and does not become a second Project Kernel.

## Targeted frontend static verification

Use `run_frontend_quality_gate_inline` for small selected frontend
targets plus only minimal source/type/config context.

The scanner split is deliberate:

- `.ts` / `.tsx` → TypeScript compiler;
- `.js` / `.jsx` / `.mjs` / `.cjs` → trusted CODE EFHC ESLint;
- `.js` / `.mjs` / `.cjs` → Node `--check` syntax verification.

Project ESLint plugins/configuration and arbitrary project scripts are not
executed by this runtime. Project-owned build, unit/E2E/browser tests and
framework-specific checks remain project-native/exact-head CI evidence.

The frontend result carries the same target/context/config evidence pattern:
selected targets, per-file SHA-256/role, config identity, tool versions, and
normalized plus raw exit codes.

## Published MCP contract

The canonical host-contract requirements live in:

`contracts/mcp_quality_gate_contract.json`

Remote E2E loads this contract and fails closed when the live MCP `tools/list` surface no longer matches required tools or fields. This prevents Skill/runtime drift such as documenting `targets` while the published tool schema omits it.

## Fallback routes

The uploaded-file/archive route and exact-GitHub route remain available for explicit/manual verification. Full project archives are not the default Python Quality Gate payload.

## Checkers

Pinned runtime toolchain:
- Flake8 7.4.1
- Ruff 0.16.9
- mypy 1.18.2
- Bandit 1.8.6

Project-owned checker configuration remains authoritative when supplied as workspace config.

## Security boundary

- ephemeral per-request workspace;
- bounded text/source/config input;
- scanner targets explicitly separated from context/config;
- path traversal and secret-like paths rejected;
- materialized project files are read-only;
- no Ruff auto-fix;
- no arbitrary project-script execution;
- no automatic dependency installation;
- isolated dependency bootstrap remains explicit-authorization + exact-pin only;
- runtime verification is not remote CI.

Runtime deployment configuration: Railway Dockerfile builder, healthcheck `/health`.
