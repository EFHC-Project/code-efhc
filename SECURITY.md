# Security Boundary

This runtime is read-only for submitted project source.

- No source mutation.
- No dependency installation during a scan.
- No network access is required by checker subprocesses.
- No shell command is constructed from submitted content.
- Project-local executable hooks/plugins are not intentionally loaded by this service.
- Inputs are bounded to text Python/config file types and 10 MB total.
- Path traversal and secret-like paths are rejected.
- Workspaces are ephemeral and deleted after each request.
- Ruff auto-fix and Bandit exit-zero are not used.
