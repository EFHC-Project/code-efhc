# Security Boundary

This runtime is read-only with respect to submitted project source.

- Project source is materialized in an ephemeral per-request workspace and source files are chmod read-only.
- Uploaded files use ChatGPT file-parameter references and bounded HTTPS downloads; redirects are revalidated and non-public/private-network targets are rejected.
- ZIP/TAR extraction rejects traversal, symlinks, hardlinks and device entries; file count, compressed/input size, relevant-file size and extracted-size are bounded.
- Secret-like paths such as `.env`, `.git`, `.ssh` and common private-key names are not materialized for scanning.
- Only Python and checker/config text files are materialized; unrelated binary assets are skipped.
- Direct GitHub intake accepts only a public `owner/repo` plus an exact 40-character commit SHA and fetches from `codeload.github.com`; moving branch names are not accepted.
- Checker subprocesses receive an application-level socket egress guard, disabled proxy targets and `PIP_NO_INDEX=1`. Ruff does not use a Python socket stack; it has no network operation in this workflow.
- `mypy` executable plugins / `python_executable` overrides and Flake8 `local-plugins` are blocked before checker execution.
- No shell command is constructed from submitted project content.
- Ruff auto-fix, Bandit exit-zero and automatic suppression are not used.
- Default dependency mode is `none`. The runtime never reads project requirement files and installs them automatically.
- Optional dependency mode requires an explicit authorization flag and explicit exact `name==version` pins. It installs wheel-only packages into a separate ephemeral target with `--no-deps`; package source builds, VCS/URL requirements and editable installs are rejected. The target is exposed only to mypy through `MYPYPATH` and is outside the scanned source tree.
