# CODE EFHC remote E2E harness.
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE = os.environ.get(
    "CODE_EFHC_RUNTIME_URL",
    "https://code-efhc-quality-gate-production.up.railway.app",
)
MCP = BASE.rstrip("/") + "/mcp"
EXACT_GITHUB_COMMIT = "7c727a07da2b18aff09bcb3a6bc0c07143654c6c"


def request_json(url: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = (
        {"Content-Type": "application/json"}
        if payload is not None
        else {}
    )
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise AssertionError(f"HTTP {exc.code} from {url}: {raw}") from exc
    return json.loads(raw)


def call_tool(name: str, arguments: dict, call_id: int) -> dict:
    return request_json(
        MCP,
        {
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )


def tool_result(response: dict) -> dict:
    assert "error" not in response, response  # nosec B101
    return response["result"]["structuredContent"]


def expect_error(response: dict, code: int = -32602) -> None:
    assert (  # nosec B101
        response.get("error", {}).get("code") == code
    ), response


def one_inline(
    files: list[dict],
    tools: list[str],
    call_id: int,
    **extra,
) -> dict:
    args = {
        "files": files,
        "tools": tools,
        "dependency_mode": "none",
    }
    args.update(extra)
    return call_tool("run_python_quality_gate_inline", args, call_id)


def main() -> int:
    cases: list[tuple[str, str]] = []

    health = request_json(BASE.rstrip("/") + "/health")
    assert health == {"status": "ok", "runtime": "0.2.3"}, health  # nosec B101
    cases.append(("E2E-001", "PASS health/runtime identity"))

    listed = request_json(
        MCP,
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    tool_map = {
        item["name"]: item
        for item in listed["result"]["tools"]
    }
    contract = json.loads(
        Path("contracts/mcp_quality_gate_contract.json").read_text(
            encoding="utf-8"
        )
    )
    required = set(contract["required_tools"])
    assert required <= set(tool_map), set(tool_map)  # nosec B101
    for tool_name, expected in contract["required_tools"].items():
        schema = tool_map[tool_name]["inputSchema"]
        properties = schema["properties"]
        required_props = set(schema.get("required", []))
        for key in expected.get("required_properties", []):
            assert key in properties, schema  # nosec B101
            assert key in required_props, schema  # nosec B101
        file_key = (
            "files"
            if "files" in properties
            else "baseline_files"
        )
        file_props = properties[file_key]["items"]["properties"]
        for key in expected.get("required_file_properties", []):
            assert key in file_props, schema  # nosec B101
        for key in expected.get("optional_file_properties", []):
            assert key in file_props, schema  # nosec B101
        for key in expected.get("optional_properties", []):
            assert key in properties, schema  # nosec B101
    cases.append(("E2E-002", "PASS canonical MCP schema contract"))

    clean = tool_result(
        one_inline(
            [
                {
                    "path": "a.py",
                    "content": (
                        "def add(a: int, b: int) -> int:\n"
                        "    return a + b\n"
                    ),
                }
            ],
            ["flake8", "ruff", "mypy", "bandit"],
            2,
            targets=["a.py"],
        )
    )
    assert clean["status"] == "PASS", clean  # nosec B101
    per_tool = {
        item["tool"]: item["status"]
        for item in clean["results"]
    }
    assert per_tool == {  # nosec B101
        "flake8": "PASS",
        "ruff": "PASS",
        "mypy": "PASS",
        "bandit": "PASS",
    }, per_tool
    cases.append(("E2E-003", "PASS targeted all-four smoke"))

    scoped = tool_result(
        one_inline(
            [
                {"path": "changed.py", "content": "x = 1\n"},
                {"path": "context.py", "content": "import os\n"},
            ],
            ["flake8", "ruff", "bandit"],
            3,
            targets=["changed.py"],
        )
    )
    assert scoped["status"] == "PASS", scoped  # nosec B101
    assert not scoped["findings"], scoped  # nosec B101
    roles = {
        item["path"]: item["role"]
        for item in scoped["intake"]["files"]
    }
    assert roles == {  # nosec B101
        "changed.py": "target",
        "context.py": "context",
    }, roles
    cases.append(("E2E-004", "PASS target/context scanner isolation"))

    mypy_context = tool_result(
        one_inline(
            [
                {"path": "pkg/__init__.py", "content": ""},
                {
                    "path": "pkg/helper.py",
                    "content": (
                        "def twice(value: int) -> int:\n"
                        "    return value * 2\n"
                    ),
                },
                {
                    "path": "pkg/changed.py",
                    "content": (
                        "from pkg.helper import twice\n\n"
                        "def result(value: int) -> int:\n"
                        "    return twice(value)\n"
                    ),
                },
            ],
            ["mypy"],
            4,
            targets=["pkg/changed.py"],
        )
    )
    assert mypy_context["status"] == "PASS", mypy_context  # nosec B101
    cases.append(("E2E-005", "PASS minimal mypy import context"))

    target_text = "x = 1\n"
    provenance = tool_result(
        one_inline(
            [
                {"path": "pkg/a.py", "content": target_text},
                {
                    "path": "pyproject.toml",
                    "content": "[tool.ruff]\nline-length = 88\n",
                },
            ],
            ["ruff"],
            5,
            targets=["pkg/a.py"],
        )
    )
    evidence = {
        item["path"]: item
        for item in provenance["intake"]["files"]
    }
    assert evidence["pkg/a.py"]["role"] == "target", evidence  # nosec B101
    assert (  # nosec B101
        evidence["pyproject.toml"]["role"] == "config"
    ), evidence
    assert evidence["pkg/a.py"]["sha256"] == hashlib.sha256(  # nosec B101
        target_text.encode()
    ).hexdigest(), evidence
    assert provenance["intake"]["config_identity"], provenance  # nosec B101
    assert provenance["runtime_version"] == "0.2.3", provenance  # nosec B101
    assert provenance["results"][0]["version"], provenance  # nosec B101
    cases.append(("E2E-006", "PASS SHA/config/runtime provenance"))

    unknown_mode = tool_result(
        one_inline(
            [
                {
                    "path": "script.py",
                    "content": "#!/usr/bin/env python3\nvalue = 1\n",
                }
            ],
            ["ruff"],
            6,
            targets=["script.py"],
        )
    )
    assert unknown_mode["status"] == "PASS", unknown_mode  # nosec B101
    assert (  # nosec B101
        unknown_mode["results"][0]["suppressed_findings"] >= 1
    ), unknown_mode
    assert not {  # nosec B101
        item["code"]
        for item in unknown_mode["findings"]
        if item["code"] == "EXE001"
    }, unknown_mode
    cases.append(("E2E-007", "PASS unknown-mode EXE001 suppression"))

    known_nonexec = tool_result(
        one_inline(
            [
                {
                    "path": "script.py",
                    "content": "#!/usr/bin/env python3\nvalue = 1\n",
                    "mode": 420,
                }
            ],
            ["ruff"],
            7,
            targets=["script.py"],
        )
    )
    assert (  # nosec B101
        known_nonexec["status"] == "FAIL_FINDINGS"
    ), known_nonexec
    assert "EXE001" in {  # nosec B101
        item["code"]
        for item in known_nonexec["findings"]
    }, known_nonexec
    cases.append(("E2E-008", "PASS known-mode EXE001 retained"))

    negative = tool_result(
        one_inline(
            [{"path": "pkg/a.py", "content": "import os\n"}],
            ["flake8", "ruff"],
            8,
            targets=["pkg/a.py"],
        )
    )
    assert negative["status"] == "FAIL_FINDINGS", negative  # nosec B101
    assert {  # nosec B101
        item["path"]
        for item in negative["findings"]
    } == {"pkg/a.py"}, negative
    cases.append(("E2E-009", "PASS project-relative finding paths"))

    compare = tool_result(
        call_tool(
            "compare_python_quality_gate",
            {
                "baseline_files": [
                    {
                        "path": "a.py",
                        "content": "import os\nimport sys\n",
                    }
                ],
                "candidate_files": [
                    {
                        "path": "a.py",
                        "content": "import os\nimport json\n",
                    }
                ],
                "baseline_targets": ["a.py"],
                "candidate_targets": ["a.py"],
                "tools": ["ruff"],
                "dependency_mode": "none",
            },
            9,
        )
    )
    assert compare["status"] == "FAIL_INTRODUCED", compare  # nosec B101
    assert compare["summary"] == {  # nosec B101
        "baseline": 2,
        "candidate": 2,
        "introduced": 1,
        "resolved": 1,
        "pre_existing": 1,
    }, compare
    assert compare["findings"] == [], compare  # nosec B101
    cases.append(("E2E-010", "PASS compact native regression summary"))

    compare_details = tool_result(
        call_tool(
            "compare_python_quality_gate",
            {
                "baseline_files": [
                    {
                        "path": "a.py",
                        "content": "import os\nimport sys\n",
                    }
                ],
                "candidate_files": [
                    {
                        "path": "a.py",
                        "content": "import os\nimport json\n",
                    }
                ],
                "baseline_targets": ["a.py"],
                "candidate_targets": ["a.py"],
                "tools": ["ruff"],
                "dependency_mode": "none",
                "include_findings": True,
            },
            10,
        )
    )
    assert {  # nosec B101
        item["classification"]
        for item in compare_details["findings"]
    } == {"INTRODUCED", "RESOLVED", "PRE_EXISTING"}, compare_details
    cases.append(("E2E-011", "PASS classified regression details"))

    missing_target = one_inline(
        [{"path": "changed.py", "content": "x = 1\n"}],
        ["ruff"],
        11,
        targets=["missing.py"],
    )
    expect_error(missing_target)
    cases.append(("E2E-012", "PASS missing target rejected"))

    non_python_target = one_inline(
        [
            {"path": "changed.py", "content": "x = 1\n"},
            {"path": "pyproject.toml", "content": "[tool.ruff]\n"},
        ],
        ["ruff"],
        12,
        targets=["pyproject.toml"],
    )
    expect_error(non_python_target)
    cases.append(("E2E-013", "PASS config cannot become scanner target"))

    mypy_plugin = tool_result(
        one_inline(
            [
                {"path": "a.py", "content": "x: int = 1\n"},
                {
                    "path": "mypy.ini",
                    "content": "[mypy]\nplugins = evil.py\n",
                },
            ],
            ["mypy"],
            13,
            targets=["a.py"],
        )
    )
    assert mypy_plugin["status"] == "FAIL_CONFIG", mypy_plugin  # nosec B101
    cases.append(("E2E-014", "PASS executable mypy plugin blocked"))

    deps = call_tool(
        "run_python_quality_gate_inline",
        {
            "files": [{"path": "a.py", "content": "x = 1\n"}],
            "targets": ["a.py"],
            "tools": ["mypy"],
            "dependency_mode": "isolated",
            "dependencies": ["typing-extensions==4.15.0"],
            "dependency_authorized": False,
        },
        14,
    )
    expect_error(deps)
    cases.append(("E2E-015", "PASS dependency bootstrap authorization gate"))

    moving = call_tool(
        "run_python_quality_gate_from_github",
        {
            "owner": "EFHC-Project",
            "repo": "code-efhc",
            "commit_sha": "main",
            "tools": ["ruff"],
            "dependency_mode": "none",
        },
        15,
    )
    expect_error(moving)
    cases.append(("E2E-016", "PASS moving GitHub ref rejected"))

    github = tool_result(
        call_tool(
            "run_python_quality_gate_from_github",
            {
                "owner": "EFHC-Project",
                "repo": "code-efhc",
                "commit_sha": EXACT_GITHUB_COMMIT,
                "tools": ["ruff"],
                "dependency_mode": "none",
            },
            16,
        )
    )
    assert (  # nosec B101
        github["intake"]["source_commit"] == EXACT_GITHUB_COMMIT
    ), github
    assert github["results"][0]["tool"] == "ruff", github  # nosec B101
    cases.append(("E2E-017", "PASS exact GitHub commit route"))

    for case, result in cases:
        print(f"{case} {result}")
    print(f"E2E SUMMARY {len(cases)}/{len(cases)} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
