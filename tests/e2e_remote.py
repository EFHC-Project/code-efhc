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


def request_json(
    url: str,
    payload: dict | None = None,
) -> dict:
    data = (
        None
        if payload is None
        else json.dumps(payload).encode("utf-8")
    )
    headers = (
        {"Content-Type": "application/json"}
        if payload is not None
        else {}
    )
    req = urllib.request.Request(
        url,
        data=data,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(  # nosec B310
            req,
            timeout=60,
        ) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(
            "utf-8",
            errors="replace",
        )
        raise AssertionError(
            f"HTTP {exc.code} from {url}: {raw}"
        ) from exc
    return json.loads(raw)


def call_tool(
    name: str,
    arguments: dict,
    call_id: int,
) -> dict:
    return request_json(
        MCP,
        {
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            },
        },
    )


def tool_result(response: dict) -> dict:
    assert "error" not in response, response  # nosec B101
    return response["result"]["structuredContent"]


def expect_error(
    response: dict,
    code: int = -32602,
) -> None:
    assert (  # nosec B101
        response.get("error", {}).get("code") == code
    ), response


def validate_result_contract(
    name: str,
    result: dict,
    contract: dict,
) -> None:
    expected = contract["required_tools"][name]
    for key in expected.get("required_result_fields", []):
        assert key in result, (name, key, result)  # nosec B101
    intake = result.get("intake")
    if expected.get("required_intake_fields"):
        assert isinstance(intake, dict), result  # nosec B101
        for key in expected["required_intake_fields"]:
            assert key in intake, (name, key, intake)  # nosec B101
    required_tool_fields = expected.get(
        "required_tool_result_fields",
        [],
    )
    for tool_result_item in result.get("results", []):
        for key in required_tool_fields:
            assert key in tool_result_item, (  # nosec B101
                name,
                key,
                tool_result_item,
            )


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
    return call_tool(
        "run_python_quality_gate_inline",
        args,
        call_id,
    )


def main() -> int:
    cases: list[tuple[str, str]] = []

    health = request_json(BASE.rstrip("/") + "/health")
    assert health == {  # nosec B101
        "status": "ok",
        "runtime": "0.2.4",
    }, health
    cases.append(("E2E-001", "PASS health/runtime identity"))

    listed = request_json(
        MCP,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        },
    )
    tool_map = {
        item["name"]: item
        for item in listed["result"]["tools"]
    }
    contract = json.loads(
        Path(
            "contracts/mcp_quality_gate_contract.json"
        ).read_text(encoding="utf-8")
    )
    required = set(contract["required_tools"])
    assert required <= set(tool_map), set(tool_map)  # nosec B101
    for tool_name, expected in contract["required_tools"].items():
        schema = tool_map[tool_name]["inputSchema"]
        properties = schema["properties"]
        required_props = set(schema.get("required", []))
        for key in expected.get(
            "required_properties",
            [],
        ):
            assert key in properties, schema  # nosec B101
            assert key in required_props, schema  # nosec B101
        file_key = (
            "files"
            if "files" in properties
            else "baseline_files"
        )
        file_props = properties[file_key]["items"]["properties"]
        for key in expected.get(
            "required_file_properties",
            [],
        ):
            assert key in file_props, schema  # nosec B101
        for key in expected.get(
            "optional_file_properties",
            [],
        ):
            assert key in file_props, schema  # nosec B101
        for key in expected.get(
            "optional_properties",
            [],
        ):
            assert key in properties, schema  # nosec B101
    cases.append(
        (
            "E2E-002",
            "PASS canonical MCP input-schema contract",
        )
    )

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
    validate_result_contract(
        "run_python_quality_gate_inline",
        clean,
        contract,
    )
    assert clean["status"] == "PASS", clean  # nosec B101
    assert clean["intake"]["targets"] == ["a.py"], clean  # nosec B101
    assert clean["intake"]["files"][0]["role"] == (  # nosec B101
        "target"
    ), clean
    cases.append(
        (
            "E2E-003",
            "PASS Python targets/provenance result contract",
        )
    )

    scoped = tool_result(
        one_inline(
            [
                {
                    "path": "changed.py",
                    "content": "x = 1\n",
                },
                {
                    "path": "context.py",
                    "content": "import os\n",
                },
            ],
            ["flake8", "ruff", "bandit"],
            3,
            targets=["changed.py"],
        )
    )
    roles = {
        item["path"]: item["role"]
        for item in scoped["intake"]["files"]
    }
    assert scoped["status"] == "PASS", scoped  # nosec B101
    assert roles == {  # nosec B101
        "changed.py": "target",
        "context.py": "context",
    }, roles
    cases.append(
        (
            "E2E-004",
            "PASS target/context scanner isolation",
        )
    )

    mypy_context = tool_result(
        one_inline(
            [
                {
                    "path": "pkg/__init__.py",
                    "content": "",
                },
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
    cases.append(
        (
            "E2E-005",
            "PASS minimal mypy import context",
        )
    )

    target_text = "x = 1\n"
    provenance = tool_result(
        one_inline(
            [
                {
                    "path": "pkg/a.py",
                    "content": target_text,
                },
                {
                    "path": "pyproject.toml",
                    "content": (
                        "[tool.ruff]\n"
                        "line-length = 88\n"
                    ),
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
    assert evidence["pkg/a.py"]["sha256"] == (  # nosec B101
        hashlib.sha256(target_text.encode()).hexdigest()
    ), evidence
    assert evidence["pyproject.toml"]["role"] == (  # nosec B101
        "config"
    ), evidence
    assert provenance["intake"]["config_identity"], provenance  # nosec B101
    assert provenance["runtime_version"] == "0.2.4", provenance  # nosec B101
    cases.append(
        (
            "E2E-006",
            "PASS SHA/config/runtime provenance",
        )
    )

    unknown_mode = tool_result(
        one_inline(
            [
                {
                    "path": "script.py",
                    "content": (
                        "#!/usr/bin/env python3\n"
                        "value = 1\n"
                    ),
                }
            ],
            ["ruff"],
            6,
            targets=["script.py"],
        )
    )
    ruff = unknown_mode["results"][0]
    assert unknown_mode["status"] == "PASS", unknown_mode  # nosec B101
    assert ruff["exit_code"] == 0, ruff  # nosec B101
    assert ruff["raw_exit_code"] == 1, ruff  # nosec B101
    assert ruff["suppressed_findings"] >= 1, ruff  # nosec B101
    cases.append(
        (
            "E2E-007",
            "PASS normalized/raw Ruff exit evidence",
        )
    )

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
                        "content": (
                            "import os\n"
                            "import pathlib\n"
                        ),
                    }
                ],
                "baseline_targets": ["a.py"],
                "candidate_targets": ["a.py"],
                "tools": ["ruff"],
                "dependency_mode": "none",
            },
            7,
        )
    )
    validate_result_contract(
        "compare_python_quality_gate",
        compare,
        contract,
    )
    assert compare["status"] == (  # nosec B101
        "FAIL_INTRODUCED"
    ), compare
    assert compare["summary"] == {  # nosec B101
        "baseline": 2,
        "candidate": 2,
        "introduced": 1,
        "resolved": 1,
        "pre_existing": 1,
    }, compare
    assert compare["findings"] == [], compare  # nosec B101
    cases.append(
        (
            "E2E-008",
            "PASS native compact baseline/candidate comparison",
        )
    )

    clean_frontend = tool_result(
        call_tool(
            "run_frontend_quality_gate_inline",
            {
                "files": [
                    {
                        "path": "src/add.ts",
                        "content": (
                            "export function add("
                            "a: number, b: number): number {\n"
                            "  return a + b;\n"
                            "}\n"
                        ),
                    }
                ],
                "targets": ["src/add.ts"],
                "tools": [
                    "typescript",
                    "eslint",
                    "node-check",
                ],
            },
            8,
        )
    )
    validate_result_contract(
        "run_frontend_quality_gate_inline",
        clean_frontend,
        contract,
    )
    statuses = {
        item["tool"]: item["status"]
        for item in clean_frontend["results"]
    }
    assert clean_frontend["status"] == "PASS", clean_frontend  # nosec B101
    assert statuses == {  # nosec B101
        "typescript": "PASS",
        "eslint": "NOT_APPLICABLE",
        "node-check": "NOT_APPLICABLE",
    }, statuses
    assert clean_frontend["intake"]["targets"] == [  # nosec B101
        "src/add.ts"
    ], clean_frontend
    cases.append(
        (
            "E2E-009",
            "PASS frontend TypeScript target smoke",
        )
    )

    clean_javascript = tool_result(
        call_tool(
            "run_frontend_quality_gate_inline",
            {
                "files": [
                    {
                        "path": "src/value.mjs",
                        "content": (
                            "export const value = 1;\n"
                        ),
                    }
                ],
                "targets": ["src/value.mjs"],
                "tools": [
                    "typescript",
                    "eslint",
                    "node-check",
                ],
            },
            9,
        )
    )
    js_statuses = {
        item["tool"]: item["status"]
        for item in clean_javascript["results"]
    }
    assert clean_javascript["status"] == (  # nosec B101
        "PASS"
    ), clean_javascript
    assert js_statuses == {  # nosec B101
        "typescript": "NOT_APPLICABLE",
        "eslint": "PASS",
        "node-check": "PASS",
    }, js_statuses
    cases.append(
        (
            "E2E-010",
            "PASS frontend JavaScript ESLint/Node smoke",
        )
    )

    bad_frontend = tool_result(
        call_tool(
            "run_frontend_quality_gate_inline",
            {
                "files": [
                    {
                        "path": "src/bad.ts",
                        "content": (
                            'const value: number = "bad";\n'
                        ),
                    }
                ],
                "targets": ["src/bad.ts"],
                "tools": ["typescript"],
            },
            9,
        )
    )
    assert bad_frontend["status"] == (  # nosec B101
        "FAIL_FINDINGS"
    ), bad_frontend
    assert any(  # nosec B101
        item.get("code") == "TS2322"
        for item in bad_frontend["findings"]
    ), bad_frontend
    cases.append(
        (
            "E2E-011",
            "PASS frontend TypeScript negative case",
        )
    )

    missing_target = one_inline(
        [
            {
                "path": "changed.py",
                "content": "x = 1\n",
            }
        ],
        ["ruff"],
        10,
        targets=["missing.py"],
    )
    expect_error(missing_target)
    cases.append(
        (
            "E2E-012",
            "PASS missing Python target rejected",
        )
    )

    non_python_target = one_inline(
        [
            {
                "path": "changed.py",
                "content": "x = 1\n",
            },
            {
                "path": "pyproject.toml",
                "content": "[tool.ruff]\n",
            },
        ],
        ["ruff"],
        11,
        targets=["pyproject.toml"],
    )
    expect_error(non_python_target)
    cases.append(
        (
            "E2E-013",
            "PASS config cannot become Python scanner target",
        )
    )

    deps = call_tool(
        "run_python_quality_gate_inline",
        {
            "files": [
                {
                    "path": "a.py",
                    "content": "x = 1\n",
                }
            ],
            "targets": ["a.py"],
            "tools": ["mypy"],
            "dependency_mode": "isolated",
            "dependencies": [
                "typing-extensions==4.15.0"
            ],
            "dependency_authorized": False,
        },
        12,
    )
    expect_error(deps)
    cases.append(
        (
            "E2E-014",
            "PASS dependency bootstrap authorization gate",
        )
    )

    moving = call_tool(
        "run_python_quality_gate_from_github",
        {
            "owner": "EFHC-Project",
            "repo": "code-efhc",
            "commit_sha": "main",
            "tools": ["ruff"],
            "dependency_mode": "none",
        },
        13,
    )
    expect_error(moving)
    cases.append(
        (
            "E2E-015",
            "PASS moving GitHub ref rejected",
        )
    )

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
            14,
        )
    )
    assert github["intake"]["source_commit"] == (  # nosec B101
        EXACT_GITHUB_COMMIT
    ), github
    assert github["intake"]["targets"], github  # nosec B101
    assert github["intake"]["files"], github  # nosec B101
    cases.append(
        (
            "E2E-016",
            "PASS exact GitHub target/provenance route",
        )
    )

    for case, result in cases:
        print(f"{case} {result}")
    print(
        f"E2E SUMMARY {len(cases)}/{len(cases)} PASS"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
