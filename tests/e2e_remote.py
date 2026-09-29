# CODE EFHC remote E2E harness.
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get(
    "CODE_EFHC_RUNTIME_URL",
    "https://code-efhc-quality-gate-production.up.railway.app",
)
MCP = BASE.rstrip("/") + "/mcp"
EXACT_GITHUB_COMMIT = "7c727a07da2b18aff09bcb3a6bc0c07143654c6c"


def request_json(url: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"} if payload is not None else {}
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
    assert "error" not in response, response
    return response["result"]["structuredContent"]


def expect_error(response: dict, code: int = -32602) -> None:
    assert response.get("error", {}).get("code") == code, response


def one_inline(
    files: list[dict],
    tools: list[str],
    call_id: int,
    **extra,
) -> dict:
    args = {"files": files, "tools": tools, "dependency_mode": "none"}
    args.update(extra)
    return call_tool("run_python_quality_gate_inline", args, call_id)


def main() -> int:
    cases: list[tuple[str, str]] = []

    health = request_json(BASE.rstrip("/") + "/health")
    assert health["status"] == "ok", health
    cases.append(("E2E-001", "PASS health"))

    tools = request_json(
        MCP,
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    tool_map = {x["name"]: x for x in tools["result"]["tools"]}
    required = {
        "run_python_quality_gate",
        "run_python_quality_gate_from_github",
        "run_python_quality_gate_inline",
    }
    assert required <= set(tool_map), set(tool_map)
    inline_schema = tool_map["run_python_quality_gate_inline"]["inputSchema"]
    assert "targets" in inline_schema["properties"], inline_schema
    cases.append(("E2E-002", "PASS MCP discovery + targets schema"))

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
    assert clean["status"] == "PASS", clean
    per_tool = {r["tool"]: r["status"] for r in clean["results"]}
    assert per_tool == {
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
    assert scoped["status"] == "PASS", scoped
    assert not scoped["findings"], scoped
    cases.append(("E2E-004", "PASS context excluded from scanner targets"))

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
    assert mypy_context["status"] == "PASS", mypy_context
    assert mypy_context["results"][0]["status"] == "PASS", mypy_context
    cases.append(("E2E-005", "PASS mypy minimal import context"))

    missing_target = one_inline(
        [{"path": "changed.py", "content": "x = 1\n"}],
        ["ruff"],
        5,
        targets=["missing.py"],
    )
    expect_error(missing_target)
    assert "quality-gate target was not supplied" in missing_target["error"]["message"]
    cases.append(("E2E-006", "PASS missing target rejected"))

    non_python_target = one_inline(
        [
            {"path": "changed.py", "content": "x = 1\n"},
            {"path": "pyproject.toml", "content": "[tool.ruff]\n"},
        ],
        ["ruff"],
        6,
        targets=["pyproject.toml"],
    )
    expect_error(non_python_target)
    assert "target is not Python" in non_python_target["error"]["message"]
    cases.append(("E2E-007", "PASS non-Python target rejected"))

    negative = tool_result(
        one_inline(
            [{"path": "a.py", "content": "import os\n"}],
            ["flake8", "ruff"],
            7,
            targets=["a.py"],
        )
    )
    assert negative["status"] == "FAIL_FINDINGS", negative
    codes = {(f["tool"], f.get("code")) for f in negative["findings"]}
    assert ("flake8", "F401") in codes, negative
    assert ("ruff", "F401") in codes, negative
    assert {
        f["path"]
        for f in negative["findings"]
        if f.get("code") == "F401"
    } == {"a.py"}, negative
    cases.append((
        "E2E-008",
        "PASS targeted F401 + project-relative evidence paths",
    ))

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
            8,
            targets=["a.py"],
        )
    )
    assert mypy_plugin["status"] == "FAIL_CONFIG", mypy_plugin
    assert mypy_plugin["results"][0]["status"] == "CONFIG_ERROR", mypy_plugin
    assert "blocked executable mypy plugin" in mypy_plugin["results"][0]["stderr"]
    cases.append(("E2E-009", "PASS mypy executable plugin blocked"))

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
        9,
    )
    expect_error(deps)
    cases.append(("E2E-010", "PASS unauthorized dependency bootstrap rejected"))

    moving = call_tool(
        "run_python_quality_gate_from_github",
        {
            "owner": "EFHC-Project",
            "repo": "code-efhc",
            "commit_sha": "main",
            "tools": ["ruff"],
            "dependency_mode": "none",
        },
        10,
    )
    expect_error(moving)
    cases.append(("E2E-011", "PASS moving GitHub ref rejected"))

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
            11,
        )
    )
    assert github["intake"]["source_commit"] == EXACT_GITHUB_COMMIT, github
    assert github["results"][0]["tool"] == "ruff", github
    assert github["results"][0]["status"] in {
        "PASS",
        "FINDINGS",
        "CONFIG_ERROR",
    }, github
    cases.append(
        (
            "E2E-012",
            f"PASS exact GitHub commit; Ruff={github['results'][0]['status']}",
        )
    )

    for case, result in cases:
        print(f"{case} {result}")
    print(f"E2E SUMMARY {len(cases)}/{len(cases)} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
