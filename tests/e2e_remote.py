from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("CODE_EFHC_RUNTIME_URL", "https://code-efhc-quality-gate-production.up.railway.app")
MCP = BASE.rstrip("/") + "/mcp"
EXACT_GITHUB_COMMIT = "7c727a07da2b18aff09bcb3a6bc0c07143654c6c"


def request_json(url: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"} if payload is not None else {})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise AssertionError(f"HTTP {exc.code} from {url}: {raw}") from exc
    return json.loads(raw)


def call_tool(name: str, arguments: dict, call_id: int) -> dict:
    return request_json(MCP, {
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })


def tool_result(response: dict) -> dict:
    assert "error" not in response, response
    return response["result"]["structuredContent"]


def expect_error(response: dict, code: int = -32602) -> None:
    assert response.get("error", {}).get("code") == code, response


def one_inline(files: list[dict], tools: list[str], call_id: int, **extra) -> dict:
    args = {"files": files, "tools": tools, "dependency_mode": "none"}
    args.update(extra)
    return call_tool("run_python_quality_gate_inline", args, call_id)


def main() -> int:
    cases: list[tuple[str, str]] = []

    health = request_json(BASE.rstrip("/") + "/health")
    assert health["status"] == "ok", health
    assert health["runtime"] == "0.2.0", health
    cases.append(("E2E-001", "PASS health runtime 0.2.0"))

    tools = request_json(MCP, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    names = {x["name"] for x in tools["result"]["tools"]}
    required = {
        "run_python_quality_gate",
        "run_python_quality_gate_from_github",
        "run_python_quality_gate_inline",
    }
    assert required <= names, names
    cases.append(("E2E-002", "PASS MCP tool discovery"))

    clean = tool_result(one_inline(
        [{"path": "a.py", "content": "def add(a: int, b: int) -> int:\n    return a + b\n"}],
        ["flake8", "ruff", "mypy", "bandit"],
        2,
    ))
    assert clean["status"] == "PASS", clean
    per_tool = {r["tool"]: r["status"] for r in clean["results"]}
    assert per_tool == {"flake8": "PASS", "ruff": "PASS", "mypy": "PASS", "bandit": "PASS"}, per_tool
    cases.append(("E2E-003", "PASS all four real checkers"))

    flake8 = tool_result(one_inline([{"path": "a.py", "content": "import os\n"}], ["flake8"], 3))
    assert flake8["status"] == "FAIL_FINDINGS", flake8
    assert any(f.get("code") == "F401" for f in flake8["findings"]), flake8
    cases.append(("E2E-004", "PASS Flake8 negative F401"))

    ruff = tool_result(one_inline([{"path": "a.py", "content": "import os\n"}], ["ruff"], 4))
    assert ruff["status"] == "FAIL_FINDINGS", ruff
    assert any(f.get("code") == "F401" for f in ruff["findings"]), ruff
    cases.append(("E2E-005", "PASS Ruff negative F401"))

    mypy = tool_result(one_inline(
        [{"path": "a.py", "content": 'def bad() -> int:\n    return "x"\n'}],
        ["mypy"],
        5,
    ))
    assert mypy["status"] == "FAIL_FINDINGS", mypy
    assert any(f.get("code") == "return-value" for f in mypy["findings"]), mypy
    cases.append(("E2E-006", "PASS mypy negative return-value"))

    bandit = tool_result(one_inline(
        [{"path": "a.py", "content": 'import subprocess\n\nsubprocess.Popen("echo hi", shell=True)\n'}],
        ["bandit"],
        6,
    ))
    assert bandit["status"] == "FAIL_FINDINGS", bandit
    assert any((f.get("code") or "").startswith("B6") for f in bandit["findings"]), bandit
    cases.append(("E2E-007", "PASS Bandit security finding"))

    traversal = one_inline([{"path": "../evil.py", "content": "x = 1\n"}], ["ruff"], 7)
    expect_error(traversal)
    cases.append(("E2E-008", "PASS traversal rejected"))

    mypy_plugin = tool_result(one_inline(
        [
            {"path": "a.py", "content": "x: int = 1\n"},
            {"path": "mypy.ini", "content": "[mypy]\nplugins = evil.py\n"},
        ],
        ["mypy"],
        8,
    ))
    assert mypy_plugin["status"] == "FAIL_CONFIG", mypy_plugin
    assert mypy_plugin["results"][0]["status"] == "CONFIG_ERROR", mypy_plugin
    assert "blocked executable mypy plugin" in mypy_plugin["results"][0]["stderr"], mypy_plugin
    cases.append(("E2E-009", "PASS mypy executable plugin blocked"))

    flake8_plugin = tool_result(one_inline(
        [
            {"path": "a.py", "content": "x = 1\n"},
            {"path": ".flake8", "content": "[flake8:local-plugins]\nextension = X = evil:Plugin\n"},
        ],
        ["flake8"],
        9,
    ))
    assert flake8_plugin["status"] == "FAIL_CONFIG", flake8_plugin
    assert flake8_plugin["results"][0]["status"] == "CONFIG_ERROR", flake8_plugin
    cases.append(("E2E-010", "PASS Flake8 local plugin blocked"))

    deps = call_tool("run_python_quality_gate_inline", {
        "files": [{"path": "a.py", "content": "x = 1\n"}],
        "tools": ["mypy"],
        "dependency_mode": "isolated",
        "dependencies": ["typing-extensions==4.15.0"],
        "dependency_authorized": False,
    }, 10)
    expect_error(deps)
    cases.append(("E2E-011", "PASS unauthorized dependency bootstrap rejected"))

    moving = call_tool("run_python_quality_gate_from_github", {
        "owner": "EFHC-Project",
        "repo": "code-efhc",
        "commit_sha": "main",
        "tools": ["ruff"],
        "dependency_mode": "none",
    }, 11)
    expect_error(moving)
    cases.append(("E2E-012", "PASS moving GitHub ref rejected"))

    github = tool_result(call_tool("run_python_quality_gate_from_github", {
        "owner": "EFHC-Project",
        "repo": "code-efhc",
        "commit_sha": EXACT_GITHUB_COMMIT,
        "tools": ["ruff"],
        "dependency_mode": "none",
    }, 12))
    assert github["intake"]["source_commit"] == EXACT_GITHUB_COMMIT, github
    assert github["results"][0]["tool"] == "ruff", github
    assert github["results"][0]["status"] in {"PASS", "FINDINGS", "CONFIG_ERROR"}, github
    cases.append(("E2E-013", f"PASS exact GitHub commit echoed; Ruff={github['results'][0]['status']}"))

    for case, result in cases:
        print(f"{case} {result}")
    print(f"E2E SUMMARY {len(cases)}/{len(cases)} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
