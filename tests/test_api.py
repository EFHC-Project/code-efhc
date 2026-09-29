import unittest

from fastapi.testclient import TestClient

from app.server import app


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.c = TestClient(app)

    def test_health(self):
        body = self.c.get("/health").json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["runtime"], "0.2.2")

    def test_mcp_lists_file_and_github_tools(self):
        r = self.c.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
            },
        )
        self.assertEqual(r.status_code, 200)
        tools = {
            x["name"]: x
            for x in r.json()["result"]["tools"]
        }
        self.assertIn("run_python_quality_gate", tools)
        self.assertIn("run_python_quality_gate_from_github", tools)
        self.assertEqual(
            tools["run_python_quality_gate"]["_meta"]["openai/fileParams"],
            ["files"],
        )
        file_def = tools["run_python_quality_gate"]["inputSchema"]["$defs"][
            "OpenAIFile"
        ]
        self.assertEqual(
            file_def["required"],
            ["download_url", "file_id"],
        )
        self.assertEqual(
            set(file_def["properties"]),
            {"download_url", "file_id", "mime_type", "file_name"},
        )
        inline_schema = tools["run_python_quality_gate_inline"][
            "inputSchema"
        ]["properties"]
        self.assertIn("targets", inline_schema)

    def test_quality_gate_contract(self):
        r = self.c.post(
            "/v1/quality-gate",
            json={
                "files": [{"path": "a.py", "content": "x=1\n"}],
                "tools": ["ruff"],
            },
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()["results"]), 1)
        self.assertEqual(
            r.json()["intake"]["source_kind"],
            "inline",
        )

    def test_inline_targets_limit_checker_scope(self):
        r = self.c.post(
            "/v1/quality-gate",
            json={
                "files": [
                    {"path": "changed.py", "content": "x = 1\n"},
                    {"path": "context.py", "content": "import os\n"},
                ],
                "targets": ["changed.py"],
                "tools": ["flake8", "ruff", "bandit"],
            },
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "PASS")
        self.assertEqual(
            {
                x["tool"]: x["status"]
                for x in body["results"]
            },
            {
                "flake8": "PASS",
                "ruff": "PASS",
                "bandit": "PASS",
            },
        )

    def test_inline_mypy_uses_minimal_context(self):
        r = self.c.post(
            "/v1/quality-gate",
            json={
                "files": [
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
                "targets": ["pkg/changed.py"],
                "tools": ["mypy"],
            },
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "PASS")
        self.assertEqual(
            body["results"][0]["status"],
            "PASS",
        )

    def test_inline_rejects_target_not_supplied(self):
        r = self.c.post(
            "/v1/quality-gate",
            json={
                "files": [
                    {
                        "path": "changed.py",
                        "content": "x = 1\n",
                    }
                ],
                "targets": ["missing.py"],
                "tools": ["ruff"],
            },
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn(
            "quality-gate target was not supplied",
            r.json()["detail"],
        )

    def test_finding_paths_are_project_relative(self):
        r = self.c.post(
            "/v1/quality-gate",
            json={
                "files": [
                    {
                        "path": "pkg/bad.py",
                        "content": "import os\n",
                    }
                ],
                "targets": ["pkg/bad.py"],
                "tools": ["ruff"],
            },
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "FAIL_FINDINGS")
        self.assertTrue(body["findings"])
        self.assertEqual(
            {item["path"] for item in body["findings"]},
            {"pkg/bad.py"},
        )

    def test_mcp_rejects_isolated_deps_without_authorization(self):
        r = self.c.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "run_python_quality_gate_inline",
                    "arguments": {
                        "files": [
                            {
                                "path": "a.py",
                                "content": "x=1\n",
                            }
                        ],
                        "tools": ["mypy"],
                        "dependency_mode": "isolated",
                        "dependencies": [
                            "types-requests==2.32.4.20250913"
                        ],
                        "dependency_authorized": False,
                    },
                },
            },
        )
        self.assertIn("error", r.json())
        self.assertEqual(
            r.json()["error"]["code"],
            -32602,
        )


if __name__ == "__main__":
    unittest.main()
