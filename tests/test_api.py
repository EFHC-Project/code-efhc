import hashlib
import unittest

from fastapi.testclient import TestClient

from app.server import app


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.c = TestClient(app)

    def test_health(self):
        body = self.c.get("/health").json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["runtime"], "0.2.3")

    def test_mcp_schema_matches_targeted_contract(self):
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
            item["name"]: item
            for item in r.json()["result"]["tools"]
        }
        self.assertIn("run_python_quality_gate", tools)
        self.assertIn("run_python_quality_gate_from_github", tools)
        self.assertIn("run_python_quality_gate_inline", tools)
        self.assertIn("compare_python_quality_gate", tools)
        self.assertEqual(
            tools["run_python_quality_gate"]["_meta"]["openai/fileParams"],
            ["files"],
        )

        inline = tools["run_python_quality_gate_inline"]["inputSchema"]
        self.assertIn("targets", inline["properties"])
        self.assertIn("targets", inline["required"])
        inline_file = inline["properties"]["files"]["items"]
        self.assertIn("mode", inline_file["properties"])

        compare = tools["compare_python_quality_gate"]["inputSchema"]
        for key in (
            "baseline_files",
            "candidate_files",
            "baseline_targets",
            "candidate_targets",
        ):
            self.assertIn(key, compare["properties"])
            self.assertIn(key, compare["required"])

    def test_target_context_config_provenance(self):
        target = "x = 1\n"
        config = "[tool.ruff]\nline-length = 88\n"
        r = self.c.post(
            "/v1/quality-gate",
            json={
                "files": [
                    {"path": "pkg/a.py", "content": target},
                    {
                        "path": "pkg/context.py",
                        "content": "VALUE = 1\n",
                    },
                    {
                        "path": "pyproject.toml",
                        "content": config,
                    },
                ],
                "targets": ["pkg/a.py"],
                "tools": ["ruff"],
            },
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["runtime_version"], "0.2.3")
        self.assertEqual(body["intake"]["targets"], ["pkg/a.py"])
        evidence = {
            item["path"]: item
            for item in body["intake"]["files"]
        }
        self.assertEqual(evidence["pkg/a.py"]["role"], "target")
        self.assertEqual(evidence["pkg/context.py"]["role"], "context")
        self.assertEqual(
            evidence["pyproject.toml"]["role"],
            "config",
        )
        self.assertEqual(
            evidence["pkg/a.py"]["sha256"],
            hashlib.sha256(target.encode()).hexdigest(),
        )
        self.assertIsNotNone(body["intake"]["config_identity"])

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
                item["tool"]: item["status"]
                for item in body["results"]
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
        self.assertEqual(body["results"][0]["status"], "PASS")

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

    def test_ruff_exe001_suppressed_when_mode_unknown(self):
        source = "#!/usr/bin/env python3\nvalue = 1\n"
        r = self.c.post(
            "/v1/quality-gate",
            json={
                "files": [{"path": "script.py", "content": source}],
                "targets": ["script.py"],
                "tools": ["ruff"],
            },
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "PASS")
        result = body["results"][0]
        self.assertGreaterEqual(result["suppressed_findings"], 1)
        self.assertNotIn(
            "EXE001",
            {item["code"] for item in body["findings"]},
        )
        self.assertEqual(
            body["intake"]["files"][0]["mode_provenance"],
            "unknown",
        )

    def test_ruff_exe001_retained_when_nonexec_mode_known(self):
        source = "#!/usr/bin/env python3\nvalue = 1\n"
        r = self.c.post(
            "/v1/quality-gate",
            json={
                "files": [
                    {
                        "path": "script.py",
                        "content": source,
                        "mode": 420,
                    }
                ],
                "targets": ["script.py"],
                "tools": ["ruff"],
            },
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "FAIL_FINDINGS")
        self.assertIn(
            "EXE001",
            {item["code"] for item in body["findings"]},
        )
        self.assertEqual(
            body["intake"]["files"][0]["mode_provenance"],
            "supplied",
        )

    def test_compare_is_compact_and_multiset_aware(self):
        r = self.c.post(
            "/v1/quality-gate/compare",
            json={
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
            },
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "FAIL_INTRODUCED")
        self.assertEqual(
            body["summary"],
            {
                "baseline": 2,
                "candidate": 2,
                "introduced": 1,
                "resolved": 1,
                "pre_existing": 1,
            },
        )
        self.assertEqual(body["findings"], [])

    def test_compare_can_return_classified_findings(self):
        r = self.c.post(
            "/v1/quality-gate/compare",
            json={
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
                "include_findings": True,
            },
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(
            {item["classification"] for item in body["findings"]},
            {"INTRODUCED", "RESOLVED", "PRE_EXISTING"},
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
                                "content": "x = 1\n",
                            }
                        ],
                        "targets": ["a.py"],
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
        self.assertEqual(r.json()["error"]["code"], -32602)


if __name__ == "__main__":
    unittest.main()
