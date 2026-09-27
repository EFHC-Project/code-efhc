import unittest
from fastapi.testclient import TestClient

from app.server import app


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.c = TestClient(app)

    def test_health(self):
        body = self.c.get("/health").json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["runtime"], "0.2.0")

    def test_mcp_lists_file_and_github_tools(self):
        r = self.c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(r.status_code, 200)
        tools = {x["name"]: x for x in r.json()["result"]["tools"]}
        self.assertIn("run_python_quality_gate", tools)
        self.assertIn("run_python_quality_gate_from_github", tools)
        self.assertEqual(tools["run_python_quality_gate"]["_meta"]["openai/fileParams"], ["files"])
        file_def = tools["run_python_quality_gate"]["inputSchema"]["$defs"]["OpenAIFile"]
        self.assertEqual(file_def["required"], ["download_url", "file_id"])
        self.assertEqual(set(file_def["properties"]), {"download_url", "file_id", "mime_type", "file_name"})

    def test_quality_gate_contract(self):
        r = self.c.post("/v1/quality-gate", json={"files": [{"path": "a.py", "content": "x=1\n"}], "tools": ["ruff"]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()["results"]), 1)
        self.assertEqual(r.json()["intake"]["source_kind"], "inline")

    def test_mcp_rejects_isolated_deps_without_authorization(self):
        r = self.c.post("/mcp", json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "run_python_quality_gate_inline", "arguments": {
                "files": [{"path": "a.py", "content": "x=1\n"}],
                "tools": ["mypy"],
                "dependency_mode": "isolated",
                "dependencies": ["types-requests==2.32.4.20250913"],
                "dependency_authorized": False
            }}
        })
        self.assertIn("error", r.json())
        self.assertEqual(r.json()["error"]["code"], -32602)


if __name__ == "__main__":
    unittest.main()
