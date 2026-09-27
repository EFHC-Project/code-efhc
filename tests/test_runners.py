import tempfile
import unittest
from pathlib import Path

from app.runners import _unsafe_config


class RunnerGuardTests(unittest.TestCase):
    def test_blocks_mypy_plugins(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "mypy.ini").write_text("[mypy]\nplugins = project_plugin.py\n", encoding="utf-8")
            self.assertIn("blocked executable mypy plugin", _unsafe_config(root, "mypy"))

    def test_blocks_flake8_local_plugins(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".flake8").write_text("[flake8:local-plugins]\nextension = X = pkg:Plugin\n", encoding="utf-8")
            self.assertIn("blocked Flake8 local-plugins", _unsafe_config(root, "flake8"))


if __name__ == "__main__":
    unittest.main()
