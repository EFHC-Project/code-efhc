import io
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from app.intake import _extract_zip, _prepare_dependencies, _project_root
from app.security import InputRejected


def make_zip(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return out.getvalue()


class IntakeTests(unittest.TestCase):
    def test_extracts_relevant_and_skips_binary(self):
        data = make_zip([("project/a.py", b"x=1\n"), ("project/logo.png", b"PNG")])
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            count, total, skipped = _extract_zip(data, root)
            self.assertEqual(count, 1)
            self.assertEqual(total, 4)
            self.assertEqual(skipped, 1)
            self.assertEqual(_project_root(root).name, "project")

    def test_rejects_traversal(self):
        data = make_zip([("../evil.py", b"x=1")])
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(InputRejected):
                _extract_zip(data, Path(td))

    def test_rejects_zip_symlink(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as zf:
            info = zipfile.ZipInfo("link.py")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "target.py")
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(InputRejected):
                _extract_zip(out.getvalue(), Path(td))

    def test_archive_size_limit_counts_skipped_binary_entries(self):
        data = make_zip([("project/logo.png", b"01234567890")])
        with tempfile.TemporaryDirectory() as td, patch("app.intake.MAX_EXTRACTED_BYTES", 10):
            with self.assertRaises(InputRejected):
                _extract_zip(data, Path(td))


class DependencyIsolationTests(unittest.TestCase):
    def test_isolated_mode_uses_wheel_only_no_deps_target(self):
        class Proc:
            returncode = 0
            stdout = "ok"
            stderr = ""

        with tempfile.TemporaryDirectory() as td, patch("app.intake.subprocess.run", return_value=Proc()) as run:
            target, pins = _prepare_dependencies(Path(td), "isolated", ["typing-extensions==4.15.0"], True)
            self.assertEqual(pins, ["typing-extensions==4.15.0"])
            cmd = run.call_args.args[0]
            self.assertIn("--only-binary=:all:", cmd)
            self.assertIn("--no-deps", cmd)
            self.assertIn("--target", cmd)
            self.assertTrue(target.endswith("deps"))


if __name__ == "__main__":
    unittest.main()
