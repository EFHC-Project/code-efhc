import io
import stat
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from app.intake import (
    _extract_zip,
    _prepare_dependencies,
    _project_root,
    uploaded_workspace,
)
from app.models import UploadedCheckRequest
from app.security import InputRejected


def make_zip(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return out.getvalue()


def make_tar(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
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


class UploadedWorkspaceTests(unittest.TestCase):
    def test_accepts_opaque_host_id_and_autodetects_zip(self):
        req = UploadedCheckRequest(
            files=[
                {
                    "download_url": "https://files.example.test/blob",
                    "file_id": "opaque-host-ref-123",
                    "file_name": "project.bin",
                    "mime_type": "application/octet-stream",
                }
            ],
            tools=["ruff"],
        )
        data = make_zip([("project/a.py", b"x = 1\n")])
        with patch("app.intake._download_limited", return_value=data):
            with uploaded_workspace(req) as prepared:
                self.assertEqual(
                    prepared.intake.source_kind,
                    "uploaded",
                )
                self.assertEqual(
                    prepared.intake.source_identity,
                    "opaque-host-ref-123",
                )
                self.assertEqual(prepared.intake.file_count, 1)
                self.assertTrue((prepared.root / "a.py").is_file())

    def test_autodetects_tar_without_archive_extension(self):
        req = UploadedCheckRequest(
            files=[
                {
                    "download_url": "https://files.example.test/blob",
                    "file_id": "opaque-host-ref-456",
                    "file_name": "project.data",
                    "mime_type": "application/octet-stream",
                }
            ],
            tools=["ruff"],
        )
        data = make_tar([("project/a.py", b"x = 1\n")])
        with patch("app.intake._download_limited", return_value=data):
            with uploaded_workspace(req) as prepared:
                self.assertEqual(prepared.intake.file_count, 1)
                self.assertTrue((prepared.root / "a.py").is_file())

    def test_accepts_multiple_uploaded_plain_files(self):
        req = UploadedCheckRequest(
            files=[
                {
                    "download_url": "https://files.example.test/a",
                    "file_id": "opaque-a",
                    "file_name": "a.py",
                },
                {
                    "download_url": "https://files.example.test/b",
                    "file_id": "opaque-b",
                    "file_name": "b.py",
                },
            ],
            tools=["ruff"],
        )
        with patch(
            "app.intake._download_limited",
            side_effect=[b"x = 1\n", b"y = 2\n"],
        ):
            with uploaded_workspace(req) as prepared:
                self.assertEqual(prepared.intake.file_count, 2)
                self.assertEqual(
                    prepared.intake.source_identity,
                    "opaque-a,opaque-b",
                )

    def test_rejects_malformed_archive_hint(self):
        req = UploadedCheckRequest(
            files=[
                {
                    "download_url": "https://files.example.test/broken",
                    "file_id": "opaque-broken",
                    "file_name": "broken.zip",
                    "mime_type": "application/zip",
                }
            ],
            tools=["ruff"],
        )
        with patch(
            "app.intake._download_limited",
            return_value=b"not-a-zip",
        ):
            with self.assertRaisesRegex(
                InputRejected,
                "invalid or unsupported archive",
            ):
                with uploaded_workspace(req):
                    pass


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
