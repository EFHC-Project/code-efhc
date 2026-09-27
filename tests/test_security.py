import unittest
from unittest.mock import patch

from app.security import (
    DependencyRejected,
    InputRejected,
    validate_dependencies,
    validate_github_ref,
    validate_https_public_url,
    validate_path,
)


class SecurityTests(unittest.TestCase):
    def test_accept_py(self):
        self.assertEqual(validate_path("src/a.py"), "src/a.py")

    def test_reject_traversal(self):
        with self.assertRaises(InputRejected):
            validate_path("../x.py")

    def test_reject_env(self):
        with self.assertRaises(InputRejected):
            validate_path(".env")

    def test_reject_binary(self):
        with self.assertRaises(InputRejected):
            validate_path("x.bin")

    def test_exact_github_commit_required(self):
        with self.assertRaises(InputRejected):
            validate_github_ref("openai", "repo", "main")

    def test_dependency_authorization_required(self):
        with self.assertRaises(DependencyRejected):
            validate_dependencies("isolated", ["types-requests==2.32.4.20250913"], False)

    def test_dependency_url_rejected(self):
        with self.assertRaises(DependencyRejected):
            validate_dependencies("isolated", ["pkg @ https://example.com/pkg.whl"], True)

    @patch("app.security.socket.getaddrinfo")
    def test_private_download_target_rejected(self, ga):
        ga.return_value = [(2, 1, 6, "", ("127.0.0.1", 443))]
        with self.assertRaises(InputRejected):
            validate_https_public_url("https://example.test/file.zip")


if __name__ == "__main__":
    unittest.main()
