import unittest

from app.frontend import frontend_workspace
from app.models import FileInput
from app.security import InputRejected


class FrontendWorkspaceTests(unittest.TestCase):
    def test_targets_context_and_config_are_separate(self):
        files = [
            FileInput(
                path="src/changed.ts",
                content="export const value: number = 1;\n",
            ),
            FileInput(
                path="src/context.ts",
                content="export type Value = number;\n",
            ),
            FileInput(
                path="tsconfig.json",
                content='{"compilerOptions":{"strict":true}}\n',
            ),
        ]
        with frontend_workspace(
            files,
            ["src/changed.ts"],
        ) as prepared:
            self.assertEqual(
                prepared.intake.targets,
                ["src/changed.ts"],
            )
            roles = {
                item.path: item.role
                for item in prepared.intake.files
            }
            self.assertEqual(
                roles,
                {
                    "src/changed.ts": "target",
                    "src/context.ts": "context",
                    "tsconfig.json": "config",
                },
            )
            self.assertIsNotNone(
                prepared.intake.config_identity
            )

    def test_rejects_config_as_target(self):
        files = [
            FileInput(
                path="tsconfig.json",
                content="{}\n",
            )
        ]
        with self.assertRaisesRegex(
            InputRejected,
            "frontend target is not source code",
        ):
            with frontend_workspace(
                files,
                ["tsconfig.json"],
            ):
                pass

    def test_rejects_unsupplied_target(self):
        files = [
            FileInput(
                path="src/context.ts",
                content="export const x = 1;\n",
            )
        ]
        with self.assertRaisesRegex(
            InputRejected,
            "frontend target was not supplied",
        ):
            with frontend_workspace(
                files,
                ["src/changed.ts"],
            ):
                pass


if __name__ == "__main__":
    unittest.main()
