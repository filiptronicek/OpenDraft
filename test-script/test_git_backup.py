"""Focused tests for deployment-owned remote Git backup.

Run from the project root:
    venv/bin/python test-script/test_git_backup.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from dulwich.client import SendPackResult  # noqa: E402

from app.services.git_backup_service import (  # noqa: E402
    GitBackupConfig,
    GitBackupConfigError,
    backup_ref,
    push_project,
)


class GitBackupTests(unittest.TestCase):
    def make_config(self, root: Path, **overrides) -> tuple[GitBackupConfig, str]:
        token = "top-secret-gitea-token"
        token_file = root / "gitea-token"
        token_file.write_text(token, encoding="utf-8")
        values = {
            "enabled": True,
            "remote_url": "https://gitea.example.test/film/opendraft-backups.git",
            "username": "opendraft",
            "token_file": token_file,
            "ref_prefix": "opendraft",
            "ca_bundle": None,
        }
        values.update(overrides)
        return GitBackupConfig(**values), token

    def test_disabled_backup_is_a_noop(self):
        config = GitBackupConfig(False, "", "", None)
        result = push_project(Path("/unused"), "user", "film", config=config)
        self.assertEqual(result["status"], "disabled")

    def test_requires_https_and_credential_free_url(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for url in (
                "http://gitea.example.test/backup.git",
                "https://user:secret@gitea.example.test/backup.git",
            ):
                config, _ = self.make_config(root, remote_url=url)
                with self.assertRaises(GitBackupConfigError):
                    config.validate()

    def test_invalid_enabled_value_is_rejected(self):
        with patch.dict(
            os.environ,
            {"OPENDRAFT_GIT_BACKUP_ENABLED": "tru"},
            clear=True,
        ):
            with self.assertRaises(GitBackupConfigError):
                GitBackupConfig.from_env()

    def test_enabled_value_is_trimmed_and_case_insensitive(self):
        with patch.dict(
            os.environ,
            {"OPENDRAFT_GIT_BACKUP_ENABLED": " True "},
            clear=True,
        ):
            self.assertTrue(GitBackupConfig.from_env().enabled)

    def test_ref_is_scoped_by_user_and_project(self):
        config = GitBackupConfig(False, "", "", None)
        one = backup_ref(config, "user-a", "my-film")
        two = backup_ref(config, "user-b", "my-film")
        self.assertEqual(one, "refs/heads/opendraft/user-a/my-film")
        self.assertNotEqual(one, two)
        self.assertIn("-", backup_ref(config, "user@example.com", "Café Film"))

    def test_push_passes_secret_separately_and_never_forces(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config, token = self.make_config(root)
            expected_ref = "refs/heads/opendraft/user-1/my-film"
            result = SendPackResult({}, ref_status={expected_ref.encode(): None})

            with patch(
                "app.services.git_backup_service.porcelain.push",
                return_value=result,
            ) as mocked:
                status = push_project(root, "user-1", "my-film", config=config)

            self.assertEqual(status["status"], "succeeded")
            args, kwargs = mocked.call_args
            self.assertEqual(args[1], config.remote_url)
            self.assertNotIn(token, args[1])
            self.assertEqual(kwargs["password"], token)
            self.assertFalse(kwargs["force"])
            self.assertEqual(kwargs["refspecs"], [f"HEAD:{expected_ref}"])

    def test_remote_rejection_preserves_success_and_redacts_token(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config, token = self.make_config(root)
            ref = "refs/heads/opendraft/user-1/my-film"
            rejected = SendPackResult(
                {}, ref_status={ref.encode(): f"denied {token}"}
            )

            with patch(
                "app.services.git_backup_service.porcelain.push",
                return_value=rejected,
            ):
                with self.assertLogs(
                    "app.services.git_backup_service", "WARNING"
                ) as logs:
                    status = push_project(
                        root, "user-1", "my-film", config=config
                    )

            self.assertEqual(status["status"], "failed")
            self.assertNotIn(token, status["message"] or "")
            self.assertNotIn(token, "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
