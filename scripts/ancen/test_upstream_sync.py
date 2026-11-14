# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Exercise synchronization decisions without contacting GitHub or changing Git."""

import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import upstream_sync


class UpstreamSyncTests(unittest.TestCase):
    def exercise(self, *, incorporated=False, duplicate=False, conflict=False):
        calls = []
        state = json.dumps({"version": "v1.0.0", "commit": "old", "repository": "makeplane/plane"})

        def run(*args, **kwargs):
            calls.append(args)
            output, code = "", 0
            if args[:3] == ("gh", "api", "repos/makeplane/plane/releases/latest"):
                output = json.dumps({"tag_name": "v1.1.0", "body": "Security fixes"})
            elif args[:2] == ("git", "rev-parse"):
                output = "a" * 40
            elif args[:2] == ("git", "merge-base"):
                code = 0 if incorporated else 1
            elif args[:3] == ("gh", "pr", "list"):
                output = "[{\"number\": 1}]" if duplicate else "[]"
            elif args[:2] == ("git", "ls-remote"):
                code = 2
            elif args[:3] == ("git", "merge", "--no-commit"):
                code = int(conflict)
            elif args[:2] == ("git", "diff"):
                output = "apps/api/plane/authentication/oidc.py\n"
            return SimpleNamespace(stdout=output, returncode=code)

        with (
            patch.dict(upstream_sync.os.environ, {"GITHUB_REPOSITORY": "VeguiDev/plane"}),
            patch.object(upstream_sync, "run", side_effect=run),
            patch.object(upstream_sync.Path, "read_text", return_value=state),
            patch.object(upstream_sync.Path, "write_text") as write,
        ):
            upstream_sync.main()
        return calls, write

    def test_no_downgrade(self):
        calls, write = self.exercise(incorporated=True)
        self.assertFalse(any(args[:2] == ("git", "push") for args in calls))
        write.assert_not_called()

    def test_no_duplicate_or_branch_overwrite(self):
        calls, write = self.exercise(duplicate=True)
        self.assertFalse(any(args[:2] == ("git", "switch") for args in calls))
        write.assert_not_called()

    def test_clean_merge_dispatches_ci_and_draft_pr_without_force(self):
        calls, write = self.exercise()
        self.assertTrue(any(args[:3] == ("gh", "workflow", "run") for args in calls))
        self.assertTrue(any(args[:3] == ("gh", "pr", "create") and "--draft" in args for args in calls))
        self.assertFalse(any("--force" in arg for args in calls for arg in args))
        state = json.loads(write.call_args.args[0])
        self.assertEqual(state["version"], "v1.1.0")

    def test_conflicts_only_report_and_never_mark_version_integrated(self):
        calls, write = self.exercise(conflict=True)
        self.assertIn(("git", "merge", "--abort"), calls)
        self.assertIn("No upstream code has been integrated", write.call_args.args[0])
        self.assertEqual(write.call_count, 1)


if __name__ == "__main__":
    unittest.main()
