# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import io
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from ensure_candidate_unused import ensure_unused


class CandidatePublicationTests(unittest.TestCase):
    def test_only_missing_tags_allow_publication(self):
        def lookup(request, timeout):
            if isinstance(request, str):
                return io.BytesIO(b'{"token":"test-public-read-token"}')
            raise HTTPError(request.full_url, 404, "missing", {}, None)

        with patch("ensure_candidate_unused.urlopen", side_effect=lookup) as request:
            ensure_unused("0.1.0-rc.2", "a" * 40)
        self.assertEqual(request.call_count, 30)

    def test_existing_version_cannot_be_overwritten(self):
        with patch(
            "ensure_candidate_unused.urlopen",
            side_effect=[
                io.BytesIO(b'{"token":"test-public-read-token"}'),
                io.BytesIO(b""),
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "overwrite"):
                ensure_unused("0.1.0-rc.1", "a" * 40)

    def test_lookup_failure_is_not_treated_as_missing(self):
        with patch(
            "ensure_candidate_unused.urlopen",
            side_effect=[
                io.BytesIO(b'{"token":"test-public-read-token"}'),
                HTTPError("https://ghcr.io/test", 403, "forbidden", {}, None),
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "lookup failed"):
                ensure_unused("0.1.0-rc.2", "a" * 40)

    def test_stable_and_invalid_commit_rejected(self):
        for version, commit in [("0.1.0", "a" * 40), ("0.1.0-rc.2", "short")]:
            with self.assertRaises(RuntimeError):
                ensure_unused(version, commit)
