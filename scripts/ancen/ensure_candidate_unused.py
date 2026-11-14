#!/usr/bin/env python3
# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Fail closed before publishing: never reuse a candidate version or commit tag."""

import json
import os
import re
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def ensure_unused(version, commit):
    if not re.fullmatch(r"\d+\.\d+\.\d+-[a-z0-9][a-z0-9.-]*", version):
        raise RuntimeError("Only a versioned prerelease can use the candidate pipeline")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError("Expected full immutable source commit")
    for component in ("frontend", "admin", "space", "live", "backend", "proxy"):
        repository = f"veguidev/plane-{component}"
        query = urlencode({"service": "ghcr.io", "scope": f"repository:{repository}:pull"})
        with urlopen(f"https://ghcr.io/token?{query}", timeout=30) as response:
            token = json.load(response)["token"]
        for tag in (
            version,
            f"sha-{commit}",
            f"sha-{commit}-amd64",
            f"sha-{commit}-arm64",
        ):
            request = Request(
                f"https://ghcr.io/v2/{repository}/manifests/{tag}",
                method="HEAD",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": (
                        "application/vnd.oci.image.index.v1+json, "
                        "application/vnd.docker.distribution.manifest.list.v2+json"
                    ),
                },
            )
            try:
                with urlopen(request, timeout=30):
                    pass
            except HTTPError as error:
                if error.code == 404:
                    continue
                raise RuntimeError("Registry lookup failed; refusing publication") from None
            raise RuntimeError(f"Refusing to overwrite published reference: {repository}:{tag}")


if __name__ == "__main__":
    with open(".ancen/version") as source:
        ensure_unused(source.read().strip(), os.environ["GITHUB_SHA"])
