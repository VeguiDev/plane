# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Prepare review-only upstream release PRs. Never deploy or force-push."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def run(*args, check=True):
    return subprocess.run(args, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def main():
    repo = os.environ["GITHUB_REPOSITORY"]
    release = json.loads(run("gh", "api", "repos/makeplane/plane/releases/latest").stdout)
    tag = release["tag_name"]
    if release.get("prerelease") or release.get("draft") or not re.fullmatch(r"v\d+\.\d+\.\d+(?:-\d+)?", tag):
        raise SystemExit("No supported stable upstream release")
    state_path = Path(".ancen/upstream.json")
    state = json.loads(state_path.read_text())
    previous_version = state["version"]
    run("git", "fetch", "https://github.com/makeplane/plane.git", f"refs/tags/{tag}")
    upstream = run("git", "rev-parse", "FETCH_HEAD^{commit}").stdout.strip()
    if run("git", "merge-base", "--is-ancestor", upstream, "HEAD", check=False).returncode == 0:
        print("Latest upstream release already incorporated; no downgrade from preview.")
        return
    branch = f"upstream-sync/{tag}"
    if json.loads(
        run("gh", "pr", "list", "--repo", repo, "--head", branch, "--state", "all", "--json", "number").stdout
    ):
        print("Synchronization PR already exists; operator must review it.")
        return
    if run("git", "ls-remote", "--exit-code", "origin", f"refs/heads/{branch}", check=False).returncode == 0:
        raise SystemExit("Remote branch exists; refusing to overwrite it")
    run("git", "config", "user.name", "github-actions[bot]")
    run("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
    run("git", "switch", "-c", branch)
    changed = run("git", "diff", "--name-only", state["commit"], upstream).stdout
    commits = run("git", "log", "--oneline", f"{state['commit']}..{upstream}").stdout
    merged = run("git", "merge", "--no-commit", "--no-ff", upstream, check=False)
    conflicts = ""
    if merged.returncode:
        conflicts = run("git", "diff", "--name-only", "--diff-filter=U").stdout
        run("git", "merge", "--abort")
        if not conflicts:
            raise SystemExit("Merge failed without ordinary conflicts; manual investigation required")
        Path(".ancen/pending-upstream.md").write_text(
            f"# Manual upstream merge required\n\n{tag} ({upstream})\n\nConflicts:\n```\n{conflicts}```\n"
            "No upstream code has been integrated. Resolve on this branch and rerun CI.\n"
        )
    else:
        state.update(channel="release", version=tag, commit=upstream)
        state_path.write_text(json.dumps(state, indent=2) + "\n")
    run("git", "add", "--all")
    run("git", "commit", "-m", f"chore: prepare upstream {tag} for review")
    run("git", "push", "origin", f"HEAD:refs/heads/{branch}")
    body = (
        f"## Upstream\n{state.get('repository')}\n\n"
        f"Previous: {previous_version}\n"
        f"Target: {tag} ({upstream})\n\n{release.get('html_url', '')}\n\n"
        f"## Commits\n```\n{commits[:20000]}\n```\n"
        f"## Files affected\n```\n{changed[:15000]}\n```\n"
        f"## Conflicts\n{conflicts or 'Clean Git merge; semantic compatibility NOT assumed.'}\n\n"
        "## Authentication / migrations / architecture\nMandatory human review of OIDC, authorization, "
        "migration graph and runtime dependencies. No automatic merge or deployment.\n\n"
        "## Checks\nAncen CI explicitly dispatched for this branch; inspect its results before merging. "
        "Conflicted PRs contain a report only, not the upgrade.\n\n"
        "## Changelog\n"
        + str(release.get("body", ""))[:8000]
        + "\n\n## Risks and rollback\nBack up PostgreSQL and object storage before upgrading. "
        "Keep previous image digests. If schema is incompatible, restore the matching backup; "
        "never automatically downgrade PostgreSQL or reverse migrations.\n"
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md") as report:
        report.write(body)
        report.flush()
        run(
            "gh",
            "pr",
            "create",
            "--repo",
            repo,
            "--base",
            "main",
            "--head",
            branch,
            "--title",
            f"chore: upstream {tag}" + (" — conflicts require review" if conflicts else ""),
            "--body-file",
            report.name,
            "--draft",
        )
    # Events made with GITHUB_TOKEN do not trigger ordinary push/PR workflows.
    run("gh", "workflow", "run", "ancen-ci.yml", "--repo", repo, "--ref", branch)


if __name__ == "__main__":
    main()
