"""
Day 3 ingress: a GitHub PR URL.

Not implemented yet. Will fetch the PR's changed files via the GitHub API,
write each to ``runs/<ts>/pr/<n>/<path>``, and return a list of paths. The
webhook server (`webhook/app.py`) will call this for inbound PR events.
"""

from __future__ import annotations

from pathlib import Path


def ingest_github_pr(pr_url: str, run_dir: Path, github_token: str | None = None) -> list[Path]:
    """DAY 3 — not yet implemented.

    Signature is frozen so `webhook/app.py` can import it.
    Outbound patch-PR creation is explicitly out of scope (see CLAUDE.md).
    """
    raise NotImplementedError(
        "ingress.github_pr.ingest_github_pr is a Day 3 deliverable — see CLAUDE.md for scope."
    )
