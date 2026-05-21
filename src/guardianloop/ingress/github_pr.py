"""
Ingress: a GitHub PR URL.

Fetches the PR's changed source files via the GitHub REST API, writes each to
run_dir/pr_source/<basename>, and returns the list of saved paths.

Public repos work without a token (60 req/hr limit). Set GITHUB_TOKEN in .env
for private repos or to raise the limit to 5000 req/hr.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx

from guardianloop.ingress.local import SUPPORTED_EXTENSIONS

_PR_RE = re.compile(r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)")


async def ingest_github_pr(
    pr_url: str,
    run_dir: Path,
    github_token: str | None = None,
) -> list[Path]:
    m = _PR_RE.match(pr_url.strip())
    if not m:
        raise ValueError(f"Not a valid GitHub PR URL: {pr_url!r}")

    owner, repo, pr_num = m.group(1), m.group(2), m.group(3)
    api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_num}/files"

    headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(api_url, headers=headers)
        if r.status_code == 404:
            raise ValueError(f"PR not found (check the URL and repo visibility): {pr_url}")
        if r.status_code == 403:
            raise ValueError(
                "GitHub API rate limit exceeded. Set GITHUB_TOKEN in .env for private repos."
            )
        r.raise_for_status()
        files = r.json()

    source_dir = run_dir / "pr_source"
    source_dir.mkdir(parents=True, exist_ok=True)

    saved: list[Path] = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        for f in files:
            filename: str = f.get("filename", "")
            ext = Path(filename).suffix.lower()
            if ext not in SUPPORTED_EXTENSIONS:
                continue
            raw_url: str = f.get("raw_url", "")
            if not raw_url:
                continue
            resp = await client.get(raw_url, headers=headers)
            if resp.status_code != 200:
                continue
            dest = source_dir / Path(filename).name
            counter = 0
            while dest.exists():
                counter += 1
                dest = source_dir / f"{Path(filename).stem}_{counter}{ext}"
            dest.write_bytes(resp.content)
            saved.append(dest)

    return saved
