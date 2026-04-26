"""
FastAPI app that serves the Mission Control dashboard + a small read-only API
on top of the runs/ directory.

Routes:
  GET  /                     redirect → /dashboard/
  GET  /dashboard/           index.html
  GET  /dashboard/<asset>    static asset (jsx files, etc.)
  GET  /api/runs             list all runs with a one-line summary each
  GET  /api/runs/{run_id}    full summary + report markdown for a single run
  GET  /healthz              liveness

The dashboard ships with mock data baked in (see data.jsx). The bootstrap
script in the HTML calls /api/runs on load and replaces the mock arrays with
whatever the API returns; if /api/runs is unreachable the demo still renders.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from guardianloop.config import load_config

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "ui" / "dashboard"

app = FastAPI(title="GuardianLoop Web", version="0.1.0")


def _runs_root() -> Path:
    cfg = load_config()
    return Path(cfg.runs_dir).expanduser().resolve()


def _safe_read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _summarize_run(run_dir: Path) -> dict | None:
    """One row for the dashboard table. None if the run has no usable summary yet."""
    summary = _safe_read_json(run_dir / "run_summary.json")
    if not summary:
        return None

    totals = summary.get("totals") or {}
    findings = int(totals.get("findings") or 0)
    patched = int(totals.get("patches_held") or 0)
    failed = int(totals.get("patches_failed") or 0)

    enriched = _safe_read_json(run_dir / "enriched_findings.json") or []
    cwes: list[str] = []
    seen: set[str] = set()
    for ef in enriched if isinstance(enriched, list) else []:
        finding = (ef or {}).get("finding") or {}
        cwe = finding.get("cwe_id")
        if cwe and cwe not in seen:
            seen.add(cwe)
            cwes.append(cwe)

    source = summary.get("source_file") or summary.get("source") or run_dir.name
    language = summary.get("language") or "unknown"
    started_at = summary.get("started_at") or summary.get("start") or ""
    duration = int(summary.get("duration_seconds") or summary.get("duration") or 0)

    if findings == 0:
        status = "complete"
    elif failed > 0 and patched == 0:
        status = "failed"
    else:
        status = "complete"

    return {
        "id": run_dir.name,
        "source": source,
        "language": language,
        "findings": findings,
        "patched": patched,
        "status": status,
        "duration": duration,
        "cwes": cwes,
        "started_at": started_at,
    }


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.get("/")
async def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/dashboard/")


@app.get("/api/runs")
async def list_runs() -> list[dict]:
    root = _runs_root()
    if not root.exists():
        return []
    rows: list[dict] = []
    for child in sorted(root.iterdir(), reverse=True):
        if not child.is_dir():
            continue
        row = _summarize_run(child)
        if row is not None:
            rows.append(row)
    return rows


@app.get("/api/runs/{run_id}")
async def get_run(run_id: str) -> dict:
    if "/" in run_id or "\\" in run_id or run_id in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid run id.")
    run_dir = _runs_root() / run_id
    if not run_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"No run named {run_id!r}.")
    summary = _safe_read_json(run_dir / "run_summary.json")
    if summary is None:
        raise HTTPException(status_code=404, detail="run_summary.json missing or invalid.")

    enriched = _safe_read_json(run_dir / "enriched_findings.json") or []
    verifications = _safe_read_json(run_dir / "verifications.json") or []
    report_path = run_dir / "report.md"
    report_md = ""
    try:
        if report_path.exists():
            report_md = report_path.read_text(encoding="utf-8")
    except OSError:
        report_md = ""

    return {
        "id": run_id,
        "summary": summary,
        "enriched_findings": enriched,
        "verifications": verifications,
        "report_md": report_md,
    }


# Mount the dashboard last so /api and /healthz win the route match.
if DASHBOARD_DIR.is_dir():
    app.mount(
        "/dashboard",
        StaticFiles(directory=str(DASHBOARD_DIR), html=True),
        name="dashboard",
    )
else:
    @app.get("/dashboard/")
    async def _missing_dashboard() -> dict:
        raise HTTPException(
            status_code=500,
            detail=f"Dashboard not found at {DASHBOARD_DIR}. Did the package install miss src/guardianloop/ui/dashboard/?",
        )
