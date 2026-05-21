"""
FastAPI app: Mission Control dashboard + scan API.

Read-only routes:
  GET  /                       → redirect to /dashboard/
  GET  /dashboard/             → index.html
  GET  /api/runs               → list all completed runs
  GET  /api/runs/{id}          → full summary + report markdown
  GET  /api/runs/{id}/logs     → structured log lines for live view
  GET  /healthz                → liveness

Scan submission routes (each returns {run_id} immediately; pipeline runs in bg):
  POST /api/scan/demo          → run built-in demo file
  POST /api/scan/upload        → multipart file upload
  POST /api/scan/paste         → JSON {code, filename?}
  POST /api/scan/pr            → JSON {url, token?}
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from guardianloop.config import load_config
from guardianloop.graph import build_graph, make_run_dir
from guardianloop.ingress.local import SUPPORTED_EXTENSIONS
from guardianloop.ingress.paste import ingest_paste
from guardianloop.ingress.upload import ingest_upload
from guardianloop.logging_setup import get_agent_logger
from guardianloop.state import PipelineState

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "ui" / "dashboard"

app = FastAPI(title="GuardianLoop Web", version="0.1.0")

# ---------- helpers ----------

def _runs_root() -> Path:
    cfg = load_config()
    return Path(cfg.runs_dir).expanduser().resolve()


def _safe_read_json(path: Path) -> dict | list | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _summarize_run(run_dir: Path) -> dict | None:
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

    source_raw = summary.get("source_file") or summary.get("source") or run_dir.name
    # Show only the filename, not the full absolute path
    source = Path(source_raw).name if source_raw else run_dir.name
    language = summary.get("language") or "unknown"
    started_at = summary.get("started_at") or summary.get("start") or ""

    # Compute duration from log timestamps if not stored in summary
    duration = int(summary.get("duration_seconds") or summary.get("duration") or 0)
    if duration == 0:
        try:
            from datetime import timezone
            all_ts: list[datetime] = []
            for log_file in run_dir.glob("*.log"):
                for raw in log_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    try:
                        entry = json.loads(raw.strip())
                        ts = entry.get("timestamp", "")
                        if ts:
                            all_ts.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
                    except Exception:
                        pass
            if len(all_ts) >= 2:
                duration = max(1, int((max(all_ts) - min(all_ts)).total_seconds()))
        except Exception:
            pass

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


def _validate_run_id(run_id: str) -> None:
    if "/" in run_id or "\\" in run_id or run_id in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid run id.")


async def _run_pipeline_async(source_path: Path, run_dir: Path) -> None:
    """Pipeline coroutine — runs inside a dedicated per-scan event loop (see _kick)."""
    import traceback as tb_mod
    cfg = load_config()
    logger = get_agent_logger(run_dir, "web")
    logger.info("pipeline.start", source=str(source_path), run_dir=str(run_dir))
    try:
        initial = PipelineState(source_file=source_path, run_dir=run_dir)
        graph = build_graph()
        final = await graph.ainvoke(
            initial,
            config={"configurable": {"gl_config": cfg}, "recursion_limit": 50},
        )
        status = (
            final.get("status") if isinstance(final, dict) else getattr(final, "status", "unknown")
        )
        logger.info("pipeline.done", status=status)
    except Exception as exc:
        logger.error(
            "pipeline.error",
            error=repr(exc),
            traceback=tb_mod.format_exc(),
        )


def _kick(source_path: Path, run_dir: Path) -> None:
    """Spin up a daemon thread with its own ProactorEventLoop so subprocess works on Windows."""
    # Resolve to absolute paths now, before the thread starts, so CWD is never ambiguous.
    abs_source = source_path.resolve()
    abs_run = run_dir.resolve()

    def _thread() -> None:
        asyncio.run(_run_pipeline_async(abs_source, abs_run))

    t = threading.Thread(target=_thread, daemon=True, name=f"pipeline-{abs_run.name}")
    t.start()


# ---------- read-only API ----------

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
    _validate_run_id(run_id)
    run_dir = _runs_root() / run_id
    if not run_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"No run {run_id!r}.")
    summary = _safe_read_json(run_dir / "run_summary.json")
    if summary is None:
        raise HTTPException(status_code=404, detail="run_summary.json missing or not yet written.")

    enriched = _safe_read_json(run_dir / "enriched_findings.json") or []
    verifications = _safe_read_json(run_dir / "verifications.json") or []
    patches = _safe_read_json(run_dir / "patches.json") or []
    report_md = ""
    try:
        rp = run_dir / "report.md"
        if rp.exists():
            report_md = rp.read_text(encoding="utf-8")
    except OSError:
        pass

    return {
        "id": run_id,
        "summary": summary,
        "enriched_findings": enriched,
        "verifications": verifications,
        "patches": patches,
        "report_md": report_md,
    }


_LEVEL_MAP = {"info": "info", "warning": "warn", "error": "error", "debug": "debug"}

# Agent name → pipeline viz index (0-based)
_AGENT_IDX = {"scout": 0, "classifier": 1, "fixer": 2, "red_team": 3, "report": 4}


@app.get("/api/runs/{run_id}/logs")
async def get_run_logs(run_id: str) -> dict:
    """Return structured log lines + active-agent info for the live scan view."""
    _validate_run_id(run_id)
    run_dir = _runs_root() / run_id
    if not run_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"No run {run_id!r}.")

    entries: list[dict] = []
    for log_file in run_dir.glob("*.log"):
        for raw in log_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                entries.append(json.loads(raw))
            except json.JSONDecodeError:
                pass

    entries.sort(key=lambda x: x.get("timestamp", ""))

    # Compute ms offsets from the first log entry
    t0: datetime | None = None
    if entries:
        try:
            t0 = datetime.fromisoformat(entries[0]["timestamp"].replace("Z", "+00:00"))
        except Exception:
            pass

    def _ms(ts: str) -> int:
        if t0 is None or not ts:
            return 0
        try:
            t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return max(0, int((t - t0).total_seconds() * 1000))
        except Exception:
            return 0

    logs: list[dict] = []
    for e in entries:
        agent = e.get("agent", "system")
        level = _LEVEL_MAP.get(e.get("level", "info"), "info")
        event = e.get("event", "")
        # Build a concise message: event + up to 2 extra k=v pairs
        extras = [
            f"{k}={v}"
            for k, v in e.items()
            if k not in {"agent", "level", "event", "timestamp"}
        ]
        msg = "  ".join([event] + extras[:2])
        logs.append({"ms": _ms(e.get("timestamp", "")), "agent": agent, "level": level, "msg": msg})

    events_seen: set[str] = {e.get("event", "") for e in entries}
    is_complete = (
        "report.done" in events_seen
        or (run_dir / "run_summary.json").exists()
    )

    # Walk the pipeline order to find which agent is currently active
    done_markers = {
        0: "scout.done",
        1: "classifier.done",
        2: "fixer.done",
        3: "red_team.done",
        4: "report.done",
    }
    active_agent_idx = 0
    for idx in range(5):
        if done_markers[idx] in events_seen:
            active_agent_idx = idx + 1
        else:
            break

    if is_complete:
        active_agent_idx = -1

    return {"logs": logs, "active_agent_idx": active_agent_idx, "is_complete": is_complete}


# ---------- scan submission ----------

_DEMO_FILE = Path(__file__).resolve().parents[3] / "samples" / "demo_sqli.py"


@app.post("/api/scan/rerun/{run_id}")
async def scan_rerun(run_id: str) -> dict:
    """Re-scan the same source file from an existing run."""
    _validate_run_id(run_id)
    old_run_dir = _runs_root() / run_id
    if not old_run_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"No run {run_id!r}.")
    summary = _safe_read_json(old_run_dir / "run_summary.json")
    if not summary:
        raise HTTPException(status_code=404, detail="Cannot read run summary.")
    source_raw = summary.get("source_file") or ""
    if not source_raw:
        raise HTTPException(status_code=400, detail="Source file path not recorded in summary.")
    source_path = Path(source_raw)
    if not source_path.exists():
        # Fallback: look in the run's own source/ sub-directory
        candidate = old_run_dir / "source" / source_path.name
        if candidate.exists():
            source_path = candidate
        else:
            raise HTTPException(
                status_code=404,
                detail=f"Source file '{source_path.name}' not found on disk.",
            )
    cfg = load_config()
    run_dir = make_run_dir(cfg.runs_dir)
    _kick(source_path, run_dir)
    return {"run_id": run_dir.name}


@app.post("/api/scan/demo")
async def scan_demo() -> dict:
    if not _DEMO_FILE.exists():
        raise HTTPException(status_code=404, detail="Demo file not found.")
    cfg = load_config()
    run_dir = make_run_dir(cfg.runs_dir)
    _kick(_DEMO_FILE, run_dir)
    return {"run_id": run_dir.name}


@app.post("/api/scan/upload")
async def scan_upload(file: UploadFile = File(...)) -> dict:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required.")
    ext = Path(file.filename).suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported extension {ext!r}.")
    data = await file.read()
    if len(data) > 1_048_576:
        raise HTTPException(status_code=413, detail="File too large (max 1 MB).")
    cfg = load_config()
    run_dir = make_run_dir(cfg.runs_dir)
    source_path = ingest_upload(data, file.filename, run_dir)
    _kick(source_path, run_dir)
    return {"run_id": run_dir.name}


class PasteRequest(BaseModel):
    code: str
    filename: str = ""


@app.post("/api/scan/paste")
async def scan_paste(req: PasteRequest) -> dict:
    code = req.code.strip()
    if not code:
        raise HTTPException(status_code=400, detail="Code cannot be empty.")
    cfg = load_config()
    run_dir = make_run_dir(cfg.runs_dir)
    source_path = ingest_paste(code, req.filename, run_dir)
    _kick(source_path, run_dir)
    return {"run_id": run_dir.name}


class PRRequest(BaseModel):
    url: str
    token: str = ""


@app.post("/api/scan/pr")
async def scan_pr(req: PRRequest) -> dict:
    from guardianloop.ingress.github_pr import ingest_github_pr

    token = req.token or os.getenv("GITHUB_TOKEN") or None
    cfg = load_config()
    run_dir = make_run_dir(cfg.runs_dir)
    try:
        paths = await ingest_github_pr(req.url, run_dir, github_token=token)
    except Exception as exc:
        import shutil
        shutil.rmtree(run_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not paths:
        import shutil
        shutil.rmtree(run_dir, ignore_errors=True)
        raise HTTPException(
            status_code=400,
            detail="No supported source files (.py / .cpp) found in this PR.",
        )
    _kick(paths[0], run_dir)
    return {"run_id": run_dir.name}


# ---------- static dashboard (must be last) ----------

if DASHBOARD_DIR.is_dir():
    app.mount("/dashboard", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")
else:
    @app.get("/dashboard/")
    async def _missing_dashboard() -> dict:
        raise HTTPException(
            status_code=500,
            detail=f"Dashboard not found at {DASHBOARD_DIR}.",
        )
