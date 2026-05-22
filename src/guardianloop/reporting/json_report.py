"""
JSON artifact writer. Emits:

- findings.json            raw Scout output
- enriched_findings.json   Classifier output (Finding + CVE/CVSS)
- patches.json             all Fixer patches across all iterations
- verifications.json       all Red-Team verifications across all iterations
- run_summary.json         pipeline status + totals (dashboard-friendly)
"""

from __future__ import annotations

import json
from pathlib import Path

from guardianloop.state import PipelineState


def _dump(obj) -> str:
    return json.dumps(obj, indent=2, default=str)


def _latest_per_finding(items, iter_attr: str) -> dict:
    latest: dict = {}
    for it in items:
        prev = latest.get(it.finding_id)
        if prev is None or getattr(it, iter_attr) > getattr(prev, iter_attr):
            latest[it.finding_id] = it
    return latest


def write_json_artifacts(state: PipelineState) -> Path:
    run_dir = state.run_dir
    run_dir.mkdir(parents=True, exist_ok=True)

    (run_dir / "findings.json").write_text(
        _dump([f.model_dump(mode="json") for f in state.findings]),
        encoding="utf-8",
    )
    (run_dir / "enriched_findings.json").write_text(
        _dump([ef.model_dump(mode="json") for ef in state.enriched_findings]),
        encoding="utf-8",
    )
    (run_dir / "patches.json").write_text(
        _dump([p.model_dump(mode="json") for p in state.patches]),
        encoding="utf-8",
    )
    (run_dir / "verifications.json").write_text(
        _dump([v.model_dump(mode="json") for v in state.verification_results]),
        encoding="utf-8",
    )

    final_verif = _latest_per_finding(state.verification_results, "patch_iteration")
    patches_held = sum(1 for v in final_verif.values() if not v.exploit_reproduced)
    patches_failed = sum(1 for v in final_verif.values() if v.exploit_reproduced)

    # Merge in Fixer's token-usage side-channel if it wrote one. Lets the
    # dashboard display API cost without bloating PipelineState.
    fixer_usage: dict = {}
    usage_path = run_dir / "fixer_usage.json"
    if usage_path.exists():
        try:
            fixer_usage = json.loads(usage_path.read_text(encoding="utf-8")) or {}
        except (OSError, json.JSONDecodeError):
            fixer_usage = {}

    summary = {
        "source_file": str(state.source_file),
        "run_dir": str(run_dir),
        "language": state.language,
        "loop_count": state.loop_count,
        "iterations_run": state.loop_count + 1,
        "status": state.status,
        "error": state.error,
        "totals": {
            "findings": len(state.findings),
            "enriched": len(state.enriched_findings),
            "patches": len(state.patches),
            "verifications": len(state.verification_results),
            "patches_held": patches_held,
            "patches_failed": patches_failed,
            "findings_unpatched": len(state.enriched_findings)
            - len(final_verif),
        },
        "fixer_usage": fixer_usage,
    }
    (run_dir / "run_summary.json").write_text(_dump(summary), encoding="utf-8")
    return run_dir / "run_summary.json"
