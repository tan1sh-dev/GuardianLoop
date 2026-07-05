"""
Markdown audit report writer.

Per finding, emits exactly three level-2 sections with these headers verbatim
(pedagogical objective from deck slide 8 — do not reword):

    ## What     - CWE, CVE, CVSS, file:line, snippet
    ## Why      - exploitability explanation drawn from Fixer's reasoning chain
    ## How      - patch diff + reasoning chain
"""

from __future__ import annotations

from pathlib import Path

from guardianloop.state import EnrichedFinding, Patch, PipelineState, VerificationResult


def _fence_lang(language: str) -> str:
    return {"python": "python", "cpp": "cpp"}.get(language, "")


def _latest_per_finding(items, iter_attr: str) -> dict:
    latest: dict = {}
    for it in items:
        prev = latest.get(it.finding_id)
        if prev is None or getattr(it, iter_attr) > getattr(prev, iter_attr):
            latest[it.finding_id] = it
    return latest


def _render_status(verif: VerificationResult | None) -> str:
    if verif is None:
        return "no patch verified"
    if verif.exploit_reproduced:
        return "FAILED - exploit still reproduces"
    return "HELD - patch verified"


def _render_what(ef: EnrichedFinding) -> list[str]:
    f = ef.finding
    lines = [
        "## What",
        "",
        f"- **CWE**: {f.cwe_id or 'unknown'}",
        f"- **CVE(s)**: {', '.join(ef.cve_ids) if ef.cve_ids else '-'}",
        f"- **CVSS score**: "
        f"{ef.cvss_score if ef.cvss_score is not None else 'unknown'} "
        f"({ef.cvss_severity or f.severity})",
        f"- **CVSS vector**: `{ef.cvss_vector or '-'}`",
        f"- **Tool / rule**: {f.tool} / `{f.rule_id}`",
        f"- **Location**: `{f.file_path}:{f.line_start}-{f.line_end}`",
        f"- **Enrichment source**: {ef.enrichment_source}",
        "",
        "Snippet:",
        "",
        f"```{_fence_lang(f.language)}",
        f.snippet or "(snippet unavailable)",
        "```",
        "",
    ]
    return lines


def _render_why(ef: EnrichedFinding, patch: Patch | None) -> list[str]:
    lines = ["## Why", ""]
    if ef.exploitability_summary:
        lines.append(ef.exploitability_summary)
        lines.append("")
    if patch and len(patch.reasoning_chain) >= 2:
        lines.append(f"**Fixer analysis (exploit scenario):** {patch.reasoning_chain[1]}")
        lines.append("")
    elif patch and patch.reasoning_chain:
        lines.append(f"**Fixer analysis:** {patch.reasoning_chain[0]}")
        lines.append("")
    if not ef.exploitability_summary and not patch:
        lines.append("_No exploitability summary available._")
        lines.append("")
    return lines


def _render_how(
    ef: EnrichedFinding,
    patch: Patch | None,
    verif: VerificationResult | None,
    skipped: dict | None = None,
) -> list[str]:
    lines = ["## How", ""]
    if patch is None:
        if skipped:
            lines.append(f"_Finding was skipped._")
            lines.append("")
            lines.append(f"**Reason**: {skipped.get('reason', 'Unknown')}")
        else:
            lines.append("_No patch was produced for this finding._")
        lines.append("")
        return lines

    lines.append("**Reasoning chain:**")
    lines.append("")
    for i, step in enumerate(patch.reasoning_chain, 1):
        lines.append(f"{i}. {step}")
    lines.append("")
    lines.append(f"**Patch (iteration {patch.iteration}):**")
    lines.append("")
    lines.append("```diff")
    lines.append(patch.diff or "(diff unavailable)")
    lines.append("```")
    lines.append("")
    if verif is not None:
        lines.append(
            f"**Sandbox verification**: {_render_status(verif)} "
            f"(exit {verif.sandbox_exit_code}, {verif.duration_seconds:.2f}s)."
        )
        lines.append("")
    return lines


def write_markdown_report(state: PipelineState) -> Path:
    run_dir = state.run_dir
    run_dir.mkdir(parents=True, exist_ok=True)
    report_path = run_dir / "report.md"

    latest_patch = _latest_per_finding(state.patches, "iteration")
    latest_verif = _latest_per_finding(state.verification_results, "patch_iteration")

    held = sum(1 for v in latest_verif.values() if not v.exploit_reproduced)
    failed = sum(1 for v in latest_verif.values() if v.exploit_reproduced)
    unpatched = len(state.enriched_findings) - len(latest_verif)

    lines: list[str] = []
    lines.append("# GuardianLoop Audit Report")
    lines.append("")
    lines.append(f"- **Source**: `{state.source_file}`")
    lines.append(f"- **Run directory**: `{state.run_dir}`")
    lines.append(f"- **Language**: {state.language}")
    lines.append(f"- **Findings**: {len(state.enriched_findings)}")
    lines.append(f"- **Iterations run**: {state.loop_count + 1}")
    lines.append(
        f"- **Outcome**: {held} patch(es) held, {failed} still exploitable, "
        f"{unpatched} unpatched"
    )
    lines.append(f"- **Pipeline status**: `{state.status}`")
    lines.append("")

    for i, ef in enumerate(state.enriched_findings, 1):
        f = ef.finding
        patch = latest_patch.get(f.id)
        verif = latest_verif.get(f.id)
        skipped = next((s for s in state.skipped_findings if s.get("finding_id") == f.id), None)

        lines.append("---")
        lines.append("")
        lines.append(
            f"# Finding {i} - {f.cwe_id or 'unknown CWE'} at "
            f"`{f.file_path}:{f.line_start}`"
        )
        lines.append("")
        lines.append(f"**Status**: {_render_status(verif)}")
        lines.append("")
        lines.extend(_render_what(ef))
        lines.extend(_render_why(ef, patch))
        lines.extend(_render_how(ef, patch, verif, skipped))

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path
