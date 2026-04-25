"""
Scout — static analysis agent.

Runs Semgrep on any supported file and Bandit on Python files, in parallel.
Emits deduplicated ``Finding`` objects with stable ids.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from pathlib import Path

from langchain_core.runnables import RunnableConfig

from guardianloop.config import Config
from guardianloop.logging_setup import get_agent_logger
from guardianloop.state import Finding, Language, PipelineState, Severity, Tool

SEMGREP_CONFIG = "p/default"

_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "INFO",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "CRITICAL": "CRITICAL",
}


def _detect_language(path: Path) -> Language:
    ext = path.suffix.lower()
    if ext == ".py":
        return "python"
    if ext in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}:
        return "cpp"
    return "unknown"


def _make_id(tool: Tool, rule: str, file_path: str, line_start: int) -> str:
    key = f"{tool}:{rule}:{file_path}:{line_start}".encode()
    return hashlib.sha1(key).hexdigest()[:12]


def _snippet(file_path: Path, line_start: int, line_end: int) -> str:
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(0, line_start - 1)
    end = min(len(lines), max(start + 1, line_end))
    return "\n".join(lines[start:end])


def _extract_cwe(s: str) -> str | None:
    m = re.search(r"CWE-\d+", s)
    return m.group(0) if m else None


def _normalize_severity(s: str) -> Severity:
    return _SEVERITY_MAP.get(s.upper(), "INFO")


async def _run_semgrep(source: Path, timeout: int, language: Language) -> list[Finding]:
    proc = await asyncio.create_subprocess_exec(
        "semgrep",
        "scan",
        f"--config={SEMGREP_CONFIG}",
        "--json",
        "--quiet",
        "--metrics=off",
        str(source),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return []
    try:
        data = json.loads(stdout_b.decode("utf-8", errors="replace") or "{}")
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for r in data.get("results", []):
        start_line = int(r.get("start", {}).get("line", 0) or 0)
        end_line = int(r.get("end", {}).get("line", start_line) or start_line)
        rule_id = r.get("check_id", "unknown")
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        cwe_raw = meta.get("cwe")
        cwe_id: str | None = None
        if isinstance(cwe_raw, list) and cwe_raw:
            cwe_id = _extract_cwe(str(cwe_raw[0]))
        elif isinstance(cwe_raw, str):
            cwe_id = _extract_cwe(cwe_raw)
        severity = _normalize_severity(str(extra.get("severity") or "INFO"))
        findings.append(
            Finding(
                id=_make_id("semgrep", rule_id, str(source), start_line),
                tool="semgrep",
                rule_id=rule_id,
                cwe_id=cwe_id,
                message=extra.get("message") or rule_id,
                severity=severity,
                file_path=str(source),
                line_start=start_line,
                line_end=end_line,
                snippet=_snippet(source, start_line, end_line),
                language=language,
            )
        )
    return findings


async def _run_bandit(source: Path, timeout: int) -> list[Finding]:
    proc = await asyncio.create_subprocess_exec(
        "bandit",
        "-f",
        "json",
        "-q",
        str(source),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return []
    try:
        data = json.loads(stdout_b.decode("utf-8", errors="replace") or "{}")
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for r in data.get("results", []):
        rule_id = r.get("test_id", "unknown")
        line_start = int(r.get("line_number", 0) or 0)
        line_end = line_start
        cwe_id: str | None = None
        issue_cwe = r.get("issue_cwe")
        if isinstance(issue_cwe, dict) and issue_cwe.get("id") is not None:
            cwe_id = f"CWE-{issue_cwe['id']}"
        severity = _normalize_severity(str(r.get("issue_severity") or "LOW"))
        findings.append(
            Finding(
                id=_make_id("bandit", rule_id, str(source), line_start),
                tool="bandit",
                rule_id=rule_id,
                cwe_id=cwe_id,
                message=r.get("issue_text") or rule_id,
                severity=severity,
                file_path=str(source),
                line_start=line_start,
                line_end=line_end,
                snippet=_snippet(source, line_start, line_end),
                language="python",
            )
        )
    return findings


async def scout_node(state: PipelineState, config: RunnableConfig) -> dict:
    gl: Config = config["configurable"]["gl_config"]
    logger = get_agent_logger(state.run_dir, "scout")

    source = state.source_file
    language = _detect_language(source)
    logger.info("scout.start", file=str(source), language=language)

    tasks = [_run_semgrep(source, gl.scout_timeout_seconds, language)]
    if language == "python":
        tasks.append(_run_bandit(source, gl.scout_timeout_seconds))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings: list[Finding] = []
    for r in results:
        if isinstance(r, Exception):
            logger.warning("scout.tool_error", error=str(r))
        else:
            findings.extend(r)

    seen: set[str] = set()
    deduped: list[Finding] = []
    for f in findings:
        if f.id in seen:
            continue
        seen.add(f.id)
        deduped.append(f)

    logger.info("scout.done", findings=len(deduped))
    return {"findings": deduped, "language": language, "status": "classifying"}
