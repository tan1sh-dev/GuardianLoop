"""
Scout — static analysis agent.

Runs Semgrep on any supported file and Bandit on Python files, in parallel.
Emits ``Finding`` objects with stable ids and explicit (file, line) dedup.

Semgrep rule pack is language-aware:
    * .cpp / .c / .cc / .cxx / .h / .hh / .hpp  →  ``p/cpp``
    * .py                                       →  ``p/python``

If Semgrep or Bandit is not installed (FileNotFoundError on exec), the
respective tool is skipped with a warning and the scan still completes.
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

# Semgrep registry packs, picked per-language so we don't pay for irrelevant rules.
_SEMGREP_PACKS: dict[Language, str] = {
    "cpp": "p/cpp",
    "python": "p/python",
}

_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "INFO",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "CRITICAL": "CRITICAL",
}

# Fallback CWE mapping for Bandit test ids that don't expose `issue_cwe`
# in older bandit versions or community plugins. Extend as needed.
_BANDIT_CWE_FALLBACK: dict[str, str] = {
    "B102": "CWE-78",   # exec_used
    "B301": "CWE-502",  # pickle
    "B303": "CWE-327",  # MD5/SHA1
    "B304": "CWE-327",  # weak ciphers
    "B305": "CWE-327",  # weak cipher modes
    "B306": "CWE-377",  # mktemp_q
    "B307": "CWE-78",   # eval
    "B324": "CWE-327",  # hashlib insecure
    "B501": "CWE-295",  # request without verify
    "B506": "CWE-20",   # yaml_load
    "B602": "CWE-78",   # subprocess shell=True
    "B603": "CWE-78",   # subprocess without shell
    "B605": "CWE-78",   # start_process_with_a_shell
    "B608": "CWE-89",   # SQL injection
    "B609": "CWE-78",   # linux commands wildcard
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


async def _run_semgrep(
    source: Path,
    timeout: int,
    language: Language,
    logger,
) -> list[Finding]:
    pack = _SEMGREP_PACKS.get(language)
    if pack is None:
        logger.info("scout.semgrep_skip_unsupported_language", language=language)
        return []

    try:
        proc = await asyncio.create_subprocess_exec(
            "semgrep",
            "scan",
            f"--config={pack}",
            "--json",
            "--quiet",
            "--metrics=off",
            str(source),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        logger.warning("scout.semgrep_not_installed")
        return []

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.warning("scout.semgrep_timeout", timeout=timeout)
        return []

    try:
        data = json.loads(stdout_b.decode("utf-8", errors="replace") or "{}")
    except json.JSONDecodeError:
        logger.warning(
            "scout.semgrep_bad_json",
            stderr=stderr_b.decode("utf-8", errors="replace")[:500],
        )
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
        # Some rules embed CWE in the rule id itself (e.g. "test.cwe121.foo").
        if cwe_id is None:
            cwe_id = _extract_cwe(rule_id) or _extract_cwe(str(rule_id).upper())
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


async def _run_bandit(source: Path, timeout: int, logger) -> list[Finding]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "bandit",
            "-f",
            "json",
            "-q",
            str(source),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        logger.warning("scout.bandit_not_installed")
        return []

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.warning("scout.bandit_timeout", timeout=timeout)
        return []

    try:
        data = json.loads(stdout_b.decode("utf-8", errors="replace") or "{}")
    except json.JSONDecodeError:
        logger.warning(
            "scout.bandit_bad_json",
            stderr=stderr_b.decode("utf-8", errors="replace")[:500],
        )
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
        elif rule_id in _BANDIT_CWE_FALLBACK:
            cwe_id = _BANDIT_CWE_FALLBACK[rule_id]
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


def _dedupe(semgrep: list[Finding], bandit: list[Finding]) -> list[Finding]:
    """
    Merge Semgrep + Bandit findings, deduplicated by (file_path, line_start).

    Semgrep wins on shared lines because its rule packs carry richer CWE
    metadata. Within a single tool we still drop exact-id duplicates.
    """
    seen_lines: set[tuple[str, int]] = set()
    seen_ids: set[str] = set()
    merged: list[Finding] = []

    for f in semgrep:
        if f.id in seen_ids:
            continue
        seen_ids.add(f.id)
        seen_lines.add((f.file_path, f.line_start))
        merged.append(f)

    for f in bandit:
        if f.id in seen_ids:
            continue
        if (f.file_path, f.line_start) in seen_lines:
            # Same line already covered by Semgrep — drop the duplicate.
            continue
        seen_ids.add(f.id)
        seen_lines.add((f.file_path, f.line_start))
        merged.append(f)

    return merged


async def scout_node(state: PipelineState, config: RunnableConfig) -> dict:
    gl: Config = config["configurable"]["gl_config"]
    logger = get_agent_logger(state.run_dir, "scout")

    source = state.source_file
    language = _detect_language(source)
    logger.info("scout.start", file=str(source), language=language)

    semgrep_task = _run_semgrep(source, gl.scout_timeout_seconds, language, logger)
    bandit_task = (
        _run_bandit(source, gl.scout_timeout_seconds, logger)
        if language == "python"
        else None
    )

    if bandit_task is not None:
        semgrep_results, bandit_results = await asyncio.gather(
            semgrep_task, bandit_task, return_exceptions=True
        )
    else:
        semgrep_results = await asyncio.gather(semgrep_task, return_exceptions=True)
        semgrep_results = semgrep_results[0]
        bandit_results = []

    if isinstance(semgrep_results, Exception):
        logger.warning("scout.semgrep_error", error=str(semgrep_results))
        semgrep_results = []
    if isinstance(bandit_results, Exception):
        logger.warning("scout.bandit_error", error=str(bandit_results))
        bandit_results = []

    deduped = _dedupe(semgrep_results, bandit_results)

    logger.info(
        "scout.done",
        findings=len(deduped),
        semgrep=len(semgrep_results),
        bandit=len(bandit_results),
    )
    return {"findings": deduped, "language": language, "status": "classifying"}
