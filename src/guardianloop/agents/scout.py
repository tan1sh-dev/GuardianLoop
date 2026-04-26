"""
Scout — static analysis agent.

Runs Semgrep on any supported file and Bandit on Python files, in parallel.
Emits ``Finding`` objects with stable ids and explicit (file, line) dedup.

Semgrep strategy (in priority order):
  1. ``--config <rules/>``  — project-local YAML rules; tried first every time.
  2. Regex fallback         — if Semgrep exits with an error (e.g. semgrep-core
                              unavailable on Windows), the same local YAML files
                              are re-read and their patterns are applied as
                              Python regexes.  Works for all simple patterns.
  3. ``--config auto``      — only attempted when rules/ ran cleanly but returned
                              zero findings; skipped when Semgrep errored.

On Windows (sys.platform == 'win32') every Semgrep subprocess is launched with
PYTHONUTF8=1 to prevent the cp1252 codec crash on Unicode stderr output.

If Semgrep or Bandit is not installed, the tool is skipped with a warning and
the scan completes with whatever the other tool found.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
from pathlib import Path

import yaml
from langchain_core.runnables import RunnableConfig

from guardianloop.config import Config
from guardianloop.logging_setup import get_agent_logger
from guardianloop.state import Finding, Language, PipelineState, Severity, Tool

# Absolute path to the project-local Semgrep rules directory.
# Resolved from this module's location so it works regardless of CWD.
_RULES_DIR = str(Path(__file__).resolve().parents[3] / "rules")

_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "INFO",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "CRITICAL": "CRITICAL",
}

# Fallback CWE mapping for Bandit test ids whose `issue_cwe` field can be absent
# in older versions.
_BANDIT_CWE_FALLBACK: dict[str, str] = {
    "B102": "CWE-78",
    "B301": "CWE-502",
    "B303": "CWE-327",
    "B304": "CWE-327",
    "B305": "CWE-327",
    "B306": "CWE-377",
    "B307": "CWE-78",
    "B324": "CWE-327",
    "B501": "CWE-295",
    "B506": "CWE-20",
    "B602": "CWE-78",
    "B603": "CWE-78",
    "B605": "CWE-78",
    "B608": "CWE-89",
    "B609": "CWE-78",
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


def _subprocess_env() -> dict[str, str] | None:
    """Return a modified env dict on Windows to prevent cp1252 codec crashes."""
    if sys.platform != "win32":
        return None
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    return env


def _parse_semgrep_json(stdout_b: bytes, source: Path, language: Language) -> list[Finding] | None:
    """
    Parse Semgrep JSON output.

    Returns:
        list[Finding]  — parsed results (may be empty).
        None           — stdout is not valid JSON (indicates a semgrep error).
    """
    text = stdout_b.decode("utf-8", errors="replace").strip()
    if not text or not text.startswith("{"):
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None

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
        if cwe_id is None:
            cwe_id = _extract_cwe(rule_id)

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


def _semgrep_pattern_to_regex(pattern: str) -> str | None:
    """
    Convert a simple Semgrep pattern to a Python regex string.

    Handles metavariable patterns such as ``func($A, $B)`` and
    ``$X += $Y``.  Returns None for ellipsis-based patterns (``...``)
    which require full AST matching and can't be approximated with regex.
    """
    if "..." in pattern:
        return None
    esc = re.escape(pattern)
    # re.escape in Python 3.7+ produces \$VARNAME for $VARNAME.
    # Replace each such escaped metavar with a non-greedy group that stops
    # at comma, closing paren, or newline — conservative enough for our rules.
    result = re.sub(r"\\\$[A-Za-z_][A-Za-z0-9_]*", r"[^,)\\n]+", esc)
    return result


def _scan_with_local_rules(source: Path, language: Language) -> list[Finding]:
    """
    Pure-Python regex scanner using the project's local YAML rule files.

    Invoked when the Semgrep binary fails (e.g. semgrep-core unavailable on
    Windows).  Converts simple ``pattern:`` entries to Python regexes and
    scans the source file line by line.  Ellipsis-based patterns are skipped.
    """
    rules_path = Path(_RULES_DIR)
    if not rules_path.exists():
        return []

    try:
        source_lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    findings: list[Finding] = []
    seen_ids: set[str] = set()

    for yaml_file in sorted(rules_path.glob("*.yaml")):
        try:
            with yaml_file.open(encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            continue

        for rule in data.get("rules", []):
            rule_languages = [lang.lower() for lang in (rule.get("languages") or [])]
            if language not in rule_languages:
                continue

            rule_id = rule.get("id", yaml_file.stem)
            meta = rule.get("metadata") or {}
            cwe_raw = meta.get("cwe")
            cwe_id = _extract_cwe(str(cwe_raw)) if cwe_raw else None
            severity = _normalize_severity(rule.get("severity", "INFO"))
            message = (rule.get("message") or rule_id).strip()

            # Collect every simple pattern from this rule.
            raw_patterns: list[str] = []
            if "pattern" in rule:
                raw_patterns.append(str(rule["pattern"]))
            for p_entry in rule.get("patterns", []):
                if isinstance(p_entry, dict) and "pattern" in p_entry:
                    raw_patterns.append(str(p_entry["pattern"]))

            compiled: list[re.Pattern] = []
            for raw in raw_patterns:
                regex_str = _semgrep_pattern_to_regex(raw)
                if regex_str is None:
                    continue
                try:
                    compiled.append(re.compile(regex_str))
                except re.error:
                    pass

            if not compiled:
                continue

            for i, line in enumerate(source_lines, start=1):
                if any(rx.search(line) for rx in compiled):
                    fid = _make_id("semgrep", rule_id, str(source), i)
                    if fid in seen_ids:
                        continue
                    seen_ids.add(fid)
                    findings.append(
                        Finding(
                            id=fid,
                            tool="semgrep",
                            rule_id=rule_id,
                            cwe_id=cwe_id,
                            message=message,
                            severity=severity,
                            file_path=str(source),
                            line_start=i,
                            line_end=i,
                            snippet=_snippet(source, i, i),
                            language=language,
                        )
                    )

    return findings


async def _run_semgrep(
    source: Path,
    timeout: int,
    config: str,
    language: Language,
    logger,
) -> list[Finding] | None:
    """
    Run ``semgrep scan --config <config>`` and parse results.

    Returns:
        ``None``       — binary not found OR semgrep exited with an error
                         (non-zero rc + no valid JSON).  Caller should NOT
                         attempt further registry configs; use regex fallback.
        ``[]``         — binary ran cleanly but produced no findings.
        list[Finding]  — one or more findings.

    ``--metrics=off`` is omitted for ``auto`` because Semgrep requires
    metrics enabled for the auto registry resolver.
    """
    cmd = ["semgrep", "scan", f"--config={config}", "--json", "--quiet"]
    if config != "auto":
        cmd.append("--metrics=off")
    cmd.append(str(source))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_subprocess_env(),
        )
    except FileNotFoundError:
        logger.warning("scout.semgrep_not_installed")
        return None

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.warning("scout.semgrep_timeout", config=config, timeout=timeout)
        return None  # Treat timeout as failure so regex fallback is used.

    rc = proc.returncode
    parsed = _parse_semgrep_json(stdout_b, source, language)

    if parsed is None:
        # stdout is not valid JSON — Semgrep had an internal error.
        if rc != 0:
            logger.warning(
                "scout.semgrep_error_exit",
                config=config,
                rc=rc,
                stderr=stderr_b.decode("utf-8", errors="replace")[:400],
            )
            return None  # Signal failure to caller.
        # rc == 0 but no JSON is unusual; treat as empty rather than error.
        logger.warning("scout.semgrep_no_json", config=config)
        return []

    logger.info(
        "scout.semgrep_config_done",
        config=config,
        findings=len(parsed),
    )
    return parsed


async def _run_semgrep_with_fallback(
    source: Path,
    timeout: int,
    language: Language,
    logger,
) -> list[Finding]:
    """
    Semgrep with three-tier fallback.

    1. Local rules/ via Semgrep binary.
    2. Pure-Python regex scan of local rules/ (when Semgrep binary errors).
    3. ``--config auto`` (only when local rules/ ran cleanly but found nothing).
    """
    primary = await _run_semgrep(source, timeout, _RULES_DIR, language, logger)

    if primary is None:
        # Semgrep binary failed — fall back to in-process regex scan.
        logger.info(
            "scout.semgrep_failed_using_regex_fallback",
            rules_dir=_RULES_DIR,
        )
        return _scan_with_local_rules(source, language)

    if primary:
        return primary

    # Local rules/ ran cleanly but found nothing — try the auto registry.
    logger.info("scout.semgrep_rules_no_hits_trying_auto", source=str(source))
    secondary = await _run_semgrep(source, timeout, "auto", language, logger)
    return secondary if secondary is not None else []


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
            stderr=stderr_b.decode("utf-8", errors="replace")[:400],
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

    Semgrep wins on shared lines because its rule YAML carries richer CWE
    metadata.  Within a single tool, exact-id duplicates are also dropped.
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

    semgrep_task = _run_semgrep_with_fallback(
        source, gl.scout_timeout_seconds, language, logger
    )
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
        (semgrep_results,) = await asyncio.gather(semgrep_task, return_exceptions=True)
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
