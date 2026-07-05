"""
Scout — static analysis agent.

Runs Semgrep (p/default ruleset) via WSL Ubuntu on any supported file.
WSL is required because the Semgrep pip package ships a Linux ELF binary
that cannot run natively on Windows.  The WSL call is a transparent
subprocess — from the pipeline's perspective it behaves identically to a
native Semgrep invocation.

On non-Windows platforms (Linux CI) the agent calls semgrep directly without
WSL.

Semgrep strategy:
  1. ``--config p/default``  — Semgrep's curated security ruleset (~400 rules).
     Runs offline after the first download; cached in ~/.semgrep inside WSL.
  2. No custom rules, no regex fallback, no Bandit.  The purpose of this agent
     is real AST-based analysis, not pattern matching.

If Semgrep is not installed in WSL (or WSL is unavailable), the node logs a
warning and returns an empty findings list so the pipeline can continue.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

from langchain_core.runnables import RunnableConfig

from guardianloop.config import Config
from guardianloop.logging_setup import get_agent_logger
from guardianloop.state import Finding, Language, PipelineState, RelatedFinding, Severity, Tool

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


def _win_to_wsl_path(path: Path) -> str:
    """Convert a Windows absolute path to a WSL /mnt/<drive>/... path."""
    resolved = path.resolve()
    drive = resolved.drive.rstrip(":").lower()  # e.g. "e"
    rest = resolved.as_posix().lstrip("/").split("/", 1)
    # as_posix() on Windows gives "E:/foo/bar" → parts after drive = "foo/bar"
    tail = resolved.as_posix()[len(resolved.drive):].lstrip("/")
    return f"/mnt/{drive}/{tail}"


def _semgrep_cmd(source: Path, token: str | None) -> list[str]:
    """
    Build the semgrep command appropriate for the current platform.

    When ``token`` is provided (SEMGREP_APP_TOKEN), we use ``--config auto``
    which selects the full registry ruleset for the detected language —
    including C/C++ rules that are not in the unauthenticated community tier.
    Without a token we fall back to ``p/default`` (Python, JS, and other
    languages are covered; C/C++ coverage is limited).

    On Windows we run semgrep inside WSL Ubuntu.  pip-installed semgrep lands
    in ``~/.local/bin`` which is not on the default WSL PATH, so we invoke
    bash with an explicit PATH prefix.  On Linux/macOS we call semgrep directly.
    """
    # Always run the project's custom rules/ alongside the registry.
    # --config auto requires metrics enabled (sends file-type metadata to Semgrep).
    # --config p/default is fully offline and works without authentication.
    _RULES_DIR = str(Path(__file__).resolve().parents[3] / "rules")

    if token:
        registry_config = "auto"
        metrics_flag: list[str] = []
        token_export = f"export SEMGREP_APP_TOKEN='{token}' && "
    else:
        registry_config = "p/default"
        metrics_flag = ["--metrics=off"]
        token_export = ""

    if sys.platform == "win32":
        wsl_path = _win_to_wsl_path(source)
        wsl_rules = _win_to_wsl_path(Path(_RULES_DIR))
        metrics_part = " ".join(metrics_flag)
        inner = (
            f"export PATH=\"$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\" && "
            f"{token_export}"
            f"semgrep scan "
            f"--config {registry_config} --config '{wsl_rules}' "
            f"--json --quiet {metrics_part} '{wsl_path}'"
        )
        return ["wsl", "-d", "Ubuntu", "--", "bash", "-c", inner]
    return [
        "semgrep", "scan",
        "--config", registry_config,
        "--config", _RULES_DIR,
        "--json", "--quiet",
        *metrics_flag,
        str(source),
    ]


def _parse_semgrep_json(
    stdout_b: bytes, source: Path, language: Language
) -> list[Finding] | None:
    """
    Parse Semgrep JSON output.

    Returns:
        list[Finding]  — parsed results (may be empty).
        None           — stdout is not valid JSON (scan error).
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


async def _run_semgrep(
    source: Path,
    timeout: int,
    language: Language,
    token: str | None,
    logger,
) -> list[Finding]:
    """
    Run semgrep (via WSL on Windows) and return parsed findings.

    Returns an empty list on any error so the pipeline can continue.
    """
    cmd = _semgrep_cmd(source, token)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        logger.warning("scout.semgrep_not_available", error=str(exc))
        return []

    comm_task = asyncio.create_task(proc.communicate())
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            comm_task, timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        if not comm_task.done():
            comm_task.cancel()
        logger.warning("scout.semgrep_timeout", timeout=timeout)
        return []

    rc = proc.returncode
    # Semgrep exits 1 when findings are present (not an error), 0 when clean.
    # Any other non-zero code is a real failure.
    if rc not in (0, 1):
        logger.warning(
            "scout.semgrep_error",
            rc=rc,
            stderr=stderr_b.decode("utf-8", errors="replace")[:400],
        )
        return []

    parsed = _parse_semgrep_json(stdout_b, source, language)
    if parsed is None:
        logger.warning(
            "scout.semgrep_bad_output",
            stderr=stderr_b.decode("utf-8", errors="replace")[:400],
        )
        return []

    logger.info("scout.semgrep_done", findings=len(parsed))
    return parsed


_SEVERITY_RANK: dict[str, int] = {
    "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}


def _extract_function_name(file_path: Path, line_number: int) -> str | None:
    """Best-effort extraction of the enclosing function name for a given line.

    Scans backwards from ``line_number`` looking for C/C++ or Python function
    definitions. Returns None if no enclosing function can be determined.
    """
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    # Patterns for function definitions
    # C/C++: <type> <name>(<args>) {
    c_func_re = re.compile(r"^[\w\s\*:~]+?\b(\w+)\s*\([^)]*\)\s*(?:\{|$)")
    # Python: def <name>(<args>):
    py_func_re = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(")

    for i in range(min(line_number - 1, len(lines) - 1), -1, -1):
        line = lines[i]
        m = py_func_re.match(line) or c_func_re.match(line)
        if m:
            return m.group(1)
    return None


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Group findings by (file_path, cwe_id, function_name) and keep one representative per group.

    The representative is the finding with the highest severity (ties broken by
    earliest line number). All other findings in the group are stored as
    ``related_findings`` on the representative so no information is lost.

    Findings without a CWE ID are never deduplicated — they pass through as-is.
    """
    from collections import defaultdict

    groups: dict[tuple[str, str, str | None], list[Finding]] = defaultdict(list)
    ungrouped: list[Finding] = []

    for f in findings:
        if f.cwe_id:
            key = (f.file_path, f.cwe_id, f.function_name)
            groups[key].append(f)
        else:
            ungrouped.append(f)

    deduped: list[Finding] = []
    for _key, group in groups.items():
        # Sort: highest severity first, then earliest line
        group.sort(
            key=lambda f: (-_SEVERITY_RANK.get(f.severity, 0), f.line_start),
        )
        representative = group[0]
        siblings = [
            RelatedFinding(
                id=f.id,
                rule_id=f.rule_id,
                line_start=f.line_start,
                line_end=f.line_end,
                snippet=f.snippet,
                message=f.message,
            )
            for f in group[1:]
        ]
        # Merge related_findings (in case the representative already had some)
        merged = list(representative.related_findings) + siblings
        representative = representative.model_copy(update={"related_findings": merged})
        deduped.append(representative)

    deduped.extend(ungrouped)
    # Stable sort by line number so the pipeline processes them in source order
    deduped.sort(key=lambda f: f.line_start)
    return deduped


async def scout_node(state: PipelineState, config: RunnableConfig) -> dict:
    gl: Config = config["configurable"]["gl_config"]
    logger = get_agent_logger(state.run_dir, "scout")

    source = state.source_file
    language = _detect_language(source)
    logger.info("scout.start", file=str(source), language=language)

    findings = await _run_semgrep(source, gl.scout_timeout_seconds, language, gl.semgrep_app_token, logger)
    raw_count = len(findings)

    # Annotate each finding with its enclosing function name for deduplication
    annotated: list[Finding] = []
    for f in findings:
        func = _extract_function_name(source, f.line_start)
        if func:
            f = f.model_copy(update={"function_name": func})
        annotated.append(f)

    deduped = _deduplicate_findings(annotated)

    logger.info(
        "scout.done",
        raw_findings=raw_count,
        deduplicated_findings=len(deduped),
        reduced_by=raw_count - len(deduped),
    )
    return {
        "findings": deduped,
        "language": language,
        "status": "classifying",
        "raw_findings_count": raw_count,
    }
