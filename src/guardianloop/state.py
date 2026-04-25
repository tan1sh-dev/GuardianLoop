"""
Pydantic schemas — the single source of truth for every inter-agent message.

Rule (also enforced in CLAUDE.md): do not invent ad-hoc fields in agent code.
If you need a new field, add it here and open a PR.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Language = Literal["python", "cpp", "unknown"]
Tool = Literal["semgrep", "bandit"]
EnrichmentSource = Literal["nvd", "fallback", "none"]
PipelineStatus = Literal[
    "pending",
    "scanning",
    "classifying",
    "fixing",
    "verifying",
    "reporting",
    "complete",
    "failed",
]


class Finding(BaseModel):
    """Raw SAST output from Scout."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="Stable ID: sha1 of tool+rule+file+line")
    tool: Tool
    rule_id: str
    cwe_id: str | None = Field(default=None, description="e.g. 'CWE-121'")
    message: str
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    snippet: str = ""
    language: Language = "unknown"


class EnrichedFinding(BaseModel):
    """Finding + NVD CVE/CVSS enrichment from Classifier."""

    model_config = ConfigDict(extra="forbid")

    finding: Finding
    cve_ids: list[str] = Field(default_factory=list)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_severity: Severity | None = None
    cvss_vector: str | None = None
    enrichment_source: EnrichmentSource = "none"
    exploitability_summary: str = ""


class Patch(BaseModel):
    """A Fixer-proposed patch for a single finding, with CoT reasoning."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    patched_code: str = Field(description="Full replacement contents of the target file")
    diff: str = Field(default="", description="Unified diff vs. the original file")
    reasoning_chain: list[str] = Field(
        default_factory=list,
        description="Chain-of-thought steps emitted by the Fixer — feeds the markdown report",
    )
    iteration: int = 0
    model: str = "gemini-2.5-pro"


class VerificationResult(BaseModel):
    """Red-Team's sandbox outcome for a single patch."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    patch_iteration: int
    exploit_reproduced: bool
    sandbox_stdout: str = ""
    sandbox_stderr: str = ""
    sandbox_exit_code: int = 0
    duration_seconds: float = 0.0


class PipelineState(BaseModel):
    """
    LangGraph shared state. Nodes return partial dicts; lists are replaced,
    not merged — so nodes that add items must return the full concatenated list.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    source_file: Path
    language: Language = "unknown"
    run_dir: Path
    findings: list[Finding] = Field(default_factory=list)
    enriched_findings: list[EnrichedFinding] = Field(default_factory=list)
    patches: list[Patch] = Field(default_factory=list)
    verification_results: list[VerificationResult] = Field(default_factory=list)
    loop_count: int = 0
    status: PipelineStatus = "pending"
    error: str | None = None
