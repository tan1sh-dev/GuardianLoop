from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from guardianloop.state import (
    EnrichedFinding,
    Finding,
    Patch,
    PipelineState,
    VerificationResult,
)


def test_finding_round_trip():
    f = Finding(
        id="x",
        tool="semgrep",
        rule_id="r",
        cwe_id="CWE-89",
        message="m",
        severity="HIGH",
        file_path="a.py",
        line_start=1,
        line_end=2,
        snippet="code",
        language="python",
    )
    data = f.model_dump()
    assert Finding(**data) == f


def test_finding_rejects_extra_fields():
    with pytest.raises(ValidationError):
        Finding(
            id="x",
            tool="semgrep",
            rule_id="r",
            message="m",
            severity="HIGH",
            file_path="a.py",
            line_start=1,
            line_end=2,
            extra_field="nope",
        )


def test_enriched_finding_clamps_cvss_upper_bound(sample_finding: Finding):
    with pytest.raises(ValidationError):
        EnrichedFinding(finding=sample_finding, cvss_score=20.0)


def test_enriched_finding_accepts_no_cvss(sample_finding: Finding):
    ef = EnrichedFinding(finding=sample_finding, enrichment_source="none")
    assert ef.cvss_score is None
    assert ef.cve_ids == []


def test_pipeline_state_defaults(tmp_run_dir: Path):
    state = PipelineState(source_file=Path("x.py"), run_dir=tmp_run_dir)
    assert state.findings == []
    assert state.patches == []
    assert state.verification_results == []
    assert state.loop_count == 0
    assert state.status == "pending"
    assert state.error is None


def test_patch_and_verification_round_trip(sample_finding: Finding):
    p = Patch(finding_id=sample_finding.id, patched_code="ok", reasoning_chain=["a"])
    v = VerificationResult(
        finding_id=sample_finding.id, patch_iteration=0, exploit_reproduced=False
    )
    assert Patch(**p.model_dump()) == p
    assert VerificationResult(**v.model_dump()) == v
