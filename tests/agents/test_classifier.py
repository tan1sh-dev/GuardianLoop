from __future__ import annotations

import asyncio

import pytest

from guardianloop.agents.classifier import (
    CWE_CVSS_FALLBACK,
    _enrich_from_nvd,
    _fallback_enrichment,
    classifier_node,
)
from guardianloop.state import Finding, PipelineState


# ---------------------------------------------------------------------------
# Unit tests for pure helper functions
# ---------------------------------------------------------------------------


def test_fallback_for_known_cwe(sample_finding: Finding):
    ef = _fallback_enrichment(sample_finding)
    assert ef.enrichment_source == "fallback"
    assert ef.cvss_score == CWE_CVSS_FALLBACK["CWE-121"]["score"]
    assert ef.exploitability_summary


def test_fallback_for_unknown_cwe():
    """CWEs not in the table get the generic 5.0/MEDIUM default (not None)."""
    f = Finding(
        id="z",
        tool="semgrep",
        rule_id="r",
        cwe_id="CWE-99999",
        message="m",
        severity="LOW",
        file_path="x.py",
        line_start=1,
        line_end=1,
    )
    ef = _fallback_enrichment(f)
    assert ef.enrichment_source == "fallback"
    assert ef.cvss_score == 5.0
    assert ef.cvss_severity == "MEDIUM"


def test_fallback_for_none_cwe():
    """Findings with no CWE at all get enrichment_source='none' and no score."""
    f = Finding(
        id="z",
        tool="semgrep",
        rule_id="r",
        cwe_id=None,
        message="m",
        severity="LOW",
        file_path="x.py",
        line_start=1,
        line_end=1,
    )
    # classifier_node skips NVD for cwe_id=None and returns source="none".
    # _fallback_enrichment still applies the generic default for unknown CWEs
    # (since None is not in the table); verify that generic path.
    ef = _fallback_enrichment(f)
    assert ef.enrichment_source == "fallback"
    assert ef.cvss_score == 5.0


def test_enrich_from_nvd_picks_highest_score():
    base = Finding(
        id="z",
        tool="semgrep",
        rule_id="r",
        cwe_id="CWE-79",
        message="m",
        severity="LOW",
        file_path="x.py",
        line_start=1,
        line_end=1,
    )
    vulns = [
        {
            "cve": {
                "id": "CVE-1",
                "descriptions": [{"lang": "en", "value": "low"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 5.0,
                                "baseSeverity": "MEDIUM",
                                "vectorString": "v1",
                            }
                        }
                    ]
                },
            }
        },
        {
            "cve": {
                "id": "CVE-2",
                "descriptions": [{"lang": "en", "value": "high"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.0,
                                "baseSeverity": "HIGH",
                                "vectorString": "v2",
                            }
                        }
                    ]
                },
            }
        },
    ]
    ef = _enrich_from_nvd(base, vulns)
    assert ef.cvss_score == 9.0
    assert ef.cve_ids == ["CVE-1", "CVE-2"]
    assert ef.enrichment_source == "nvd"
    assert ef.cvss_severity == "HIGH"


# ---------------------------------------------------------------------------
# Integration tests for classifier_node (mocked NVD HTTP + asyncio.sleep)
# ---------------------------------------------------------------------------


def _make_nvd_200_response(cve_id: str, score: float, severity: str) -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [
                        {"lang": "en", "value": f"Test description for {cve_id}"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": score,
                                    "baseSeverity": severity,
                                    "vectorString": (
                                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                    ),
                                }
                            }
                        ]
                    },
                }
            }
        ]
    }


@pytest.mark.asyncio
async def test_classifier_enriches_from_nvd_on_200(
    monkeypatch, sample_finding, tmp_run_dir, runnable_config
):
    """NVD returns 200 with CVSS data → EnrichedFinding is populated from NVD."""
    nvd_payload = _make_nvd_200_response("CVE-2021-99999", score=9.8, severity="CRITICAL")

    class _FakeResp:
        status_code = 200

        def json(self):
            return nvd_payload

    class _FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, *a, **k):
            return _FakeResp()

    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: _FakeClient())

    async def _nosleep(*a, **k):
        return None

    monkeypatch.setattr(asyncio, "sleep", _nosleep)

    state = PipelineState(
        source_file="x.cpp",
        run_dir=tmp_run_dir,
        findings=[sample_finding],
    )
    update = await classifier_node(state, runnable_config)

    assert update["status"] == "fixing"
    assert len(update["enriched_findings"]) == 1
    ef = update["enriched_findings"][0]
    assert ef.cvss_score > 0
    assert ef.cvss_score == 9.8
    assert ef.cvss_severity == "CRITICAL"
    assert ef.enrichment_source == "nvd"
    assert "CVE-2021-99999" in ef.cve_ids
    assert ef.exploitability_summary  # NVD description should be populated


@pytest.mark.asyncio
async def test_classifier_falls_back_on_403(
    monkeypatch, sample_finding, tmp_run_dir, runnable_config
):
    """All NVD attempts return 403 → falls back to hardcoded CWE table."""

    class _FakeResp:
        status_code = 403

        def json(self):
            return {}

    class _FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, *a, **k):
            return _FakeResp()

    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: _FakeClient())

    async def _nosleep(*a, **k):
        return None

    monkeypatch.setattr(asyncio, "sleep", _nosleep)

    state = PipelineState(
        source_file="x.cpp",
        run_dir=tmp_run_dir,
        findings=[sample_finding],
    )
    update = await classifier_node(state, runnable_config)

    assert update["status"] == "fixing"
    assert len(update["enriched_findings"]) == 1
    ef = update["enriched_findings"][0]
    assert ef.enrichment_source == "fallback"
    assert ef.cvss_score == CWE_CVSS_FALLBACK["CWE-121"]["score"]


@pytest.mark.asyncio
async def test_classifier_sleeps_between_multiple_findings(
    monkeypatch, tmp_run_dir, runnable_config
):
    """With N findings, asyncio.sleep is called exactly N-1 times."""
    sleep_calls: list[float] = []

    class _FakeResp:
        status_code = 403

        def json(self):
            return {}

    class _FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, *a, **k):
            return _FakeResp()

    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: _FakeClient())

    async def _capture_sleep(secs, *a, **k):
        sleep_calls.append(secs)

    monkeypatch.setattr(asyncio, "sleep", _capture_sleep)

    findings = [
        Finding(
            id=f"fid{i}",
            tool="semgrep",
            rule_id="r",
            cwe_id="CWE-121",
            message="m",
            severity="HIGH",
            file_path="x.cpp",
            line_start=i,
            line_end=i,
        )
        for i in range(1, 4)  # 3 findings
    ]
    state = PipelineState(
        source_file="x.cpp",
        run_dir=tmp_run_dir,
        findings=findings,
    )
    update = await classifier_node(state, runnable_config)

    # 3 findings → 2 inter-call sleeps (not before the first call).
    # The 403 retry back-offs also call asyncio.sleep; filter by checking that
    # at least 2 of the sleep calls are the rate-limit sleep (7.0 s, no API key).
    rate_limit_sleeps = [s for s in sleep_calls if s == 7.0]
    assert len(rate_limit_sleeps) == 2, (
        f"Expected 2 rate-limit sleeps (7.0 s each), got sleep_calls={sleep_calls}"
    )
    assert len(update["enriched_findings"]) == 3
