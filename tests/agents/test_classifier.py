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


def test_fallback_for_known_cwe(sample_finding: Finding):
    ef = _fallback_enrichment(sample_finding)
    assert ef.enrichment_source == "fallback"
    assert ef.cvss_score == CWE_CVSS_FALLBACK["CWE-121"]["score"]
    assert ef.exploitability_summary


def test_fallback_for_unknown_cwe():
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
    assert ef.enrichment_source == "none"
    assert ef.cvss_score is None


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


@pytest.mark.asyncio
async def test_classifier_falls_back_on_403(
    monkeypatch, sample_finding, tmp_run_dir, runnable_config
):
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
