"""
Classifier — NVD CVE/CVSS enrichment agent.

For each Finding, queries the NVD REST API for the CWE's associated CVEs and
extracts the highest CVSS 3.x base score.

Rate limiting (spec: free tier = 5 req/30 s):
    * No API key: sleep 7 seconds between successive NVD calls.
    * NVD_API_KEY present: sleep 1 second between calls.

Both values are intentionally conservative; 30 / 5 = 6 s minimum, 30 / 50 = 0.6 s.

On any failure (non-200, network error, timeout), the agent falls back to a
hardcoded CWE → CVSS table. Unknown CWEs get a generic score of 5.0 / MEDIUM
so downstream agents always have a numeric score to work with.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from langchain_core.runnables import RunnableConfig

from guardianloop.config import Config
from guardianloop.logging_setup import get_agent_logger
from guardianloop.state import EnrichedFinding, Finding, PipelineState, Severity

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Seconds to sleep between consecutive NVD calls, keyed on whether we have an API key.
_NVD_SLEEP_WITH_KEY: float = 1.0
_NVD_SLEEP_WITHOUT_KEY: float = 7.0

CWE_CVSS_FALLBACK: dict[str, dict[str, Any]] = {
    "CWE-121": {
        "score": 9.8,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "summary": (
            "Stack-based buffer overflow. Writing past the end of a stack buffer "
            "lets an attacker overwrite the saved return address and redirect "
            "control flow, typically leading to arbitrary code execution."
        ),
    },
    "CWE-787": {
        "score": 9.8,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "summary": (
            "Out-of-bounds write. Corrupts adjacent memory and frequently leads "
            "to remote code execution or memory disclosure."
        ),
    },
    "CWE-79": {
        "score": 6.1,
        "severity": "MEDIUM",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "summary": (
            "Cross-site scripting. Attacker-controlled content is reflected into "
            "a response without proper encoding, enabling script execution in "
            "victim browsers."
        ),
    },
    "CWE-89": {
        "score": 9.8,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "summary": (
            "SQL injection. Unparameterized query construction lets an attacker "
            "tamper with, exfiltrate, or destroy database contents."
        ),
    },
    "CWE-78": {
        "score": 9.8,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "summary": (
            "OS command injection. User input reaches a shell interpreter "
            "unescaped, letting an attacker run arbitrary commands."
        ),
    },
}

# Generic fallback for CWEs not in the table above.
_DEFAULT_FALLBACK: dict[str, Any] = {
    "score": 5.0,
    "severity": "MEDIUM",
    "vector": None,
    "summary": "",
}


class NvdClient:
    def __init__(self, api_key: str | None, timeout: int) -> None:
        self.api_key = api_key
        self.timeout = timeout

    async def fetch_cves_for_cwe(self, cwe_id: str, logger: Any) -> list[dict]:
        """Query NVD for CVEs associated with *cwe_id*.

        Returns up to 5 CVE vulnerability dicts or [] on any failure.
        Retries 3 times with exponential back-off on 403 / 429 / 503.
        """
        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {"cweId": cwe_id, "resultsPerPage": 5}
        backoff = 1.0
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for attempt in range(3):
                try:
                    r = await client.get(NVD_API_URL, params=params, headers=headers)
                    if r.status_code == 200:
                        return r.json().get("vulnerabilities", []) or []
                    if r.status_code in (403, 429, 503):
                        logger.warning(
                            "classifier.nvd_rate_limited",
                            status=r.status_code,
                            attempt=attempt,
                        )
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    logger.warning("classifier.nvd_error", status=r.status_code)
                    return []
                except (httpx.HTTPError, asyncio.TimeoutError) as e:
                    logger.warning(
                        "classifier.nvd_exception", error=str(e), attempt=attempt
                    )
                    await asyncio.sleep(backoff)
                    backoff *= 2
        return []


def _map_nvd_severity(s: str | None) -> Severity | None:
    if not s:
        return None
    upper = s.upper()
    if upper in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return upper  # type: ignore[return-value]
    return None


def _fallback_enrichment(finding: Finding) -> EnrichedFinding:
    """Return enrichment from the hardcoded table, or a 5.0/MEDIUM default."""
    cwe = finding.cwe_id
    data = CWE_CVSS_FALLBACK.get(cwe) if cwe else None
    if data:
        return EnrichedFinding(
            finding=finding,
            cvss_score=data["score"],
            cvss_severity=data["severity"],
            cvss_vector=data["vector"],
            enrichment_source="fallback",
            exploitability_summary=data["summary"],
        )
    # Unknown CWE — use a generic default so downstream agents always have a score.
    return EnrichedFinding(
        finding=finding,
        cvss_score=_DEFAULT_FALLBACK["score"],
        cvss_severity=_DEFAULT_FALLBACK["severity"],
        cvss_vector=_DEFAULT_FALLBACK["vector"],
        enrichment_source="fallback",
    )


def _enrich_from_nvd(finding: Finding, vulns: list[dict]) -> EnrichedFinding:
    """Build EnrichedFinding from NVD vulnerability dicts, picking highest CVSS score."""
    cve_ids: list[str] = []
    best_score: float | None = None
    best_severity: str | None = None
    best_vector: str | None = None
    summary = ""

    for v in vulns:
        cve = v.get("cve", {}) or {}
        cve_id = cve.get("id")
        if cve_id:
            cve_ids.append(cve_id)
        metrics = cve.get("metrics", {}) or {}
        for key in ("cvssMetricV31", "cvssMetricV30"):
            arr = metrics.get(key) or []
            if arr:
                cdata = arr[0].get("cvssData", {}) or {}
                score = cdata.get("baseScore")
                if score is not None and (best_score is None or score > best_score):
                    best_score = float(score)
                    best_severity = cdata.get("baseSeverity")
                    best_vector = cdata.get("vectorString")
                break
        if not summary:
            for d in cve.get("descriptions", []) or []:
                if d.get("lang") == "en":
                    summary = d.get("value", "")
                    break

    if best_score is None:
        # NVD returned CVEs but none had parseable CVSS data — fall back.
        fb = _fallback_enrichment(finding)
        return EnrichedFinding(
            finding=finding,
            cve_ids=cve_ids,
            cvss_score=fb.cvss_score,
            cvss_severity=fb.cvss_severity,
            cvss_vector=fb.cvss_vector,
            enrichment_source="nvd" if cve_ids else fb.enrichment_source,
            exploitability_summary=summary or fb.exploitability_summary,
        )
    return EnrichedFinding(
        finding=finding,
        cve_ids=cve_ids,
        cvss_score=best_score,
        cvss_severity=_map_nvd_severity(best_severity),
        cvss_vector=best_vector,
        enrichment_source="nvd",
        exploitability_summary=summary,
    )


async def classifier_node(state: PipelineState, config: RunnableConfig) -> dict:
    gl: Config = config["configurable"]["gl_config"]
    logger = get_agent_logger(state.run_dir, "classifier")

    sleep_secs = _NVD_SLEEP_WITH_KEY if gl.nvd_api_key else _NVD_SLEEP_WITHOUT_KEY
    client = NvdClient(gl.nvd_api_key, gl.nvd_timeout_seconds)

    logger.info(
        "classifier.start",
        findings=len(state.findings),
        rate_limit=sleep_secs,
        has_key=bool(gl.nvd_api_key),
    )

    async def _enrich_one(f: Finding) -> EnrichedFinding:
        if not f.cwe_id:
            return EnrichedFinding(finding=f, enrichment_source="none")
        vulns = await client.fetch_cves_for_cwe(f.cwe_id, logger)
        if not vulns:
            return _fallback_enrichment(f)
        return _enrich_from_nvd(f, vulns)

    enriched: list[EnrichedFinding] = []
    for i, f in enumerate(state.findings):
        if i > 0:
            # Rate-limit: sleep between successive NVD calls.
            logger.info("classifier.nvd_sleep", seconds=sleep_secs, finding_index=i)
            await asyncio.sleep(sleep_secs)
        ef = await _enrich_one(f)
        enriched.append(ef)
        logger.info(
            "classifier.enriched",
            finding_id=f.id,
            source=ef.enrichment_source,
            score=ef.cvss_score,
        )

    logger.info("classifier.done", enriched=len(enriched))
    return {"enriched_findings": enriched, "status": "fixing"}
