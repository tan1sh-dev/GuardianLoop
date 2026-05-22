from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from guardianloop.agents.fixer import (
    KeyRotator,
    _build_prompt,
    _classify_error,
    _extract_json,
    _unified_diff,
    fixer_node,
)
from guardianloop.config import Config
from guardianloop.state import (
    EnrichedFinding,
    Finding,
    Patch,
    PipelineState,
    VerificationResult,
)


def test_extract_json_bare():
    assert _extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_fenced():
    assert _extract_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_extract_json_plain_fence():
    assert _extract_json('```\n{"a": 1}\n```') == {"a": 1}


def test_unified_diff_flags_changes():
    d = _unified_diff("abc\n", "abd\n", "t.py")
    assert "-abc" in d and "+abd" in d


def test_build_prompt_handles_braces_in_source(sample_finding):
    """Regression: source containing literal { } must not break prompt building."""
    ef = EnrichedFinding(finding=sample_finding, enrichment_source="none")
    nasty_source = 'x = f"value: {y}"\nstruct S { int a; };\n'
    prompt = _build_prompt(ef, nasty_source, prior=None, prior_verif=None)
    assert nasty_source in prompt
    assert sample_finding.file_path in prompt


def test_build_prompt_handles_braces_in_sandbox_output(sample_finding):
    """Regression: sandbox output with literal '{' (e.g. ASan reports) must not break feedback block."""
    ef = EnrichedFinding(finding=sample_finding, enrichment_source="none")
    prior = Patch(
        finding_id=sample_finding.id,
        patched_code="ok",
        reasoning_chain=["a"],
        iteration=0,
    )
    nasty_stderr = "ERROR: AddressSanitizer: stack-buffer-overflow {addr=0x7fff}"
    prior_verif = VerificationResult(
        finding_id=sample_finding.id,
        patch_iteration=0,
        exploit_reproduced=True,
        sandbox_stderr=nasty_stderr,
    )
    prompt = _build_prompt(ef, "noop\n", prior=prior, prior_verif=prior_verif)
    assert nasty_stderr in prompt


def _build_gemini_mock(monkeypatch, response_json: dict):
    fake_response = MagicMock()
    fake_response.text = json.dumps(response_json)
    fake_client = MagicMock()
    fake_client.aio.models.generate_content = AsyncMock(return_value=fake_response)
    monkeypatch.setattr("google.genai.Client", lambda *a, **k: fake_client)
    return fake_client


@pytest.mark.asyncio
async def test_fixer_iteration_zero_patches_all_findings(
    monkeypatch, tmp_path, runnable_config
):
    source = tmp_path / "target.py"
    source.write_text("x=1\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    f = Finding(
        id="fid1",
        tool="bandit",
        rule_id="B608",
        cwe_id="CWE-89",
        message="sqli",
        severity="HIGH",
        file_path=str(source),
        line_start=1,
        line_end=1,
        language="python",
    )
    ef = EnrichedFinding(
        finding=f,
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        enrichment_source="fallback",
        exploitability_summary="sqli",
    )

    _build_gemini_mock(
        monkeypatch,
        {
            "reasoning_chain": [
                "what",
                "why",
                "invariant",
                "change",
                "exploit path",
            ],
            "patched_code": "x=2\n",
        },
    )

    state = PipelineState(source_file=source, run_dir=run_dir, enriched_findings=[ef])
    update = await fixer_node(state, runnable_config)

    assert update["status"] == "verifying"
    assert len(update["patches"]) == 1
    p = update["patches"][0]
    assert p.finding_id == "fid1"
    assert p.patched_code == "x=2\n"
    assert p.iteration == 0
    assert len(p.reasoning_chain) == 5
    assert "+x=2" in p.diff


@pytest.mark.asyncio
async def test_fixer_skips_held_findings_on_retry(monkeypatch, tmp_path, runnable_config):
    source = tmp_path / "target.py"
    source.write_text("x=1\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    f = Finding(
        id="fid1",
        tool="bandit",
        rule_id="B608",
        cwe_id="CWE-89",
        message="sqli",
        severity="HIGH",
        file_path=str(source),
        line_start=1,
        line_end=1,
        language="python",
    )
    ef = EnrichedFinding(finding=f, enrichment_source="none")
    prior_patch = Patch(
        finding_id="fid1", patched_code="x=2\n", reasoning_chain=["ok"], iteration=0
    )
    prior_verif = VerificationResult(
        finding_id="fid1", patch_iteration=0, exploit_reproduced=False
    )

    state = PipelineState(
        source_file=source,
        run_dir=run_dir,
        enriched_findings=[ef],
        patches=[prior_patch],
        verification_results=[prior_verif],
        loop_count=1,
    )

    def _boom(*a, **k):
        raise AssertionError("Gemini should not be called when prior patch held")

    monkeypatch.setattr("google.genai.Client", _boom)

    update = await fixer_node(state, runnable_config)

    assert update["status"] == "verifying"
    assert len(update["patches"]) == 1
    assert update["patches"][0].iteration == 0


@pytest.mark.asyncio
async def test_fixer_fails_without_api_key(tmp_path):
    cfg = Config(google_api_key=None, google_api_keys=[])
    source = tmp_path / "t.py"
    source.write_text("x=1\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await fixer_node(state, {"configurable": {"gl_config": cfg}})
    assert update["status"] == "failed"
    assert "GOOGLE_API_KEY" in (update["error"] or "")


# ---------------- KeyRotator unit tests ----------------

def test_key_rotator_current_returns_first_available():
    r = KeyRotator(keys=["a", "b", "c"])
    idx, key = r.current()
    assert idx == 0
    assert key == "a"


def test_key_rotator_rotate_advances():
    r = KeyRotator(keys=["a", "b", "c"])
    assert r.current() == (0, "a")
    assert r.rotate() == (1, "b")
    assert r.rotate() == (2, "c")


def test_key_rotator_skips_exhausted():
    r = KeyRotator(keys=["a", "b", "c"])
    r.mark_exhausted(0)
    idx, key = r.current()
    assert idx == 1
    assert key == "b"


def test_key_rotator_all_exhausted_returns_none():
    r = KeyRotator(keys=["a", "b"])
    r.mark_exhausted(0)
    r.mark_exhausted(1)
    assert r.current() is None
    assert r.rotate() is None


def test_key_rotator_empty():
    r = KeyRotator(keys=[])
    assert r.current() is None
    assert r.total == 0
    assert r.remaining == 0


# ---------------- error classification ----------------

def test_classify_error_detects_daily_quota():
    err = Exception("429 RESOURCE_EXHAUSTED: You exceeded your daily quota.")
    is_quota, _ = _classify_error(err)
    assert is_quota is True


def test_classify_error_detects_long_retry_as_quota():
    err = Exception("429 too many requests, retry_in 86400s")
    is_quota, retry = _classify_error(err)
    assert is_quota is True
    assert retry == 86400.0


def test_classify_error_short_retry_is_transient():
    err = Exception("429 burst limit, retry after 3s")
    is_quota, retry = _classify_error(err)
    assert is_quota is False
    assert retry == 3.0


def test_classify_error_non_429_is_transient():
    err = Exception("500 internal server error")
    is_quota, _ = _classify_error(err)
    assert is_quota is False


# ---------------- multi-key end-to-end ----------------

@pytest.mark.asyncio
async def test_fixer_rotates_keys_on_quota_exhaustion(
    monkeypatch, tmp_path, runnable_config
):
    """First key returns 429 quota → rotator skips to second key → success."""
    source = tmp_path / "target.py"
    source.write_text("x=1\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    f = Finding(
        id="fid1",
        tool="bandit",
        rule_id="B608",
        cwe_id="CWE-89",
        message="sqli",
        severity="HIGH",
        file_path=str(source),
        line_start=1,
        line_end=1,
        language="python",
    )
    ef = EnrichedFinding(finding=f, enrichment_source="none")

    # Override the config: 2 keys instead of 1
    cfg = runnable_config["configurable"]["gl_config"]
    object.__setattr__(cfg, "google_api_keys", ["key-dead", "key-live"])
    object.__setattr__(cfg, "google_api_key", "key-dead")

    calls: list[str] = []

    def _client_factory(api_key=None, **_):
        calls.append(api_key)
        client = MagicMock()
        if api_key == "key-dead":
            client.aio.models.generate_content = AsyncMock(
                side_effect=Exception(
                    "429 RESOURCE_EXHAUSTED: daily quota exceeded for this project"
                )
            )
        else:
            fake = MagicMock()
            fake.text = json.dumps(
                {
                    "reasoning_chain": ["a", "b", "c", "d", "e"],
                    "patched_code": "x=2\n",
                }
            )
            client.aio.models.generate_content = AsyncMock(return_value=fake)
        return client

    monkeypatch.setattr("google.genai.Client", _client_factory)

    state = PipelineState(source_file=source, run_dir=run_dir, enriched_findings=[ef])
    update = await fixer_node(state, runnable_config)

    assert update["status"] == "verifying"
    assert len(update["patches"]) == 1
    assert update["patches"][0].patched_code == "x=2\n"
    # First key tried then rotated away to second key
    assert "key-dead" in calls
    assert "key-live" in calls
