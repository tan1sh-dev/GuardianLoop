from __future__ import annotations

import pytest

from guardianloop.agents.red_team import red_team_node
from guardianloop.state import EnrichedFinding, Finding, Patch, PipelineState


def _state_with_patch(tmp_path, *, language: str = "cpp") -> PipelineState:
    source = tmp_path / ("target.py" if language == "python" else "target.cpp")
    source.write_text("noop\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    f = Finding(
        id="fid",
        tool="semgrep",
        rule_id="r",
        cwe_id="CWE-121" if language == "cpp" else "CWE-89",
        message="m",
        severity="HIGH",
        file_path=str(source),
        line_start=1,
        line_end=1,
        language=language,
    )
    ef = EnrichedFinding(finding=f, enrichment_source="fallback", cvss_score=9.8)
    patch = Patch(finding_id="fid", patched_code="ok", iteration=0)
    return PipelineState(
        source_file=source,
        run_dir=run_dir,
        enriched_findings=[ef],
        patches=[patch],
    )


def _force_docker_available(monkeypatch) -> None:
    monkeypatch.setattr(
        "guardianloop.agents.red_team.is_docker_available", lambda image: True
    )


@pytest.mark.asyncio
async def test_red_team_records_held_patch(monkeypatch, tmp_path, runnable_config):
    state = _state_with_patch(tmp_path, language="cpp")
    _force_docker_available(monkeypatch)
    monkeypatch.setattr(
        "guardianloop.agents.red_team.run_exploit_in_sandbox",
        lambda **kw: {
            "exploit_reproduced": False,
            "stdout": "patch held",
            "stderr": "",
            "exit_code": 0,
            "duration": 1.23,
            "docker_available": True,
        },
    )

    update = await red_team_node(state, runnable_config)

    assert update["status"] == "reporting"
    assert len(update["verification_results"]) == 1
    v = update["verification_results"][0]
    assert v.exploit_reproduced is False
    assert v.finding_id == "fid"
    assert v.sandbox_exit_code == 0


@pytest.mark.asyncio
async def test_red_team_flags_reproduced_exploit(
    monkeypatch, tmp_path, runnable_config
):
    state = _state_with_patch(tmp_path, language="cpp")
    _force_docker_available(monkeypatch)
    monkeypatch.setattr(
        "guardianloop.agents.red_team.run_exploit_in_sandbox",
        lambda **kw: {
            "exploit_reproduced": True,
            "stdout": "boom",
            "stderr": "==1==ERROR: AddressSanitizer: stack-buffer-overflow",
            "exit_code": 42,
            "duration": 0.5,
            "docker_available": True,
        },
    )

    update = await red_team_node(state, runnable_config)

    v = update["verification_results"][0]
    assert v.exploit_reproduced is True
    assert v.sandbox_exit_code == 42


@pytest.mark.asyncio
async def test_red_team_selects_python_image_for_python_finding(
    monkeypatch, tmp_path, runnable_config
):
    state = _state_with_patch(tmp_path, language="python")
    _force_docker_available(monkeypatch)
    captured: dict = {}

    def _capture(**kw):
        captured.update(kw)
        return {
            "exploit_reproduced": False,
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "duration": 0.1,
            "docker_available": True,
        }

    monkeypatch.setattr(
        "guardianloop.agents.red_team.run_exploit_in_sandbox", _capture
    )

    await red_team_node(state, runnable_config)
    assert captured["language"] == "python"
    assert captured["image"] == "test/python:latest"


@pytest.mark.asyncio
async def test_red_team_falls_back_to_scout_when_docker_unavailable(
    monkeypatch, tmp_path, runnable_config
):
    state = _state_with_patch(tmp_path, language="cpp")
    monkeypatch.setattr(
        "guardianloop.agents.red_team.is_docker_available", lambda image: False
    )

    sandbox_called = {"n": 0}

    def _should_not_run(**kw):
        sandbox_called["n"] += 1
        raise AssertionError("run_exploit_in_sandbox must not be called when docker is unavailable")

    monkeypatch.setattr(
        "guardianloop.agents.red_team.run_exploit_in_sandbox", _should_not_run
    )

    rescan_called = {"n": 0}

    async def _fake_rescan(*, finding, patched_code, timeout, logger):
        rescan_called["n"] += 1
        return {
            "exploit_reproduced": True,
            "stdout": f"scout_rescan: 1 findings, 1 matching CWE {finding.cwe_id}",
            "stderr": "",
            "exit_code": 0,
            "duration": 0.42,
        }

    monkeypatch.setattr("guardianloop.agents.red_team._scout_rescan", _fake_rescan)

    update = await red_team_node(state, runnable_config)

    assert sandbox_called["n"] == 0
    assert rescan_called["n"] == 1
    v = update["verification_results"][0]
    assert v.exploit_reproduced is True
    assert "scout_rescan" in v.sandbox_stdout


@pytest.mark.asyncio
async def test_red_team_falls_back_when_runtime_returns_docker_unavailable(
    monkeypatch, tmp_path, runnable_config
):
    """is_docker_available said yes, but the runtime call later reports the daemon dropped."""
    state = _state_with_patch(tmp_path, language="cpp")
    _force_docker_available(monkeypatch)
    monkeypatch.setattr(
        "guardianloop.agents.red_team.run_exploit_in_sandbox",
        lambda **kw: {
            "exploit_reproduced": False,
            "stdout": "",
            "stderr": "Docker daemon not available: connection refused",
            "exit_code": -1,
            "duration": 0.0,
            "docker_available": False,
        },
    )

    async def _fake_rescan(*, finding, patched_code, timeout, logger):
        return {
            "exploit_reproduced": False,
            "stdout": "scout_rescan: 0 findings, 0 matching CWE CWE-121",
            "stderr": "",
            "exit_code": 0,
            "duration": 0.1,
        }

    monkeypatch.setattr("guardianloop.agents.red_team._scout_rescan", _fake_rescan)

    update = await red_team_node(state, runnable_config)

    v = update["verification_results"][0]
    assert v.exploit_reproduced is False
    assert "scout_rescan" in v.sandbox_stdout
