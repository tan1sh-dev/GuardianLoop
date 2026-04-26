from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from guardianloop.agents.scout import _detect_language, _RULES_DIR, scout_node
from guardianloop.state import PipelineState

REPO_ROOT = Path(__file__).resolve().parents[2]

# Semgrep JSON output for a CWE-121 finding (local-rules metadata style: string, not list).
SEMGREP_SAMPLE = json.dumps(
    {
        "results": [
            {
                "check_id": "cwe-121-strcpy-no-bounds",
                "start": {"line": 12},
                "end": {"line": 14},
                "extra": {
                    "severity": "ERROR",
                    "message": "strcpy into fixed buffer",
                    "metadata": {"cwe": "CWE-121"},
                },
            }
        ]
    }
).encode()

BANDIT_SAMPLE = json.dumps(
    {
        "results": [
            {
                "test_id": "B608",
                "line_number": 5,
                "issue_text": "possible SQL injection",
                "issue_severity": "HIGH",
                "issue_cwe": {"id": 89},
            }
        ]
    }
).encode()


class _FakeProc:
    """Minimal asyncio.subprocess.Process stand-in for unit tests."""

    returncode: int = 0  # required: _run_semgrep reads proc.returncode after communicate()

    def __init__(self, stdout: bytes, returncode: int = 0) -> None:
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, b""

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return self.returncode


# ---------------------------------------------------------------------------
# Unit tests (mocked subprocess)
# ---------------------------------------------------------------------------


def test_detect_language():
    assert _detect_language(Path("x.py")) == "python"
    assert _detect_language(Path("x.cpp")) == "cpp"
    assert _detect_language(Path("x.cc")) == "cpp"
    assert _detect_language(Path("x.txt")) == "unknown"


@pytest.mark.asyncio
async def test_scout_on_cpp_runs_only_semgrep(tmp_path, monkeypatch, runnable_config):
    source = tmp_path / "t.cpp"
    source.write_text("int main(){return 0;}\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    semgrep_calls: list[tuple] = []

    async def fake_exec(*args, **kwargs):
        if args[0] == "semgrep":
            semgrep_calls.append(args)
            return _FakeProc(SEMGREP_SAMPLE, returncode=0)
        if args[0] == "bandit":
            raise AssertionError("bandit should not run on C++ files")
        return _FakeProc(b"{}", returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    assert update["language"] == "cpp"
    assert update["status"] == "classifying"
    assert len(update["findings"]) == 1
    f = update["findings"][0]
    assert f.cwe_id == "CWE-121"
    assert f.tool == "semgrep"
    assert f.severity == "HIGH"

    # Semgrep called exactly once — SEMGREP_SAMPLE has findings, no fallback needed.
    assert len(semgrep_calls) == 1
    first_call = semgrep_calls[0]
    # Confirms local rules/ dir is the primary config (not a registry pack).
    assert any(_RULES_DIR in str(arg) for arg in first_call)


@pytest.mark.asyncio
async def test_scout_on_python_runs_both_tools(tmp_path, monkeypatch, runnable_config):
    source = tmp_path / "t.py"
    source.write_text("x=1\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    semgrep_calls: list[tuple] = []

    async def fake_exec(*args, **kwargs):
        if args[0] == "semgrep":
            semgrep_calls.append(args)
            # Return a finding so no auto-fallback is triggered.
            return _FakeProc(SEMGREP_SAMPLE, returncode=0)
        if args[0] == "bandit":
            return _FakeProc(BANDIT_SAMPLE, returncode=0)
        return _FakeProc(b"{}", returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    assert update["language"] == "python"
    # Semgrep called exactly once (rules/ returned findings → no auto).
    assert len(semgrep_calls) == 1
    assert any(_RULES_DIR in str(arg) for arg in semgrep_calls[0])
    # Bandit finding at line 5 passes through (semgrep finding at line 12).
    assert any(f.tool == "bandit" and f.cwe_id == "CWE-89" for f in update["findings"])


@pytest.mark.asyncio
async def test_scout_auto_fallback_triggered_when_rules_empty(
    tmp_path, monkeypatch, runnable_config
):
    """When rules/ runs cleanly but finds nothing, auto is attempted as secondary."""
    source = tmp_path / "t.cpp"
    source.write_text("int main(){return 0;}\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    configs_seen: list[str] = []

    auto_result = json.dumps(
        {
            "results": [
                {
                    "check_id": "registry.cwe787",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {
                        "severity": "ERROR",
                        "message": "registry hit",
                        "metadata": {"cwe": "CWE-787"},
                    },
                }
            ]
        }
    ).encode()

    async def fake_exec(*args, **kwargs):
        config_arg = next((a for a in args if a.startswith("--config=")), "")
        configs_seen.append(config_arg)
        if "rules" in config_arg:
            # rules/ runs clean but finds nothing → returncode 0
            return _FakeProc(b'{"results": []}', returncode=0)
        # auto config returns a finding
        return _FakeProc(auto_result, returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    assert len(configs_seen) == 2
    assert any("rules" in c for c in configs_seen)
    assert any("auto" in c for c in configs_seen)
    assert len(update["findings"]) == 1
    assert update["findings"][0].cwe_id == "CWE-787"


@pytest.mark.asyncio
async def test_scout_regex_fallback_on_semgrep_error(
    tmp_path, monkeypatch, runnable_config
):
    """When Semgrep exits with a non-zero rc (e.g. semgrep-core broken on Windows),
    the regex scanner reads local YAML rules and produces findings directly."""
    source = tmp_path / "t.cpp"
    # Write a line that the cwe121-strcpy.yaml pattern will match.
    source.write_text("int main(){strcpy(buf, input); return 0;}\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    async def fake_exec(*args, **kwargs):
        # Simulate semgrep-core failure: non-zero rc, no valid JSON on stdout.
        return _FakeProc(b"<ERROR: missing output>\r\n", returncode=2)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    findings = update["findings"]
    assert len(findings) >= 1, "regex fallback should detect strcpy"
    assert any(f.cwe_id == "CWE-121" for f in findings)
    assert all(f.tool == "semgrep" for f in findings)


@pytest.mark.asyncio
async def test_scout_dedup_drops_bandit_on_semgrep_line(
    tmp_path, monkeypatch, runnable_config
):
    """Bandit and Semgrep flagging the same line → keep only the Semgrep finding."""
    source = tmp_path / "t.py"
    source.write_text('import sqlite3\nq = f"SELECT {x}"\n')
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    semgrep_at_line2 = json.dumps(
        {
            "results": [
                {
                    "check_id": "py.lang.sqli",
                    "start": {"line": 2},
                    "end": {"line": 2},
                    "extra": {
                        "severity": "ERROR",
                        "message": "f-string SQL",
                        "metadata": {"cwe": "CWE-89"},
                    },
                }
            ]
        }
    ).encode()
    bandit_at_line2 = json.dumps(
        {
            "results": [
                {
                    "test_id": "B608",
                    "line_number": 2,
                    "issue_text": "possible SQLi",
                    "issue_severity": "HIGH",
                    "issue_cwe": {"id": 89},
                }
            ]
        }
    ).encode()

    async def fake_exec(*args, **kwargs):
        if args[0] == "semgrep":
            return _FakeProc(semgrep_at_line2, returncode=0)
        return _FakeProc(bandit_at_line2, returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    findings = update["findings"]
    assert len(findings) == 1, [f.tool for f in findings]
    assert findings[0].tool == "semgrep"


@pytest.mark.asyncio
async def test_scout_returns_empty_when_semgrep_not_installed(
    tmp_path, monkeypatch, runnable_config
):
    """FileNotFoundError on semgrep → regex fallback runs; no strcpy in source → empty."""
    source = tmp_path / "t.cpp"
    source.write_text("int main(){return 0;}\n")  # no strcpy — regex fallback finds nothing
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    async def fake_exec(*args, **kwargs):
        if args[0] == "semgrep":
            raise FileNotFoundError("semgrep not installed")
        raise AssertionError(f"unexpected exec: {args[0]}")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    # Regex fallback runs but finds nothing in `int main(){return 0;}`.
    assert update["status"] == "classifying"
    assert update["findings"] == []


# ---------------------------------------------------------------------------
# Real integration test — exercises the full stack on Windows via the
# three-tier fallback: Semgrep binary → regex scanner → findings.
#
# Uses a local fixture with a generous timeout so the Semgrep attempt has
# time to complete before the regex fallback kicks in.
# ---------------------------------------------------------------------------


@pytest.fixture
def real_scan_runnable_config():
    """Generous timeout fixture for tests that spawn real processes."""
    from guardianloop.config import Config

    cfg = Config(scout_timeout_seconds=30)
    return {"configurable": {"gl_config": cfg}}


@pytest.mark.asyncio
async def test_scout_real_run_on_demo_cwe121(tmp_path, real_scan_runnable_config):
    """
    End-to-end integration test against samples/demo_cwe121.cpp.

    On platforms where semgrep-core works (Linux/CI), the finding comes from
    the real Semgrep binary.  On Windows where semgrep-core is broken, the
    regex fallback reads rules/cwe121-strcpy.yaml and detects the strcpy call
    directly.  Either way, at least one CWE-121 finding must be returned.
    """
    source = REPO_ROOT / "samples" / "demo_cwe121.cpp"
    assert source.exists(), f"demo sample missing: {source}"
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, real_scan_runnable_config)

    findings = update["findings"]
    assert len(findings) >= 1, (
        f"Scout produced zero findings on demo_cwe121.cpp. "
        f"Semgrep rules dir: {_RULES_DIR}"
    )
    cwes = [f.cwe_id for f in findings if f.cwe_id]
    assert any(c in {"CWE-121", "CWE-787"} for c in cwes), (
        f"Expected CWE-121 or CWE-787, got: {cwes} "
        f"(rules={[f.rule_id for f in findings]})"
    )
