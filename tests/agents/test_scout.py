from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from guardianloop.agents.scout import _detect_language, _semgrep_cmd, _win_to_wsl_path, scout_node
from guardianloop.state import PipelineState

REPO_ROOT = Path(__file__).resolve().parents[2]

# Semgrep JSON output as produced by ``--config p/default``.
SEMGREP_SAMPLE = json.dumps(
    {
        "results": [
            {
                "check_id": "c.lang.security.insecure-use-strcpy-fn",
                "start": {"line": 12},
                "end": {"line": 14},
                "extra": {
                    "severity": "ERROR",
                    "message": "Use of unsafe strcpy",
                    "metadata": {"cwe": ["CWE-121: Buffer Copy Without Checking Size of Input"]},
                },
            }
        ]
    }
).encode()

SEMGREP_EMPTY = json.dumps({"results": []}).encode()


class _FakeProc:
    """Minimal asyncio.subprocess.Process stand-in."""

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


def test_win_to_wsl_path():
    import sys
    if sys.platform != "win32":
        pytest.skip("WSL path conversion only applies on Windows")
    p = Path("E:/GuardianLoop/samples/demo.cpp")
    wsl = _win_to_wsl_path(p)
    assert wsl.startswith("/mnt/e/")
    assert "GuardianLoop" in wsl


@pytest.mark.asyncio
async def test_scout_semgrep_returns_findings(tmp_path, monkeypatch, runnable_config):
    source = tmp_path / "t.cpp"
    source.write_text("int main(){return 0;}\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    exec_calls: list[tuple] = []

    async def fake_exec(*args, **kwargs):
        exec_calls.append(args)
        return _FakeProc(SEMGREP_SAMPLE, returncode=1)  # rc=1 = findings present

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    assert update["status"] == "classifying"
    assert len(update["findings"]) == 1
    f = update["findings"][0]
    assert f.tool == "semgrep"
    assert f.cwe_id == "CWE-121"
    assert f.severity == "HIGH"
    # Only one subprocess call — no Bandit, no fallback
    assert len(exec_calls) == 1


@pytest.mark.asyncio
async def test_scout_semgrep_clean_returns_empty(tmp_path, monkeypatch, runnable_config):
    """rc=0 with empty results list → empty findings, no error."""
    source = tmp_path / "t.py"
    source.write_text("x = 1\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    async def fake_exec(*args, **kwargs):
        return _FakeProc(SEMGREP_EMPTY, returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    assert update["findings"] == []
    assert update["status"] == "classifying"


@pytest.mark.asyncio
async def test_scout_semgrep_not_installed(tmp_path, monkeypatch, runnable_config):
    """FileNotFoundError (WSL/semgrep not installed) → empty findings, no crash."""
    source = tmp_path / "t.cpp"
    source.write_text("int main(){return 0;}\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    async def fake_exec(*args, **kwargs):
        raise FileNotFoundError("wsl not found")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    assert update["findings"] == []
    assert update["status"] == "classifying"


@pytest.mark.asyncio
async def test_scout_semgrep_error_exit(tmp_path, monkeypatch, runnable_config):
    """Non-zero rc other than 1 → treated as error, empty findings returned."""
    source = tmp_path / "t.cpp"
    source.write_text("int main(){return 0;}\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    async def fake_exec(*args, **kwargs):
        return _FakeProc(b"<crash>", returncode=2)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    assert update["findings"] == []


@pytest.mark.asyncio
async def test_scout_semgrep_timeout(tmp_path, monkeypatch, runnable_config):
    """Timeout → kill process, return empty findings."""
    source = tmp_path / "t.cpp"
    source.write_text("int main(){return 0;}\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    async def fake_exec(*args, **kwargs):
        return _FakeProc(b"", returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(asyncio, "wait_for", _timeout_raiser)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    assert update["findings"] == []


async def _timeout_raiser(coro, timeout):
    raise asyncio.TimeoutError()


# ---------------------------------------------------------------------------
# Real integration test — exercises the full stack via WSL
# ---------------------------------------------------------------------------


@pytest.fixture
def real_scan_config():
    from guardianloop.config import Config
    return {"configurable": {"gl_config": Config(scout_timeout_seconds=120)}}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_scout_real_run_on_demo_cwe121(tmp_path, real_scan_config):
    """
    End-to-end integration test against samples/demo_cwe121.cpp.

    Requires Semgrep installed in WSL Ubuntu (Linux) or natively (CI).
    Skip with: pytest -m "not integration"
    """
    source = REPO_ROOT / "samples" / "demo_cwe121.cpp"
    assert source.exists(), f"demo sample missing: {source}"
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, real_scan_config)

    findings = update["findings"]
    assert len(findings) >= 1, "Scout returned zero findings on demo_cwe121.cpp"
    cwes = [f.cwe_id for f in findings if f.cwe_id]
    # p/default catches strcpy/buffer issues under several CWE IDs
    known = {"CWE-121", "CWE-787", "CWE-119", "CWE-120"}
    assert any(c in known for c in cwes), f"Expected a buffer-overflow CWE, got: {cwes}"
