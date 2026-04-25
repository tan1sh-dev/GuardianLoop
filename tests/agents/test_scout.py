from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from guardianloop.agents.scout import _detect_language, scout_node
from guardianloop.state import PipelineState

SEMGREP_SAMPLE = json.dumps(
    {
        "results": [
            {
                "check_id": "test.cwe121.strcpy",
                "start": {"line": 12},
                "end": {"line": 14},
                "extra": {
                    "severity": "ERROR",
                    "message": "strcpy into fixed buffer",
                    "metadata": {"cwe": ["CWE-121: Stack-based buffer overflow"]},
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
    def __init__(self, stdout: bytes) -> None:
        self._stdout = stdout

    async def communicate(self):
        return self._stdout, b""

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return 0


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

    async def fake_exec(*args, **kwargs):
        if args[0] == "semgrep":
            return _FakeProc(SEMGREP_SAMPLE)
        if args[0] == "bandit":
            raise AssertionError("bandit should not run on C++ files")
        return _FakeProc(b"{}")

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


@pytest.mark.asyncio
async def test_scout_on_python_runs_both_tools(tmp_path, monkeypatch, runnable_config):
    source = tmp_path / "t.py"
    source.write_text("x=1\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    calls: list[str] = []

    async def fake_exec(*args, **kwargs):
        calls.append(args[0])
        if args[0] == "semgrep":
            return _FakeProc(b'{"results": []}')
        if args[0] == "bandit":
            return _FakeProc(BANDIT_SAMPLE)
        return _FakeProc(b"{}")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    assert sorted(calls) == ["bandit", "semgrep"]
    assert update["language"] == "python"
    assert any(f.tool == "bandit" and f.cwe_id == "CWE-89" for f in update["findings"])
