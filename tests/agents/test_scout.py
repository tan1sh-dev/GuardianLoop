from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from guardianloop.agents.scout import _detect_language, scout_node
from guardianloop.state import PipelineState

REPO_ROOT = Path(__file__).resolve().parents[2]

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

    captured: dict = {}

    async def fake_exec(*args, **kwargs):
        if args[0] == "semgrep":
            captured["semgrep_args"] = args
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
    # Confirms language-aware pack selection.
    assert "--config=p/cpp" in captured["semgrep_args"]


@pytest.mark.asyncio
async def test_scout_on_python_runs_both_tools(tmp_path, monkeypatch, runnable_config):
    source = tmp_path / "t.py"
    source.write_text("x=1\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    calls: list[tuple] = []

    async def fake_exec(*args, **kwargs):
        calls.append(args)
        if args[0] == "semgrep":
            return _FakeProc(b'{"results": []}')
        if args[0] == "bandit":
            return _FakeProc(BANDIT_SAMPLE)
        return _FakeProc(b"{}")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    tool_names = sorted(c[0] for c in calls)
    assert tool_names == ["bandit", "semgrep"]
    # Python files use the python pack.
    semgrep_args = next(c for c in calls if c[0] == "semgrep")
    assert "--config=p/python" in semgrep_args
    assert update["language"] == "python"
    assert any(f.tool == "bandit" and f.cwe_id == "CWE-89" for f in update["findings"])


@pytest.mark.asyncio
async def test_scout_dedup_drops_bandit_on_semgrep_line(
    tmp_path, monkeypatch, runnable_config
):
    """Bandit and Semgrep flagging the same line → keep only the Semgrep finding."""
    source = tmp_path / "t.py"
    source.write_text("import sqlite3\nq = f\"SELECT {x}\"\n")
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
                        "metadata": {"cwe": ["CWE-89"]},
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
            return _FakeProc(semgrep_at_line2)
        return _FakeProc(bandit_at_line2)

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
    """FileNotFoundError on `semgrep` exec → warn and return empty, don't crash."""
    source = tmp_path / "t.cpp"
    source.write_text("int main(){return 0;}\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    async def fake_exec(*args, **kwargs):
        if args[0] == "semgrep":
            raise FileNotFoundError("semgrep not installed")
        raise AssertionError(f"unexpected exec: {args[0]}")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    assert update["status"] == "classifying"
    assert update["findings"] == []


# ---------------------------------------------------------------------------
# Real integration test against samples/demo_cwe121.cpp.
#
# Semgrep-core (the OCaml engine) is not natively supported on Windows; it
# requires WSL2. We probe at module load and skip with a clear reason if
# the engine cannot scan C++ on this host.
# ---------------------------------------------------------------------------


def _probe_semgrep_cpp() -> tuple[bool, str]:
    if shutil.which("semgrep") is None:
        return False, "semgrep binary not on PATH"
    with tempfile.NamedTemporaryFile(
        suffix=".cpp", mode="w", delete=False, encoding="utf-8"
    ) as tf:
        tf.write("int main(){return 0;}\n")
        probe_path = tf.name
    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        p = subprocess.run(
            [
                "semgrep", "scan",
                "--config=p/cpp",
                "--json", "--quiet", "--metrics=off",
                probe_path,
            ],
            capture_output=True, timeout=180, env=env,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"probe failed: {e}"
    finally:
        try:
            os.unlink(probe_path)
        except OSError:
            pass
    if p.returncode != 0:
        return False, f"semgrep exited {p.returncode} (likely semgrep-core unavailable)"
    if not p.stdout.strip().startswith(b"{"):
        return False, "semgrep produced no JSON output"
    return True, ""


_SEMGREP_OK, _SEMGREP_SKIP_REASON = _probe_semgrep_cpp()


@pytest.mark.skipif(
    not _SEMGREP_OK,
    reason=f"Semgrep cannot scan C++ on this host: {_SEMGREP_SKIP_REASON}",
)
@pytest.mark.asyncio
async def test_scout_real_run_on_demo_cwe121(tmp_path, runnable_config):
    """End-to-end: run real Semgrep on the bundled CWE-121 demo."""
    source = REPO_ROOT / "samples" / "demo_cwe121.cpp"
    assert source.exists(), f"demo sample missing: {source}"
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    state = PipelineState(source_file=source, run_dir=run_dir)
    update = await scout_node(state, runnable_config)

    findings = update["findings"]
    assert len(findings) >= 1, "Scout produced zero findings on demo_cwe121.cpp"
    cwes = [f.cwe_id for f in findings if f.cwe_id]
    assert any(c in {"CWE-121", "CWE-787"} for c in cwes), (
        f"expected CWE-121 or CWE-787 in findings, got CWEs={cwes} "
        f"(rules={[f.rule_id for f in findings]})"
    )
