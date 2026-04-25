from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from guardianloop.graph import build_graph
from guardianloop.state import PipelineState


class _FakeProc:
    def __init__(self, stdout: bytes) -> None:
        self._stdout = stdout

    async def communicate(self):
        return self._stdout, b""

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return 0


@pytest.mark.asyncio
async def test_graph_reaches_report_node_when_patch_holds(
    monkeypatch, tmp_path, fake_config
):
    source = tmp_path / "sample.cpp"
    source.write_text("int main(){return 0;}\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    semgrep_out = json.dumps(
        {
            "results": [
                {
                    "check_id": "test.cwe121",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {
                        "severity": "ERROR",
                        "message": "overflow",
                        "metadata": {"cwe": ["CWE-121"]},
                    },
                }
            ]
        }
    ).encode()

    async def fake_exec(*args, **kwargs):
        return _FakeProc(semgrep_out)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

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

    fake_resp = MagicMock()
    fake_resp.text = json.dumps(
        {
            "reasoning_chain": ["what", "why", "invariant", "change", "exploit"],
            "patched_code": "int main(){return 1;}\n",
        }
    )
    fake_client = MagicMock()
    fake_client.aio.models.generate_content = AsyncMock(return_value=fake_resp)
    monkeypatch.setattr("google.genai.Client", lambda *a, **k: fake_client)

    monkeypatch.setattr(
        "guardianloop.agents.red_team.run_exploit_in_sandbox",
        lambda **kw: {
            "exploit_reproduced": False,
            "stdout": "ok",
            "stderr": "",
            "exit_code": 0,
            "duration": 0.1,
        },
    )

    app = build_graph()
    initial = PipelineState(source_file=source, run_dir=run_dir)
    final = await app.ainvoke(
        initial,
        config={"configurable": {"gl_config": fake_config}, "recursion_limit": 50},
    )

    status = final.get("status") if isinstance(final, dict) else getattr(final, "status", None)
    assert status == "complete"
    assert (run_dir / "run_summary.json").exists()
    assert (run_dir / "report.md").exists()

    summary = json.loads((run_dir / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["totals"]["findings"] >= 1
    assert summary["totals"]["patches_held"] == 1
    assert summary["totals"]["patches_failed"] == 0
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "## What" in report
    assert "## Why" in report
    assert "## How" in report


@pytest.mark.asyncio
async def test_graph_loops_when_exploit_keeps_reproducing(
    monkeypatch, tmp_path, fake_config
):
    source = tmp_path / "sample.cpp"
    source.write_text("int main(){return 0;}\n")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    semgrep_out = json.dumps(
        {
            "results": [
                {
                    "check_id": "test.cwe121",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {
                        "severity": "ERROR",
                        "message": "overflow",
                        "metadata": {"cwe": ["CWE-121"]},
                    },
                }
            ]
        }
    ).encode()

    async def fake_exec(*args, **kwargs):
        return _FakeProc(semgrep_out)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    class _FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, *a, **k):
            resp = MagicMock()
            resp.status_code = 403
            resp.json = MagicMock(return_value={})
            return resp

    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: _FakeClient())

    async def _nosleep(*a, **k):
        return None

    monkeypatch.setattr(asyncio, "sleep", _nosleep)

    gemini_calls = {"n": 0}

    def _make_response(*a, **k):
        resp = MagicMock()
        resp.text = json.dumps(
            {
                "reasoning_chain": ["w", "y", "i", "c", "e"],
                "patched_code": f"int main(){{return {gemini_calls['n']};}}\n",
            }
        )
        gemini_calls["n"] += 1
        return resp

    fake_client = MagicMock()
    fake_client.aio.models.generate_content = AsyncMock(side_effect=_make_response)
    monkeypatch.setattr("google.genai.Client", lambda *a, **k: fake_client)

    monkeypatch.setattr(
        "guardianloop.agents.red_team.run_exploit_in_sandbox",
        lambda **kw: {
            "exploit_reproduced": True,
            "stdout": "",
            "stderr": "still exploitable",
            "exit_code": 42,
            "duration": 0.1,
        },
    )

    app = build_graph()
    initial = PipelineState(source_file=source, run_dir=run_dir)
    final = await app.ainvoke(
        initial,
        config={"configurable": {"gl_config": fake_config}, "recursion_limit": 50},
    )

    final_loop = (
        final.get("loop_count")
        if isinstance(final, dict)
        else getattr(final, "loop_count", None)
    )
    assert final_loop == fake_config.max_loop_iterations - 1
    # Fixer should have been called once per iteration (3 total).
    assert gemini_calls["n"] == fake_config.max_loop_iterations
