"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianloop.config import Config
from guardianloop.state import Finding


@pytest.fixture
def tmp_run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "run"
    d.mkdir()
    return d


@pytest.fixture
def fake_config() -> Config:
    return Config(
        model_name="gemini-2.5-pro",
        fixer_model="gemini-2.5-pro",
        classifier_model="gemini-2.5-flash",
        max_loop_iterations=3,
        scout_timeout_seconds=5,
        gemini_timeout_seconds=5,
        sandbox_timeout_seconds=5,
        nvd_timeout_seconds=2,
        python_sandbox_image="test/python:latest",
        cpp_sandbox_image="test/cpp:latest",
        runs_dir="./runs-test",
        google_api_key="test-gemini-key",
        nvd_api_key=None,
        github_webhook_secret="test-secret",
    )


@pytest.fixture
def runnable_config(fake_config: Config) -> dict:
    return {"configurable": {"gl_config": fake_config}}


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        id="abc123",
        tool="semgrep",
        rule_id="test.cwe121.strcpy",
        cwe_id="CWE-121",
        message="strcpy into fixed-size buffer",
        severity="HIGH",
        file_path="samples/demo_cwe121.cpp",
        line_start=10,
        line_end=12,
        snippet="strcpy(buf, input);",
        language="cpp",
    )
