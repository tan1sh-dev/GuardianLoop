from __future__ import annotations

from pathlib import Path

import pytest

from guardianloop.config import load_config


@pytest.fixture
def isolated_env(monkeypatch):
    """
    Isolate from both process env and any on-disk .env file.

    load_config() calls load_dotenv(), which would re-populate GOOGLE_API_KEY
    etc. from the repo's .env right after we delenv them. Stub it to a no-op
    so the test sees only the env we explicitly set via monkeypatch.
    """
    monkeypatch.setattr("guardianloop.config.load_dotenv", lambda *a, **k: False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)


def test_defaults_without_yaml(tmp_path: Path, isolated_env):
    cfg = load_config(config_path=tmp_path / "does_not_exist.yaml")
    assert cfg.model_name == "gemini-2.5-pro"
    assert cfg.fixer_model == "gemini-2.5-pro"
    assert cfg.classifier_model == "gemini-2.5-flash"
    assert cfg.max_loop_iterations == 3
    assert cfg.google_api_key is None
    assert cfg.nvd_api_key is None


def test_yaml_overrides_defaults(tmp_path: Path, isolated_env):
    yaml_path = tmp_path / "config.yaml"
    yaml_path.write_text(
        "max_loop_iterations: 5\nmodel_name: 'gemini-custom'\n", encoding="utf-8"
    )
    cfg = load_config(config_path=yaml_path)
    assert cfg.max_loop_iterations == 5
    assert cfg.model_name == "gemini-custom"


def test_env_picks_up_secrets(tmp_path: Path, monkeypatch):
    # load_dotenv stays real here, but monkeypatch.setenv takes precedence
    # because load_dotenv() defaults to override=False.
    monkeypatch.setenv("GOOGLE_API_KEY", "sekret")
    monkeypatch.setenv("NVD_API_KEY", "nvd-key")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "hook")
    cfg = load_config(config_path=tmp_path / "none.yaml")
    assert cfg.google_api_key == "sekret"
    assert cfg.nvd_api_key == "nvd-key"
    assert cfg.github_webhook_secret == "hook"
