"""
Config loader: reads config.yaml for tunables + .env for secrets.

Tunables are public and committed. Secrets (GOOGLE_API_KEY, NVD_API_KEY,
GITHUB_WEBHOOK_SECRET) are loaded from environment variables and never
written to config.yaml.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = _REPO_ROOT / "config.yaml"


class Config(BaseModel):
    model_name: str = "gemini-2.5-pro"
    fixer_model: str = "gemini-2.5-pro"
    classifier_model: str = "gemini-2.5-flash"

    max_loop_iterations: int = Field(default=3, ge=1, le=10)

    scout_timeout_seconds: int = 60
    gemini_timeout_seconds: int = 120
    sandbox_timeout_seconds: int = 30
    nvd_timeout_seconds: int = 10

    python_sandbox_image: str = "guardianloop/python-sandbox:latest"
    cpp_sandbox_image: str = "guardianloop/cpp-sandbox:latest"

    nvd_rate_limit_without_key: int = 5
    nvd_rate_limit_with_key: int = 50

    runs_dir: str = "./runs"

    google_api_key: str | None = None
    nvd_api_key: str | None = None
    github_webhook_secret: str | None = None
    semgrep_app_token: str | None = None


def load_config(config_path: Path | None = None) -> Config:
    """Load config.yaml if present, overlay secrets from environment."""
    load_dotenv()
    path = config_path or DEFAULT_CONFIG_PATH
    data: dict = {}
    if path.exists():
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    data["google_api_key"] = os.getenv("GOOGLE_API_KEY") or None
    data["nvd_api_key"] = os.getenv("NVD_API_KEY") or None
    data["github_webhook_secret"] = os.getenv("GITHUB_WEBHOOK_SECRET") or None
    data["semgrep_app_token"] = os.getenv("SEMGREP_APP_TOKEN") or None
    return Config(**data)
