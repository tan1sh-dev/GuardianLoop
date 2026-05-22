"""
Config loader: reads config.yaml for tunables + .env for secrets.

Tunables are public and committed. Secrets (GOOGLE_API_KEY, NVD_API_KEY,
GITHUB_WEBHOOK_SECRET) are loaded from environment variables and never
written to config.yaml.

Multi-key rotation: the Fixer agent can use multiple Gemini API keys to
work around free-tier daily quotas. Set any combination of:
    GOOGLE_API_KEY=...
    GOOGLE_API_KEY_2=...
    GOOGLE_API_KEY_3=...
    ...
or pass a comma-separated list via:
    GOOGLE_API_KEYS=key1,key2,key3
All discovered keys are collected into ``Config.google_api_keys`` and the
Fixer cycles through them when one hits a 429 quota.
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
    fixer_fallback_model: str = "gemini-2.5-flash"
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

    # Primary key (kept for backwards compatibility with existing call sites
    # and tests). Equal to ``google_api_keys[0]`` when keys are configured.
    google_api_key: str | None = None
    # Full rotation list — populated from GOOGLE_API_KEY, GOOGLE_API_KEY_N,
    # and GOOGLE_API_KEYS (comma-sep) at load time. De-duplicated, order
    # preserved.
    google_api_keys: list[str] = Field(default_factory=list)

    nvd_api_key: str | None = None
    github_webhook_secret: str | None = None
    semgrep_app_token: str | None = None


def _collect_google_keys() -> list[str]:
    """
    Discover every Gemini API key from the environment, preserving the order:
      1. GOOGLE_API_KEY
      2. GOOGLE_API_KEY_2, GOOGLE_API_KEY_3, ... (scan up to _20)
      3. GOOGLE_API_KEYS (comma-separated, appended last)

    Empty values are skipped. Duplicates are removed while preserving order.
    """
    found: list[str] = []

    primary = os.getenv("GOOGLE_API_KEY") or ""
    if primary.strip():
        found.append(primary.strip())

    for i in range(2, 21):
        v = os.getenv(f"GOOGLE_API_KEY_{i}") or ""
        if v.strip():
            found.append(v.strip())

    bulk = os.getenv("GOOGLE_API_KEYS") or ""
    if bulk.strip():
        for k in bulk.split(","):
            k = k.strip()
            if k:
                found.append(k)

    # De-duplicate, keep first occurrence
    seen: set[str] = set()
    uniq: list[str] = []
    for k in found:
        if k not in seen:
            seen.add(k)
            uniq.append(k)
    return uniq


def load_config(config_path: Path | None = None) -> Config:
    """Load config.yaml if present, overlay secrets from environment."""
    load_dotenv()
    path = config_path or DEFAULT_CONFIG_PATH
    data: dict = {}
    if path.exists():
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

    keys = _collect_google_keys()
    data["google_api_keys"] = keys
    data["google_api_key"] = keys[0] if keys else None

    data["nvd_api_key"] = os.getenv("NVD_API_KEY") or None
    data["github_webhook_secret"] = os.getenv("GITHUB_WEBHOOK_SECRET") or None
    data["semgrep_app_token"] = os.getenv("SEMGREP_APP_TOKEN") or None
    return Config(**data)
