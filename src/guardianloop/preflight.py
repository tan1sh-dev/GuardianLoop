"""
Preflight configuration checks.

Validates the environment and configuration before starting the pipeline.
Fails fast if keys are missing or invalid, preventing 2 minutes of scanning
before discovering a bad key.
"""

from __future__ import annotations

import asyncio
from typing import NamedTuple

from google import genai
from google.genai.errors import APIError

from guardianloop.config import Config


class PreflightResult(NamedTuple):
    is_valid: bool
    errors: list[str]
    warnings: list[str]


async def _check_gemini_key(api_key: str) -> str | None:
    """Returns an error message if the key is invalid, else None."""
    try:
        # A lightweight call to validate the key
        client = genai.Client(api_key=api_key)
        # Just listing models is a cheap way to verify auth
        # Running sync call in thread
        await asyncio.to_thread(client.models.list)
        return None
    except APIError as e:
        return f"Gemini API Error: {str(e)}"
    except Exception as e:
        return f"Failed to validate Gemini API key: {str(e)}"


async def validate_config(cfg: Config) -> PreflightResult:
    """
    Validate the configuration.
    Returns (is_valid, errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Check model config
    if cfg.fixer_model == cfg.fixer_fallback_model:
        warnings.append(
            f"fixer_model and fixer_fallback_model are both set to '{cfg.fixer_model}'. "
            "The fallback cascade will provide no benefit."
        )

    # Check keys
    keys = list(cfg.google_api_keys or ([] if not cfg.google_api_key else [cfg.google_api_key]))
    if not keys:
        errors.append(
            "No Gemini API keys configured. Set GOOGLE_API_KEY (and "
            "optionally GOOGLE_API_KEY_2, _3, ... or GOOGLE_API_KEYS=a,b,c)."
        )
    else:
        # Just check the first key to ensure the format/auth is generally correct
        first_key = keys[0]
        err = await _check_gemini_key(first_key)
        if err:
            errors.append(f"Primary GOOGLE_API_KEY is invalid: {err}")

    return PreflightResult(len(errors) == 0, errors, warnings)
