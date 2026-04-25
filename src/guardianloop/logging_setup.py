"""
structlog configuration. Every agent gets a logger bound to its name that
writes JSON events to runs/<timestamp>/<agent>.log (in addition to stderr).

Agents must not use print() or the stdlib logging module directly.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import structlog

_CONFIGURED = False


def configure_logging(run_dir: Path) -> None:
    """One-time global structlog + stdlib bootstrap. Idempotent."""
    global _CONFIGURED
    run_dir.mkdir(parents=True, exist_ok=True)
    if _CONFIGURED:
        return

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    has_stderr = any(
        isinstance(h, logging.StreamHandler) and getattr(h, "stream", None) is sys.stderr
        for h in root.handlers
    )
    if not has_stderr:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(sh)

    _CONFIGURED = True


def get_agent_logger(run_dir: Path, agent_name: str) -> structlog.BoundLogger:
    """
    Return a structlog logger bound to ``agent_name`` that writes JSON to
    ``runs/<ts>/<agent>.log`` in addition to the shared stderr stream.
    """
    configure_logging(run_dir)

    stdlib_logger = logging.getLogger(f"guardianloop.{agent_name}")
    stdlib_logger.setLevel(logging.INFO)

    log_path = run_dir / f"{agent_name}.log"
    already_attached = any(
        getattr(h, "baseFilename", None) == str(log_path) for h in stdlib_logger.handlers
    )
    if not already_attached:
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(message)s"))
        stdlib_logger.addHandler(fh)

    return structlog.wrap_logger(stdlib_logger).bind(agent=agent_name)
