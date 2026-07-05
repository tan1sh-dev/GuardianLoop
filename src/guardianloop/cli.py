"""
Command-line entrypoint. Day 1 accepts a local file path only.

Usage:
    python -m guardianloop.cli samples/demo_cwe121.cpp
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from guardianloop.config import load_config
from guardianloop.graph import build_graph, make_run_dir
from guardianloop.ingress.local import ingest_local
from guardianloop.logging_setup import configure_logging, get_agent_logger
from guardianloop.state import PipelineState


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="guardianloop",
        description="Run the GuardianLoop pipeline on a local source file.",
    )
    parser.add_argument(
        "source",
        type=Path,
        help="Path to the file to scan (C++ or Python).",
    )
    args = parser.parse_args(argv)
    return asyncio.run(_run(args.source))


async def _run(source: Path) -> int:
    cfg = load_config()
    run_dir = make_run_dir(cfg.runs_dir)
    configure_logging(run_dir)
    logger = get_agent_logger(run_dir, "cli")
    logger.info("pipeline.start", source=str(source), run_dir=str(run_dir))

    from guardianloop.preflight import validate_config
    preflight = await validate_config(cfg)
    for warning in preflight.warnings:
        logger.warning("preflight.warning", msg=warning)
        print(f"WARNING: {warning}")
    if not preflight.is_valid:
        for err in preflight.errors:
            logger.error("preflight.error", msg=err)
            print(f"ERROR: {err}")
        return 1

    try:
        source_path = ingest_local(source)
    except Exception as e:
        logger.error("pipeline.ingress_error", error=str(e))
        return 2

    initial = PipelineState(source_file=source_path, run_dir=run_dir)
    app = build_graph()
    final = await app.ainvoke(
        initial,
        config={"configurable": {"gl_config": cfg}, "recursion_limit": 50},
    )

    status = final.get("status") if isinstance(final, dict) else getattr(final, "status", "unknown")
    logger.info("pipeline.done", status=status, run_dir=str(run_dir))
    print(f"Run complete: {run_dir} (status: {status})")
    return 0 if status == "complete" else 1


if __name__ == "__main__":
    sys.exit(main())
