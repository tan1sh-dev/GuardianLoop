"""
LangGraph wiring for GuardianLoop.

Topology:
    scout -> classifier -> fixer -> red_team
                                       |
                                       +--[any exploit still reproduces
                                       |   AND loop_count+1 < max]--> increment_loop -> fixer
                                       |
                                       +--[otherwise]-----------------> report -> END
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, StateGraph

from guardianloop.agents.classifier import classifier_node
from guardianloop.agents.fixer import fixer_node
from guardianloop.agents.red_team import red_team_node
from guardianloop.agents.scout import scout_node
from guardianloop.config import Config
from guardianloop.logging_setup import get_agent_logger
from guardianloop.reporting.json_report import write_json_artifacts
from guardianloop.reporting.markdown_report import write_markdown_report
from guardianloop.reporting.sarif_report import write_sarif_artifact
from guardianloop.state import PipelineState


async def increment_loop_node(state: PipelineState) -> dict:
    """Tiny node that bumps loop_count before re-entering Fixer."""
    return {"loop_count": state.loop_count + 1, "status": "fixing"}


async def report_node(state: PipelineState, config: RunnableConfig) -> dict:
    """Terminal node. Writes run_summary.json, findings.json, patches.json, report.md, report.sarif."""
    state.status = "complete"  # Mutate state so artifacts capture the final status
    logger = get_agent_logger(state.run_dir, "report")
    logger.info("report.start", run_dir=str(state.run_dir))
    write_json_artifacts(state)
    write_markdown_report(state)
    write_sarif_artifact(state)
    logger.info("report.done", run_dir=str(state.run_dir))
    return {"status": "complete"}


def route_after_red_team(state: PipelineState, config: RunnableConfig) -> str:
    """Loop back to Fixer if any exploit still reproduces and we haven't hit the cap."""
    gl: Config = config["configurable"]["gl_config"]
    reproduced = any(
        v.exploit_reproduced and v.patch_iteration == state.loop_count
        for v in state.verification_results
    )
    if reproduced and state.loop_count + 1 < gl.max_loop_iterations:
        return "retry"
    return "done"


def build_graph():
    g = StateGraph(PipelineState)
    g.add_node("scout", scout_node)
    g.add_node("classifier", classifier_node)
    g.add_node("fixer", fixer_node)
    g.add_node("red_team", red_team_node)
    g.add_node("increment_loop", increment_loop_node)
    g.add_node("report", report_node)

    g.set_entry_point("scout")
    g.add_edge("scout", "classifier")
    g.add_edge("classifier", "fixer")
    g.add_edge("fixer", "red_team")
    g.add_conditional_edges(
        "red_team",
        route_after_red_team,
        {"retry": "increment_loop", "done": "report"},
    )
    g.add_edge("increment_loop", "fixer")
    g.add_edge("report", END)
    return g.compile()


def make_run_dir(root: str) -> Path:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(root) / ts
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir
