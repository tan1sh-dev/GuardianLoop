"""
Red-Team — Docker sandbox exploit verification.

For each patch produced at the current iteration, write the patched code + an
exploit harness into a temp dir, run it in the language-appropriate sandbox
image, and record whether the exploit still reproduced.
"""

from __future__ import annotations

import asyncio

from langchain_core.runnables import RunnableConfig

from guardianloop.config import Config
from guardianloop.logging_setup import get_agent_logger
from guardianloop.sandbox.docker_runner import run_exploit_in_sandbox
from guardianloop.state import Finding, PipelineState, VerificationResult


def _find_finding(state: PipelineState, finding_id: str) -> Finding | None:
    for ef in state.enriched_findings:
        if ef.finding.id == finding_id:
            return ef.finding
    return None


async def red_team_node(state: PipelineState, config: RunnableConfig) -> dict:
    gl: Config = config["configurable"]["gl_config"]
    logger = get_agent_logger(state.run_dir, "red_team")

    patches_this_iter = [p for p in state.patches if p.iteration == state.loop_count]
    new_results: list[VerificationResult] = list(state.verification_results)

    logger.info(
        "red_team.start",
        iteration=state.loop_count,
        patches=len(patches_this_iter),
    )

    for patch in patches_this_iter:
        finding = _find_finding(state, patch.finding_id)
        if finding is None:
            logger.warning("red_team.orphan_patch", finding_id=patch.finding_id)
            continue
        image = (
            gl.python_sandbox_image
            if finding.language == "python"
            else gl.cpp_sandbox_image
        )
        logger.info(
            "red_team.verify_start",
            finding_id=patch.finding_id,
            iteration=patch.iteration,
            image=image,
        )

        result = await asyncio.to_thread(
            run_exploit_in_sandbox,
            language=finding.language,
            image=image,
            patched_code=patch.patched_code,
            finding=finding,
            timeout=gl.sandbox_timeout_seconds,
        )

        verification = VerificationResult(
            finding_id=patch.finding_id,
            patch_iteration=patch.iteration,
            exploit_reproduced=bool(result["exploit_reproduced"]),
            sandbox_stdout=(result.get("stdout") or "")[:8000],
            sandbox_stderr=(result.get("stderr") or "")[:8000],
            sandbox_exit_code=int(result.get("exit_code", 0) or 0),
            duration_seconds=float(result.get("duration", 0.0) or 0.0),
        )
        new_results = [
            v
            for v in new_results
            if not (
                v.finding_id == patch.finding_id
                and v.patch_iteration == patch.iteration
            )
        ]
        new_results.append(verification)
        logger.info(
            "red_team.verify_done",
            finding_id=patch.finding_id,
            reproduced=verification.exploit_reproduced,
            exit_code=verification.sandbox_exit_code,
        )

    return {"verification_results": new_results, "status": "reporting"}
