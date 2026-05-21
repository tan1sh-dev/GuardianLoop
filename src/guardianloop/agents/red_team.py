"""
Red-Team — exploit verification.

Primary path: write the patched code + an exploit harness into a temp dir, run
it inside the language-appropriate sandbox image, and decide whether the
exploit reproduced via exit-code or AddressSanitizer output.

Fallback path (Day 1 behaviour): if the Docker daemon isn't running or the
sandbox image isn't built, re-run Scout's SAST tools against the patched code
and treat any finding with the same CWE as "exploit reproduced".
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path

from langchain_core.runnables import RunnableConfig

from guardianloop.config import Config
from guardianloop.logging_setup import get_agent_logger
from guardianloop.sandbox.docker_runner import is_docker_available, run_exploit_in_sandbox
from guardianloop.state import Finding, PipelineState, VerificationResult


def _find_finding(state: PipelineState, finding_id: str) -> Finding | None:
    for ef in state.enriched_findings:
        if ef.finding.id == finding_id:
            return ef.finding
    return None


def _suffix_for_language(language: str) -> str:
    if language == "python":
        return ".py"
    if language == "cpp":
        return ".cpp"
    return ".txt"


async def _scout_rescan(
    *,
    finding: Finding,
    patched_code: str,
    timeout: int,
    logger,
) -> dict:
    """
    Re-run Scout's SAST tools against the patched code. If a finding with the
    same CWE still appears, treat the exploit as reproduced.
    """
    from guardianloop.agents.scout import (
        _detect_language,
        _run_semgrep,
    )

    suffix = _suffix_for_language(finding.language)
    start = time.monotonic()

    # delete=False so the file remains readable on Windows while the subprocess runs.
    fh = tempfile.NamedTemporaryFile(
        prefix="guardianloop-rescan-", suffix=suffix, mode="w", delete=False, encoding="utf-8"
    )
    try:
        fh.write(patched_code)
        fh.close()
        tmp = Path(fh.name)
        language = _detect_language(tmp)

        all_findings = await _run_semgrep(tmp, timeout, language, None, logger)
        same_cwe = [f for f in all_findings if f.cwe_id == finding.cwe_id]
        reproduced = bool(same_cwe)
        return {
            "exploit_reproduced": reproduced,
            "stdout": (
                f"scout_rescan: {len(all_findings)} findings, "
                f"{len(same_cwe)} matching CWE {finding.cwe_id}"
            ),
            "stderr": "",
            "exit_code": 0,
            "duration": time.monotonic() - start,
        }
    finally:
        try:
            Path(fh.name).unlink()
        except OSError:
            pass


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

        docker_ok = await asyncio.to_thread(is_docker_available, image)

        if docker_ok:
            logger.info(
                "red_team.verify_start",
                path="docker",
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
            # Belt-and-suspenders: docker_runner returned a not-available signal.
            if result.get("docker_available") is False:
                logger.info(
                    "red_team.docker_unavailable_at_runtime_falling_back",
                    finding_id=patch.finding_id,
                    stderr=(result.get("stderr") or "")[:200],
                )
                result = await _scout_rescan(
                    finding=finding,
                    patched_code=patch.patched_code,
                    timeout=gl.scout_timeout_seconds,
                    logger=logger,
                )
        else:
            logger.info(
                "red_team.verify_start",
                path="scout_fallback",
                finding_id=patch.finding_id,
                iteration=patch.iteration,
                image=image,
                reason="docker_unavailable_or_image_missing",
            )
            result = await _scout_rescan(
                finding=finding,
                patched_code=patch.patched_code,
                timeout=gl.scout_timeout_seconds,
                logger=logger,
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
