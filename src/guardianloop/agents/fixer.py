"""
Fixer — Gemini 2.5 Pro chain-of-thought patch generator.

On iteration 0, every enriched finding gets a patch attempt.
On iteration N>0, only findings whose prior verification still reproduced the
exploit get re-patched; the failed sandbox output is fed back into the prompt.

The model is asked to respond with REASONING: / PATCHED_CODE: marker blocks.
Each finding gets up to two LLM attempts — transient parse or network errors
trigger one retry. The response parser also accepts a JSON fallback so older
prompts (and the test fixtures) keep working.

Uses the modern ``google-genai`` SDK (``from google import genai``). The legacy
``google-generativeai`` package is deprecated and must not be used.
"""

from __future__ import annotations

import asyncio
import difflib
import json
import re

from google import genai
from google.genai import types
from langchain_core.runnables import RunnableConfig

from guardianloop.config import Config
from guardianloop.logging_setup import get_agent_logger
from guardianloop.state import EnrichedFinding, Patch, PipelineState, VerificationResult

MAX_ATTEMPTS = 2

FIXER_SYSTEM = (
    "You are GuardianLoop's Fixer agent. Given a vulnerable source file and a "
    "vulnerability finding, produce a minimally-invasive patch that eliminates "
    "the vulnerability while preserving intended behavior. Think step by step."
)

_INSTRUCTIONS = """
Respond using exactly these two banner lines, each on its own line, in this order:

REASONING:
1. What the vulnerability is, in one sentence.
2. Why it is exploitable, with a concrete attack scenario.
3. What invariant the fix must establish.
4. The minimum code change to establish that invariant.
5. What an exploit would need to do to re-trigger the vulnerability,
   so the Red-Team agent knows what to try.

PATCHED_CODE:
<full replacement contents of the file — no fences, no commentary, no diff markers>

The five numbered points are required. Do not wrap PATCHED_CODE in backticks.
"""


def _make_client(api_key: str) -> genai.Client:
    """Single chokepoint for SDK construction so tests can monkeypatch one symbol."""
    return genai.Client(api_key=api_key)


def _build_feedback_block(prior: Patch | None, prior_verif: VerificationResult | None) -> str:
    """Built via f-strings to avoid str.format() KeyError when sandbox output contains literal '{' or '}'."""
    if prior is None or prior_verif is None:
        return ""
    sandbox = (prior_verif.sandbox_stdout + "\n" + prior_verif.sandbox_stderr).strip()
    prev_reasoning = (
        "\n".join(f"  - {s}" for s in prior.reasoning_chain) or "  (none)"
    )
    sandbox_excerpt = sandbox[:2000] or "(empty)"
    return (
        "\nPRIOR ATTEMPT FAILED. The Red-Team sandbox still reproduced the exploit "
        "after your previous patch.\n"
        f"Previous iteration: {prior.iteration}\n"
        "Previous reasoning chain:\n"
        f"{prev_reasoning}\n"
        "Sandbox output (truncated):\n"
        f"{sandbox_excerpt}\n\n"
        "Your new patch must address the specific failure above.\n"
    )


def _build_prompt(
    ef: EnrichedFinding,
    source: str,
    prior: Patch | None,
    prior_verif: VerificationResult | None,
) -> str:
    """
    Built via f-strings, NOT str.format(), so arbitrary contents in ``source``
    (Python f-strings, C++ initializer lists, ASan output) cannot raise
    KeyError or accidentally interpolate.
    """
    f = ef.finding
    cvss_score = ef.cvss_score if ef.cvss_score is not None else "unknown"
    cvss_vector = ef.cvss_vector or "unknown"
    cwe = f.cwe_id or "unknown"
    exploitability = ef.exploitability_summary or "unknown"

    metadata = (
        f"File: {f.file_path}\n"
        f"Language: {f.language}\n\n"
        "Vulnerability:\n"
        f"- Tool: {f.tool}\n"
        f"- Rule: {f.rule_id}\n"
        f"- CWE: {cwe}\n"
        f"- Severity: {f.severity}\n"
        f"- CVSS score: {cvss_score}\n"
        f"- CVSS vector: {cvss_vector}\n"
        f"- Location: lines {f.line_start}-{f.line_end}\n"
        f"- Message: {f.message}\n"
        f"- Exploitability: {exploitability}\n\n"
    )
    fenced_source = (
        "Full source:\n"
        f"```{f.language}\n"
        f"{source}\n"
        "```\n"
    )
    feedback = _build_feedback_block(prior, prior_verif)
    return metadata + fenced_source + feedback + _INSTRUCTIONS


def _extract_json(text: str) -> dict:
    """Permissive JSON extractor — bare object, ```json fenced, or plain ``` fenced."""
    text = (text or "").strip()
    if text.startswith("```"):
        newline = text.find("\n")
        if newline != -1:
            text = text[newline + 1 :]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
        if text.lower().startswith("json"):
            text = text[4:].lstrip()
    return json.loads(text)


_REASONING_RE = re.compile(
    r"REASONING:\s*\n(.*?)(?=\nPATCHED_CODE:)",
    re.DOTALL | re.IGNORECASE,
)
_PATCH_RE = re.compile(r"PATCHED_CODE:\s*\n(.*)", re.DOTALL | re.IGNORECASE)
_NUMBERED_LINE_RE = re.compile(r"^\s*\d+[.)]\s*(.+?)\s*$")


def _parse_markers(text: str) -> dict:
    """Parse a REASONING: / PATCHED_CODE: response into the same shape _extract_json returns."""
    if not text:
        raise ValueError("empty response")
    r = _REASONING_RE.search(text)
    p = _PATCH_RE.search(text)
    if not r or not p:
        raise ValueError("missing REASONING or PATCHED_CODE markers")

    reasoning_block = r.group(1).strip()
    reasoning: list[str] = []
    current: list[str] = []
    for line in reasoning_block.splitlines():
        m = _NUMBERED_LINE_RE.match(line)
        if m:
            if current:
                reasoning.append(" ".join(current).strip())
                current = []
            current.append(m.group(1))
        elif line.strip() and current:
            current.append(line.strip())
    if current:
        reasoning.append(" ".join(current).strip())
    if not reasoning:
        reasoning = [ln.strip() for ln in reasoning_block.splitlines() if ln.strip()]

    patched = p.group(1).strip()
    # Strip a stray fence if the model added one despite instructions.
    if patched.startswith("```"):
        nl = patched.find("\n")
        if nl != -1:
            patched = patched[nl + 1 :]
    if patched.endswith("```"):
        patched = patched[:-3].rstrip("\r\n")

    return {"reasoning_chain": reasoning, "patched_code": patched}


def _parse_response(text: str) -> dict:
    """Try the markers format first; fall back to JSON for backward compatibility."""
    raw = (text or "").strip()
    if not raw:
        raise ValueError("empty response")

    # Sniff: if the body (past any leading fence) opens with '{', treat as JSON.
    body = raw
    if body.startswith("```"):
        nl = body.find("\n")
        if nl != -1:
            body = body[nl + 1 :].lstrip()
    if body.startswith("{"):
        return _extract_json(raw)
    return _parse_markers(raw)


def _unified_diff(original: str, patched: str, path: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def _latest_by_finding(items: list, key: str = "iteration") -> dict:
    latest: dict = {}
    for item in items:
        prev = latest.get(item.finding_id)
        if prev is None or getattr(item, key) > getattr(prev, key):
            latest[item.finding_id] = item
    return latest


async def _generate_with_retry(
    *,
    client: genai.Client,
    model: str,
    prompt: str,
    gen_config: types.GenerateContentConfig,
    timeout: int,
    logger,
    finding_id: str,
) -> dict:
    """Up to ``MAX_ATTEMPTS`` Gemini calls per finding. Returns the parsed dict or raises."""
    last_err: Exception | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            resp = await asyncio.wait_for(
                client.aio.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=gen_config,
                ),
                timeout=timeout,
            )
            data = _parse_response(resp.text or "")
            if not data.get("patched_code"):
                raise ValueError("model produced empty patched_code")
            return data
        except Exception as e:  # noqa: BLE001 — we log + retry, then re-raise.
            last_err = e
            err_str = str(e)
            # Parse retry-after hint from 429 responses; fall back to exponential backoff.
            retry_after = 2 ** attempt
            import re as _re
            m = _re.search(r"retry[_ ]in[^\d]*(\d+(?:\.\d+)?)\s*s", err_str, _re.I)
            if m:
                retry_after = min(float(m.group(1)), 120)
            logger.warning(
                "fixer.attempt_failed",
                finding_id=finding_id,
                attempt=attempt,
                of=MAX_ATTEMPTS,
                error=err_str,
                retry_after=retry_after if attempt < MAX_ATTEMPTS else None,
            )
            if attempt < MAX_ATTEMPTS:
                await asyncio.sleep(retry_after)
    raise last_err if last_err is not None else RuntimeError("fixer: unknown failure")


async def fixer_node(state: PipelineState, config: RunnableConfig) -> dict:
    gl: Config = config["configurable"]["gl_config"]
    logger = get_agent_logger(state.run_dir, "fixer")

    if not gl.google_api_key:
        logger.error("fixer.no_api_key")
        return {
            "status": "failed",
            "error": "GOOGLE_API_KEY is not set; Fixer cannot run.",
        }

    source = state.source_file.read_text(encoding="utf-8", errors="replace")
    new_patches: list[Patch] = list(state.patches)

    last_patch = _latest_by_finding(state.patches, "iteration")
    last_verif = _latest_by_finding(state.verification_results, "patch_iteration")

    logger.info(
        "fixer.start",
        iteration=state.loop_count,
        enriched=len(state.enriched_findings),
        model=gl.fixer_model,
    )

    # Lazy SDK init: on retry iterations where every prior patch held, we must
    # not touch genai at all. Tests assert this by monkeypatching genai.Client
    # to raise.
    client: genai.Client | None = None
    gen_config: types.GenerateContentConfig | None = None

    for ef in state.enriched_findings:
        f = ef.finding
        if state.loop_count > 0:
            prior_verif_check = last_verif.get(f.id)
            if prior_verif_check is not None and not prior_verif_check.exploit_reproduced:
                continue

        prior = last_patch.get(f.id)
        prior_verif = last_verif.get(f.id) if state.loop_count > 0 else None

        prompt = _build_prompt(ef, source, prior, prior_verif)
        logger.info("fixer.prompting", finding_id=f.id, iteration=state.loop_count)

        if client is None:
            client = _make_client(gl.google_api_key)
            gen_config = types.GenerateContentConfig(
                system_instruction=FIXER_SYSTEM,
                temperature=0.2,
            )

        try:
            data = await _generate_with_retry(
                client=client,
                model=gl.fixer_model,
                prompt=prompt,
                gen_config=gen_config,
                timeout=gl.gemini_timeout_seconds,
                logger=logger,
                finding_id=f.id,
            )
        except Exception as e:  # noqa: BLE001 — surface skips, don't fail the whole run.
            logger.error(
                "fixer.gave_up",
                finding_id=f.id,
                error=str(e),
                attempts=MAX_ATTEMPTS,
            )
            continue

        patched_code = data.get("patched_code") or ""
        reasoning = data.get("reasoning_chain") or []
        if not patched_code:
            logger.warning("fixer.empty_patch", finding_id=f.id)
            continue
        if not isinstance(reasoning, list):
            reasoning = [str(reasoning)]

        patch = Patch(
            finding_id=f.id,
            patched_code=patched_code,
            diff=_unified_diff(source, patched_code, f.file_path),
            reasoning_chain=[str(s) for s in reasoning],
            iteration=state.loop_count,
            model=gl.fixer_model,
        )
        new_patches = [
            p
            for p in new_patches
            if not (p.finding_id == f.id and p.iteration == state.loop_count)
        ]
        new_patches.append(patch)
        logger.info(
            "fixer.patch_ready",
            finding_id=f.id,
            iteration=state.loop_count,
            steps=len(patch.reasoning_chain),
        )

    return {"patches": new_patches, "status": "verifying"}
