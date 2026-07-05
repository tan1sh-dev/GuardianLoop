"""
Fixer — Gemini chain-of-thought patch generator with multi-key rotation.

On iteration 0, every enriched finding gets a patch attempt.
On iteration N>0, only findings whose prior verification still reproduced the
exploit get re-patched; the failed sandbox output is fed back into the prompt.

The model is asked to respond with REASONING: / PATCHED_CODE: marker blocks.
The response parser also accepts a JSON fallback so older prompts (and the
test fixtures) keep working.

Reliability layers, in order of escalation per finding:
    1. Same key, same model, exponential backoff with jitter (transient 5xx /
       parse errors).
    2. Rotate to next API key on 429 quota exhaustion. Exhausted keys are
       marked for the rest of the run.
    3. When every key is exhausted on the primary model, downgrade to the
       fallback model (default gemini-2.5-flash) and retry the full key set.
    4. If even fallback fails, log and skip the finding — pipeline continues.

Usage budget per run, in API calls (worst case):
    (n_keys * primary_attempts) + (n_keys * fallback_attempts)

Uses the modern ``google-genai`` SDK (``from google import genai``). The legacy
``google-generativeai`` package is deprecated and must not be used.
"""

from __future__ import annotations

import asyncio
import difflib
import json
import random
import re
from dataclasses import dataclass, field

from google import genai
from google.genai import types
from langchain_core.runnables import RunnableConfig

from guardianloop.config import Config
from guardianloop.logging_setup import get_agent_logger
from guardianloop.state import EnrichedFinding, Patch, PipelineState, VerificationResult

# Per-key, per-model attempts before rotating away. Transient errors (parse
# failure, 5xx, timeout) burn attempts on the same key; quota errors rotate
# immediately without consuming further attempts on the dead key.
MAX_ATTEMPTS_PER_KEY = 5

FIXER_SYSTEM = (
    "You are GuardianLoop's Fixer agent. Given a vulnerable source file and a "
    "vulnerability finding, produce a minimally-invasive patch that eliminates "
    "the vulnerability while preserving intended behavior. Think step by step.\n"
    "CRITICAL GUIDELINES:\n"
    "- Path Traversal (CWE-22): Use Python's modern `pathlib` library to resolve and validate paths instead of `os.path.commonpath` (which is case-insensitive on Windows and easily bypassed).\n"
    "- Password Hashing: When fixing plaintext passwords or weak hashes, always use a dedicated modern library like `bcrypt` or `argon2`. NEVER use `hashlib` with static salts.\n"
    "- Hardcoded Secrets (CWE-798): When moving secrets to environment variables, DO NOT fetch them and raise exceptions in the global scope of a module, as this breaks imports. Fetch them lazily inside the function that needs them.\n"
    "- Open Redirect (CWE-601): Always strictly validate the redirect target URL. Ensure it is a relative path (e.g., starts with '/' but not '//') or explicitly validate the domain against a whitelist before redirecting.\n"
    "- Integer Overflow (CWE-190): When patching C++ integer overflow on arithmetic addition/subtraction, use compiler builtins like `__builtin_add_overflow(a, b, &res)` or `__builtin_sub_overflow(a, b, &res)` instead of manual conditional checks.\n"
    "- Insecure Randomness (CWE-330): Swap out `random` for Python's cryptographically secure `secrets` module when generating security tokens, passwords, or session IDs.\n"
    "- Dead Code & Cleanups: When removing or replacing vulnerable code (e.g., hardcoded secrets or insecure imports like `pickle`), completely purge the dead code, unused imports, and left-behind keys. Do not just comment them out."
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


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------

class QuotaExhaustedError(Exception):
    """Raised when a 429 indicates the key is out of daily/monthly budget,
    not just rate-limited. Triggers immediate key rotation."""


@dataclass
class KeyRotator:
    """
    Round-robin over a list of API keys with per-key quota tracking.

    A key is "exhausted" once the SDK reports a 429 whose retry-after hint is
    longer than ``_QUOTA_THRESHOLD_SECONDS`` (5 min) — almost always indicates
    a daily-quota rejection rather than a transient burst.
    """

    keys: list[str]
    _exhausted: set[int] = field(default_factory=set)
    _cursor: int = 0

    @property
    def total(self) -> int:
        return len(self.keys)

    @property
    def remaining(self) -> int:
        return len(self.keys) - len(self._exhausted)

    def current(self) -> tuple[int, str] | None:
        """Return (index, key) for the active key, or None if all exhausted."""
        if not self.keys:
            return None
        for _ in range(len(self.keys)):
            idx = self._cursor % len(self.keys)
            if idx not in self._exhausted:
                return idx, self.keys[idx]
            self._cursor += 1
        return None

    def mark_exhausted(self, idx: int) -> None:
        self._exhausted.add(idx)

    def rotate(self) -> tuple[int, str] | None:
        """Advance cursor past the current key. Returns next available, or None."""
        self._cursor += 1
        return self.current()


_QUOTA_THRESHOLD_SECONDS = 300.0  # retry-after > 5 min ⇒ quota, not burst
_RETRY_AFTER_RE = re.compile(
    r"retry[_ ]?(?:after|in)[^\d]*(\d+(?:\.\d+)?)\s*s",
    re.IGNORECASE,
)
_QUOTA_HINT_RE = re.compile(
    r"(?:daily[_ ]quota|monthly[_ ]quota|per[-_ ]day|free[-_ ]tier|quota[_ ]?exceeded)",
    re.IGNORECASE,
)


def _classify_error(err: Exception) -> tuple[bool, float]:
    """
    Returns (is_quota_exhaustion, retry_after_seconds).

    Heuristics on the stringified error:
      * Contains a quota hint phrase                       → quota exhausted
      * Contains retry-after > _QUOTA_THRESHOLD_SECONDS    → quota exhausted
      * Status 429 with no retry hint                      → transient
      * Otherwise                                          → transient
    """
    s = str(err)
    is_429 = "429" in s or "RESOURCE_EXHAUSTED" in s.upper()

    retry_after = 0.0
    m = _RETRY_AFTER_RE.search(s)
    if m:
        try:
            retry_after = float(m.group(1))
        except ValueError:
            retry_after = 0.0

    if is_429 and (_QUOTA_HINT_RE.search(s) or retry_after > _QUOTA_THRESHOLD_SECONDS):
        return True, retry_after
    return False, retry_after


def _is_503_overload(err: Exception) -> bool:
    s = str(err).lower()
    return "503" in s and ("high demand" in s or "unavailable" in s)


# ---------------------------------------------------------------------------
# Prompt + response
# ---------------------------------------------------------------------------

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


def _extract_usage(resp) -> dict:
    """Pull token counts off a Gemini response. The exact field names vary
    between SDK versions, so we probe defensively. Returns {} if unavailable."""
    usage_obj = getattr(resp, "usage_metadata", None)
    if usage_obj is None:
        return {}
    try:
        return {
            "prompt_tokens": int(getattr(usage_obj, "prompt_token_count", 0) or 0),
            "completion_tokens": int(getattr(usage_obj, "candidates_token_count", 0) or 0),
            "total_tokens": int(getattr(usage_obj, "total_token_count", 0) or 0),
        }
    except (TypeError, ValueError):
        return {}


# ---------------------------------------------------------------------------
# Generation with rotation + cascade
# ---------------------------------------------------------------------------

async def _call_once(
    *,
    api_key: str,
    model: str,
    prompt: str,
    gen_config: types.GenerateContentConfig,
    timeout: int,
) -> tuple[dict, dict]:
    """One Gemini call. Returns (parsed_response, usage_dict). Raises on failure."""
    client = _make_client(api_key)
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
    return data, _extract_usage(resp)


async def _generate_with_rotation(
    *,
    rotator: KeyRotator,
    primary_model: str,
    fallback_model: str,
    prompt: str,
    gen_config: types.GenerateContentConfig,
    timeout: int,
    logger,
    finding_id: str,
) -> tuple[dict, dict]:
    """
    Try every key on ``primary_model``; on exhaustion, try every key on
    ``fallback_model``. Returns (parsed_response, usage_dict) on first success.
    """
    last_err: Exception | None = None

    # Track if we need a global 503 retry
    primary_failed_due_to_503 = False
    models_to_try = [(0, primary_model)]

    for stage, model in models_to_try:
        # Reset rotator state for subsequent stages
        if stage > 0:
            rotator = KeyRotator(keys=list(rotator.keys))

        current = rotator.current()
        if current is None:
            if stage == 0:
                continue
            else:
                break

        if stage == 1:
            logger.warning(
                "fixer.model_downgrade",
                finding_id=finding_id,
                from_model=primary_model,
                to_model=fallback_model,
            )
        elif stage == 0.5:
            logger.warning(
                "fixer.global_503_cooldown",
                finding_id=finding_id,
                model=primary_model,
                seconds=30.0,
            )
            await asyncio.sleep(30.0)

        tried_indices: set[int] = set()
        while current is not None:
            idx, key = current
            if idx in tried_indices:
                # We have tried all available keys in this stage
                break
            tried_indices.add(idx)

            key_id = f"key#{idx + 1}/{rotator.total}"

            for attempt in range(1, MAX_ATTEMPTS_PER_KEY + 1):
                try:
                    logger.info(
                        "fixer.calling",
                        finding_id=finding_id,
                        model=model,
                        key=key_id,
                        attempt=attempt,
                    )
                    data, usage = await _call_once(
                        api_key=key,
                        model=model,
                        prompt=prompt,
                        gen_config=gen_config,
                        timeout=timeout,
                    )
                    usage["key_index"] = idx
                    usage["model"] = model
                    return data, usage

                except Exception as e:  # noqa: BLE001
                    last_err = e
                    is_quota, retry_after = _classify_error(e)

                    is_503 = _is_503_overload(e)

                    if is_quota:
                        logger.warning(
                            "fixer.key_exhausted",
                            finding_id=finding_id,
                            model=model,
                            key=key_id,
                            retry_after=retry_after,
                            error=str(e)[:200],
                        )
                        rotator.mark_exhausted(idx)
                        break  # break attempt loop, rotate keys

                    # Transient error: backoff with jitter and retry same key.
                    backoff = min(2 ** attempt + random.uniform(0, 1), 60.0)
                    if retry_after and retry_after <= _QUOTA_THRESHOLD_SECONDS:
                        backoff = retry_after
                    elif is_503 and backoff < 15.0:
                        backoff = 15.0 + random.uniform(0, 5.0)
                    if attempt < MAX_ATTEMPTS_PER_KEY:
                        logger.info(
                            "fixer.attempt_retry",
                            finding_id=finding_id,
                            model=model,
                            key=key_id,
                            attempt=attempt,
                            of=MAX_ATTEMPTS_PER_KEY,
                            backoff_seconds=backoff,
                            error=str(e)[:200],
                        )
                    else:
                        logger.warning(
                            "fixer.attempt_failed",
                            finding_id=finding_id,
                            model=model,
                            key=key_id,
                            attempt=attempt,
                            of=MAX_ATTEMPTS_PER_KEY,
                            error=str(e)[:200],
                        )
                    if attempt < MAX_ATTEMPTS_PER_KEY:
                        await asyncio.sleep(backoff)

            # All attempts on this key failed (transient) OR key marked
            # exhausted (quota) — either way, rotate.
            if last_err and _is_503_overload(last_err):
                # 503 is a model-wide capacity issue; rotating keys won't help.
                # Break the key loop to skip to the next stage (fallback model).
                break

            current = rotator.rotate()

        if stage == 0 and last_err and _is_503_overload(last_err):
            primary_failed_due_to_503 = True

        if stage == 0:
            if fallback_model and fallback_model != primary_model:
                models_to_try.append((1, fallback_model))

        if stage in (0, 0.5) and fallback_model != primary_model:
            logger.warning(
                "fixer.all_keys_exhausted",
                finding_id=finding_id,
                model=model,
                total_keys=rotator.total,
            )

    raise last_err if last_err is not None else RuntimeError(
        "fixer: all keys/models exhausted with no recorded error"
    )


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

async def fixer_node(state: PipelineState, config: RunnableConfig) -> dict:
    gl: Config = config["configurable"]["gl_config"]
    logger = get_agent_logger(state.run_dir, "fixer")

    keys = list(gl.google_api_keys or ([] if not gl.google_api_key else [gl.google_api_key]))
    if not keys:
        logger.error("fixer.no_api_key")
        return {
            "status": "failed",
            "error": (
                "No Gemini API keys configured. Set GOOGLE_API_KEY (and "
                "optionally GOOGLE_API_KEY_2, _3, … or GOOGLE_API_KEYS=a,b,c)."
            ),
        }

    source = state.source_file.read_text(encoding="utf-8", errors="replace")
    new_patches: list[Patch] = list(state.patches)

    last_patch = _latest_by_finding(state.patches, "iteration")
    last_verif = _latest_by_finding(state.verification_results, "patch_iteration")

    if gl.fixer_model == gl.fixer_fallback_model:
        logger.warning(
            "fixer.identical_fallback",
            model=gl.fixer_model,
            msg="fixer_model and fixer_fallback_model are identical. Fallback cascade will provide no benefit."
        )

    logger.info(
        "fixer.start",
        iteration=state.loop_count,
        enriched=len(state.enriched_findings),
        primary_model=gl.fixer_model,
        fallback_model=gl.fixer_fallback_model,
        keys_available=len(keys),
    )

    gen_config = types.GenerateContentConfig(
        system_instruction=FIXER_SYSTEM,
        temperature=0.2,
    )
    # NOTE: rotator is created per-finding inside the loop below,
    # so each finding gets an independent shot at all API keys.

    # Aggregate usage across all findings for the run summary.
    run_usage = {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "calls": 0,
        "by_model": {},  # model_name → {prompt, completion, total, calls}
    }

    # Chain patches: each finding's prompt receives the progressively-patched
    # source so fixes accumulate instead of each patch independently fixing
    # only one vulnerability against the original.
    running_source = source

    _INTER_FINDING_DELAY = 5  # seconds between API calls to avoid rate-limit bursts
    for _ef_idx, ef in enumerate(state.enriched_findings):
        f = ef.finding
        if state.loop_count > 0:
            prior_verif_check = last_verif.get(f.id)
            if prior_verif_check is not None and not prior_verif_check.exploit_reproduced:
                continue

        prior = last_patch.get(f.id)
        prior_verif = last_verif.get(f.id) if state.loop_count > 0 else None

        prompt = _build_prompt(ef, running_source, prior, prior_verif)
        rotator = KeyRotator(keys=keys)
        # Cooldown between successive API calls to stay within RPM limits
        if _ef_idx > 0:
            logger.info("fixer.rate_limit_cooldown", seconds=_INTER_FINDING_DELAY)
            await asyncio.sleep(_INTER_FINDING_DELAY)

        logger.info("fixer.prompting", finding_id=f.id, iteration=state.loop_count)

        try:
            data, usage = await _generate_with_rotation(
                rotator=rotator,
                primary_model=gl.fixer_model,
                fallback_model=gl.fixer_fallback_model,
                prompt=prompt,
                gen_config=gen_config,
                timeout=gl.gemini_timeout_seconds,
                logger=logger,
                finding_id=f.id,
            )
        except Exception as e:  # noqa: BLE001
            logger.error(
                "fixer.gave_up",
                finding_id=f.id,
                error=str(e)[:300],
                keys_remaining=rotator.remaining,
            )
            # Record the skipped finding
            state.skipped_findings.append({
                "finding_id": f.id,
                "reason": f"Fixer gave up after exhausting keys: {str(e)[:200]}"
            })
            continue

        # Accumulate usage
        run_usage["calls"] += 1
        run_usage["prompt_tokens"] += usage.get("prompt_tokens", 0)
        run_usage["completion_tokens"] += usage.get("completion_tokens", 0)
        run_usage["total_tokens"] += usage.get("total_tokens", 0)
        model_used = usage.get("model", gl.fixer_model)
        
        
        bucket = run_usage["by_model"].setdefault(
            model_used,
            {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "calls": 0},
        )
        bucket["calls"] += 1
        bucket["prompt_tokens"] += usage.get("prompt_tokens", 0)
        bucket["completion_tokens"] += usage.get("completion_tokens", 0)
        bucket["total_tokens"] += usage.get("total_tokens", 0)

        patched_code = data.get("patched_code") or ""
        reasoning = data.get("reasoning_chain") or []
        if not patched_code:
            logger.warning("fixer.empty_patch", finding_id=f.id)
            continue
        if not isinstance(reasoning, list):
            reasoning = [str(reasoning)]

        # Diff is computed against the running (already-patched) source so
        # each finding's diff shows only the change it introduces.
        patch = Patch(
            finding_id=f.id,
            patched_code=patched_code,
            diff=_unified_diff(running_source, patched_code, f.file_path),
            reasoning_chain=[str(s) for s in reasoning],
            iteration=state.loop_count,
            model=model_used,
        )
        new_patches = [
            p
            for p in new_patches
            if not (p.finding_id == f.id and p.iteration == state.loop_count)
        ]
        new_patches.append(patch)

        # Update running source so the next finding's prompt includes this fix.
        running_source = patched_code

        logger.info(
            "fixer.patch_ready",
            finding_id=f.id,
            iteration=state.loop_count,
            model=model_used,
            steps=len(patch.reasoning_chain),
            tokens=usage.get("total_tokens", 0),
        )

    logger.info(
        "fixer.done",
        patches=len(new_patches),
        total_tokens=run_usage["total_tokens"],
        calls=run_usage["calls"],
    )

    # Persist usage so the report node can include it in run_summary.json.
    # We attach it to the patch list via a side-channel file the report node
    # reads — no PipelineState schema change required.
    try:
        usage_path = state.run_dir / "fixer_usage.json"
        usage_path.write_text(json.dumps(run_usage, indent=2), encoding="utf-8")
    except OSError:
        pass

    return {"patches": new_patches, "skipped_findings": state.skipped_findings, "status": "verifying"}
