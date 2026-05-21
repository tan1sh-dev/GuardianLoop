# GuardianLoop - Agent Operator Guide

This file briefs Claude Code, Gemini CLI, Cursor, and any other AI coding assistant that teammates run against this repo. Read it end-to-end before making changes.

## What this project is

Four-agent autonomous security pipeline orchestrated via LangGraph, plus a terminal Report node:

1. **Scout** (`src/guardianloop/agents/scout.py`) - runs Semgrep + Bandit, emits `Finding` objects.
2. **Classifier** (`src/guardianloop/agents/classifier.py`) - enriches each `Finding` with CVE/CVSS data from the NVD API.
3. **Fixer** (`src/guardianloop/agents/fixer.py`) - uses Gemini 2.5 Pro with chain-of-thought prompting to produce `Patch` candidates.
4. **Red-Team** (`src/guardianloop/agents/red_team.py`) - runs each patch through a Docker sandbox to verify the exploit no longer works. On failure, loops back to Fixer up to `max_loop_iterations` (default 3).
5. **Report** (in `graph.py`) - terminal node; writes `runs/<ts>/run_summary.json` and `runs/<ts>/report.md`.

## Where the schemas live

All Pydantic models are in `src/guardianloop/state.py`:
- `Finding` - raw SAST output
- `EnrichedFinding` - `Finding` + CVE/CVSS
- `Patch` - Fixer's candidate fix + reasoning chain
- `VerificationResult` - Red-Team's sandbox outcome
- `PipelineState` - the full LangGraph state

**Rule:** do not invent ad-hoc fields in agent code. If you need a new field, add it to `state.py` and open a PR. Silent schema edits break the other agents mid-run.

## Conventions (non-negotiable)

- **LangGraph nodes are `async def`.** Never call `asyncio.run()` inside a node - it creates a nested event loop and either deadlocks or raises `RuntimeError`. For sync-only libraries (e.g. the `docker` SDK) use `asyncio.to_thread`.
- **Gemini SDK: `google-genai`** (`from google import genai` / `from google.genai import types`). The legacy `google-generativeai` package is deprecated — do not import it. All Gemini calls route through the `_make_client` helper in `agents/fixer.py`; tests monkeypatch `google.genai.Client` to inject fakes.
- **Model routing**: Fixer = `gemini-2.5-pro`; Classifier's optional LLM path = `gemini-2.5-flash`. Both are configurable via `config.yaml` (`fixer_model`, `classifier_model`).
- **Logging**: every agent binds a `structlog` logger to its agent name and writes JSON events to `runs/<ts>/<agent>.log`. Do not use `print` or the stdlib `logging` module directly in agent code.
- **Config**: tunables go in `config.yaml`. Secrets go in `.env` (see `.env.example`). Never commit `.env`.
- **Determinism in tests**: every subprocess, HTTP, LLM, and Docker call must be mockable. Tests under `tests/` monkeypatch these boundaries - keep the seams intact.
- **Sandbox flags**: `--network=none --read-only --tmpfs /tmp --memory=512m --cpus=1`. Do not loosen these.

## How to run

```bash
make install           # pip install -e .[dev]
make test              # pytest
make lint              # ruff check
make docker-build      # build the two sandbox images (required for real Red-Team runs)
make demo              # end-to-end on samples/demo_cwe121.cpp
make webhook           # FastAPI GitHub webhook on :8000
```

Start the Mission Control Dashboard separately (not in Makefile):

```bash
uvicorn guardianloop.web.app:app --host 0.0.0.0 --port 8080
```

Then open `http://localhost:8080/dashboard/` in a browser.

Dev server configs are in `.claude/launch.json` — Claude Code's `preview_start` reads from there.

A real `make demo` needs `GOOGLE_API_KEY` set in `.env` and both sandbox images built. Tests mock both.

## Phased delivery - do not jump ahead

- **Day 1 (done)**: local file path input, both sandbox images, full pipeline, demo smoke test, Mission Control Dashboard (FastAPI + static JSX at :8080), webhook scaffold with real HMAC.
- **Day 2**: File upload ingress — fill in `ingress/upload.py`.
- **Day 3**: GitHub PR URL ingress — fill in `ingress/github_pr.py`.

## Out of scope

Do not add the following without an explicit product decision:
- SARIF output
- Outbound patch-PR creation (Fixer opening a PR back to the source repo)
- Per-vulnerability Docker images (we use one image per language, harness mounted in at runtime)
- Per-agent LangGraph state trace UI (the dashboard is read-only run history, not a live trace UI)

If you see an AI assistant suggesting any of these, push back.

## Markdown report structure

`reporting/markdown_report.py` emits exactly these three sections, in this order, with these exact headers:

- `## What` - CWE, CVE, CVSS score, file:line, snippet
- `## Why` - exploitability explanation, pedagogical tone, drawn from Fixer's reasoning chain
- `## How` - the patch diff plus the reasoning chain

These are the pedagogical objective (slide 8 of the deck). Do not reword them.
