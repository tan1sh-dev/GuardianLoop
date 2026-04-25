# GuardianLoop

Autonomous multi-agent pipeline for detecting, patching, and adversarially verifying security vulnerabilities in C++ and Python code.

## Pipeline

```
Scout (Semgrep + Bandit)
  -> Classifier (NVD CVE/CVSS enrichment)
    -> Fixer (Gemini 2.5 Pro, chain-of-thought)
      -> Red-Team (Docker sandbox exploit verification)
        -> [if exploit reproduces and loop_count < 3] back to Fixer
        -> [else] Report (JSON + markdown)
```

## Quickstart

```bash
make install
cp .env.example .env        # fill in GOOGLE_API_KEY
make docker-build           # builds python + cpp sandbox images
make demo                   # runs the pipeline on samples/demo_cwe121.cpp
```

Artifacts land in `./runs/<timestamp>/`:
- `findings.json`, `patches.json`, `run_summary.json`
- `report.md` — the What / Why / How audit report
- `<agent>.log` — structlog JSON events per agent

## Layout

```
src/guardianloop/agents/     # Scout, Classifier, Fixer, Red-Team
src/guardianloop/graph.py    # LangGraph orchestration + Report terminal node
src/guardianloop/state.py    # Pydantic schemas (single source of truth)
src/guardianloop/sandbox/    # Docker runner + exploit harness
src/guardianloop/reporting/  # JSON + markdown report writers
src/guardianloop/ingress/    # local file (Day 1), upload (Day 2), GitHub PR (Day 3)
src/guardianloop/webhook/    # FastAPI GitHub webhook (HMAC-validated)
src/guardianloop/ui/         # Streamlit read-only viewer
samples/                     # demo_cwe121.cpp, demo_cwe89.py
docker/                      # python + cpp sandbox Dockerfiles
tests/                       # pytest unit + integration tests
```

## Agent-assistant guide

If you are running Claude Code, Gemini CLI, Cursor, or similar against this repo, read [CLAUDE.md](CLAUDE.md) first.
