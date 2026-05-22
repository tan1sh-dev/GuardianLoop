# GuardianLoop — Architecture

> An autonomous multi-agent security pipeline that finds vulnerabilities,
> generates patches with chain-of-thought reasoning, and **verifies the fix
> actually works** by re-running the original exploit in a hardened sandbox.

## TL;DR for evaluators

| | |
| --- | --- |
| **Pipeline** | Scout → Classifier → Fixer → Red-Team → Report, orchestrated via LangGraph |
| **Novelty** | A Red-Team agent that *verifies* each LLM-generated patch via Docker sandbox, feeds failures back into the next Fixer iteration |
| **LLM** | Gemini 2.5 Pro (Fixer) + 2.5 Flash (Classifier), with multi-key rotation and automatic fallback |
| **Verification** | `--network=none --read-only --tmpfs /tmp --memory=512m --cpus=1` per patch |
| **Languages** | Python (Bandit + Semgrep) and C/C++ (Semgrep + AddressSanitizer harness) |
| **Reproducibility** | 54 unit tests, mocked boundaries at every external call (LLM/HTTP/Docker/subprocess) |

## The five-agent pipeline

```
                    ┌─────────────────────────────────────────────┐
                    │              run_dir/                       │
                    │   findings.json → enriched → patches → …    │
                    └─────────────────────────────────────────────┘
                              ▲             ▲           ▲
                              │             │           │
   source ──► Scout ──► Classifier ──► Fixer ──► Red-Team ──► Report
   (file)     │           │              │          │          │
              │           │              │          │          └── report.md
              │           │              │          │              run_summary.json
              │           │              │          │
              │           │              │          └── Docker sandbox
              │           │              │              exploit re-run
              │           │              │              ✗ → loop back to Fixer
              │           │              │              ✓ → continue
              │           │              │
              │           │              └── Gemini 2.5 Pro
              │           │                  Chain-of-thought patch
              │           │                  Multi-key rotation
              │           │                  Flash fallback
              │           │
              │           └── NVD API: CVE + CVSS enrichment
              │
              └── Semgrep + Bandit SAST
                  CWE-tagged findings
```

### 1. Scout — `agents/scout.py`
Runs Semgrep + Bandit in subprocess, normalizes both outputs into the
unified `Finding` schema. Emits a deterministic SHA1 id per finding so
downstream agents can correlate.

### 2. Classifier — `agents/classifier.py`
For each Finding, queries the NVD CVE API by CWE id. Attaches CVSS 3.1
score + vector, picks the highest-severity CVE as the canonical example,
and synthesizes a one-paragraph exploitability summary (Gemini Flash).

### 3. Fixer — `agents/fixer.py`
The crown jewel. Prompts Gemini 2.5 Pro with the vulnerable file + full
metadata (CWE, CVSS, severity, location, NVD context). Response is parsed
from a strict `REASONING:` / `PATCHED_CODE:` marker format that captures a
**5-step chain of thought**:
  1. What the vulnerability is
  2. Why it is exploitable
  3. What invariant the fix must establish
  4. The minimum code change to establish it
  5. What an exploit would need to do to re-trigger

Reliability layers, in order of escalation:
  1. **Same key, exponential backoff** for transient parse/network errors
  2. **Rotate to next API key** on `429 RESOURCE_EXHAUSTED` (daily-quota)
  3. **Downgrade primary → fallback model** (Pro → Flash) when all keys
     are exhausted on Pro
  4. **Skip finding, continue pipeline** if even fallback fails — no
     silent total failures

### 4. Red-Team — `agents/red_team.py`
Builds a per-language Docker sandbox (Python or C++), mounts the patched
source, executes a deterministic harness, and asserts the original exploit
no longer succeeds. Per-container guards:
```
--network=none      # no exfiltration
--read-only         # no filesystem corruption
--tmpfs /tmp        # writable scratch only
--memory=512m       # cap blast radius
--cpus=1            # cap CPU
```
On `exploit_reproduced == True`, the LangGraph router loops back to Fixer
(up to `max_loop_iterations`, default 3), passing the sandbox stderr into
the next prompt as concrete failure context.

### 5. Report — `graph.py`
Terminal node. Writes:
- `findings.json` / `enriched_findings.json` / `patches.json` /
  `verifications.json` — full per-stage state for audit
- `run_summary.json` — totals + token usage + status (dashboard-friendly)
- `report.md` — three-section pedagogical breakdown (What / Why / How)
  designed for engineer learning, not just incident triage

## What makes this academically novel

| Common security tools | GuardianLoop |
| --- | --- |
| SAST emits findings → human triages | Agents triage, generate, **and verify** the fix |
| LLM patch suggestions | Patches **proved** to fix the exploit via sandbox re-run |
| Single-shot LLM call | Feedback loop — failed verification → next Fixer iteration with the failure context |
| Token usage hidden | Full per-run token + cost telemetry, exposed in dashboard |

## What makes this production-ready for industry

- **Reliability**: multi-key Gemini rotation + Pro → Flash fallback means a
  single quota exhaustion never kills a pipeline.
- **Safety**: every executable verification runs network-disabled, RO root,
  CPU/RAM-capped — by design, never reflectively executed in the host.
- **Auditable**: every agent writes JSON-structured logs to its own file
  in `run_dir`; the pipeline state is fully reconstructible from disk.
- **CI integration**: `examples/github-actions/guardianloop-scan.yml`
  shows the production deployment pattern with sticky PR comments,
  branch-protection gating, and quota-resilient secret rotation.
- **No vendor lock-in for sandbox**: any container runtime that speaks the
  Docker CLI works; the harness contract is the only stable interface.

## Repository layout

```
src/guardianloop/
  agents/         scout · classifier · fixer · red_team
  reporting/      markdown_report · json_report
  ingress/        local · upload · paste · github_pr
  web/            FastAPI dashboard + scan submission API
  ui/dashboard/   React (in-browser Babel) — no build step required
  state.py        Pydantic schemas — the inter-agent contract
  graph.py        LangGraph topology + routing
  config.py       config.yaml + .env loader, multi-key collection

tests/            54 unit tests, mocked boundaries throughout
examples/         CI templates for production deployment
docs/             this file
samples/          demo vulnerable files for end-to-end smoke testing
```
