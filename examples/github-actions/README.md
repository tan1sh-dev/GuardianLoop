# GuardianLoop · CI integration templates

Drop-in workflow templates for using GuardianLoop as a security gate in your
repo's CI. Each template is independently usable — copy the file into
`.github/workflows/` of the target repo and configure the secrets listed at
the top of the file.

## `guardianloop-scan.yml` — PR security review

Runs the full GuardianLoop pipeline on every PR that touches Python or C/C++
source files. For each finding it produces:

- A Gemini-generated patch with chain-of-thought reasoning,
- A Docker-sandboxed verification that the original exploit no longer reproduces,
- An aggregated markdown summary posted to the PR as a sticky comment.

**Fails the PR check** if any verified exploit still reproduces after patching,
so reviewers can block the merge until the engineer addresses it.

### Required repo secrets

| Secret | Purpose | Required |
| --- | --- | :-: |
| `GOOGLE_API_KEY` | Primary Gemini key for the Fixer agent | ✅ |
| `GOOGLE_API_KEY_2`, `_3`, ... | Additional keys for quota rotation | ⚪ |
| `NVD_API_KEY` | Raises NVD CVE lookup rate limit (5→50 per 30s) | ⚪ |
| `SEMGREP_APP_TOKEN` | Unlocks full Semgrep ruleset including C/C++ | ⚪ |

### Why multi-key rotation matters in CI

Free-tier Gemini accounts cap at ~50 daily Pro requests. A busy repo with
multiple PRs/day will exhaust a single key by lunchtime. GuardianLoop's
rotation transparently advances to the next key on `429 RESOURCE_EXHAUSTED`,
and downgrades to `gemini-2.5-flash` as a final safety net before failing
the run — so the security gate stays green even under quota pressure.

### Customizing

- **Different file types**: edit the `paths:` filter and the `grep -E` regex
  in *Identify changed source files*.
- **Stricter gate**: change the final step to fail on `findings > 0` instead
  of `patches_failed > 0`.
- **Async mode**: drop the final `exit 1` step to make the comment advisory
  rather than blocking.
