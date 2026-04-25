"""
FastAPI GitHub webhook server.

- Validates X-Hub-Signature-256 against GITHUB_WEBHOOK_SECRET using an HMAC
  constant-time comparison.
- Missing or invalid signatures return HTTP 401.
- Missing server-side secret returns HTTP 503 (service not configured).
- Actual PR scanning dispatches to ingress.github_pr.ingest_github_pr, which
  is a Day 3 deliverable — for now the handler acknowledges the event.

Run: `make webhook`   (uvicorn guardianloop.webhook.app:app --port 8000)
"""

from __future__ import annotations

import hashlib
import hmac

from fastapi import FastAPI, Header, HTTPException, Request

from guardianloop.config import Config, load_config

app = FastAPI(title="GuardianLoop Webhook", version="0.1.0")


def _get_config() -> Config:
    return load_config()


def _verify_signature(secret: str, body: bytes, signature_header: str | None) -> None:
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing X-Hub-Signature-256 header.")
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(status_code=401, detail="Invalid X-Hub-Signature-256.")


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
) -> dict:
    cfg = _get_config()
    if not cfg.github_webhook_secret:
        raise HTTPException(
            status_code=503,
            detail="GITHUB_WEBHOOK_SECRET is not configured on the server.",
        )

    body = await request.body()
    _verify_signature(cfg.github_webhook_secret, body, x_hub_signature_256)

    if x_github_event == "ping":
        return {"status": "pong"}
    if x_github_event == "pull_request":
        # Day 3: parse payload, call ingress.github_pr.ingest_github_pr,
        # run the pipeline, and comment the audit report back on the PR.
        return {
            "status": "accepted",
            "note": "PR scanning dispatch is a Day 3 deliverable (see CLAUDE.md).",
        }
    return {"status": "ignored", "event": x_github_event}
