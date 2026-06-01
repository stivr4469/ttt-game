"""
Outbound webhook notifications — single-URL, per-tenant best-effort delivery.

Reads configuration from vault (via get_connector_secret) then falls back to
environment variables, so it works with both the secret-store and plain env
setups.

  OUTBOUND_WEBHOOK_URL    — destination URL (skip silently if empty)
  OUTBOUND_WEBHOOK_SECRET — HMAC-SHA256 signing secret (optional)

Payload envelope:
  {"event": <event_type>, "data": <payload>, "ts": <ISO-8601 UTC>}

Signature header (when secret is set):
  X-Signature: sha256=<hex>
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone

import httpx

import secret_store

log = logging.getLogger(__name__)

_TIMEOUT = 10.0


async def notify(
    event_type: str,
    payload: dict,
    tenant_id: str | None = None,
) -> None:
    """POST a JSON notification to the configured outbound webhook URL.

    Fire-and-forget: all exceptions are caught and logged as warnings so
    callers are never interrupted.
    """
    try:
        # Resolve URL — vault first, env fallback (sync call)
        url: str = secret_store.get_connector_secret(
            "OUTBOUND_WEBHOOK_URL",
            os.getenv("OUTBOUND_WEBHOOK_URL", ""),
        )
        if not url:
            return  # not configured — skip silently

        # Resolve signing secret — vault first, env fallback (sync call)
        signing_secret: str = secret_store.get_connector_secret(
            "OUTBOUND_WEBHOOK_SECRET",
            os.getenv("OUTBOUND_WEBHOOK_SECRET", ""),
        )

        body: dict = {
            "event": event_type,
            "data": payload,
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        if tenant_id is not None:
            body["tenant_id"] = tenant_id

        raw = json.dumps(body, separators=(",", ":")).encode()

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if signing_secret:
            sig = hmac.new(
                signing_secret.encode(),
                raw,
                hashlib.sha256,
            ).hexdigest()
            headers["X-Signature"] = f"sha256={sig}"

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(url, content=raw, headers=headers)
            if resp.status_code >= 400:
                log.warning(
                    "Outbound webhook returned %s for event=%s url=%s",
                    resp.status_code,
                    event_type,
                    url,
                )
    except Exception as exc:
        log.warning(
            "Outbound webhook delivery failed for event=%s: %s",
            event_type,
            exc,
        )
