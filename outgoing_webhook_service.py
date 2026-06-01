"""
Сервис исходящих вебхуков — уведомления о смене статуса findings/тестов.

Конфиг в OUTGOING_WEBHOOKS env var как JSON-массив:
[{"url": "https://...", "secret": "...", "events": ["finding.opened", "test.failed"]}]

Поддерживаемые event_type:
  finding.opened   — новый finding создан
  finding.resolved — finding закрыт
  test.failed      — тест вернул FAIL
  test.error       — тест вернул ERROR
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any
from urllib.parse import urlparse

import httpx

log = logging.getLogger(__name__)

MAX_RETRIES = 3


def _load_webhooks() -> list[dict]:
    raw = os.getenv("OUTGOING_WEBHOOKS", "[]")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        log.warning("OUTGOING_WEBHOOKS env var is not valid JSON")
        return []


def _sign(payload: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def _validate_webhook_url(url: str) -> None:
    """Validate webhook URL to prevent SSRF attacks."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Webhook URL must use http/https, got: {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError(f"Webhook URL missing host: {url!r}")
    # Block internal/metadata addresses
    hostname = parsed.hostname or ""
    if hostname in ("169.254.169.254", "metadata.google.internal") or hostname.startswith("169.254."):
        raise ValueError(f"Webhook URL targets internal address: {hostname!r}")


async def deliver(event_type: str, payload: dict[str, Any]) -> None:
    """Доставить событие всем подписанным вебхукам. Ошибки логируются, не поднимаются."""
    webhooks = _load_webhooks()
    if not webhooks:
        return

    body = json.dumps(
        {"event": event_type, "timestamp": time.time(), "data": payload}
    ).encode()

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        for wh in webhooks:
            if event_type not in wh.get("events", []):
                continue
            url = wh["url"]

            try:
                _validate_webhook_url(url)
            except ValueError as exc:
                log.warning("Skipping invalid webhook URL: %s", exc)
                continue

            headers: dict[str, str] = {
                "Content-Type": "application/json",
                "X-Webhook-Event": event_type,
            }
            secret = wh.get("secret", "")
            if secret:
                headers["X-Webhook-Signature"] = _sign(body, secret)

            for attempt in range(MAX_RETRIES):
                try:
                    resp = await client.post(url, content=body, headers=headers)
                    resp.raise_for_status()
                    log.info("Webhook delivered to %s on attempt %d", url, attempt + 1)
                    break
                except httpx.HTTPStatusError as exc:
                    if attempt < MAX_RETRIES - 1:
                        delay = 2 ** attempt
                        log.warning(
                            "Webhook attempt %d failed (HTTP %s) for %s, retrying in %ds: %s",
                            attempt + 1, exc.response.status_code, url, delay, exc,
                        )
                        await asyncio.sleep(delay)
                    else:
                        log.error(
                            "Webhook delivery permanently failed (HTTP %s) for %s after %d attempts: %s",
                            exc.response.status_code, url, MAX_RETRIES, exc, exc_info=True,
                        )
                except httpx.RequestError as exc:
                    if attempt < MAX_RETRIES - 1:
                        delay = 2 ** attempt
                        log.warning(
                            "Webhook attempt %d failed for %s, retrying in %ds: %s",
                            attempt + 1, url, delay, exc,
                        )
                        await asyncio.sleep(delay)
                    else:
                        log.error(
                            "Webhook delivery permanently failed for %s after %d attempts: %s",
                            url, MAX_RETRIES, exc, exc_info=True,
                        )
                except Exception as exc:
                    log.warning("Webhook delivery failed for %s to %s: %s", event_type, url, exc)
                    break
