"""
sync_controls_map.py — синхронизировать controls_map.json с Evidence Tracker API.

Использование (CLI):
    python sync_controls_map.py

Использование как модуль:
    from sync_controls_map import sync_controls_map
    count = await sync_controls_map()

Логика:
  - GET {EVIDENCE_TRACKER_URL}/api/v1/controls/?limit=200
  - Строит dict {control.code: str(control.id)} для каждого контроля
  - Атомарно записывает controls_map.json (через tmp-файл + os.replace)
  - При HTTP-ошибке логирует предупреждение и оставляет существующий файл нетронутым
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

import httpx

from constants import CONTROLS_MAP_FILE

log = logging.getLogger(__name__)

_TIMEOUT = 15.0


async def sync_controls_map() -> int:
    """
    Получить список контролей из Evidence Tracker и перезаписать controls_map.json.

    Returns:
        Количество синхронизированных контролей.

    Raises:
        Ничего — при сбое логирует warning и возвращает 0.
    """
    base_url = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")
    api_key = os.getenv("EVIDENCE_API_KEY", "")

    url = f"{base_url}/api/v1/controls/?limit=200"
    headers: dict[str, str] = {}
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        log.warning(
            "sync_controls_map: HTTP %s from %s — keeping existing controls_map.json",
            exc.response.status_code,
            url,
        )
        return 0
    except Exception as exc:
        log.warning(
            "sync_controls_map: could not reach Evidence Tracker (%s) — keeping existing controls_map.json. Error: %s",
            url,
            exc,
        )
        return 0

    try:
        data = response.json()
    except Exception as exc:
        log.warning("sync_controls_map: invalid JSON from %s: %s", url, exc)
        return 0

    # API returns a plain list: [{"id": "...", "code": "CC1.1", ...}, ...]
    if isinstance(data, dict):
        # Defensive: handle {"items": [...]} envelope if API changes
        items = data.get("items", [])
    elif isinstance(data, list):
        items = data
    else:
        log.warning("sync_controls_map: unexpected response type %s from %s", type(data), url)
        return 0

    controls_map: dict[str, str] = {}
    for item in items:
        code = item.get("code")
        control_id = item.get("id")
        if code and control_id:
            controls_map[code] = str(control_id)

    count = len(controls_map)
    if count == 0:
        log.warning("sync_controls_map: response contained 0 controls — skipping write to avoid data loss")
        return 0

    # Atomic write: tmp file → os.replace
    tmp_path = CONTROLS_MAP_FILE + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(controls_map, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, CONTROLS_MAP_FILE)
    except OSError as exc:
        log.error("sync_controls_map: failed to write %s: %s", CONTROLS_MAP_FILE, exc)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return 0

    log.info("sync_controls_map: synced %d controls → %s", count, CONTROLS_MAP_FILE)
    return count


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    synced = asyncio.run(sync_controls_map())
    if synced > 0:
        print(f"OK: synced {synced} controls → {CONTROLS_MAP_FILE}")
        sys.exit(0)
    else:
        print(
            f"WARNING: no controls synced — {CONTROLS_MAP_FILE} left unchanged (see logs above)",
            file=sys.stderr,
        )
        sys.exit(1)
