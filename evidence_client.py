"""
HTTP-клиент для Evidence Tracker API.
Retry с exponential backoff, явные таймауты, API-ключ, structured logging.
При исчерпании всех попыток evidence записывается в EventQueue для последующей доставки.
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from log_config import get_logger

log = get_logger(__name__)

_DEFAULT_TIMEOUT  = 30   # секунд на один запрос — при параллельных агентах может очередь
_MAX_RETRIES      = 2    # попытки
_RETRY_BACKOFF    = 2.0  # множитель задержки между попытками


class EvidenceClientError(RuntimeError):
    pass


class EvidenceClient:
    def __init__(
        self,
        base_url: str,
        agent_name: str = "default",
        timeout: int = _DEFAULT_TIMEOUT,
        tenant_id: Optional[str] = None,
    ):
        self.base_url    = base_url.rstrip("/")
        self.timeout     = timeout
        self._agent_name = agent_name

        # Сначала пробует {AGENT_NAME}_API_KEY, потом EVIDENCE_API_KEY как fallback
        env_var = f"{agent_name.upper()}_API_KEY"
        api_key = os.getenv(env_var) or os.getenv("EVIDENCE_API_KEY", "")

        # tenant_id: явный аргумент → contextvar → None
        if tenant_id is None:
            try:
                from tenant_context import get_current_tenant_id
                tenant_id = get_current_tenant_id()
            except ImportError:
                pass

        self._tenant_id = tenant_id

        headers: dict = {
            "X-API-Key":    api_key,
            "Content-Type": "application/json",
        }
        if tenant_id:
            headers["X-Tenant-ID"] = str(tenant_id)

        self._session = requests.Session()
        self._session.headers.update(headers)

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        kwargs.setdefault("timeout", self.timeout)

        last_exc: Optional[Exception] = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                resp = self._session.request(method, url, **kwargs)
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.Timeout as e:
                last_exc = e
                log.warning("Evidence Tracker timeout", extra={"url": url, "attempt": attempt})
            except requests.exceptions.ConnectionError as e:
                last_exc = e
                log.warning("Evidence Tracker connection error", extra={"url": url, "attempt": attempt})
            except requests.exceptions.HTTPError as e:
                # 4xx — не ретраим: это ошибка запроса, не инфраструктуры
                status = e.response.status_code if e.response else 0
                if status < 500:
                    log.error("Evidence Tracker client error",
                              extra={"url": url, "status": status, "body": e.response.text[:200]})
                    raise EvidenceClientError(f"HTTP {status}: {e.response.text[:200]}") from e
                last_exc = e
                log.warning("Evidence Tracker server error", extra={"url": url, "status": status, "attempt": attempt})

            if attempt < _MAX_RETRIES:
                delay = _RETRY_BACKOFF ** attempt
                log.info("Retrying", extra={"url": url, "delay_s": round(delay, 2), "next_attempt": attempt + 1})
                time.sleep(delay)

        raise EvidenceClientError(f"All {_MAX_RETRIES} retries failed for {url}") from last_exc

    # ── Frameworks ──────────────────────────────────────────────────────────
    def get_frameworks(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/api/v1/frameworks/")

    def create_framework(self, name: str, description: str) -> Dict[str, Any]:
        return self._request("POST", "/api/v1/frameworks/", json={"name": name, "description": description})

    # ── Controls ────────────────────────────────────────────────────────────
    def get_controls(self, framework_id: Optional[str] = None) -> List[Dict[str, Any]]:
        params = {"framework_id": framework_id} if framework_id else {}
        try:
            result = self._request("GET", "/api/v1/controls/", params=params)
            if result:
                return result
        except (EvidenceClientError, Exception) as _exc:
            log.warning(
                "get_controls: HTTP failed, falling back to control_mapping",
                extra={"error": str(_exc)},
            )
        try:
            from control_mapping import CONTROL_MAPPINGS
            return [
                {
                    "id": m.soc2,
                    "code": m.soc2,
                    "title": m.description,
                    "framework": "SOC2",
                    "category": m.category,
                    "status": "UNKNOWN",
                }
                for m in CONTROL_MAPPINGS
            ]
        except Exception as _map_exc:
            log.error("get_controls: fallback also failed", extra={"error": str(_map_exc)})
            return []

    def create_control(self, framework_id: str, code: str, title: str, description: str) -> Dict[str, Any]:
        return self._request("POST", "/api/v1/controls/", json={
            "framework_id": framework_id,
            "code":         code,
            "title":        title,
            "description":  description,
        })

    def update_control_status(self, control_id: str, status: str) -> Dict[str, Any]:
        return self._request("PATCH", f"/api/v1/controls/{control_id}/status", json={"status": status})

    def submit_test_result(
        self,
        control_id: str,
        status: str,
        test_key: str,
        resource_id: str = "*",
        producer: str = "agent",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit a test result through the proper test engine pipeline.

        Routes through POST /api/v1/test-results/batch which triggers
        rollup derivation and cross-walk propagation to other frameworks.
        Status must be one of: PASS, FAIL, ERROR, NA.
        """
        payload = {
            "producer": producer,
            "trigger": "agent",
            "results": [{
                "test_key": test_key,
                "resource_id": resource_id,
                "status": status,
                "details": {**(details or {}), "control_id": control_id},
            }],
        }
        try:
            return self._request("POST", "/api/v1/test-results/batch", json=payload)
        except EvidenceClientError as exc:
            log.warning(
                "submit_test_result failed for %s (%s), falling back to direct status",
                test_key, control_id, extra={"error": str(exc)}
            )
            # Fallback: direct status update (deprecated path)
            return self.update_control_status(control_id, status)

    # ── Evidence ────────────────────────────────────────────────────────────
    def create_evidence(self, control_id: str, title: str, content: str, source: str) -> Dict[str, Any]:
        # Обрезаем до лимита сервера (100 KB) чтобы не получить 422
        if len(content) > 99_000:
            content = content[:99_000] + "…[truncated]"
        title_safe = title[:490]   # лимит сервера 500

        try:
            result = self._request("POST", "/api/v1/evidence/", json={
                "control_id": control_id,
                "title":      title_safe,
                "content":    content,
                "source":     source,
            })
        except EvidenceClientError as exc:
            log.error(
                "evidence_client: все попытки исчерпаны, ставим в retry-очередь",
                extra={"control_id": control_id, "source": source, "error": str(exc)},
            )
            self._enqueue_retry(control_id, title_safe, content, source)
            return {"queued": True, "control_id": control_id, "source": source}

        # Публикуем EVIDENCE_ADDED (best-effort)
        try:
            from event_bus import get_event_bus, ComplianceEvent, ComplianceEventType
            bus = get_event_bus()
            ev_event = ComplianceEvent.create(
                event_type=ComplianceEventType.EVIDENCE_ADDED,
                entity_type="evidence",
                entity_id=str(result.get("id", "unknown")),
                actor=f"agent:{source}",
                payload={
                    "control_id": control_id,
                    "title":      title_safe,
                    "source":     source,
                    "created_at": result.get("created_at"),
                },
                severity="info",
            )
            bus.publish(ev_event)
        except Exception as _bus_exc:
            log.debug(
                "evidence_client: не удалось опубликовать EVIDENCE_ADDED",
                extra={"error": str(_bus_exc)},
            )
        return result

    def _enqueue_retry(self, control_id: str, title: str, content: str, source: str) -> None:
        """Записать неудавшееся evidence в EventQueue через синхронный sqlite3 (без asyncio)."""
        import sqlite3 as _sqlite3
        import os as _os
        try:
            db_url = _os.getenv("DATABASE_URL", "")
            if not db_url or "sqlite" not in db_url:
                log.warning("evidence_client: _enqueue_retry поддерживается только для SQLite")
                return
            # Extract file path from sqlite+aiosqlite:///./path or sqlite:///path
            db_path = db_url.split("///", 1)[-1]
            conn = _sqlite3.connect(db_path, timeout=5)
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO event_queue (id, event_type, entity_id, payload, status, created_at, tenant_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        "evidence.retry",
                        control_id,
                        json.dumps({
                            "control_id": control_id,
                            "title":      title,
                            "content":    content,
                            "source":     source,
                            "base_url":   self.base_url,
                        }),
                        "pending",
                        datetime.now(timezone.utc).isoformat(),
                        self._tenant_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception as eq_exc:
            log.error(
                "evidence_client: не удалось записать в EventQueue",
                extra={"error": str(eq_exc)},
            )

    def submit_test_results(self, producer: str, results: list[dict],
                            run_id: str | None = None,
                            trigger: str = "scheduled") -> dict:
        """Отправить результаты тестов батчем в Test Engine API."""
        payload = {
            "producer": producer,
            "trigger": trigger,
            "results": results,
        }
        if run_id:
            payload["run_id"] = run_id
        try:
            return self._request("POST", "/api/v1/test-results/batch", json=payload)
        except Exception as e:
            log.warning("submit_test_results failed: %s", e)
            return {"error": str(e), "inserted": 0, "skipped": len(results)}

    def get_evidence(self, control_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"limit": limit}
        if control_id:
            params["control_id"] = control_id
        return self._request("GET", "/api/v1/evidence/", params=params)
