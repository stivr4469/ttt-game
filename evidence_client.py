"""
HTTP-клиент для Evidence Tracker API.
Retry с exponential backoff, явные таймауты, API-ключ, structured logging.
"""

import os
import time
import requests
from typing import Any, Dict, List, Optional
from log_config import get_logger

log = get_logger(__name__)

_DEFAULT_TIMEOUT  = 10   # секунд на один запрос
_MAX_RETRIES      = 3
_RETRY_BACKOFF    = 1.5  # множитель задержки между попытками


class EvidenceClientError(RuntimeError):
    pass


class EvidenceClient:
    def __init__(self, base_url: str, agent_name: str = "default", timeout: int = _DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        
        # Сначала пробует {AGENT_NAME}_API_KEY, потом EVIDENCE_API_KEY как fallback
        env_var = f"{agent_name.upper()}_API_KEY"
        api_key = os.getenv(env_var) or os.getenv("EVIDENCE_API_KEY", "soc2-dev-key")
        
        self._session = requests.Session()
        self._session.headers.update({
            "X-API-Key":    api_key,
            "Content-Type": "application/json",
        })

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
        return self._request("GET", "/api/v1/controls/", params=params)

    def create_control(self, framework_id: str, code: str, title: str, description: str) -> Dict[str, Any]:
        return self._request("POST", "/api/v1/controls/", json={
            "framework_id": framework_id,
            "code":         code,
            "title":        title,
            "description":  description,
        })

    def update_control_status(self, control_id: str, status: str) -> Dict[str, Any]:
        return self._request("PATCH", f"/api/v1/controls/{control_id}/status", json={"status": status})

    # ── Evidence ────────────────────────────────────────────────────────────
    def create_evidence(self, control_id: str, title: str, content: str, source: str) -> Dict[str, Any]:
        # Обрезаем до лимита сервера (100 KB) чтобы не получить 422
        if len(content) > 99_000:
            content = content[:99_000] + "…[truncated]"
        return self._request("POST", "/api/v1/evidence/", json={
            "control_id": control_id,
            "title":      title[:490],   # лимит сервера 500
            "content":    content,
            "source":     source,
        })

    def get_evidence(self, control_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"limit": limit}
        if control_id:
            params["control_id"] = control_id
        return self._request("GET", "/api/v1/evidence/", params=params)
