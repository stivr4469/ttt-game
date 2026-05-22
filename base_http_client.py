"""Базовый HTTP-клиент с retry, timeout и структурированным логированием."""
import time
import requests
from typing import Any
from log_config import get_logger

log = get_logger(__name__)

_DEFAULT_TIMEOUT = 20
_MAX_RETRIES     = 3
_RETRY_BACKOFF   = 2.0


class BaseHTTPClient:
    """
    Обёртка над requests.Session с:
    - автоматическим retry (exponential backoff) для 5xx и сетевых ошибок
    - единым timeout
    - структурированным логированием ошибок
    """

    def __init__(
        self,
        base_url: str = "",
        timeout: int = _DEFAULT_TIMEOUT,
        max_retries: int = _MAX_RETRIES,
    ):
        self.base_url    = base_url.rstrip("/")
        self.timeout     = timeout
        self.max_retries = max_retries
        self._session    = requests.Session()

    def _request(self, method: str, url: str, **kwargs) -> Any:
        """Выполняет запрос с retry. url должен быть полным."""
        kwargs.setdefault("timeout", self.timeout)
        last_exc: Exception = RuntimeError("no attempts made")
        for attempt in range(self.max_retries):
            try:
                resp = self._session.request(method, url, **kwargs)
                resp.raise_for_status()
                return resp.json() if resp.content else {}
            except requests.exceptions.HTTPError as exc:
                # 4xx — не ретраить, пробрасываем сразу
                if exc.response is not None and exc.response.status_code < 500:
                    raise
                last_exc = exc
            except requests.exceptions.RequestException as exc:
                last_exc = exc

            if attempt < self.max_retries - 1:
                wait = _RETRY_BACKOFF ** attempt
                log.warning(
                    "HTTP request failed, retrying",
                    extra={"url": url, "attempt": attempt + 1, "wait": wait, "error": str(last_exc)},
                )
                time.sleep(wait)

        log.error(
            "HTTP request failed after retries",
            extra={"url": url, "attempts": self.max_retries, "error": str(last_exc)},
        )
        raise last_exc

    def _get(self, path: str, **kwargs) -> Any:
        return self._request("GET", f"{self.base_url}{path}", **kwargs)

    def _post(self, path: str, **kwargs) -> Any:
        return self._request("POST", f"{self.base_url}{path}", **kwargs)
