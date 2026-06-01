"""
Ollama client — замена облачных LLM для self-hosted режима.

Использование:
    client = OllamaClient()  # читает OLLAMA_BASE_URL из env
    response = await client.chat([{"role": "user", "content": "..."}])
"""
import logging
import os
from typing import Optional
from urllib.parse import urlparse

import httpx

log = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))


class OllamaClient:
    def __init__(self, base_url: str = OLLAMA_BASE_URL, model: str = OLLAMA_MODEL):
        self._base_url = base_url.rstrip("/")
        self.model = model
        self._timeout = OLLAMA_TIMEOUT

        # Validate URL at construction time
        _parsed = urlparse(self._base_url)
        if _parsed.scheme not in ("http", "https"):
            raise ValueError(f"OLLAMA_BASE_URL must use http/https: {self._base_url!r}")
        if not _parsed.netloc:
            raise ValueError(f"OLLAMA_BASE_URL missing host: {self._base_url!r}")

        # Keep backward-compatible attribute
        self.base_url = self._base_url

    async def chat(self, messages: list[dict], model: Optional[str] = None, stream: bool = False) -> str:
        """Отправить сообщения и получить ответ (non-streaming по умолчанию)."""
        model = model or self.model
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base_url}/api/chat",
                json={"model": model, "messages": messages, "stream": False},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("message", {}).get("content", "")

    async def generate(self, prompt: str, model: Optional[str] = None) -> str:
        """Простая генерация текста по prompt."""
        model = model or self.model
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base_url}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
            )
            resp.raise_for_status()
            return resp.json().get("response", "")

    async def is_available(self) -> bool:
        """Проверить доступность Ollama."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{self._base_url}/api/tags")
                return resp.status_code == 200
        except Exception as exc:
            log.debug("Ollama not available at %s: %s", self._base_url, exc)
            return False

    async def list_models(self) -> list[str]:
        """Список доступных моделей."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self._base_url}/api/tags")
                resp.raise_for_status()
                return [m["name"] for m in resp.json().get("models", [])]
        except Exception as exc:
            log.debug("Ollama list_models failed: %s", exc)
            return []
