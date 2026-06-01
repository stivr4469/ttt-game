"""
LLM status routes — информация о текущем LLM-провайдере.
"""
import logging

from fastapi import APIRouter, Depends

from llm_router import get_active_provider
from ollama_client import OllamaClient

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/llm", tags=["llm"])


@router.get("/status")
async def llm_status() -> dict:
    """
    Возвращает информацию о текущем LLM-провайдере.

    Если провайдер — Ollama, дополнительно проверяет доступность и
    возвращает список доступных моделей.
    """
    provider = get_active_provider()
    result: dict = {"provider": provider, "available": True}

    if provider == "ollama":
        client = OllamaClient()
        result["available"] = await client.is_available()
        if result["available"]:
            result["models"] = await client.list_models()

    return result
