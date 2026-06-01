"""
LLM Router — выбирает провайдера по конфигурации.

Порядок приоритета:
1. ANTHROPIC_API_KEY → Claude (Anthropic)
2. OPENAI_API_KEY → GPT (OpenAI) или OpenRouter-compatible
3. OLLAMA_BASE_URL → Ollama (локальная LLM, self-hosted)
"""
import os
import logging
from typing import Optional

log = logging.getLogger(__name__)


MAX_CONTENT_LEN = 50_000  # ~12k tokens


async def llm_chat(messages: list[dict], system: str = "", model: Optional[str] = None) -> str:
    """
    Unified chat interface. Автоматически выбирает провайдера.
    messages: [{"role": "user"|"assistant", "content": "..."}]
    """
    for msg in messages:
        if len(str(msg.get("content", ""))) > MAX_CONTENT_LEN:
            raise ValueError(f"Message content exceeds maximum length of {MAX_CONTENT_LEN} chars")

    if os.getenv("ANTHROPIC_API_KEY"):
        return await _anthropic_chat(messages, system, model)
    elif os.getenv("OPENAI_API_KEY") or os.getenv("OPENROUTER_API_KEY"):
        return await _openai_chat(messages, system, model)
    else:
        return await _ollama_chat(messages, system, model)


async def _anthropic_chat(messages: list[dict], system: str, model: Optional[str] = None) -> str:
    import asyncio
    try:
        import anthropic  # type: ignore
        client = anthropic.AsyncAnthropic()
        resp = await asyncio.wait_for(
            client.messages.create(
                model=model or os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"),
                max_tokens=4096,
                system=system or "You are a SOC2 compliance assistant.",
                messages=messages,
            ),
            timeout=30,
        )
        return resp.content[0].text
    except Exception as exc:
        log.error("Anthropic error: %s", exc, exc_info=True)
        raise


async def _openai_chat(messages: list[dict], system: str, model: Optional[str] = None) -> str:
    import asyncio
    try:
        import openai  # type: ignore

        # Поддержка OpenRouter через openai-compatible API
        api_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENROUTER_API_KEY", "")
        base_url = os.getenv("OPENAI_BASE_URL", "https://openrouter.ai/api/v1") if os.getenv("OPENROUTER_API_KEY") and not os.getenv("OPENAI_API_KEY") else None

        client_kwargs: dict = {"api_key": api_key, "timeout": 30.0}
        if base_url:
            client_kwargs["base_url"] = base_url

        client = openai.AsyncOpenAI(**client_kwargs)
        full_messages = ([{"role": "system", "content": system}] if system else []) + messages
        default_model = os.getenv("OPENROUTER_MODEL", os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
        resp = await client.chat.completions.create(
            model=model or default_model,
            messages=full_messages,
        )
        return resp.choices[0].message.content or ""
    except Exception as exc:
        log.error("OpenAI/OpenRouter error: %s", exc, exc_info=True)
        raise


async def _ollama_chat(messages: list[dict], system: str, model: Optional[str] = None) -> str:
    from ollama_client import OllamaClient
    client = OllamaClient()
    full_messages = ([{"role": "system", "content": system}] if system else []) + messages
    return await client.chat(full_messages, model=model)


def get_active_provider() -> str:
    """Вернуть имя активного LLM-провайдера."""
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    elif os.getenv("OPENAI_API_KEY") or os.getenv("OPENROUTER_API_KEY"):
        return "openai"
    else:
        return "ollama"
