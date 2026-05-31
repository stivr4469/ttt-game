"""Централизованная конфигурация через Pydantic BaseSettings."""

import os
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Evidence Tracker
    evidence_api_key: str = "soc2-dev-key"
    evidence_tracker_url: str = "http://localhost:8001"

    # JWT
    jwt_secret_key: str = "dev-secret-change-in-prod-32chars!!"

    # CORS — разделённые запятой origins
    cors_origins: str = "http://localhost:8080,http://localhost:3000"

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"

    # Slack
    slack_webhook_url: str = ""

    # GitHub
    github_token: str = ""
    github_repo: str = "stivr4469/compliance-sandbox"

    # LLM
    openai_api_key: str = ""
    openai_base_url: str = "https://openrouter.ai/api/v1"
    openai_model: str = "google/gemini-flash-1.5"

    # Policy generation — Haiku: дешевле и быстро для document generation
    openrouter_api_key: str = ""
    policy_model: str = "anthropic/claude-haiku-4-5-20251001"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",  # .env может содержать поля не объявленные здесь
    }


@lru_cache
def get_settings() -> Settings:
    return Settings()
