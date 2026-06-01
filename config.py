"""Централизованная конфигурация через Pydantic BaseSettings."""

import logging
from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings

log = logging.getLogger(__name__)


class Settings(BaseSettings):
    # Evidence Tracker
    evidence_api_key: str = ""
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

    # Ollama — self-hosted LLM
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    ollama_timeout: int = 120

    # DB connection pool (PostgreSQL only; ignored for SQLite)
    db_pool_size: int = 20
    db_max_overflow: int = 10
    db_pool_timeout: int = 30
    db_pool_recycle: int = 1800

    # CORS origins list (used by FastAPI middleware)
    cors_origins_list: list[str] = ["http://localhost:3000", "http://localhost:8000"]

    @model_validator(mode="after")
    def _warn_missing_api_key(self) -> "Settings":
        if not self.evidence_api_key:
            log.warning(
                "EVIDENCE_API_KEY is not set — Evidence Tracker requests will be unauthenticated. "
                "Set the EVIDENCE_API_KEY environment variable."
            )
        return self

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        import os
        if os.getenv("ENVIRONMENT") == "production":
            required = {
                "JWT_SECRET_KEY": self.jwt_secret_key,
                "EVIDENCE_API_KEY": self.evidence_api_key,
            }
            missing = [
                k for k, v in required.items()
                if not v or v in ("", "soc2-dev-key", "dev-secret-change-in-prod-32chars!!")
            ]
            if missing:
                raise ValueError(f"Missing required production secrets: {missing}")
        return self

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",  # .env может содержать поля не объявленные здесь
    }


@lru_cache
def get_settings() -> Settings:
    return Settings()
