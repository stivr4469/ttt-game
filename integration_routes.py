"""
Integration management API — read-only health and metadata endpoints.

GET /api/integrations/        — list all registered integrations
GET /api/integrations/health  — run check_connection() on all integrations

These endpoints require a valid auth token (any role).

To register integrations at startup, call IntegrationRegistry.instance().register(...)
before the FastAPI app starts serving (e.g. in a startup event handler or in main).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from auth import require_auth
from integrations import IntegrationRegistry

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


@router.get("/", summary="List registered integrations")
async def list_integrations(
    payload: dict = Depends(require_auth),
) -> list[dict]:
    """Return metadata for all registered integrations.

    Response example::

        [
            {"name": "jira", "version": "2.0", "type": "JiraIntegrationClient"},
        ]
    """
    return IntegrationRegistry.instance().list_integrations()


@router.get("/health", summary="Health-check all registered integrations")
async def check_all_health(
    payload: dict = Depends(require_auth),
) -> dict[str, dict]:
    """Run check_connection() on every registered integration client.

    Response example::

        {
            "jira": {"connected": true, "latency_ms": 42, "error": null}
        }

    Errors from individual integrations are caught and surfaced in the response
    body rather than raising HTTP exceptions, so a single unhealthy integration
    does not obscure the status of the others.
    """
    return await IntegrationRegistry.instance().check_all()
