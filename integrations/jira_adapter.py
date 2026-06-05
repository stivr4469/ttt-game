"""
Jira integration adapter.

Implements the Generic Integration Sync Framework for Jira REST API v3.

Usage:
    from integrations.jira_adapter import JiraIntegrationClient

    client = JiraIntegrationClient({
        "base_url":    "https://yourorg.atlassian.net",
        "email":       "bot@yourorg.com",
        "api_token":   "<api-token>",
        "project_key": "SEC",
    })
    # Or rely on env-var / secret-store fallback by passing an empty config:
    client = JiraIntegrationClient({})

    results = await client.sync()
    health  = await client.check_connection()

Maps Jira issues ↔ internal Finding format.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from integrations.base import (
    BaseFieldMapper,
    BaseIntegrationClient,
    SyncResult,
    SyncStatus,
)
from log_config import get_logger
from secret_store import get_connector_secret

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FIELDS_QUERY = "summary,status,priority,assignee,created,updated,labels,description"
_DEFAULT_MAX_RESULTS = 100

# Mapping from Jira priority names to internal severity labels.
_PRIORITY_TO_SEVERITY: Dict[str, str] = {
    "highest": "critical",
    "high":    "high",
    "medium":  "medium",
    "low":     "low",
    "lowest":  "info",
}

# Mapping from internal severity to Jira priority names.
_SEVERITY_TO_PRIORITY: Dict[str, str] = {v: k.capitalize() for k, v in _PRIORITY_TO_SEVERITY.items()}
_SEVERITY_TO_PRIORITY["critical"] = "Highest"


# ---------------------------------------------------------------------------
# Field mapper
# ---------------------------------------------------------------------------

class JiraFieldMapper(BaseFieldMapper):
    """Maps Jira issue format ↔ internal compliance Finding format."""

    def map_inbound(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a Jira issue dict → internal Finding format.

        Args:
            raw: A Jira issue object as returned by GET /rest/api/3/issue/{key}
                 or from a search result's ``issues`` array.

        Returns:
            Dict with keys: id, title, status, severity, assignee,
            created_at, updated_at, labels, source.
        """
        fields = raw.get("fields") or {}
        assignee = fields.get("assignee") or {}
        priority = fields.get("priority") or {}
        status   = fields.get("status") or {}

        priority_name = priority.get("name", "").lower()
        severity = _PRIORITY_TO_SEVERITY.get(priority_name, "medium")

        return {
            "id":         raw.get("key", ""),
            "title":      fields.get("summary", ""),
            "status":     status.get("name", ""),
            "severity":   severity,
            "assignee":   assignee.get("emailAddress") or assignee.get("displayName", ""),
            "created_at": fields.get("created", ""),
            "updated_at": fields.get("updated", ""),
            "labels":     fields.get("labels", []),
            "source":     "jira",
        }

    def map_outbound(self, internal: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an internal Finding dict → Jira issue fields for create/update.

        Args:
            internal: Internal platform item dict with at minimum a ``title`` key.

        Returns:
            Dict suitable for use as the ``fields`` body of POST /rest/api/3/issue.
        """
        priority_name = _SEVERITY_TO_PRIORITY.get(
            (internal.get("severity") or "medium").lower(), "Medium"
        )
        description_text = internal.get("description", internal.get("title", ""))

        body: Dict[str, Any] = {
            "summary":  internal.get("title", ""),
            "priority": {"name": priority_name},
            "labels":   internal.get("labels", ["soc2", "compliance"]),
            "description": {
                "type":    "doc",
                "version": 1,
                "content": [
                    {
                        "type":    "paragraph",
                        "content": [{"type": "text", "text": description_text}],
                    }
                ],
            },
        }

        # Include assignee if provided (Jira uses accountId).
        if internal.get("assignee_account_id"):
            body["assignee"] = {"accountId": internal["assignee_account_id"]}

        return body

    def validate_inbound(self, raw: Dict[str, Any]) -> List[str]:
        """Validate a raw Jira issue before mapping.

        Returns:
            List of error messages; empty list means valid.
        """
        errors: List[str] = []
        if not raw.get("key"):
            errors.append("Missing issue key")
        if not (raw.get("fields") or {}).get("summary"):
            errors.append("Missing summary")
        return errors


# ---------------------------------------------------------------------------
# Integration client
# ---------------------------------------------------------------------------

class JiraIntegrationClient(BaseIntegrationClient):
    """Async Jira REST API v3 integration client.

    Config keys (all optional — fall back to secret-store / env vars):
        base_url    — Jira cloud base URL, e.g. https://yourorg.atlassian.net
        email       — Atlassian account email for Basic Auth
        api_token   — Atlassian API token
        project_key — Default project key used in JQL queries (default: "SEC")
    """

    integration_name    = "jira"
    integration_version = "2.0"

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)

        # Resolve credentials: config dict takes priority, then secret-store / env.
        self._base_url    = (config.get("base_url")    or get_connector_secret("JIRA_URL", "")).rstrip("/")
        self._email       = config.get("email")        or get_connector_secret("JIRA_USER", "")
        self._api_token   = config.get("api_token")    or get_connector_secret("JIRA_API_TOKEN", "")
        self._project_key = config.get("project_key")  or get_connector_secret("JIRA_PROJECT_KEY", "SEC")

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    def create_mapper(self) -> JiraFieldMapper:
        """Return a JiraFieldMapper instance."""
        return JiraFieldMapper()

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _make_client(self) -> httpx.AsyncClient:
        """Build a configured httpx.AsyncClient for Jira REST API v3."""
        return httpx.AsyncClient(
            base_url=f"{self._base_url}/rest/api/3",
            auth=(self._email, self._api_token),
            headers={
                "Accept":       "application/json",
                "Content-Type": "application/json",
            },
            timeout=15.0,
        )

    async def _api(
        self, method: str, path: str, client: Optional[httpx.AsyncClient] = None, **kwargs: Any
    ) -> Any:
        """Execute a single Jira API call.

        Args:
            method: HTTP method string (GET, POST, PUT, …).
            path:   Path relative to /rest/api/3 (e.g. "/issue/SEC-1").
            client: Optionally pass an existing AsyncClient to reuse connections.

        Returns:
            Parsed JSON response body, or {} for empty responses.

        Raises:
            httpx.HTTPStatusError: on 4xx/5xx responses.
        """
        _own_client = client is None
        if _own_client:
            client = self._make_client()
        try:
            resp = await client.request(method, path, **kwargs)
            resp.raise_for_status()
            return resp.json() if resp.content else {}
        finally:
            if _own_client:
                await client.aclose()

    # ------------------------------------------------------------------
    # BaseIntegrationClient implementation
    # ------------------------------------------------------------------

    async def check_connection(self) -> Dict[str, Any]:
        """Call GET /rest/api/3/myself to validate credentials and measure latency.

        Returns:
            {"connected": bool, "latency_ms": int, "error": str | None,
             "account_id": str | None}
        """
        if not self._base_url or not self._email or not self._api_token:
            return {
                "connected":  False,
                "latency_ms": 0,
                "error":      "Missing Jira credentials (base_url / email / api_token)",
            }

        start = time.monotonic()
        try:
            data = await self._api("GET", "/myself")
            latency_ms = int((time.monotonic() - start) * 1000)
            log.info(
                "Jira connection OK account_id=%s latency_ms=%d",
                data.get("accountId"),
                latency_ms,
            )
            return {
                "connected":  True,
                "latency_ms": latency_ms,
                "error":      None,
                "account_id": data.get("accountId"),
            }
        except Exception as exc:
            latency_ms = int((time.monotonic() - start) * 1000)
            log.warning("Jira connection check failed: %s", exc)
            return {
                "connected":  False,
                "latency_ms": latency_ms,
                "error":      str(exc),
            }

    async def fetch_items(
        self, since: Optional[datetime] = None, **kwargs: Any
    ) -> List[Dict[str, Any]]:
        """Fetch Jira issues via JQL with pagination.

        Args:
            since:       If provided, restricts results to issues updated at or
                         after this datetime (incremental sync).
            project_key: Override the default project key for this call.

        Returns:
            List of raw Jira issue dicts (``id``, ``key``, ``fields``, …).
        """
        project_key = kwargs.get("project_key", self._project_key)
        jql_parts = [f"project = {project_key}"]

        if since is not None:
            # Jira JQL date format: "YYYY/MM/DD HH:MM"
            date_str = since.astimezone(timezone.utc).strftime("%Y/%m/%d %H:%M")
            jql_parts.append(f'updatedDate >= "{date_str}"')

        jql = " AND ".join(jql_parts) + " ORDER BY updated DESC"

        issues: List[Dict[str, Any]] = []
        start_at = 0
        max_results = kwargs.get("max_results", _DEFAULT_MAX_RESULTS)

        async with self._make_client() as client:
            while True:
                data = await self._api(
                    "GET",
                    "/search",
                    client=client,
                    params={
                        "jql":        jql,
                        "fields":     _FIELDS_QUERY,
                        "startAt":    start_at,
                        "maxResults": max_results,
                    },
                )
                batch = data.get("issues", [])
                issues.extend(batch)

                total = data.get("total", 0)
                start_at += len(batch)

                if start_at >= total or not batch:
                    break

        log.info(
            "Fetched %d Jira issues from project=%s since=%s",
            len(issues),
            project_key,
            since,
        )
        return issues

    async def push_item(self, internal_data: Dict[str, Any]) -> SyncResult:
        """Create or update a Jira issue from internal platform data.

        If ``internal_data`` contains a ``jira_key`` field the issue is updated
        (PATCH-style via issue fields update).  Otherwise a new issue is created.

        Args:
            internal_data: Internal platform Finding dict.

        Returns:
            SyncResult with status SYNCED on success, FAILED on error.
        """
        jira_key: Optional[str] = internal_data.get("jira_key")
        outbound = self.mapper.map_outbound(internal_data)

        try:
            if jira_key:
                # Update existing issue fields.
                await self._api("PUT", f"/issue/{jira_key}", json={"fields": outbound})
                log.info("Updated Jira issue key=%s", jira_key)
                return SyncResult(
                    status=SyncStatus.SYNCED,
                    external_id=jira_key,
                    internal_id=internal_data.get("id"),
                    changes={"updated": True},
                )
            else:
                # Create a new issue.
                project_key = internal_data.get("project_key", self._project_key)
                body: Dict[str, Any] = {
                    "fields": {
                        "project":    {"key": project_key},
                        "issuetype":  {"name": internal_data.get("issue_type", "Task")},
                        **outbound,
                    }
                }
                result = await self._api("POST", "/issue", json=body)
                new_key = result.get("key", "")
                log.info("Created Jira issue key=%s", new_key)
                return SyncResult(
                    status=SyncStatus.SYNCED,
                    external_id=new_key,
                    internal_id=internal_data.get("id"),
                    changes={"created": True, "url": f"{self._base_url}/browse/{new_key}"},
                )
        except Exception as exc:
            log.exception(
                "Failed to push item to Jira internal_id=%s", internal_data.get("id")
            )
            return SyncResult(
                status=SyncStatus.FAILED,
                external_id=jira_key or "new",
                internal_id=internal_data.get("id"),
                error=str(exc),
            )
