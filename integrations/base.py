"""
Generic Integration Sync Framework — base abstractions.

Adding a new integration (e.g. ServiceNow, Azure DevOps) requires only:
  1. Subclass BaseFieldMapper  → implement map_inbound / map_outbound
  2. Subclass BaseIntegrationClient → implement create_mapper / check_connection /
     fetch_items / push_item
  3. Register with IntegrationRegistry.instance().register("name", client)
"""
import abc
import enum
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------

class SyncStatus(str, enum.Enum):
    SYNCED = "synced"
    PENDING = "pending"
    FAILED = "failed"
    CONFLICT = "conflict"
    SKIPPED = "skipped"


@dataclass
class SyncResult:
    """Result of syncing a single item between an external system and the platform."""

    status: SyncStatus
    external_id: str
    internal_id: Optional[str] = None
    # Maps field name → (old_value, new_value) for audit purposes.
    changes: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass
class WebhookEvent:
    """Parsed payload from an inbound webhook call."""

    source: str          # e.g. "jira", "github", "okta"
    event_type: str      # e.g. "issue.updated", "user.deactivated"
    external_id: str
    payload: Dict[str, Any]
    received_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# ---------------------------------------------------------------------------
# Field mapper
# ---------------------------------------------------------------------------

class BaseFieldMapper(abc.ABC):
    """Maps between an external system's data format and the internal compliance platform format.

    Subclass and implement map_inbound / map_outbound.
    Optionally override validate_inbound to add schema-level checks.
    """

    @abc.abstractmethod
    def map_inbound(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Convert external system data → internal platform format.

        Args:
            raw: Raw item dict as returned by the external system's API.

        Returns:
            Dict conforming to the internal platform schema.
        """
        ...

    @abc.abstractmethod
    def map_outbound(self, internal: Dict[str, Any]) -> Dict[str, Any]:
        """Convert internal platform format → external system format.

        Args:
            internal: Internal platform item dict.

        Returns:
            Dict ready to be POSTed / PATCHed to the external system's API.
        """
        ...

    def validate_inbound(self, raw: Dict[str, Any]) -> List[str]:
        """Validate a raw external item before mapping.

        Returns:
            List of human-readable error messages. Empty list means the item
            is valid and safe to map.
        """
        return []


# ---------------------------------------------------------------------------
# Integration client
# ---------------------------------------------------------------------------

class BaseIntegrationClient(abc.ABC):
    """Base class for all integration clients (Jira, GitHub, Okta, ServiceNow, …).

    Subclasses must implement:
      - create_mapper()     — return the field-mapper instance
      - check_connection()  — connectivity probe
      - fetch_items()       — pull items from the external system
      - push_item()         — push one item to the external system

    The sync() template method orchestrates a full incremental or full sync.
    Override upsert_internal() to persist the mapped data to the database.
    Override handle_webhook() to react to real-time events.
    """

    integration_name: str = "unknown"
    integration_version: str = "1.0"

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self._mapper: Optional[BaseFieldMapper] = None

    # ------------------------------------------------------------------
    # Mapper (lazy-initialised via factory)
    # ------------------------------------------------------------------

    @property
    def mapper(self) -> BaseFieldMapper:
        """Lazily initialise and cache the field mapper."""
        if self._mapper is None:
            self._mapper = self.create_mapper()
        return self._mapper

    @abc.abstractmethod
    def create_mapper(self) -> BaseFieldMapper:
        """Factory method — return the concrete BaseFieldMapper for this integration."""
        ...

    # ------------------------------------------------------------------
    # Abstract operations
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def check_connection(self) -> Dict[str, Any]:
        """Probe connectivity to the external system.

        Returns:
            Dict with at minimum:
              {"connected": bool, "latency_ms": int, "error": str | None}
        """
        ...

    @abc.abstractmethod
    async def fetch_items(
        self, since: Optional[datetime] = None, **kwargs: Any
    ) -> List[Dict[str, Any]]:
        """Fetch items from the external system.

        Args:
            since: If provided, fetch only items updated after this datetime
                   (incremental sync). None means full sync.

        Returns:
            List of raw item dicts from the external system.
        """
        ...

    @abc.abstractmethod
    async def push_item(self, internal_data: Dict[str, Any]) -> SyncResult:
        """Create or update one item in the external system.

        Args:
            internal_data: Internal platform item dict.

        Returns:
            SyncResult describing the outcome.
        """
        ...

    # ------------------------------------------------------------------
    # Template methods (override to customise)
    # ------------------------------------------------------------------

    async def sync(self, since: Optional[datetime] = None) -> List[SyncResult]:
        """Run a full (or incremental) sync.

        Fetches all items from the external system, validates and maps each
        one, then calls upsert_internal() to persist it.  Per-item errors are
        captured as FAILED SyncResults so that one bad item does not abort the
        entire sync.

        Args:
            since: Incremental cutoff datetime.  None = full sync.

        Returns:
            List of SyncResult, one per item fetched.
        """
        results: List[SyncResult] = []
        try:
            raw_items = await self.fetch_items(since=since)
        except Exception:
            log.exception(
                "Sync fetch failed for integration=%s", self.integration_name
            )
            return results

        for raw in raw_items:
            ext_id = str(raw.get("id", "unknown"))
            try:
                errors = self.mapper.validate_inbound(raw)
                if errors:
                    results.append(
                        SyncResult(
                            status=SyncStatus.FAILED,
                            external_id=ext_id,
                            error=f"Validation: {'; '.join(errors)}",
                        )
                    )
                    continue

                internal = self.mapper.map_inbound(raw)
                result = await self.upsert_internal(internal, raw)
                results.append(result)

            except Exception:
                log.exception(
                    "Error syncing item id=%s from integration=%s",
                    ext_id,
                    self.integration_name,
                )
                results.append(
                    SyncResult(
                        status=SyncStatus.FAILED,
                        external_id=ext_id,
                        error="Unexpected error — see server logs",
                    )
                )

        log.info(
            "Sync complete integration=%s total=%d failed=%d",
            self.integration_name,
            len(results),
            sum(1 for r in results if r.status == SyncStatus.FAILED),
        )
        return results

    async def upsert_internal(
        self, internal: Dict[str, Any], raw: Dict[str, Any]
    ) -> SyncResult:
        """Persist a mapped item to the internal database.

        Default implementation is a no-op that returns SYNCED.
        Override in subclasses (or mix-ins) to write to the DB.

        Args:
            internal: Mapped item in internal platform format.
            raw:      Original raw dict from the external system
                      (used to extract external_id).

        Returns:
            SyncResult describing the outcome.
        """
        return SyncResult(
            status=SyncStatus.SYNCED,
            external_id=str(raw.get("id", "unknown")),
            internal_id=internal.get("id"),
        )

    async def handle_webhook(self, event: WebhookEvent) -> SyncResult:
        """Process an inbound webhook event for real-time updates.

        Default returns SKIPPED.  Override for integrations that support webhooks.

        Args:
            event: Parsed WebhookEvent from the webhook router.

        Returns:
            SyncResult describing the outcome.
        """
        return SyncResult(
            status=SyncStatus.SKIPPED,
            external_id=event.external_id,
            error="Webhook handling not implemented for this integration",
        )

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        """Return recent sync history.

        Default returns an empty list.
        Override with a DB-backed implementation for production use.
        """
        return []


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class IntegrationRegistry:
    """Singleton registry that tracks all registered integration clients.

    Usage:
        registry = IntegrationRegistry.instance()
        registry.register("jira", JiraIntegrationClient(config))
        client = registry.get("jira")
    """

    _instance: Optional["IntegrationRegistry"] = None
    # Class-level dict shared across all instances (there should only be one).
    _clients: Dict[str, BaseIntegrationClient] = {}

    @classmethod
    def instance(cls) -> "IntegrationRegistry":
        """Return the process-global singleton registry."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register(self, name: str, client: BaseIntegrationClient) -> None:
        """Register an integration client under the given name.

        Args:
            name:   Unique integration identifier (e.g. "jira", "github").
            client: Fully constructed BaseIntegrationClient subclass instance.
        """
        self._clients[name] = client
        log.info(
            "Registered integration name=%s version=%s class=%s",
            name,
            client.integration_version,
            type(client).__name__,
        )

    def get(self, name: str) -> Optional[BaseIntegrationClient]:
        """Return the client registered under *name*, or None if not found."""
        return self._clients.get(name)

    def list_integrations(self) -> List[Dict[str, Any]]:
        """Return a list of summary dicts for all registered integrations."""
        return [
            {
                "name": name,
                "version": client.integration_version,
                "type": type(client).__name__,
            }
            for name, client in self._clients.items()
        ]

    async def check_all(self) -> Dict[str, Dict[str, Any]]:
        """Run check_connection() on all registered integrations in parallel.

        Returns:
            Dict mapping integration name → check_connection() result dict.
            Exceptions are caught and surfaced as {"connected": False, "error": "..."}.
        """
        import asyncio

        async def _probe(name: str, client: BaseIntegrationClient) -> tuple[str, dict]:
            try:
                result = await client.check_connection()
                return name, result
            except Exception as exc:
                log.exception("Health check failed for integration=%s", name)
                return name, {"connected": False, "error": str(exc)}

        pairs = await asyncio.gather(
            *(_probe(name, client) for name, client in self._clients.items()),
            return_exceptions=False,
        )
        return dict(pairs)
