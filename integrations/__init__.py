"""
integrations — Generic Integration Sync Framework.

Public API:

    from integrations import (
        BaseIntegrationClient,
        BaseFieldMapper,
        SyncStatus,
        SyncResult,
        IntegrationRegistry,
        WebhookEvent,
    )

Adding a new integration requires only two classes:
  1. MyFieldMapper(BaseFieldMapper)        — map_inbound / map_outbound
  2. MyIntegrationClient(BaseIntegrationClient) — create_mapper / check_connection /
                                                  fetch_items / push_item

Then register it:
    IntegrationRegistry.instance().register("myservice", MyIntegrationClient(config))
"""
from integrations.base import (
    BaseFieldMapper,
    BaseIntegrationClient,
    IntegrationRegistry,
    SyncResult,
    SyncStatus,
    WebhookEvent,
)

__all__ = [
    "BaseIntegrationClient",
    "BaseFieldMapper",
    "SyncStatus",
    "SyncResult",
    "IntegrationRegistry",
    "WebhookEvent",
]
