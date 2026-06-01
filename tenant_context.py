"""Tenant context — единое хранилище current tenant_id для текущего запроса."""
from contextvars import ContextVar
from typing import Optional

_current_tenant_id: ContextVar[Optional[str]] = ContextVar("tenant_id", default=None)


def get_current_tenant_id() -> Optional[str]:
    return _current_tenant_id.get()


def set_current_tenant_id(tenant_id: Optional[str]) -> None:
    _current_tenant_id.set(tenant_id)
