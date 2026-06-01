"""
TenantMiddleware — устанавливает tenant_id из JWT в request.state и contextvar.

Фаза 0: nullable, не блокирует запросы без тенанта.
Фаза 2 (будущее): enforce=True будет требовать тенанта для всех non-public эндпоинтов.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from tenant_context import set_current_tenant_id

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"  # default tenant для existing data


class TenantMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        tenant_id = None

        # 1. Из Authorization Bearer JWT
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                from auth import decode_token
                payload = decode_token(auth_header[7:])
                if payload:
                    tenant_id = payload.get("tenant_id")
            except Exception:
                pass

        # 2. Из cookie (если есть)
        if not tenant_id:
            token = request.cookies.get("access_token")
            if token:
                try:
                    from auth import decode_token
                    payload = decode_token(token)
                    if payload:
                        tenant_id = payload.get("tenant_id")
                except Exception:
                    pass

        # 3. Fallback — default tenant (Фаза 0)
        if not tenant_id:
            tenant_id = DEFAULT_TENANT_ID

        request.state.tenant_id = tenant_id
        set_current_tenant_id(tenant_id)

        response = await call_next(request)
        return response
