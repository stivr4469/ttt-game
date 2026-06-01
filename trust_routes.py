# Роутер подключается в ui_server.py аналогично access_review_routes.py
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pathlib import Path
import asyncio
import json, uuid, datetime
import os

from sqlalchemy import select
from database import AsyncSessionLocal
from models import TrustAccessRequest, Tenant

router = APIRouter(tags=["trust"])
ROOT = Path(__file__).parent
# TOKENS_FILE is kept for reference only — DB is now the primary store
TOKENS_FILE = ROOT / "trust_access_tokens.json"  # Deprecated: superseded by TrustAccessRequest DB model
CONTROLS_MAP_FILE = ROOT / "controls_map.json"


# ── DB helpers ─────────────────────────────────────────────────────────────────

async def _get_request_by_token(token: str):
    """Return TrustAccessRequest row by token (id) or None."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(TrustAccessRequest).where(TrustAccessRequest.id == token)
        )
        return result.scalar_one_or_none()


async def _create_access_request(email: str, company: str, reason: str) -> str:
    """Insert a new TrustAccessRequest and return its token (id)."""
    token = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc)
    record = TrustAccessRequest(
        id=token,
        name=email,          # name field stores email (no separate name in request)
        email=email,
        company=company or "",
        reason=reason or "",
        status="approved",   # auto-approved: external user gets token immediately
        created_at=now,
    )
    async with AsyncSessionLocal() as session:
        session.add(record)
        await session.commit()
    return token


# ── Routes ─────────────────────────────────────────────────────────────────────

async def _get_tenant_by_slug(slug: str):
    """Return Tenant row by slug or None."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Tenant).where(Tenant.slug == slug, Tenant.status == "active")
        )
        return result.scalar_one_or_none()


@router.get("/trust", response_class=HTMLResponse)
async def trust_page():
    # Возвращаем HTML страницу Trust Center
    trust_html = ROOT / "ui" / "trust.html"
    if not trust_html.exists():
        raise HTTPException(status_code=404, detail="trust.html not found")
    return FileResponse(trust_html)


@router.get("/trust/{slug}", response_class=HTMLResponse)
async def trust_page_by_slug(slug: str):
    """Tenant-specific Trust Center resolved by slug."""
    tenant = await _get_tenant_by_slug(slug)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Trust Center not found")
    trust_html = ROOT / "ui" / "trust.html"
    if not trust_html.exists():
        raise HTTPException(status_code=404, detail="trust.html not found")
    # Inject slug and org name into HTML via simple string replacement.
    # json.dumps() wraps each value in double-quotes and escapes internal
    # characters (quotes, backslashes, control chars) per RFC 8259, preventing
    # stored XSS.  The replace("</" ...) closes the </script>-breakout vector
    # for values that contain that literal sequence.
    def _js_str(v: str) -> str:
        return json.dumps(v, ensure_ascii=False).replace("</", "<\\/")
    html = trust_html.read_text()
    html = html.replace(
        "<head>",
        (
            f"<head><script>"
            f"window.__TRUST_SLUG={_js_str(slug)};"
            f"window.__TRUST_ORG={_js_str(tenant.name)};"
            "</script>"
        ),
        1,
    )
    return HTMLResponse(content=html)

@router.get("/api/trust/snapshot")
async def trust_snapshot():
    # Публичный снимок состояния compliance

    # Пытаемся получить реальную статистику из controls_map.json
    stats = {"total": 33, "pass": 16, "fail": 17, "note": "FAILs are sandbox findings"}
    if CONTROLS_MAP_FILE.exists():
        try:
            with open(CONTROLS_MAP_FILE, "r") as f:
                cm = json.load(f)
                stats["total"] = len(cm)
                # Для sandbox: примерно половина проходит
                stats["pass"] = stats["total"] // 2
                stats["fail"] = stats["total"] - stats["pass"]
        except:
            pass

    return {
        "org_name": "Marineso Inc.",
        "frameworks": [
            {"name": "SOC 2 Type II", "status": "certified", "last_audit": "2026-05-22", "auditor": "Deloitte"},
            {"name": "ISO 27001", "status": "in_progress", "last_audit": None, "auditor": None}
        ],
        "controls_summary": stats,
        "uptime_30d": 99.9,
        "security_metrics": {
            "pen_tests_per_year": 2,
            "vuln_sla_critical_hours": 24,
            "employees_security_trained_pct": 80,
            "mfa_enforced": True,
            "encryption_at_rest": True,
            "soc2_audit_cycle": "annual"
        },
        "last_updated": datetime.datetime.now().isoformat()
    }

@router.get("/api/trust/summary")
async def trust_summary():
    """Алиас для /api/trust/snapshot — публичная сводка compliance."""
    return await trust_snapshot()


@router.get("/api/trust/{slug}/snapshot")
async def trust_snapshot_by_slug(slug: str):
    """Tenant-specific compliance snapshot resolved by public slug."""
    tenant = await _get_tenant_by_slug(slug)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Trust Center not found")

    from tenant_context import set_current_tenant_id
    set_current_tenant_id(tenant.id)

    base = await trust_snapshot()
    base["org_name"] = tenant.name
    base["slug"] = slug
    return base


@router.post("/api/trust/{slug}/request-access")
async def request_access_by_slug(slug: str, request: Request):
    """Per-tenant access request via slug."""
    tenant = await _get_tenant_by_slug(slug)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Trust Center not found")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    email = body.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

    token = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc)
    record = TrustAccessRequest(
        id=token,
        name=email,
        email=email,
        company=body.get("company", ""),
        reason=body.get("reason", ""),
        status="approved",
        created_at=now,
        tenant_id=tenant.id,
    )
    async with AsyncSessionLocal() as session:
        session.add(record)
        await session.commit()

    from outbound_webhook import notify as _ob_notify
    asyncio.create_task(_ob_notify(
        "trust.access_requested",
        {"email": email, "org": tenant.name},
        tenant_id=tenant.id,
    ))

    return {"token": token, "expires_in_hours": 72, "org": tenant.name}


@router.post("/api/trust/request-access")
async def request_access(request: Request):
    # Генерация токена доступа и сохранение в DB
    try:
        body = await request.json()
        email = body.get("email")
        company = body.get("company", "")
        reason = body.get("reason", "")
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

    token = await _create_access_request(email=email, company=company, reason=reason)

    return {"token": token, "expires_in_hours": 72}

@router.get("/api/trust/details")
async def trust_details(token: str):
    # Расширенные данные при наличии валидного токена
    record = await _get_request_by_token(token)
    if record is None:
        raise HTTPException(status_code=403, detail="Invalid token")

    # Токены действительны 72 часа с момента создания
    created_at = record.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=datetime.timezone.utc)
    expires_at = created_at + datetime.timedelta(hours=72)
    if expires_at < datetime.datetime.now(datetime.timezone.utc):
        raise HTTPException(status_code=403, detail="Token expired")

    # Читаем все контроли из controls_map.json
    controls = []
    if CONTROLS_MAP_FILE.exists():
        with open(CONTROLS_MAP_FILE, "r") as f:
            cm = json.load(f)
            for code, cid in cm.items():
                controls.append({
                    "code": code,
                    "id": cid,
                    "status": "PASS" if hash(code) % 2 == 0 else "FAIL" # Имитация статусов для sandbox
                })

    return {
        "org_name": "Marineso Inc.",
        "access_granted_to": record.email,
        "controls": controls,
        "note": "This is a detailed compliance view under NDA"
    }
