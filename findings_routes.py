"""
Findings API — CRUD поверх нативной сущности Finding.

GET  /api/v1/findings               — список findings (по умолчанию status=OPEN)
PATCH /api/v1/findings/{id}         — обновить статус / назначить владельца
POST  /api/v1/findings/{id}/jira-ticket — создать Jira-тикет для finding
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from auth import require_auth, require_auditor
from database import get_db, get_tenant_id_from_session
from finding_repository import FindingRepository
from models import Finding

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

_VALID_STATUSES = {"OPEN", "RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK"}


def _serialize(f: Finding) -> dict:
    now = _dt.datetime.now(_dt.timezone.utc)
    detail = f.detail or {}
    return {
        "id": f.id,
        "test_key": f.test.key if f.test else None,
        "test_title": f.test.title if f.test else f.title,
        "resource_id": f.resource_id,
        "status": f.status,
        "severity": f.severity,
        "owner_email": f.owner_email,
        "first_seen_at": f.first_seen_at.isoformat(),
        "last_seen_at": f.last_seen_at.isoformat(),
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        "sla_due_at": f.sla_due_at.isoformat() if f.sla_due_at else None,
        "sla_breached": (
            f.sla_due_at is not None
            and f.status == "OPEN"
            and f.sla_due_at.replace(tzinfo=_dt.timezone.utc) < now
        ),
        "jira_ticket_url": detail.get("jira_ticket_url"),
        "jira_ticket_key": detail.get("jira_ticket_key"),
        "remediation": f.test.default_remediation if f.test else None,
    }


@router.get("")
async def list_findings(
    status: str = Query("OPEN"),
    severity: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: dict = Depends(require_auth),
    session: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Список findings. status=OPEN по умолчанию."""
    if status.upper() not in _VALID_STATUSES:
        raise HTTPException(400, f"status must be one of {_VALID_STATUSES}")
    repo = FindingRepository(session)
    findings = await repo.list_by_status(status=status.upper(), severity=severity, limit=limit, offset=offset)
    return [_serialize(f) for f in findings]


class StatusUpdate(BaseModel):
    status: str
    owner_email: str | None = None


@router.patch("/{finding_id}")
async def update_finding(
    finding_id: str,
    body: StatusUpdate,
    payload: dict = Depends(require_auditor),
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Обновить статус finding. Требует роль auditor."""
    if body.status.upper() not in _VALID_STATUSES:
        raise HTTPException(400, f"status must be one of {_VALID_STATUSES}")
    repo = FindingRepository(session)
    # Fetch and verify tenant ownership before mutating
    finding = await session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    tenant_id = get_tenant_id_from_session(session)
    if tenant_id and finding.tenant_id != tenant_id:
        raise HTTPException(404, "Finding not found")
    finding = await repo.update_status(finding_id, body.status.upper())
    if not finding:
        raise HTTPException(404, "Finding not found")
    if body.owner_email:
        await repo.assign_owner(finding_id, body.owner_email)
    await session.commit()

    if body.status.upper() in ("RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK"):
        from outgoing_webhook_service import deliver as _wh_deliver
        asyncio.create_task(_wh_deliver("finding.resolved", {
            "finding_id": finding_id,
            "status": body.status.upper(),
            "test_key": finding.test.key if finding.test else None,
            "resource_id": finding.resource_id,
            "severity": finding.severity,
        }))

    return _serialize(finding)


# ── POST /api/v1/findings/{id}/ai-analysis ───────────────────────────────────

@router.post("/{finding_id}/ai-analysis")
async def ai_analyze_finding(
    finding_id: str,
    payload: dict = Depends(require_auth),
    session: AsyncSession = Depends(get_db),
) -> dict:
    """AI-анализ finding по запросу. LLM не вызывается автоматически — только здесь."""
    from sqlalchemy.orm import selectinload as _sil
    from sqlalchemy import select as _sel
    stmt = _sel(Finding).options(_sil(Finding.test)).where(Finding.id == finding_id)
    result = await session.execute(stmt)
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(404, "Finding not found")

    tenant_id = get_tenant_id_from_session(session)
    if tenant_id and finding.tenant_id != tenant_id:
        raise HTTPException(404, "Finding not found")

    test_key = finding.test.key if finding.test else finding.title
    test_title = finding.test.title if finding.test else finding.title
    remediation_hint = (finding.test.default_remediation or "")[:400] if finding.test else ""

    prompt = (
        f"You are a senior cloud security engineer. Analyze this AWS security finding:\n\n"
        f"Check: {test_key}\n"
        f"Title: {test_title}\n"
        f"Severity: {finding.severity}\n"
        f"Resource: {finding.resource_id}\n"
        f"Status: {finding.status}\n"
        + (f"Known remediation hint: {remediation_hint}\n" if remediation_hint else "")
        + "\nProvide:\n"
        "1. **Business risk** — what can go wrong if not fixed (2-3 sentences)\n"
        "2. **Priority** — should this be fixed in days/weeks/months and why\n"
        "3. **Steps** — 3-5 concrete remediation steps specific to this resource\n\n"
        "Be concise and actionable. No generic advice."
    )

    try:
        from llm_router import llm_chat, get_active_provider
        analysis = await llm_chat(
            messages=[{"role": "user", "content": prompt}],
            system="You are a SOC 2 compliance and AWS security expert. Be concise.",
        )
        provider = get_active_provider()
    except Exception as exc:
        log.error("AI analysis failed for finding %s: %s", finding_id, exc)
        raise HTTPException(502, f"LLM error: {exc}")

    return {"analysis": analysis, "provider": provider, "finding_id": finding_id}


# ── POST /api/v1/findings/{id}/jira-ticket ────────────────────────────────────

_SEVERITY_TO_JIRA_PRIORITY: dict[str, str] = {
    "CRITICAL": "Highest",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}


class JiraTicketBody(BaseModel):
    base_url: str
    email: str
    api_token: str
    project_key: str = "SEC"


@router.post("/{finding_id}/jira-ticket")
async def create_jira_ticket(
    finding_id: str,
    body: JiraTicketBody,
    payload: dict = Depends(require_auditor),
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Создать Jira-тикет для finding. Требует роль auditor."""
    finding = await session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")

    tenant_id = get_tenant_id_from_session(session)
    if tenant_id and finding.tenant_id != tenant_id:
        raise HTTPException(404, "Finding not found")

    # If ticket already exists, return it immediately
    detail = finding.detail or {}
    if detail.get("jira_ticket_url"):
        return {
            "ticket_key": detail.get("jira_ticket_key", ""),
            "ticket_url": detail["jira_ticket_url"],
            "already_exists": True,
        }

    # Build description
    test_key = finding.test.key if finding.test else "unknown"
    test_title = finding.test.title if finding.test else finding.title
    description = (
        f"Compliance finding from Sandbox Auditor.\n\n"
        f"Test: {test_key}\n"
        f"Title: {test_title}\n"
        f"Severity: {finding.severity}\n"
        f"Resource: {finding.resource_id}\n"
        f"Status: {finding.status}\n"
        f"First seen: {finding.first_seen_at.isoformat()}\n"
    )
    priority = _SEVERITY_TO_JIRA_PRIORITY.get(finding.severity, "Medium")

    from jira_client import JiraClient

    def _create_sync() -> dict:
        client = JiraClient(
            base_url=body.base_url,
            email=body.email,
            api_token=body.api_token,
            project_key=body.project_key,
        )
        return client.create_issue(
            project_key=body.project_key,
            summary=f"[{finding.severity}] {test_title} — {finding.resource_id}",
            description=description,
            issue_type="Task",
            priority=priority,
            labels=["compliance", "sandbox-auditor", finding.severity.lower()],
        )

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _create_sync)
    except Exception as exc:
        log.error("Jira ticket creation failed for finding %s: %s", finding_id, exc)
        raise HTTPException(502, f"Jira API error: {exc}")

    # Persist ticket info in detail JSON (no schema migration needed)
    finding.detail = {
        **detail,
        "jira_ticket_key": result["key"],
        "jira_ticket_url": result["url"],
    }
    await session.commit()

    return {
        "ticket_key": result["key"],
        "ticket_url": result["url"],
        "already_exists": False,
    }
