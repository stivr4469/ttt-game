import uuid
import json
import os
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from auth import require_auditor
from pydantic import BaseModel
from log_config import get_logger
from constants import CONTROLS_MAP_FILE
from database import AsyncSessionLocal
from models import AuditorComment as AuditorCommentModel
from sqlalchemy import select

log = get_logger(__name__)
router = APIRouter(prefix="/api/auditor", tags=["auditor"])

VALID_SEVERITIES = {"observation", "finding", "exception"}

class AuditorComment(BaseModel):
    control_code: str      # "CC6.1"
    comment: str           # текст комментария
    severity: str          # "observation" | "finding" | "exception"
    auditor_name: str      # имя аудитора

def _comment_to_dict(c: AuditorCommentModel) -> dict:
    """Конвертирует ORM-объект AuditorComment в dict."""
    return {
        "id": c.id,
        "control_code": c.control_code,
        "comment": c.comment,
        "severity": c.severity,
        "auditor_name": c.auditor_name,
        "created_at": c.created_at.isoformat().replace("+00:00", "Z") if c.created_at else None,
    }

@router.get("/controls")
async def get_auditor_controls():
    """Возвращает список контролей со статусом, кол-вом evidence и комментариев."""
    from control_mapping import CONTROL_MAPPINGS
    from db_repository import ControlRepository, EvidenceRepository

    # Читаем напрямую из SQLite — убраны HTTP вызовы к EvidenceClient(localhost:8080).
    async with AsyncSessionLocal() as session:
        ctrl_repo = ControlRepository(session)
        ev_repo = EvidenceRepository(session)

        all_statuses = await ctrl_repo.list_all()
        statuses_by_code = {cs.control_id: cs.status for cs in all_statuses}

        all_evidence = await ev_repo.list_all(limit=5000)
        ev_counts: dict[str, int] = {}
        for ev in all_evidence:
            cid = ev.control_id or ""
            ev_counts[cid] = ev_counts.get(cid, 0) + 1

        comment_counts: dict[str, int] = {}
        result = await session.execute(select(AuditorCommentModel))
        for c in result.scalars().all():
            comment_counts[c.control_code] = comment_counts.get(c.control_code, 0) + 1

    results = [
        {
            "control_code": m.soc2,
            "status": statuses_by_code.get(m.soc2, "UNKNOWN"),
            "evidence_count": ev_counts.get(m.soc2, 0),
            "comment_count": comment_counts.get(m.soc2, 0),
        }
        for m in CONTROL_MAPPINGS
    ]
    return sorted(results, key=lambda x: x["control_code"])

@router.get("/controls/{control_code}/evidence")
async def get_control_evidence(control_code: str):
    """Возвращает список evidence для конкретного контроля."""
    from db_repository import EvidenceRepository

    try:
        async with AsyncSessionLocal() as session:
            repo = EvidenceRepository(session)
            items = await repo.list_by_control(control_code, limit=100)
        evidence = [
            {
                "id": ev.id,
                "control_id": ev.control_id,
                "title": ev.title,
                "source": ev.source,
                "content": ev.content,
                "confidence_score": ev.confidence_score,
                "created_at": ev.created_at.isoformat() if ev.created_at else None,
            }
            for ev in items
        ]
        return {"evidence": evidence}
    except Exception as e:
        log.error("Auditor Portal: Failed to fetch evidence", extra={"control_code": control_code, "error": str(e)})
        return {"evidence": [], "error": "Database error"}

@router.post("/comments")
async def add_comment(comment: AuditorComment, _: dict = Depends(require_auditor)):
    """Добавляет новый аудиторский комментарий."""
    if comment.severity not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"severity must be one of {VALID_SEVERITIES}")

    new_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    async with AsyncSessionLocal() as session:
        db_obj = AuditorCommentModel(
            id=new_id,
            control_code=comment.control_code,
            comment=comment.comment,
            severity=comment.severity,
            auditor_name=comment.auditor_name,
            created_at=now,
        )
        session.add(db_obj)
        await session.commit()
        await session.refresh(db_obj)
    return _comment_to_dict(db_obj)

@router.get("/comments")
async def get_all_comments(control_code: Optional[str] = None):
    """Возвращает список всех комментариев или фильтрует по коду контроля."""
    async with AsyncSessionLocal() as session:
        stmt = select(AuditorCommentModel)
        if control_code:
            stmt = stmt.where(AuditorCommentModel.control_code == control_code)
        result = await session.execute(stmt)
        return [_comment_to_dict(c) for c in result.scalars().all()]

@router.get("/comments/{control_code}")
async def get_control_comments(control_code: str):
    """Возвращает комментарии по конкретному контролю."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AuditorCommentModel).where(
                AuditorCommentModel.control_code == control_code
            )
        )
        return [_comment_to_dict(c) for c in result.scalars().all()]

@router.get("/summary")
async def get_auditor_summary():
    """Сводная информация для Auditor Portal."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(AuditorCommentModel))
        comments = result.scalars().all()
    findings = sum(1 for c in comments if c.severity == "finding")
    exceptions = sum(1 for c in comments if c.severity == "exception")
    coded_with_comments = len(set(c.control_code for c in comments))
    return {
        "total_comments": len(comments),
        "findings_count": findings,
        "exceptions_count": exceptions,
        "controls_reviewed": coded_with_comments,
    }
