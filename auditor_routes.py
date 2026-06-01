import uuid
import json
import os
from datetime import datetime, timezone
from typing import Optional, List, Dict
from fastapi import APIRouter, Depends, HTTPException
from auth import require_auditor
from pydantic import BaseModel
from log_config import get_logger
from evidence_client import EvidenceClient
from constants import CONTROLS_MAP_FILE
from database import AsyncSessionLocal
from models import AuditorComment as AuditorCommentModel
from sqlalchemy import select

# Re-use evidence tracker URL from environment
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")

log = get_logger(__name__)
router = APIRouter(prefix="/api/auditor", tags=["auditor"])

VALID_SEVERITIES = {"observation", "finding", "exception"}

# Единственный экземпляр клиента для всего модуля
_evidence_client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="auditor")

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
    # 1. Загрузить карту контролей
    if not os.path.exists(CONTROLS_MAP_FILE):
        raise HTTPException(status_code=500, detail="controls_map.json not found")

    with open(CONTROLS_MAP_FILE, "r") as f:
        controls_map = json.load(f)

    # 2. Получить текущие данные из Evidence Tracker
    try:
        et_controls = _evidence_client.get_controls()
        et_evidence = _evidence_client.get_evidence(limit=1000)
    except Exception as e:
        log.warning("Auditor Portal: Evidence Tracker unavailable", extra={"error": str(e)})
        et_controls = []
        et_evidence = []

    # Подсчитать evidence на контроль
    ev_counts = {}
    for ev in et_evidence:
        cid = str(ev.get("control_id"))
        ev_counts[cid] = ev_counts.get(cid, 0) + 1

    # Мапа статусов
    statuses = {str(c["id"]): c["status"] for c in et_controls}

    # 3. Загрузить комментарии
    comment_counts = {}
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(AuditorCommentModel))
        db_comments = result.scalars().all()
    for c in db_comments:
        comment_counts[c.control_code] = comment_counts.get(c.control_code, 0) + 1

    # 4. Сформировать итоговый список
    results = []
    for code, cid in controls_map.items():
        results.append({
            "control_code": code,
            "status": statuses.get(cid, "UNKNOWN"),
            "evidence_count": ev_counts.get(cid, 0),
            "comment_count": comment_counts.get(code, 0)
        })

    return sorted(results, key=lambda x: x["control_code"])

@router.get("/controls/{control_code}/evidence")
async def get_control_evidence(control_code: str):
    """Возвращает список evidence для конкретного контроля."""
    if not os.path.exists(CONTROLS_MAP_FILE):
        return {"evidence": [], "error": "Internal configuration error"}

    with open(CONTROLS_MAP_FILE, "r") as f:
        controls_map = json.load(f)

    cid = controls_map.get(control_code)
    if not cid:
        raise HTTPException(status_code=404, detail="Control code unknown")

    try:
        evidence = _evidence_client.get_evidence(control_id=cid, limit=100)
        return {"evidence": evidence}
    except Exception as e:
        log.error("Auditor Portal: Failed to fetch evidence", extra={"control_code": control_code, "error": str(e)})
        return {"evidence": [], "error": "Evidence Tracker unavailable"}

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
