import uuid
import json
import os
from datetime import datetime, timezone
from typing import Optional, List, Dict
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from log_config import get_logger
from evidence_client import EvidenceClient
from constants import CONTROLS_MAP_FILE

# Re-use evidence tracker URL from environment
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")

log = get_logger(__name__)
router = APIRouter(prefix="/api/auditor", tags=["auditor"])

COMMENTS_FILE = "auditor_comments.json"
VALID_SEVERITIES = {"observation", "finding", "exception"}

# Единственный экземпляр клиента для всего модуля
_evidence_client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="auditor")

class AuditorComment(BaseModel):
    control_code: str      # "CC6.1"
    comment: str           # текст комментария
    severity: str          # "observation" | "finding" | "exception"
    auditor_name: str      # имя аудитора

def _load_comments() -> Dict[str, List[dict]]:
    """Загружает комментарии из JSON файла."""
    if not os.path.exists(COMMENTS_FILE):
        with open(COMMENTS_FILE, "w") as f:
            json.dump({"comments": []}, f)
        return {"comments": []}
    try:
        with open(COMMENTS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"comments": []}

def _save_comments(data: Dict[str, List[dict]]):
    """Сохраняет комментарии в JSON файл."""
    with open(COMMENTS_FILE, "w") as f:
        json.dump(data, f, indent=2)

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
    comments_data = _load_comments()
    comment_counts = {}
    for c in comments_data["comments"]:
        code = c["control_code"]
        comment_counts[code] = comment_counts.get(code, 0) + 1

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
async def add_comment(comment: AuditorComment):
    """Добавляет новый аудиторский комментарий."""
    if comment.severity not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"severity must be one of {VALID_SEVERITIES}")
    
    data = _load_comments()
    new_entry = {
        "id": str(uuid.uuid4()),
        "control_code": comment.control_code,
        "comment": comment.comment,
        "severity": comment.severity,
        "auditor_name": comment.auditor_name,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    }
    data["comments"].append(new_entry)
    _save_comments(data)
    return new_entry

@router.get("/comments")
async def get_all_comments(control_code: Optional[str] = None):
    """Возвращает список всех комментариев или фильтрует по коду контроля."""
    data = _load_comments()
    if control_code:
        return [c for c in data["comments"] if c["control_code"] == control_code]
    return data["comments"]

@router.get("/comments/{control_code}")
async def get_control_comments(control_code: str):
    """Возвращает комментарии по конкретному контролю."""
    data = _load_comments()
    return [c for c in data["comments"] if c["control_code"] == control_code]

@router.get("/summary")
async def get_auditor_summary():
    """Сводная информация для Auditor Portal."""
    data = _load_comments()
    comments = data["comments"]
    
    findings = len([c for c in comments if c["severity"] == "finding"])
    exceptions = len([c for c in comments if c["severity"] == "exception"])
    
    # Уникальные контроли с комментариями
    coded_with_comments = len(set(c["control_code"] for c in comments))
    
    return {
        "total_comments": len(comments),
        "findings_count": findings,
        "exceptions_count": exceptions,
        "controls_reviewed": coded_with_comments
    }
