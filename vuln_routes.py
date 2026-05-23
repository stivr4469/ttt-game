import json
import os
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from auth import require_auth, require_admin
from vuln_agent import VulnAgent
from constants import CONTROLS_MAP_FILE

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])
VULNS_FILE = Path(__file__).parent / "vulnerabilities.json"

def _load_vulns() -> List[dict]:
    if not VULNS_FILE.exists():
        return []
    try:
        return json.loads(VULNS_FILE.read_text(encoding="utf-8"))
    except:
        return []

def _save_vulns(vulns: List[dict]):
    VULNS_FILE.write_text(json.dumps(vulns, indent=2, ensure_ascii=False), encoding="utf-8")

@router.get("")
async def get_vulnerabilities(
    severity: Optional[str] = Query(None),
    sla_status: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    payload: dict = Depends(require_auth)
):
    """Возвращает список уязвимостей с фильтрацией."""
    vulns = _load_vulns()
    if severity:
        vulns = [v for v in vulns if v["severity"] == severity.lower()]
    if sla_status:
        vulns = [v for v in vulns if v["sla_status"] == sla_status.lower()]
    if state:
        vulns = [v for v in vulns if v["state"] == state.lower()]
    return vulns

@router.get("/summary")
async def get_vuln_summary(payload: dict = Depends(require_auth)):
    """Возвращает статистику уязвимостей."""
    vulns = _load_vulns()
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    breached = 0
    at_risk = 0
    
    for v in vulns:
        if v["state"] != "open": continue
        stats[v["severity"]] = stats.get(v["severity"], 0) + 1
        if v["sla_status"] == "breached": breached += 1
        if v["sla_status"] == "at_risk": at_risk += 1
        
    return {
        "total_open": sum(stats.values()),
        "by_severity": stats,
        "sla_breached": breached,
        "sla_at_risk": at_risk
    }

@router.get("/{vuln_id}")
async def get_vulnerability(vuln_id: str, payload: dict = Depends(require_auth)):
    """Возвращает детали одной уязвимости."""
    vulns = _load_vulns()
    for v in vulns:
        if v["id"] == vuln_id:
            return v
    raise HTTPException(status_code=404, detail=f"Vulnerability {vuln_id} not found")

@router.post("/scan")
async def scan_vulnerabilities(payload: dict = Depends(require_admin)):
    """Запускает сканирование уязвимостей."""
    controls_map = {}
    if os.path.exists(CONTROLS_MAP_FILE):
        with open(CONTROLS_MAP_FILE) as f:
            controls_map = json.load(f)
            
    agent = VulnAgent()
    return agent.run(controls_map)

@router.patch("/{vuln_id}")
async def update_vulnerability(vuln_id: str, data: dict, payload: dict = Depends(require_auth)):
    """Обновляет статус уязвимости."""
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
        
    vulns = _load_vulns()
    for v in vulns:
        if v["id"] == vuln_id:
            if "state" in data: v["state"] = data["state"]
            if "jira_ticket" in data: v["jira_ticket"] = data["jira_ticket"]
            _save_vulns(vulns)
            return v
            
    raise HTTPException(status_code=404, detail=f"Vulnerability {vuln_id} not found")
