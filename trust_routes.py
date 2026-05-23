# Роутер подключается в ui_server.py аналогично access_review_routes.py
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pathlib import Path
import json, uuid, datetime
import os

router = APIRouter(tags=["trust"])
ROOT = Path(__file__).parent
TOKENS_FILE = ROOT / "trust_access_tokens.json"
CONTROLS_MAP_FILE = ROOT / "controls_map.json"

def load_tokens():
    if not TOKENS_FILE.exists():
        return {}
    try:
        with open(TOKENS_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_tokens(tokens):
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f, indent=2)

@router.get("/trust", response_class=HTMLResponse)
async def trust_page():
    # Возвращаем HTML страницу Trust Center
    trust_html = ROOT / "ui" / "trust.html"
    if not trust_html.exists():
        raise HTTPException(status_code=404, detail="trust.html not found")
    return FileResponse(trust_html)

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


@router.post("/api/trust/request-access")
async def request_access(request: Request):
    # Генерация токена доступа
    try:
        body = await request.json()
        email = body.get("email")
        company = body.get("company")
        reason = body.get("reason")
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

    token = str(uuid.uuid4())
    expires_at = (datetime.datetime.now() + datetime.timedelta(hours=72)).isoformat()
    
    tokens = load_tokens()
    tokens[token] = {
        "email": email,
        "company": company,
        "reason": reason,
        "created_at": datetime.datetime.now().isoformat(),
        "expires_at": expires_at
    }
    save_tokens(tokens)

    return {"token": token, "expires_in_hours": 72}

@router.get("/api/trust/details")
async def trust_details(token: str):
    # Расширенные данные при наличии валидного токена
    tokens = load_tokens()
    if token not in tokens:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    t_data = tokens[token]
    if datetime.datetime.fromisoformat(t_data["expires_at"]) < datetime.datetime.now():
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
        "access_granted_to": t_data["email"],
        "controls": controls,
        "note": "This is a detailed compliance view under NDA"
    }
