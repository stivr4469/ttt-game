#!/usr/bin/env python3
"""UI сервер для SOC 2 Compliance Dashboard."""

import os
import json
import asyncio
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import requests as req
from fastapi import FastAPI, HTTPException, UploadFile, File, Body, Depends, Cookie, Form, Request, Response
from fastapi.responses import StreamingResponse, HTMLResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from dotenv import dotenv_values, set_key
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry, REGISTRY
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from log_config import get_logger
from auth import authenticate_user, create_access_token, decode_token, ROLES
from config import get_settings

log = get_logger(__name__)
settings = get_settings()

# Constants
EVIDENCE_TRACKER = settings.evidence_tracker_url
EVIDENCE_API_KEY = settings.evidence_api_key
ENV_FILE = Path(__file__).parent / ".env"
ROOT = Path(__file__).parent
_tracker_headers = {"X-API-Key": EVIDENCE_API_KEY}

# Prometheus metrics — отдельный реестр чтобы избежать дублирования при перезапуске
_APP_REGISTRY = CollectorRegistry(auto_describe=True)
_REQUEST_COUNT = Counter(
    "http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"],
    registry=_APP_REGISTRY,
)
_REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds", "HTTP request latency", ["endpoint"],
    registry=_APP_REGISTRY,
)

AGENTS = {
    "scanner": {"label": "AWS Scanner",      "cmd": ["python3", "scanner.py"],                      "desc": "S3, IAM, EC2, CloudTrail — LocalStack/AWS",  "icon": "☁️"},
    "prowler": {"label": "Prowler Runner",   "cmd": ["python3", "prowler_runner.py"],               "desc": "160 SOC 2 проверок из каталога Prowler",     "icon": "🔍"},
    "hr":      {"label": "HR Agent",         "cmd": ["python3", "hr_agent.py"],                     "desc": "Okta + HR roster: offboarding, training",    "icon": "👥"},
    "survey":  {"label": "Survey Agent",     "cmd": ["python3", "survey_agent.py"],                 "desc": "Опрос сотрудников по знанию политик",         "icon": "📋"},
    "github":  {"label": "GitHub Agent",     "cmd": ["python3", "github_agent.py"],                 "desc": "CI/CD, Secrets Scanning, Issues",            "icon": "🐙"},
    "policy":  {"label": "Policy Generator", "cmd": ["python3", "policy_agent.py", "--governance"], "desc": "AI-черновики для 9 governance контролей",    "icon": "📄"},
}

SENSITIVE_KEYS = {"TOKEN", "KEY", "SECRET", "PASSWORD", "WEBHOOK", "API"}

_running_agents: set[str] = set()

# ── Pydantic request models ────────────────────────────────────────────────────
class PolicyDraftRequest(BaseModel):
    title: str = ""
    content: str = ""
    created_by: str = "anonymous"
    change_summary: str = "No description"

class ApproveRequest(BaseModel):
    approver_email: str = "unknown"

class RejectRequest(BaseModel):
    reviewer_email: str = "unknown"
    reason: str = ""

# ── Scheduler ─────────────────────────────────────────────────────────────────
scheduler = AsyncIOScheduler()

async def run_daily_scan():
    """Запускает полный pipeline всех агентов раз в сутки."""
    log.info("Scheduler: starting daily compliance scan")
    controls_map_path = os.path.join(os.path.dirname(__file__), "controls_map.json")
    controls_map = None
    if os.path.exists(controls_map_path):
        with open(controls_map_path) as f:
            controls_map = json.load(f)

    from scanner import main as run_scanner
    from hr_agent import main as run_hr
    from survey_agent import main as run_survey
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, lambda: run_scanner(controls_map))
        await loop.run_in_executor(None, lambda: run_hr(controls_map))
        await loop.run_in_executor(None, lambda: run_survey(controls_map))
        log.info("Scheduler: daily scan completed")
    except Exception as e:
        log.error(f"Scheduler: daily scan failed: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler.add_job(
        run_daily_scan,
        CronTrigger(hour=3, minute=0),
        id="daily_scan",
        replace_existing=True,
    )
    scheduler.start()
    log.info("Scheduler started: daily scan at 03:00 UTC")
    yield
    scheduler.shutdown()

# ── Application Initialization ────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="SOC 2 Dashboard", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

_cors_origins = settings.cors_origins.split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        t0 = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - t0
        # security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # metrics (skip /metrics itself to avoid recursion)
        if not request.url.path.startswith("/metrics"):
            _REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.url.path,
                status=response.status_code,
            ).inc()
            _REQUEST_LATENCY.labels(endpoint=request.url.path).observe(elapsed)
        return response


app.add_middleware(SecurityHeadersMiddleware)

# Import and Include Routers
from access_review_routes import router as access_review_router
from auditor_routes import router as auditor_router
from audit_timeline_routes import router as timeline_router
from trust_routes import router as trust_router
from gap_analysis_routes import router as gap_analysis_router
from webhook_routes import router as webhook_router
from background_check_routes import router as bg_check_router
from training_routes import router as training_router
from report_routes import router as report_router
from risk_routes import router as risk_router, router_alias as risk_alias_router
from vuln_routes import router as vuln_router
from questionnaire_routes import router as questionnaire_router
from pentest_routes import router as pentest_router, router_alias as pentest_alias_router
from custom_controls_routes import router as custom_controls_router
from chaos_routes import router as chaos_router
from control_mapping_routes import router as control_mapping_router
from time_machine_routes import router as time_machine_router
from cac_routes import router as cac_router
from vendor_risk_routes import router as vendor_risk_router
from policy_lifecycle_routes import router as policy_lifecycle_router
from evidence_confidence_routes import router as evidence_confidence_router
from decision_log_routes import router as decision_log_router
from compliance_engine_routes import router as compliance_engine_router
app.include_router(access_review_router)
app.include_router(auditor_router)
app.include_router(timeline_router)
app.include_router(trust_router)
app.include_router(gap_analysis_router)
app.include_router(webhook_router)
app.include_router(bg_check_router)
app.include_router(training_router)
app.include_router(report_router)
app.include_router(risk_router)
app.include_router(risk_alias_router)
app.include_router(vuln_router)
app.include_router(questionnaire_router)
app.include_router(pentest_router)
app.include_router(pentest_alias_router)
app.include_router(custom_controls_router)
app.include_router(chaos_router)
app.include_router(control_mapping_router)
app.include_router(time_machine_router)
app.include_router(cac_router)
app.include_router(vendor_risk_router)
app.include_router(policy_lifecycle_router)
app.include_router(evidence_confidence_router)
app.include_router(decision_log_router)
app.include_router(compliance_engine_router)

# ── Auth dependencies ──────────────────────────────────────────────────────────
async def require_auth(access_token: str | None = Cookie(None)):
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(access_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token invalid")
    return payload

async def require_admin(payload: dict = Depends(require_auth)):
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return payload

async def require_scanner(payload: dict = Depends(require_auth)):
    if payload.get("role") not in ("admin", "scanner"):
        raise HTTPException(status_code=403, detail="Scanner role required")
    return payload

# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    """Проверяет доступность Evidence Tracker."""
    try:
        r = req.get(f"{EVIDENCE_TRACKER}/health", headers=_tracker_headers, timeout=3)
        tracker_ok = r.status_code == 200
    except Exception:
        tracker_ok = False
    return {
        "status": "ok" if tracker_ok else "degraded",
        "ui_server": "ok",
        "evidence_tracker": "ok" if tracker_ok else "unavailable",
    }

# ── Page routes ────────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return (ROOT / "ui" / "login.html").read_text(encoding="utf-8")

@app.get("/auditor-portal", response_class=HTMLResponse)
async def auditor_portal_page():
    return (ROOT / "ui" / "auditor.html").read_text(encoding="utf-8")

@app.get("/", response_class=HTMLResponse)
async def index(access_token: Optional[str] = Cookie(None)):
    if not access_token:
        return RedirectResponse(url="/login")
    payload = decode_token(access_token)
    if not payload:
        return RedirectResponse(url="/login")
    return (ROOT / "ui" / "index.html").read_text(encoding="utf-8")

@app.get("/controls", response_class=HTMLResponse)
async def controls_page(access_token: Optional[str] = Cookie(None)):
    if not access_token or not decode_token(access_token):
        return RedirectResponse(url="/login")
    return (ROOT / "ui" / "index.html").read_text(encoding="utf-8")

@app.get("/agents", response_class=HTMLResponse)
async def agents_page(access_token: Optional[str] = Cookie(None)):
    if not access_token or not decode_token(access_token):
        return RedirectResponse(url="/login")
    return (ROOT / "ui" / "index.html").read_text(encoding="utf-8")

@app.get("/access-review", response_class=HTMLResponse)
async def access_review_page():
    return FileResponse("ui/access_review.html")

@app.get("/training", response_class=HTMLResponse)
async def training_page():
    return FileResponse(ROOT / "ui" / "training.html")

@app.get("/risk-register", response_class=HTMLResponse)
async def risk_register_page():
    return FileResponse(ROOT / "ui" / "risk-register.html")

@app.get("/vulnerabilities", response_class=HTMLResponse)
async def vuln_page():
    return FileResponse(ROOT / "ui" / "vulnerabilities.html")

@app.get("/questionnaires", response_class=HTMLResponse)
async def questionnaires_page():
    return FileResponse(ROOT / "ui" / "questionnaires.html")

@app.get("/background-checks", response_class=HTMLResponse)
async def bg_checks_page():
    return FileResponse(ROOT / "ui" / "background-checks.html")

@app.get("/audit-timeline", response_class=HTMLResponse)
async def audit_timeline_page():
    return FileResponse(ROOT / "ui" / "audit-timeline.html")

@app.get("/pentests", response_class=HTMLResponse)
async def pentests_page():
    return FileResponse(ROOT / "ui" / "pentests.html")

# ── Auth API ───────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
@limiter.limit("10/minute")
async def login(request: Request, email: str = Form(...), password: str = Form(...)):
    user = authenticate_user(email, password)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Invalid credentials"})
    token = create_access_token({"sub": user["email"], "role": user["role"], "name": user["name"]})
    response = JSONResponse(content={"token": token, "role": user["role"], "name": user["name"]})
    response.set_cookie("access_token", token, httponly=True, samesite="lax", max_age=28800)
    return response

@app.post("/api/auth/logout")
async def logout():
    response = JSONResponse(content={"status": "logged out"})
    response.delete_cookie("access_token")
    return response

@app.get("/api/auth/me")
async def me(access_token: str | None = Cookie(None)):
    if not access_token:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
    payload = decode_token(access_token)
    if not payload:
        return JSONResponse(status_code=401, content={"detail": "Token invalid or expired"})
    role = payload.get("role", "viewer")
    return {
        "email": payload.get("sub"),
        "name": payload.get("name"),
        "role": role,
        "permissions": ROLES.get(role, ROLES["viewer"]),
    }

# ── Compliance API ─────────────────────────────────────────────────────────────
@app.get("/api/controls")
async def get_controls():
    try:
        r = req.get(f"{EVIDENCE_TRACKER}/api/v1/controls/?limit=100", headers=_tracker_headers, timeout=10)
        return r.json()
    except Exception as e:
        raise HTTPException(502, str(e))

@app.get("/api/evidence")
async def get_evidence(control_id: str = "", limit: int = 100):
    try:
        url = f"{EVIDENCE_TRACKER}/api/v1/evidence/?limit={limit}"
        if control_id:
            url += f"&control_id={control_id}"
        r = req.get(url, headers=_tracker_headers, timeout=10)
        return r.json()
    except Exception as e:
        raise HTTPException(502, str(e))

@app.get("/api/registry/services")
async def registry_services():
    from registry import load_registry
    return load_registry()["services"]

@app.post("/api/registry/stack-analysis")
async def stack_analysis(payload: dict):
    from registry import get_controls_for_stack
    services = payload.get("services", [])
    framework = payload.get("framework", "soc2")
    return get_controls_for_stack(services, framework)

@app.get("/api/agents")
async def list_agents():
    return {k: {"label": v["label"], "desc": v["desc"], "icon": v["icon"]} for k, v in AGENTS.items()}

@app.get("/api/running")
async def get_running_agents():
    return {"running": list(_running_agents)}

@app.get("/api/run/{agent_name}")
async def run_agent(agent_name: str, payload: dict = Depends(require_scanner)):
    if agent_name not in AGENTS:
        raise HTTPException(404, f"Agent '{agent_name}' not found")
    if agent_name in _running_agents:
        raise HTTPException(409, f"Agent '{agent_name}' is already running")
    agent = AGENTS[agent_name]
    async def stream():
        _running_agents.add(agent_name)
        yield f"data: {json.dumps({'type': 'start', 'agent': agent['label']})}\n\n"
        try:
            proc = await asyncio.create_subprocess_exec(*agent["cmd"], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, cwd=str(ROOT))
            async for raw in proc.stdout:
                text = raw.decode("utf-8", errors="replace").rstrip()
                if text: yield f"data: {json.dumps({'type': 'line', 'text': text})}\n\n"
            await proc.wait()
            yield f"data: {json.dumps({'type': 'done', 'code': proc.returncode})}\n\n"
        except Exception as ex:
            yield f"data: {json.dumps({'type': 'error', 'text': str(ex)})}\n\n"
        finally:
            _running_agents.discard(agent_name)
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── Config API ─────────────────────────────────────────────────────────────────
def _mask(key: str, val: str) -> str:
    if any(s in key.upper() for s in SENSITIVE_KEYS):
        return val[:4] + "***" if len(val) > 4 else "***"
    return val

@app.get("/api/config")
async def get_config():
    if not ENV_FILE.exists(): return {}
    values = dotenv_values(ENV_FILE)
    return {k: {"value": _mask(k, v or ""), "sensitive": any(s in k.upper() for s in SENSITIVE_KEYS)} for k, v in values.items()}

@app.post("/api/config")
async def update_config(data: dict = Body(...), payload: dict = Depends(require_admin)):
    for key, value in data.items():
        if value and not value.endswith("***"):
            set_key(str(ENV_FILE), key, value)
    return {"ok": True, "updated": len(data)}

@app.post("/api/config/upload")
async def upload_config(file: UploadFile = File(...), payload: dict = Depends(require_admin)):
    """Парсит загруженный .env файл и возвращает preview с маскировкой секретов."""
    content = (await file.read()).decode("utf-8", errors="replace")
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            sensitive = any(s in k.upper() for s in SENSITIVE_KEYS)
            result[k] = {"masked": _mask(k, v), "sensitive": sensitive}
    return result

# ── Scheduler API ──────────────────────────────────────────────────────────────
@app.get("/api/scheduler/status")
async def scheduler_status():
    jobs = []
    for job in scheduler.get_jobs():
        jobs.append({"id": job.id, "next_run": str(job.next_run_time), "trigger": str(job.trigger)})
    return {"running": scheduler.running, "jobs": jobs}

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(generate_latest(_APP_REGISTRY), media_type=CONTENT_TYPE_LATEST)


@app.post("/api/scheduler/trigger")
async def trigger_scan_now(payload: dict = Depends(require_admin)):
    asyncio.create_task(run_daily_scan())
    return {"status": "triggered", "message": "Daily scan started in background"}

# ── ESignature API ─────────────────────────────────────────────────────────────
@app.post("/api/esignature/webhook")
async def esignature_webhook(payload: dict = Body(...)):
    envelope_id = payload.get("envelope_id")
    if not envelope_id:
        return JSONResponse(status_code=400, content={"detail": "envelope_id required"})
    from esignature_agent import ESignatureAgent
    return ESignatureAgent().simulate_signature(envelope_id)

@app.get("/api/esignature/pending")
async def esignature_pending():
    from esignature_agent import ESignatureAgent
    return {"pending": ESignatureAgent().get_pending_signatures()}

@app.get("/api/esignature/{envelope_id}/status")
async def esignature_status(envelope_id: str):
    from esignature_agent import ESignatureAgent
    return ESignatureAgent().check_docusign_status(envelope_id)

# ── Remediation API ────────────────────────────────────────────────────────────
@app.get("/api/remediations")
async def get_remediations():
    from remediation_agent import RemediationAgent
    return RemediationAgent().get_all_remediations()

@app.post("/api/remediations/sync")
async def sync_remediations():
    from remediation_agent import RemediationAgent
    updated = RemediationAgent().sync_statuses()
    return {"synced": updated, "count": len(updated)}

@app.post("/api/remediations/create")
async def create_remediation(payload: dict = Body(...)):
    from remediation_agent import RemediationAgent
    return RemediationAgent().create_remediation_ticket(
        payload.get("control_code", ""),
        payload.get("finding", "Control failed"),
    )

# ── Celery Task API ────────────────────────────────────────────────────────────
@app.post("/api/tasks/run/{agent_name}")
async def enqueue_agent(agent_name: str, payload: dict = Depends(require_scanner)):
    from tasks import run_scanner_task, run_hr_agent_task, run_github_agent_task, run_policy_agent_task, run_full_pipeline_task
    task_map = {
        "scanner": run_scanner_task, "hr_agent": run_hr_agent_task,
        "github_agent": run_github_agent_task, "policy_agent": run_policy_agent_task, "all": run_full_pipeline_task,
    }
    if agent_name not in task_map:
        return JSONResponse(status_code=404, content={"detail": f"Unknown agent: {agent_name}"})
    task = task_map[agent_name].delay()
    return {"task_id": task.id, "status": "queued", "agent": agent_name}

@app.get("/api/tasks/{task_id}/status")
async def task_status(task_id: str):
    from celery_app import celery_app
    from celery.result import AsyncResult
    result = AsyncResult(task_id, app=celery_app)
    return {"task_id": task_id, "status": result.status, "result": result.result if result.ready() else None, "ready": result.ready()}

@app.get("/api/tasks/active")
async def active_tasks():
    from celery_app import celery_app
    try:
        inspect = celery_app.control.inspect(timeout=1.0)
        return {"active": inspect.active() or {}}
    except Exception:
        return {"active": {}, "note": "Redis unavailable"}

# ── Policy Approval Workflow API ───────────────────────────────────────────────
@app.post("/api/policies/{control_code}/draft")
async def create_policy_draft(control_code: str, payload: PolicyDraftRequest):
    from policy_workflow import PolicyWorkflow
    return PolicyWorkflow().create_draft(control_code, payload.title, payload.content, payload.created_by, payload.change_summary)

@app.post("/api/policies/{control_code}/versions/{version}/submit")
async def submit_policy(control_code: str, version: int):
    from policy_workflow import PolicyWorkflow
    return PolicyWorkflow().submit_for_approval(control_code, version)

@app.post("/api/policies/{control_code}/versions/{version}/approve")
async def approve_policy(control_code: str, version: int, payload: ApproveRequest):
    from policy_workflow import PolicyWorkflow
    return PolicyWorkflow().approve(control_code, version, payload.approver_email)

@app.post("/api/policies/{control_code}/versions/{version}/reject")
async def reject_policy(control_code: str, version: int, payload: RejectRequest):
    from policy_workflow import PolicyWorkflow
    return PolicyWorkflow().reject(control_code, version, payload.reviewer_email, payload.reason)

@app.get("/api/policies/{control_code}/history")
async def policy_history(control_code: str):
    from policy_workflow import PolicyWorkflow
    return {"control_code": control_code, "versions": PolicyWorkflow().get_history(control_code)}

@app.get("/api/policies/pending")
async def pending_approvals():
    from policy_workflow import PolicyWorkflow
    return {"pending": PolicyWorkflow().get_pending()}

if __name__ == "__main__":
    import uvicorn
    print("🛡️  SOC 2 Dashboard → http://localhost:8080")
    uvicorn.run("ui_server:app", host="0.0.0.0", port=8080, reload=False)
