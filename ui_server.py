#!/usr/bin/env python3
"""UI сервер для SOC 2 Compliance Dashboard."""

import os
import json
import asyncio
import hashlib
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional, AsyncGenerator

import httpx
from fastapi import FastAPI, HTTPException, UploadFile, File, Body, Depends, Cookie, Form
from fastapi.responses import StreamingResponse, HTMLResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import dotenv_values, set_key
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import text

import time

from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from log_config import get_logger
from auth import authenticate_user, create_access_token, decode_token, ROLES
from auth import require_auth, require_admin, require_auditor
from config import get_settings
from database import init_db, engine, AsyncSessionLocal, check_db_health
from metrics import http_requests_total, http_request_duration_seconds, sse_clients_connected

log = get_logger(__name__)
_settings = get_settings()

# ── Background task registry (prevents GC of fire-and-forget tasks) ───────────
_background_tasks: set[asyncio.Task] = set()


def _task_done_callback(task: asyncio.Task) -> None:
    _background_tasks.discard(task)
    if not task.cancelled() and task.exception():
        log.error("Background task failed: %s", task.exception(), exc_info=task.exception())

# Constants
EVIDENCE_TRACKER = os.getenv("EVIDENCE_TRACKER_URL", _settings.evidence_tracker_url)
EVIDENCE_API_KEY = os.getenv("UI_API_KEY") or os.getenv("EVIDENCE_API_KEY", "")
ENV_FILE = Path(__file__).parent / ".env"
ROOT = Path(__file__).parent
_tracker_headers = {"X-API-Key": EVIDENCE_API_KEY}

# ── SSE Clients ────────────────────────────────────────────────────────────────
_sse_clients: list[asyncio.Queue] = []


async def _broadcast_event(event: dict) -> None:
    """Отправить событие всем подключённым SSE-клиентам."""
    dead = []
    for q in _sse_clients:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        try:
            _sse_clients.remove(q)
        except ValueError:
            pass


AGENTS = {
    "scanner": {"label": "AWS Scanner",      "cmd": ["python3", "scanner.py"],                      "desc": "S3, IAM, EC2, CloudTrail — LocalStack/AWS",  "icon": "☁️"},
    "prowler": {"label": "Prowler Runner",   "cmd": ["python3", "prowler_runner.py"],               "desc": "160 SOC 2 проверок из каталога Prowler",     "icon": "🔍"},
    "hr":      {"label": "HR Agent",         "cmd": ["python3", "hr_agent.py"],                     "desc": "Okta + HR roster: offboarding, training",    "icon": "👥"},
    "survey":  {"label": "Survey Agent",     "cmd": ["python3", "survey_agent.py"],                 "desc": "Опрос сотрудников по знанию политик",         "icon": "📋"},
    "github":  {"label": "GitHub Agent",     "cmd": ["python3", "github_agent.py"],                 "desc": "CI/CD, Secrets Scanning, Issues",            "icon": "🐙"},
    "policy":  {"label": "Policy Generator", "cmd": ["python3", "policy_agent.py", "--governance"], "desc": "AI-черновики для 9 governance контролей",    "icon": "📄"},
}

SENSITIVE_KEYS = {"TOKEN", "KEY", "SECRET", "PASSWORD", "WEBHOOK", "API"}

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
        _t = asyncio.create_task(_broadcast_event({"type": "agent_done", "agent": "scanner", "trigger": "scheduler"}))
        _background_tasks.add(_t)
        _t.add_done_callback(_task_done_callback)
        await loop.run_in_executor(None, lambda: run_hr(controls_map))
        _t = asyncio.create_task(_broadcast_event({"type": "agent_done", "agent": "hr", "trigger": "scheduler"}))
        _background_tasks.add(_t)
        _t.add_done_callback(_task_done_callback)
        await loop.run_in_executor(None, lambda: run_survey(controls_map))
        _t = asyncio.create_task(_broadcast_event({"type": "agent_done", "agent": "survey", "trigger": "scheduler"}))
        _background_tasks.add(_t)
        _t.add_done_callback(_task_done_callback)
        log.info("Scheduler: daily scan completed")
    except Exception as e:
        log.error("Scheduler: daily scan failed: %s", e)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
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
    # Cancel remaining background tasks
    for task in list(_background_tasks):
        task.cancel()
    if _background_tasks:
        await asyncio.gather(*_background_tasks, return_exceptions=True)
    # Dispose database engine
    await engine.dispose()

# ── Application Initialization ────────────────────────────────────────────────
app = FastAPI(title="SOC 2 Dashboard", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _settings.cors_origins.split(",") if o.strip()] or ["http://localhost:8000"],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
    allow_credentials=True,
)

from tenant_middleware import TenantMiddleware  # noqa: E402
app.add_middleware(TenantMiddleware)


# ── Audit log middleware ───────────────────────────────────────────────────────
_AUDIT_SKIP_PATHS = {"/api/auth/login", "/api/auth/logout", "/health", "/health/ready"}
_AUDIT_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# ── Prometheus instrumentation middleware ──────────────────────────────────────
_METRICS_SKIP_PREFIXES = ("/health", "/metrics", "/static")


@app.middleware("http")
async def prometheus_middleware(request, call_next):
    start = time.monotonic()
    response = await call_next(request)
    path = request.url.path
    if not any(path.startswith(p) for p in _METRICS_SKIP_PREFIXES):
        duration = time.monotonic() - start
        endpoint = path.rstrip("/") or "/"
        http_requests_total.labels(
            method=request.method,
            endpoint=endpoint,
            status=str(response.status_code),
        ).inc()
        http_request_duration_seconds.labels(
            method=request.method,
            endpoint=endpoint,
        ).observe(duration)
    return response


@app.get("/metrics", include_in_schema=False)
async def prometheus_metrics():
    """Prometheus metrics endpoint."""
    from fastapi.responses import Response
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.middleware("http")
async def audit_mutations(request, call_next):
    response = await call_next(request)
    method = request.method
    path = request.url.path
    if method not in _AUDIT_METHODS or path in _AUDIT_SKIP_PATHS:
        return response
    if response.status_code >= 400:
        return response

    async def _log():
        try:
            token = request.cookies.get("access_token")
            payload = decode_token(token) if token else None
            user_email = payload.get("sub", "anonymous") if payload else "anonymous"
            from audit_log_repository import AuditLogRepository
            from database import AsyncSessionLocal
            async with AsyncSessionLocal() as session:
                repo = AuditLogRepository(session)
                await repo.log(
                    action=f"{method} {path}",
                    user_email=user_email,
                    details={"status": response.status_code},
                )
                await session.commit()
        except Exception as exc:
            log.debug("Audit middleware error: %s", exc)

    _t = asyncio.create_task(_log())
    _background_tasks.add(_t)
    _t.add_done_callback(_task_done_callback)
    return response

# Import and Include Routers
from audit_package_routes import router as audit_package_router
from access_review_routes import router as access_review_router
from asset_routes import router as asset_router
from auditor_routes import router as auditor_router
from audit_timeline_routes import router as audit_timeline_router
from background_check_routes import router as background_check_router
from cac_routes import router as cac_router
from chaos_routes import router as chaos_router
from compliance_engine_routes import router as compliance_engine_router
from control_mapping_routes import router as control_mapping_router
from custom_controls_routes import router as custom_controls_router
from decision_log_routes import router as decision_log_router
from event_routes import router as event_router
from evidence_confidence_routes import router as evidence_confidence_router
from gap_analysis_routes import router as gap_analysis_router
from governance_routes import router as governance_router
from graph_routes import router as graph_router
from pentest_routes import router as pentest_router
from policy_lifecycle_routes import router as policy_lifecycle_router
from questionnaire_routes import router as questionnaire_router
from replay_routes import router as replay_router
from report_routes import router as report_router
from risk_routes import router as risk_router
from state_routes import router as state_router
from time_machine_routes import router as time_machine_router
from time_machine_routes import compliance_router as time_machine_compliance_router
from training_routes import router as training_router
from trust_routes import router as trust_router
from vendor_risk_routes import router as vendor_risk_router
from vuln_routes import router as vuln_router
from webhook_routes import router as webhook_router
from test_results_routes import router as test_engine_router
from evidence_chain_routes import router as evidence_chain_router
from audit_log_routes import router as audit_log_router
from findings_routes import router as findings_router
from sse_routes import router as sse_router
from tenant_routes import router as tenant_router
from llm_routes import router as llm_router

app.include_router(audit_package_router)
app.include_router(access_review_router)
app.include_router(asset_router)
app.include_router(auditor_router)
app.include_router(audit_timeline_router)
app.include_router(background_check_router)
app.include_router(cac_router)
app.include_router(chaos_router)
app.include_router(compliance_engine_router)
app.include_router(control_mapping_router)
app.include_router(custom_controls_router)
app.include_router(decision_log_router)
app.include_router(event_router)
app.include_router(evidence_confidence_router)
app.include_router(gap_analysis_router)
app.include_router(governance_router)
app.include_router(graph_router)
app.include_router(pentest_router)
app.include_router(policy_lifecycle_router)
app.include_router(questionnaire_router)
app.include_router(replay_router)
app.include_router(report_router)
app.include_router(risk_router)
app.include_router(state_router)
app.include_router(time_machine_router)
app.include_router(time_machine_compliance_router)
app.include_router(training_router)
app.include_router(trust_router)
app.include_router(vendor_risk_router)
app.include_router(vuln_router)
app.include_router(webhook_router)
app.include_router(test_engine_router)
app.include_router(evidence_chain_router)
app.include_router(audit_log_router)
app.include_router(findings_router)
app.include_router(sse_router)
app.include_router(tenant_router)
app.include_router(llm_router)

# ── Auth dependencies ──────────────────────────────────────────────────────────
# require_auth, require_admin, require_auditor imported from auth.py (source of truth)

def require_scanner(payload: dict = Depends(require_auth)):
    """Roles admin or scanner."""
    if payload.get("role") not in ("admin", "scanner"):
        raise HTTPException(status_code=403, detail="Scanner role required")
    return payload

# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    """Проверяет доступность Evidence Tracker и базы данных."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{EVIDENCE_TRACKER}/health", headers=_tracker_headers)
        tracker_ok = r.status_code == 200
    except Exception:
        tracker_ok = False

    db_ok = await check_db_health()

    overall_ok = tracker_ok and db_ok
    response_body = {
        "status": "ok" if overall_ok else "degraded",
        "ui_server": "ok",
        "evidence_tracker": "ok" if tracker_ok else "unavailable",
        "database": "healthy" if db_ok else "unhealthy",
    }
    if not overall_ok:
        raise HTTPException(status_code=503, detail=response_body)
    return response_body


@app.get("/health/ready")
async def health_ready():
    """Readiness probe — returns 503 if not ready to serve traffic."""
    db_ok = False
    try:
        async with AsyncSessionLocal() as s:
            await s.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass

    if not db_ok:
        raise HTTPException(status_code=503, detail={"ready": False, "database": "unhealthy"})
    return {"ready": True, "database": "healthy"}

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

@app.get("/access-review", response_class=HTMLResponse)
async def access_review_page():
    return FileResponse("ui/access_review.html")

@app.get("/training", response_class=HTMLResponse)
async def training_page():
    return (ROOT / "ui" / "training.html").read_text(encoding="utf-8")

@app.get("/background-checks", response_class=HTMLResponse)
async def background_checks_page():
    return (ROOT / "ui" / "background-checks.html").read_text(encoding="utf-8")

@app.get("/vulnerabilities", response_class=HTMLResponse)
async def vulnerabilities_page():
    return (ROOT / "ui" / "vulnerabilities.html").read_text(encoding="utf-8")

@app.get("/pentests", response_class=HTMLResponse)
async def pentests_page():
    return (ROOT / "ui" / "pentests.html").read_text(encoding="utf-8")

@app.get("/risk-register", response_class=HTMLResponse)
async def risk_register_page():
    return (ROOT / "ui" / "risk-register.html").read_text(encoding="utf-8")

@app.get("/audit-timeline", response_class=HTMLResponse)
async def audit_timeline_page():
    return (ROOT / "ui" / "audit-timeline.html").read_text(encoding="utf-8")

@app.get("/questionnaires", response_class=HTMLResponse)
async def questionnaires_page():
    return (ROOT / "ui" / "questionnaires.html").read_text(encoding="utf-8")

@app.get("/trust", response_class=HTMLResponse)
async def trust_page():
    return (ROOT / "ui" / "trust.html").read_text(encoding="utf-8")

@app.get("/tests-catalog", response_class=HTMLResponse, include_in_schema=False)
async def tests_catalog_page():
    return (ROOT / "ui" / "tests.html").read_text(encoding="utf-8")

@app.get("/time-machine", response_class=HTMLResponse, include_in_schema=False)
async def time_machine_page():
    return (ROOT / "ui" / "time_machine.html").read_text(encoding="utf-8")

@app.get("/onboarding", response_class=HTMLResponse)
async def onboarding_page():
    return (ROOT / "ui" / "onboarding.html").read_text(encoding="utf-8")

@app.get("/ai-decisions", response_class=HTMLResponse)
async def ai_decisions_page():
    return (ROOT / "ui" / "ai_decisions.html").read_text(encoding="utf-8")

# ── Auth API ───────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(email: str = Form(...), password: str = Form(...)):
    user = authenticate_user(email, password)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Invalid credentials"})
    token = create_access_token({"sub": user["email"], "role": user["role"], "name": user["name"]})
    # Token is delivered via HttpOnly cookie only — not included in response body
    response = JSONResponse(content={"role": user["role"], "name": user["name"]})
    response.set_cookie(
        "access_token", token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=28800,
    )
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
async def get_controls(_: dict = Depends(require_auth)):
    from db_repository import ControlRepository
    from database import AsyncSessionLocal
    from control_mapping import CONTROL_MAPPINGS

    controls: list = []
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{EVIDENCE_TRACKER}/api/v1/controls/?limit=100", headers=_tracker_headers)
        data = r.json()
        if isinstance(data, list):
            controls = data
        elif isinstance(data, dict):
            controls = data.get("items", data.get("controls", []))
    except Exception:
        pass

    if not controls:
        controls = [
            {
                "id": m.soc2,
                "code": m.soc2,
                "title": m.description,
                "description": m.description,
                "framework": "SOC2",
                "category": m.category,
                "status": "UNKNOWN",
            }
            for m in CONTROL_MAPPINGS
        ]

    # Статусы из SQLite — агенты пишут сюда по SOC2-коду
    db_statuses: dict = {}
    try:
        async with AsyncSessionLocal() as session:
            repo = ControlRepository(session)
            all_statuses = await repo.list_all()
            db_statuses = {cs.control_id: cs.status for cs in all_statuses}
    except Exception:
        pass

    soc2_index: set = {m.soc2 for m in CONTROL_MAPPINGS}
    soc2_by_description: dict = {m.description: m.soc2 for m in CONTROL_MAPPINGS}

    for ctrl in controls:
        code = ctrl.get("code") or ctrl.get("id", "")
        if code not in soc2_index:
            title = ctrl.get("title", "") or ctrl.get("description", "")
            normalized = soc2_by_description.get(title, code)
            if normalized in soc2_index:
                ctrl["code"] = normalized
                code = normalized
        if code in db_statuses:
            ctrl["status"] = db_statuses[code]

    return controls

@app.get("/api/evidence")
async def get_evidence(control_id: str = "", limit: int = 100, _: dict = Depends(require_auth)):
    try:
        url = f"{EVIDENCE_TRACKER}/api/v1/evidence/?limit={limit}"
        if control_id:
            url += f"&control_id={control_id}"
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(url, headers=_tracker_headers)
            data = r.json()
            if isinstance(data, list):
                return data
    except Exception:
        pass
    # Fallback: read from local SQLite DB
    from db_repository import EvidenceRepository
    from database import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        repo = EvidenceRepository(session)
        if control_id:
            items = await repo.list_by_control(control_id, limit=limit)
        else:
            items = await repo.list_all(limit=limit)
        return [
            {
                "id": ev.id,
                "control_id": ev.control_id,
                "title": ev.title,
                "source": ev.source,
                "confidence_score": ev.confidence_score,
                "created_at": ev.created_at.isoformat() if ev.created_at else None,
            }
            for ev in items
        ]

@app.get("/api/evidence/chain-status")
async def evidence_chain_status(_: dict = Depends(require_auth)):
    """Return hash-chain integrity status for all controls that have local evidence.

    Clients can use this to display 'Evidence Immutable' badges per control.
    Response: list of {control_id, valid, chain_length, broken_at}
    """
    from db_repository import EvidenceRepository
    from database import AsyncSessionLocal
    import hashlib

    async with AsyncSessionLocal() as session:
        repo = EvidenceRepository(session)
        all_ev = await repo.list_all(limit=5000)

    by_control: dict[str, list] = {}
    for ev in all_ev:
        cid = ev.control_id or ""
        by_control.setdefault(cid, []).append(ev)

    results = []
    for control_id, records in by_control.items():
        records.sort(key=lambda e: e.created_at or "")
        broken_at = None
        prev_hash = None
        for ev in records:
            if prev_hash is None:
                prev_hash = ev.sha256_hash
                continue
            ev_prev = getattr(ev, "previous_hash", None)
            if ev_prev and ev_prev != prev_hash:
                broken_at = ev.id
                break
            prev_hash = ev.sha256_hash
        results.append({
            "control_id": control_id,
            "valid": broken_at is None,
            "chain_length": len(records),
            "broken_at": broken_at,
        })
    return results


@app.get("/api/registry/services")
async def registry_services(_: dict = Depends(require_auth)):
    from registry import load_registry
    return load_registry()["services"]

@app.post("/api/registry/stack-analysis")
async def stack_analysis(payload: dict, _: dict = Depends(require_admin)):
    from registry import get_controls_for_stack
    services = payload.get("services", [])
    framework = payload.get("framework", "soc2")
    return get_controls_for_stack(services, framework)

@app.get("/api/agents")
async def list_agents():
    return {k: {"label": v["label"], "desc": v["desc"], "icon": v["icon"]} for k, v in AGENTS.items()}

@app.get("/api/run/{agent_name}")
async def run_agent(agent_name: str, payload: dict = Depends(require_scanner)):
    if agent_name not in AGENTS:
        raise HTTPException(404, f"Agent '{agent_name}' not found")
    agent = AGENTS[agent_name]
    async def stream():
        yield f"data: {json.dumps({'type': 'start', 'agent': agent['label']})}\n\n"
        try:
            agent_env = {**os.environ, "DATABASE_URL": os.environ.get("DATABASE_URL", f"sqlite+aiosqlite:///{ROOT}/compliance.db")}
            proc = await asyncio.create_subprocess_exec(*agent["cmd"], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, cwd=str(ROOT), env=agent_env)
            async for raw in proc.stdout:
                text = raw.decode("utf-8", errors="replace").rstrip()
                if text: yield f"data: {json.dumps({'type': 'line', 'text': text})}\n\n"
            await proc.wait()
            yield f"data: {json.dumps({'type': 'done', 'code': proc.returncode})}\n\n"
            _t = asyncio.create_task(_broadcast_event({"type": "agent_done", "agent": agent_name, "code": proc.returncode}))
            _background_tasks.add(_t)
            _t.add_done_callback(_task_done_callback)
        except Exception as ex:
            yield f"data: {json.dumps({'type': 'error', 'text': str(ex)})}\n\n"
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── SSE Endpoints ──────────────────────────────────────────────────────────────
@app.get("/api/events/stream")
async def events_stream(_: dict = Depends(require_auth)):
    """SSE stream для real-time уведомлений об изменении статусов контролей."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _sse_clients.append(queue)
    sse_clients_connected.set(len(_sse_clients))

    async def cleanup() -> None:
        try:
            _sse_clients.remove(queue)
            sse_clients_connected.set(len(_sse_clients))
        except ValueError:
            pass

    async def stream() -> AsyncGenerator[str, None]:
        try:
            while True:
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=25.0)
                    yield f"data: {json.dumps(data)}\n\n"
                except asyncio.TimeoutError:
                    yield "data: {\"type\": \"heartbeat\"}\n\n"
        except Exception:
            pass
        finally:
            await cleanup()

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )

@app.post("/api/events/broadcast")
async def broadcast_event(payload: dict = Body(...), _: dict = Depends(require_admin)):
    """Отправить тестовое событие всем SSE-клиентам."""
    await _broadcast_event(payload)
    return {"ok": True, "clients": len(_sse_clients)}

# ── Celery Agent Endpoints (альтернатива subprocess+SSE) ───────────────────────
@app.post("/api/run/{agent_name}/celery")
async def enqueue_agent_celery(agent_name: str, payload: dict = Depends(require_scanner)):
    """
    Запустить агента через Celery (async queue).
    Альтернатива subprocess+SSE режиму — агент выполняется в отдельном воркере.
    Возвращает task_id для опроса статуса.
    """
    CELERY_AGENT_TASKS = {
        "scanner": "tasks.run_scanner",
        "hr":      "tasks.run_hr_agent",
        "github":  "tasks.run_github_agent",
        "policy":  "tasks.run_policy_agent",
    }
    task_name = CELERY_AGENT_TASKS.get(agent_name)
    if not task_name:
        raise HTTPException(404, f"No Celery task for agent '{agent_name}'")
    tenant_id = payload.get("tenant_id")
    try:
        from celery_app import celery_app
        result = celery_app.send_task(task_name, kwargs={"tenant_id": tenant_id})
        return {"task_id": result.id, "agent": agent_name, "mode": "celery", "status": "queued"}
    except Exception as exc:
        raise HTTPException(503, f"Celery unavailable: {exc}")

@app.get("/api/run/{task_id}/status")
async def get_celery_task_status(task_id: str, _: dict = Depends(require_auth)):
    """Проверить статус Celery-задачи по task_id."""
    try:
        from celery_app import celery_app
        result = celery_app.AsyncResult(task_id)
        return {
            "task_id": task_id,
            "status": result.status,
            "result": result.result if result.ready() else None,
        }
    except Exception as exc:
        raise HTTPException(503, f"Celery unavailable: {exc}")

# ── Config API ─────────────────────────────────────────────────────────────────
_CONFIG_ALLOWLIST = {
    "EVIDENCE_TRACKER_URL", "JIRA_URL", "JIRA_PROJECT_KEY",
    "SLACK_WEBHOOK_URL", "SMTP_HOST", "SMTP_PORT", "SMTP_FROM",
    "GITHUB_WEBHOOK_SECRET", "OKTA_WEBHOOK_SECRET", "SLACK_SIGNING_SECRET",
    "OUTGOING_WEBHOOKS", "ENVIRONMENT",
}


def _mask(key: str, val: str) -> str:
    if any(s in key.upper() for s in SENSITIVE_KEYS):
        return val[:4] + "***" if len(val) > 4 else "***"
    return val

@app.get("/api/config")
async def get_config(_: dict = Depends(require_admin)):
    if not ENV_FILE.exists(): return {}
    values = dotenv_values(ENV_FILE)
    return {k: {"value": _mask(k, v or ""), "sensitive": any(s in k.upper() for s in SENSITIVE_KEYS)} for k, v in values.items()}

@app.post("/api/config")
async def update_config(data: dict = Body(...), payload: dict = Depends(require_admin)):
    updated = 0
    for key, value in data.items():
        if key not in _CONFIG_ALLOWLIST:
            raise HTTPException(status_code=400, detail=f"Key '{key}' is not configurable via API")
        if value and not value.endswith("***"):
            # Strip newlines from value to prevent file injection
            value = value.replace("\n", "").replace("\r", "")
            set_key(str(ENV_FILE), key, value)
            updated += 1
    return {"ok": True, "updated": updated}

# ── Scheduler API ──────────────────────────────────────────────────────────────
@app.get("/api/scheduler/status")
async def scheduler_status(_: dict = Depends(require_auth)):
    jobs = []
    for job in scheduler.get_jobs():
        jobs.append({"id": job.id, "next_run": str(job.next_run_time), "trigger": str(job.trigger)})
    return {"running": scheduler.running, "jobs": jobs}

@app.post("/api/scheduler/trigger")
async def trigger_scan_now(_: dict = Depends(require_admin)):
    _t = asyncio.create_task(run_daily_scan())
    _background_tasks.add(_t)
    _t.add_done_callback(_task_done_callback)
    return {"status": "triggered", "message": "Daily scan started in background"}

# ── ESignature API ─────────────────────────────────────────────────────────────
@app.post("/api/esignature/webhook")
async def esignature_webhook(payload: dict = Body(...), _: dict = Depends(require_auth)):
    envelope_id = payload.get("envelope_id")
    if not envelope_id:
        return JSONResponse(status_code=400, content={"detail": "envelope_id required"})
    from esignature_agent import ESignatureAgent
    return ESignatureAgent().simulate_signature(envelope_id)

@app.get("/api/esignature/pending")
async def esignature_pending(_: dict = Depends(require_auth)):
    from esignature_agent import ESignatureAgent
    return {"pending": ESignatureAgent().get_pending_signatures()}

@app.get("/api/esignature/{envelope_id}/status")
async def esignature_status(envelope_id: str, _: dict = Depends(require_auth)):
    from esignature_agent import ESignatureAgent
    return ESignatureAgent().check_docusign_status(envelope_id)

# ── Remediation API ────────────────────────────────────────────────────────────
@app.get("/api/remediations")
async def get_remediations(_: dict = Depends(require_auth)):
    from remediation_agent import RemediationAgent
    return RemediationAgent().get_all_remediations()

@app.post("/api/remediations/sync")
async def sync_remediations(_: dict = Depends(require_auth)):
    from remediation_agent import RemediationAgent
    updated = RemediationAgent().sync_statuses()
    return {"synced": updated, "count": len(updated)}

@app.post("/api/remediations/create")
async def create_remediation(payload: dict = Body(...), _: dict = Depends(require_auth)):
    from remediation_agent import RemediationAgent
    return RemediationAgent().create_remediation_ticket(
        payload.get("control_code", ""),
        payload.get("finding", "Control failed"),
    )

# ── Celery Task API ────────────────────────────────────────────────────────────
@app.post("/api/tasks/run/{agent_name}")
async def enqueue_agent(agent_name: str, auth_payload: dict = Depends(require_scanner)):
    from tasks import run_scanner_task, run_hr_agent_task, run_github_agent_task, run_policy_agent_task, run_full_pipeline_task
    task_map = {
        "scanner": run_scanner_task, "hr_agent": run_hr_agent_task,
        "github_agent": run_github_agent_task, "policy_agent": run_policy_agent_task, "all": run_full_pipeline_task,
    }
    if agent_name not in task_map:
        return JSONResponse(status_code=404, content={"detail": f"Unknown agent: {agent_name}"})
    tenant_id = auth_payload.get("tenant_id")
    task = task_map[agent_name].delay(tenant_id=tenant_id)
    return {"task_id": task.id, "status": "queued", "agent": agent_name}

@app.get("/api/tasks/{task_id}/status")
async def task_status(task_id: str, _: dict = Depends(require_auth)):
    from celery_app import celery_app
    from celery.result import AsyncResult
    result = AsyncResult(task_id, app=celery_app)
    return {"task_id": task_id, "status": result.status, "result": result.result if result.ready() else None, "ready": result.ready()}

@app.get("/api/tasks/active")
async def active_tasks(_: dict = Depends(require_auth)):
    from celery_app import celery_app
    try:
        inspect = celery_app.control.inspect(timeout=1.0)
        return {"active": inspect.active() or {}}
    except Exception:
        return {"active": {}, "note": "Redis unavailable"}

# ── Policy Approval Workflow API ───────────────────────────────────────────────
@app.post("/api/policies/{control_code}/draft")
async def create_policy_draft(control_code: str, payload: PolicyDraftRequest, _: dict = Depends(require_admin)):
    from policy_workflow import PolicyWorkflow
    return PolicyWorkflow().create_draft(control_code, payload.title, payload.content, payload.created_by, payload.change_summary)

@app.post("/api/policies/{control_code}/versions/{version}/submit")
async def submit_policy(control_code: str, version: int, _: dict = Depends(require_admin)):
    from policy_workflow import PolicyWorkflow
    return PolicyWorkflow().submit_for_approval(control_code, version)

@app.post("/api/policies/{control_code}/versions/{version}/approve")
async def approve_policy(control_code: str, version: int, payload: ApproveRequest, _: dict = Depends(require_admin)):
    from policy_workflow import PolicyWorkflow
    return PolicyWorkflow().approve(control_code, version, payload.approver_email)

@app.post("/api/policies/{control_code}/versions/{version}/reject")
async def reject_policy(control_code: str, version: int, payload: RejectRequest, _: dict = Depends(require_admin)):
    from policy_workflow import PolicyWorkflow
    return PolicyWorkflow().reject(control_code, version, payload.reviewer_email, payload.reason)

@app.get("/api/policies/{control_code}/history")
async def policy_history(control_code: str, _: dict = Depends(require_auth)):
    from policy_workflow import PolicyWorkflow
    return {"control_code": control_code, "versions": PolicyWorkflow().get_history(control_code)}

@app.get("/api/policies/pending")
async def pending_approvals(_: dict = Depends(require_auth)):
    from policy_workflow import PolicyWorkflow
    return {"pending": PolicyWorkflow().get_pending()}

if __name__ == "__main__":
    import uvicorn
    print("🛡️  SOC 2 Dashboard → http://localhost:8080")
    uvicorn.run("ui_server:app", host="0.0.0.0", port=8080, reload=False)
