from fastapi import APIRouter
from fastapi.responses import JSONResponse
import json
import os
from datetime import datetime, timezone, date, timedelta
from log_config import get_logger
from evidence_client import EvidenceClient
from constants import CONTROLS_MAP_FILE

router = APIRouter(prefix="/api/access-review", tags=["access-review"])
log = get_logger(__name__)

EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")
REVIEW_DATA_FILE = "access_review_data.json"

_USERS = [
    {
        "id": "u001",
        "name": "Alice Johnson",
        "email": "alice@acme.com",
        "role": "Engineer",
        "department": "Engineering",
        "access_level": "admin",
        "last_login": "2026-05-01",
        "mfa_enabled": True,
        "status": "pending",
        "systems": ["AWS", "GitHub", "Okta"],
    },
    {
        "id": "u002",
        "name": "Bob Martinez",
        "email": "bob@acme.com",
        "role": "DevOps",
        "department": "Engineering",
        "access_level": "admin",
        "last_login": "2026-05-18",
        "mfa_enabled": True,
        "status": "pending",
        "systems": ["AWS", "GitHub", "Datadog", "PagerDuty"],
    },
    {
        "id": "u003",
        "name": "Carol White",
        "email": "carol@acme.com",
        "role": "Manager",
        "department": "Engineering",
        "access_level": "write",
        "last_login": "2026-05-10",
        "mfa_enabled": True,
        "status": "pending",
        "systems": ["GitHub", "Jira", "Confluence"],
    },
    {
        "id": "u004",
        "name": "David Kim",
        "email": "david@acme.com",
        "role": "HR",
        "department": "Human Resources",
        "access_level": "read",
        "last_login": "2026-05-12",
        "mfa_enabled": True,
        "status": "pending",
        "systems": ["Okta", "BambooHR"],
    },
    {
        "id": "u005",
        "name": "Elena Sokolova",
        "email": "elena@acme.com",
        "role": "Finance",
        "department": "Finance",
        "access_level": "read",
        "last_login": "2026-05-08",
        "mfa_enabled": False,
        "status": "pending",
        "systems": ["QuickBooks", "Stripe Dashboard"],
    },
    {
        "id": "u006",
        "name": "Frank Osei",
        "email": "frank@acme.com",
        "role": "Auditor",
        "department": "Compliance",
        "access_level": "read",
        "last_login": "2026-05-20",
        "mfa_enabled": True,
        "status": "pending",
        "systems": ["AWS", "GitHub", "Okta", "Confluence"],
    },
    {
        "id": "u007",
        "name": "Grace Liu",
        "email": "grace@acme.com",
        "role": "Engineer",
        "department": "Engineering",
        "access_level": "write",
        "last_login": "2026-01-15",
        "mfa_enabled": False,
        "status": "pending",
        "systems": ["GitHub", "AWS"],
    },
    {
        "id": "u008",
        "name": "Henry Brown",
        "email": "henry@acme.com",
        "role": "Manager",
        "department": "Finance",
        "access_level": "admin",
        "last_login": "2026-02-03",
        "mfa_enabled": True,
        "status": "pending",
        "systems": ["QuickBooks", "AWS", "Okta"],
    },
]


def _load_decisions() -> dict:
    if not os.path.exists(REVIEW_DATA_FILE):
        return {}
    try:
        with open(REVIEW_DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_decisions(data: dict) -> None:
    with open(REVIEW_DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _is_dormant(last_login_str: str) -> bool:
    try:
        last = date.fromisoformat(last_login_str)
        return (date.today() - last).days > 90
    except ValueError:
        return False


@router.get("/users")
async def get_users():
    decisions = _load_decisions()
    users_out = []
    for u in _USERS:
        entry = dict(u)
        if u["id"] in decisions:
            entry["status"] = decisions[u["id"]]["decision"]
        users_out.append(entry)
    return JSONResponse({
        "review_period": "Q2 2026",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "users": users_out,
    })


@router.post("/decision")
async def post_decision(body: dict):
    user_id = body.get("user_id", "")
    decision = body.get("decision", "")
    reviewer = body.get("reviewer", "")
    reason = body.get("reason", "")

    if decision not in ("approve", "revoke", "escalate"):
        return JSONResponse(
            {"error": "decision must be approve, revoke or escalate"},
            status_code=400,
        )

    known_ids = {u["id"] for u in _USERS}
    if user_id not in known_ids:
        return JSONResponse({"error": "unknown user_id"}, status_code=404)

    decisions = _load_decisions()
    decisions[user_id] = {
        "decision": decision,
        "reviewer": reviewer,
        "reason": reason,
        "decided_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_decisions(decisions)
    log.info("access_review_decision", extra={"user_id": user_id, "decision": decision, "reviewer": reviewer})
    return {"status": "saved", "user_id": user_id, "decision": decision}


@router.post("/submit")
async def submit_review():
    decisions = _load_decisions()

    total = len(_USERS)
    approved = sum(1 for d in decisions.values() if d["decision"] == "approve")
    revoked = sum(1 for d in decisions.values() if d["decision"] == "revoke")
    escalated = sum(1 for d in decisions.values() if d["decision"] == "escalate")
    pending = total - len(decisions)

    summary = {
        "total": total,
        "approved": approved,
        "revoked": revoked,
        "escalated": escalated,
        "pending": pending,
        "review_period": "Q2 2026",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }

    controls_map: dict = {}
    if os.path.exists(CONTROLS_MAP_FILE):
        with open(CONTROLS_MAP_FILE, "r", encoding="utf-8") as f:
            controls_map = json.load(f)

    client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="access_review")
    evidence_ids = []
    content = json.dumps(summary, ensure_ascii=False, indent=2)

    for code in ("CC6.2", "CC6.5"):
        ctrl_id = controls_map.get(code)
        if not ctrl_id:
            log.warning("control not found in controls_map", extra={"code": code})
            continue
        try:
            ev = client.create_evidence(
                control_id=ctrl_id,
                title=f"Quarterly Access Review Q2 2026 — {code}",
                content=content,
                source="MANUAL",
            )
            evidence_ids.append(ev.get("id"))
            client.update_control_status(ctrl_id, "PASS")
            log.info("evidence created", extra={"control": code, "evidence_id": ev.get("id")})
        except Exception as exc:
            log.error("failed to create evidence", extra={"control": code, "error": str(exc)})

    return {"status": "submitted", "evidence_ids": evidence_ids, "summary": summary}


@router.get("/status")
async def get_status():
    decisions = _load_decisions()
    total = len(_USERS)
    approved = sum(1 for d in decisions.values() if d["decision"] == "approve")
    revoked = sum(1 for d in decisions.values() if d["decision"] == "revoke")
    escalated = sum(1 for d in decisions.values() if d["decision"] == "escalate")
    reviewed = len(decisions)
    pending = total - reviewed
    return {
        "total": total,
        "reviewed": reviewed,
        "pending": pending,
        "approved": approved,
        "revoked": revoked,
        "escalated": escalated,
    }
