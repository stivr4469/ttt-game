"""
Remediation Agent — создаёт Jira-тикеты для FAIL-контролей,
обновляет evidence, отслеживает статус.

Хранение: SQLite (через async ORM).
"""
import asyncio
import os
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Optional
from log_config import get_logger
from evidence_client import EvidenceClient


def _run_async(coro):
    """Запускает async корутину из синхронного контекста."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            return future.result(timeout=30)
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)

log = get_logger(__name__)

EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")
JIRA_PROJECT_KEY     = os.getenv("JIRA_PROJECT_KEY", "SEC")

PRIORITY_MAP = {
    "CC6.1": "Critical", "CC6.2": "Critical", "CC6.3": "High",
    "CC7.1": "High",     "CC7.2": "High",     "CC8.1": "High",
}

REMEDIATION_DESCRIPTIONS = {
    "CC6.1": "Enable MFA for all users. Review IAM policies. Disable dormant accounts (>90 days).",
    "CC6.2": "Implement automated user provisioning/deprovisioning via Okta SCIM.",
    "CC6.3": "Review and enforce least-privilege IAM: remove wildcard permissions.",
    "CC6.7": "Enable TLS 1.2+ on all endpoints. Disable HTTP. Review certificate expiry.",
    "CC7.1": "Enable CloudTrail in all regions. Set up S3 access logging.",
    "CC7.2": "Configure AWS GuardDuty. Set up anomaly detection alerts.",
    "CC8.1": "Enforce branch protection with required reviews and CI status checks.",
    "CC3.4": "Implement change management process. Require JIRA ticket for all infra changes.",
}


class RemediationAgent:
    def __init__(self, jira_url: str = "", jira_user: str = "", jira_token: str = ""):
        self.jira_url   = jira_url   or os.getenv("JIRA_URL", "")
        self.jira_user  = jira_user  or os.getenv("JIRA_USER", "")
        self.jira_token = jira_token or os.getenv("JIRA_API_TOKEN", "")
        self._jira: Optional[object] = None
        self.evidence_client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="remediation")

    @property
    def jira(self):
        if self._jira is None:
            from jira_client import JiraClient
            self._jira = JiraClient(self.jira_url, self.jira_user, self.jira_token)
        return self._jira

    # ── Async DB helpers ──────────────────────────────────────────────────────

    async def _load_db(self) -> dict:
        """Загружает все ремедиации из SQLite. Возвращает {"remediations": {...}}."""
        from database import AsyncSessionLocal
        from models import Remediation
        from sqlalchemy import select as sa_select
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                sa_select(Remediation).order_by(Remediation.created_at)
            )
            rows = result.scalars().all()
            if not rows:
                return {"remediations": {}}
            remediations = {}
            for r in rows:
                remediations[r.control_code] = {
                    "control_code": r.control_code,
                    "jira_key":     r.jira_key or "",
                    "jira_url":     r.jira_url or "",
                    "finding":      r.finding,
                    "priority":     r.priority,
                    "created_at":   r.created_at.isoformat(),
                    "status":       r.status,
                    "mock":         r.is_mock,
                }
            return {"remediations": remediations}

    async def _save_db(self, data: dict) -> None:
        """Сохраняет/обновляет ремедиации в SQLite. Upsert по control_code (unique)."""
        from database import AsyncSessionLocal
        from models import Remediation
        from sqlalchemy import select as sa_select
        async with AsyncSessionLocal() as session:
            for control_code, record in data.get("remediations", {}).items():
                result = await session.execute(
                    sa_select(Remediation).where(Remediation.control_code == control_code)
                )
                existing = result.scalar_one_or_none()
                if existing:
                    existing.jira_key = record.get("jira_key") or existing.jira_key
                    existing.jira_url = record.get("jira_url") or existing.jira_url
                    existing.finding  = record.get("finding", existing.finding)
                    existing.priority = record.get("priority", existing.priority)
                    existing.status   = record.get("status", existing.status)
                    existing.is_mock  = record.get("mock", existing.is_mock)
                else:
                    entry = Remediation(
                        id=str(uuid.uuid4()),
                        control_code=control_code,
                        jira_key=record.get("jira_key", ""),
                        jira_url=record.get("jira_url", ""),
                        finding=record.get("finding", ""),
                        priority=record.get("priority", "Medium"),
                        status=record.get("status", "open"),
                        is_mock=record.get("mock", False),
                    )
                    session.add(entry)
            try:
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_remediations(self) -> dict:
        return _run_async(self._load_db())

    def _save_remediations(self, data: dict) -> None:
        _run_async(self._save_db(data))

    def create_remediation_ticket(self, control_code: str, finding: str) -> dict:
        """Создаёт Jira-тикет для FAIL-контроля. Идемпотентно."""
        # Проверка дубликата: unified _load_remediations обрабатывает оба режима
        data = self._load_remediations()
        existing_record = data["remediations"].get(control_code)

        if existing_record:
            log.info("Remediation ticket already exists", extra={"control_code": control_code, "key": existing_record.get("jira_key")})
            return existing_record

        description = REMEDIATION_DESCRIPTIONS.get(
            control_code,
            f"Remediate SOC 2 finding for {control_code}: {finding}"
        )
        priority = PRIORITY_MAP.get(control_code, "Medium")
        summary  = f"[SOC2 {control_code}] Remediation: {finding[:80]}"

        ticket = None
        if self.jira_url and self.jira_user and self.jira_token:
            try:
                ticket = self.jira.create_issue(
                    project_key=JIRA_PROJECT_KEY,
                    summary=summary,
                    description=description,
                    priority=priority,
                    labels=["soc2", "compliance", "remediation", control_code.lower().replace(".", "")],
                )
                log.info("Jira ticket created", extra={"control_code": control_code, "key": ticket["key"]})
            except Exception as e:
                log.warning("Jira unavailable, using mock ticket", extra={"error": str(e)})

        if not ticket:
            import uuid
            mock_key = f"SEC-{abs(hash(control_code)) % 9000 + 1000}"
            ticket = {
                "key": mock_key,
                "id":  str(uuid.uuid4()),
                "url": f"https://mock-jira.example.com/browse/{mock_key}",
                "mock": True,
            }

        record = {
            "control_code": control_code,
            "jira_key":     ticket["key"],
            "jira_url":     ticket["url"],
            "finding":      finding,
            "priority":     priority,
            "created_at":   datetime.now(timezone.utc).isoformat(),
            "status":       "open",
            "mock":         ticket.get("mock", False),
        }

        # Сохранение: unified _save_remediations обрабатывает оба режима
        data = self._load_remediations()
        data["remediations"][control_code] = record
        self._save_remediations(data)

        return record

    def process_fail_controls(self, controls: List[Dict]) -> List[dict]:
        results = []
        for ctrl in controls:
            code   = ctrl.get("control_code") or ctrl.get("code", "")
            status = ctrl.get("status", "")
            if status.upper() != "FAIL" or not code:
                continue
            finding = ctrl.get("finding", ctrl.get("title", f"{code} control failed"))
            try:
                record = self.create_remediation_ticket(code, finding)
                results.append(record)
            except Exception as e:
                log.error("Failed to create remediation ticket", extra={"control_code": code, "error": str(e)})
                results.append({"control_code": code, "error": str(e)})
        return results

    def get_all_remediations(self) -> dict:
        return self._load_remediations()

    def sync_statuses(self) -> List[dict]:
        if not (self.jira_url and self.jira_user and self.jira_token):
            return []
        log.info("sync_statuses синхронизирует статусы через DB")
        data    = self._load_remediations()
        updated = []
        for code, record in data["remediations"].items():
            if record.get("mock"):
                continue
            try:
                status_info = self.jira.get_issue(record["jira_key"])
                record["status"]    = status_info["status"].lower()
                record["assignee"]  = status_info["assignee"]
                record["synced_at"] = datetime.now(timezone.utc).isoformat()
                updated.append(code)
            except Exception as e:
                log.warning("Jira sync failed for ticket", extra={"key": record["jira_key"], "error": str(e)})
        if updated:
            self._save_remediations(data)
        return updated
