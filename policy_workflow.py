"""
Policy Approval Workflow — версионирование политик, трекинг изменений,
формальный процесс одобрения (draft → pending_approval → approved/rejected).
"""

import os
import json
from datetime import datetime, timezone
from typing import Optional

from log_config import get_logger
from evidence_client import EvidenceClient

log = get_logger(__name__)

EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")
VERSIONS_FILE = "policy_versions.json"

VALID_STATUSES = {"draft", "pending_approval", "approved", "rejected"}


class PolicyWorkflow:
    def __init__(self, versions_file: str = VERSIONS_FILE):
        self.versions_file = versions_file
        self.evidence_client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="policy_workflow")

    # ── Хранилище ─────────────────────────────────────────────────────────────

    def _load(self) -> dict:
        """Читает policy_versions.json, создаёт файл если не существует."""
        if not os.path.exists(self.versions_file):
            empty = {"policies": {}}
            self._save(empty)
            return empty
        with open(self.versions_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save(self, data: dict) -> None:
        """Записывает данные в policy_versions.json."""
        with open(self.versions_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    # ── Основные методы workflow ───────────────────────────────────────────────

    def create_draft(
        self,
        control_code: str,
        title: str,
        content: str,
        created_by: str,
        change_summary: str,
    ) -> dict:
        """
        Создаёт новый черновик политики для указанного контроля.
        Версия автоматически инкрементируется.
        Возвращает: {"control_code", "version", "status"}
        """
        data = self._load()
        policies = data["policies"]

        if control_code not in policies:
            policies[control_code] = {
                "current_version": 0,
                "versions": [],
            }

        policy = policies[control_code]
        next_version = policy["current_version"] + 1

        version_record = {
            "version": next_version,
            "title": title,
            "content": content,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": created_by,
            "status": "draft",
            "approved_by": None,
            "approved_at": None,
            "change_summary": change_summary,
        }

        policy["versions"].append(version_record)
        policy["current_version"] = next_version

        self._save(data)

        log.info(
            "Policy draft created",
            extra={"control_code": control_code, "version": next_version, "created_by": created_by},
        )

        return {"control_code": control_code, "version": next_version, "status": "draft"}

    def submit_for_approval(self, control_code: str, version: int) -> dict:
        """
        Переводит черновик в статус pending_approval.
        Только версии со статусом "draft" можно отправить на одобрение.
        Возвращает: {"control_code", "version", "status"} или {"error": ...}
        """
        data = self._load()
        version_record = self._find_version(data, control_code, version)

        if version_record is None:
            return {"error": f"version {version} not found for control {control_code}"}

        if version_record["status"] != "draft":
            return {"error": "only draft versions can be submitted"}

        version_record["status"] = "pending_approval"
        self._save(data)

        log.info(
            "Policy submitted for approval",
            extra={"control_code": control_code, "version": version},
        )

        return {"control_code": control_code, "version": version, "status": "pending_approval"}

    def approve(self, control_code: str, version: int, approver_email: str) -> dict:
        """
        Одобряет версию политики (pending_approval → approved).
        Создаёт evidence в Evidence Tracker.
        Возвращает: {"control_code", "version", "status", "evidence_id"} или {"error": ...}
        """
        data = self._load()
        version_record = self._find_version(data, control_code, version)

        if version_record is None:
            return {"error": f"version {version} not found for control {control_code}"}

        if version_record["status"] != "pending_approval":
            return {"error": "only pending_approval versions can be approved"}

        now = datetime.now(timezone.utc).isoformat()
        version_record["status"] = "approved"
        version_record["approved_by"] = approver_email
        version_record["approved_at"] = now

        self._save(data)

        # Создаём evidence в Evidence Tracker
        evidence_id = None
        try:
            title = f"[APPROVED v{version}] {version_record['title']}"
            evidence_result = self.evidence_client.create_evidence(
                control_id=control_code,
                title=title,
                content=json.dumps(version_record, ensure_ascii=False),
                source="MANUAL",
            )
            evidence_id = evidence_result.get("id")
            log.info(
                "Evidence created for approved policy",
                extra={"control_code": control_code, "version": version, "evidence_id": evidence_id},
            )
        except Exception as e:
            log.error(
                "Failed to create evidence for approved policy",
                extra={"control_code": control_code, "version": version, "error": str(e)},
            )

        return {
            "control_code": control_code,
            "version": version,
            "status": "approved",
            "evidence_id": evidence_id,
        }

    def reject(self, control_code: str, version: int, reviewer_email: str, reason: str) -> dict:
        """
        Отклоняет версию политики (pending_approval → rejected).
        Добавляет причину отклонения в запись.
        Возвращает: {"control_code", "version", "status", "reason"} или {"error": ...}
        """
        data = self._load()
        version_record = self._find_version(data, control_code, version)

        if version_record is None:
            return {"error": f"version {version} not found for control {control_code}"}

        if version_record["status"] != "pending_approval":
            return {"error": "only pending_approval versions can be rejected"}

        version_record["status"] = "rejected"
        version_record["rejection_reason"] = reason
        version_record["rejected_by"] = reviewer_email
        version_record["rejected_at"] = datetime.now(timezone.utc).isoformat()

        self._save(data)

        log.info(
            "Policy rejected",
            extra={"control_code": control_code, "version": version, "reviewer": reviewer_email},
        )

        return {
            "control_code": control_code,
            "version": version,
            "status": "rejected",
            "reason": reason,
        }

    def get_history(self, control_code: str) -> list:
        """
        Возвращает все версии политики для контроля,
        отсортированные по номеру версии (убывание).
        """
        data = self._load()
        policy = data["policies"].get(control_code)
        if not policy:
            return []
        return sorted(policy["versions"], key=lambda v: v["version"], reverse=True)

    def get_pending(self) -> list:
        """
        Возвращает все версии со статусом pending_approval по всем контролям.
        """
        data = self._load()
        pending = []
        for control_code, policy in data["policies"].items():
            for version_record in policy["versions"]:
                if version_record["status"] == "pending_approval":
                    pending.append({"control_code": control_code, **version_record})
        return pending

    # ── Вспомогательные ───────────────────────────────────────────────────────

    def _find_version(self, data: dict, control_code: str, version: int) -> Optional[dict]:
        """Находит запись версии по control_code и номеру версии (по ссылке для мутации)."""
        policy = data["policies"].get(control_code)
        if not policy:
            return None
        for record in policy["versions"]:
            if record["version"] == version:
                return record
        return None
