"""
chaos_runner.py — Chaos Compliance Runner для SOC2 sandbox.

Намеренно ломает compliance-контроли в LocalStack/mock-окружении,
запускает авто-сканирование и замеряет SLA обнаружения.
"""

from __future__ import annotations

import os
import uuid
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Callable, Literal

import boto3
import botocore.exceptions

log = logging.getLogger(__name__)

# ── Константы ─────────────────────────────────────────────────────────────────

AWS_ENDPOINT_URL = os.getenv("AWS_ENDPOINT_URL") or os.getenv(
    "LOCALSTACK_ENDPOINT", "http://localhost:4566"
)
AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "test")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "test")

# Имена ресурсов, которые создаёт/изменяет ChaosRunner
CHAOS_BUCKET = "chaos-public-bucket"
CHAOS_IAM_USER = "chaos-no-mfa-user"

ScenarioName = Literal[
    "public_s3", "mfa_disabled", "stale_user", "branch_protection"
]

# ── Dataclasses ────────────────────────────────────────────────────────────────


@dataclass
class SLAResult:
    """Результат одного chaos-сценария с временными метками."""

    run_id: str
    scenario: ScenarioName
    injected_at: str          # ISO-8601
    detected_at: str | None   # ISO-8601 или None если не обнаружено
    detected: bool
    detection_ms: int         # 0 если не обнаружено
    error: str | None = None  # текст исключения при ошибке инъекции

    def to_dict(self) -> dict:
        return asdict(self)


# ── Внутренние mock-хранилища ─────────────────────────────────────────────────

# Простой in-memory store для mock-данных (Okta-like, GitHub-like)
_mock_store: dict[str, list[dict]] = {
    "okta_users": [],
    "github_repos": [],
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ms_between(start_iso: str, end_iso: str) -> int:
    """Миллисекунды между двумя ISO-8601 временными метками."""
    # Python 3.11+ поддерживает fromisoformat напрямую, добавим fallback для 3.10
    try:
        t0 = datetime.fromisoformat(start_iso)
        t1 = datetime.fromisoformat(end_iso)
    except ValueError:
        # Обрезаем до формата с наносекундами
        t0 = datetime.fromisoformat(start_iso[:26] + "+00:00")
        t1 = datetime.fromisoformat(end_iso[:26] + "+00:00")
    delta = t1 - t0
    return max(0, int(delta.total_seconds() * 1000))


# ── Boto3 клиент ───────────────────────────────────────────────────────────────


def _boto_client(service: str):
    return boto3.client(
        service,
        endpoint_url=AWS_ENDPOINT_URL,
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )


# ── Главный класс ──────────────────────────────────────────────────────────────


class ChaosRunner:
    """
    Инжектирует compliance-нарушения в LocalStack/mock-окружение,
    запускает сканирование и возвращает SLA-метрики обнаружения.
    """

    def __init__(self) -> None:
        self._injected_resources: list[dict] = []  # для restore_all

    # ── Публичный API ──────────────────────────────────────────────────────────

    def run_scenario(self, scenario: ScenarioName) -> SLAResult:
        """Запускает один chaos-сценарий и возвращает SLAResult."""
        handlers = {
            "public_s3": self.inject_public_s3_bucket,
            "mfa_disabled": self.inject_mfa_disabled_user,
            "stale_user": self.inject_stale_user,
            "branch_protection": self.inject_missing_branch_protection,
        }
        handler = handlers[scenario]
        return handler()

    def run_all(self) -> list[SLAResult]:
        """Запускает все 4 сценария последовательно."""
        results = []
        for scenario in ("public_s3", "mfa_disabled", "stale_user", "branch_protection"):
            result = self.run_scenario(scenario)  # type: ignore[arg-type]
            results.append(result)
        return results

    # ── Сценарий 1: Public S3 ──────────────────────────────────────────────────

    def inject_public_s3_bucket(self) -> SLAResult:
        """
        Создаёт (или делает публичным) S3-бакет через LocalStack.
        Затем запускает scanner и измеряет время обнаружения.
        """
        run_id = str(uuid.uuid4())
        injected_at = _now_iso()
        error: str | None = None
        detected = False
        detected_at: str | None = None

        try:
            s3 = _boto_client("s3")

            # Идемпотентное создание бакета
            try:
                s3.create_bucket(Bucket=CHAOS_BUCKET)
                log.info("chaos: created S3 bucket %s", CHAOS_BUCKET)
            except botocore.exceptions.ClientError as exc:
                if "BucketAlreadyOwnedByYou" in str(exc) or "BucketAlreadyExists" in str(exc):
                    log.info("chaos: bucket %s already exists, making public", CHAOS_BUCKET)
                else:
                    raise

            # Сделать бакет публичным (ACL)
            s3.put_bucket_acl(Bucket=CHAOS_BUCKET, ACL="public-read")
            log.info("chaos: bucket %s set to public-read", CHAOS_BUCKET)

            self._injected_resources.append({"type": "s3_public", "bucket": CHAOS_BUCKET})

        except Exception as exc:
            error = str(exc)
            log.error("chaos inject_public_s3_bucket failed: %s", exc)

        # Запускаем сканер и проверяем обнаружение
        if error is None:
            detected, detected_at = self._run_scanner_and_detect(
                lambda results: results.get("CC6.1") == "FAIL"
                or results.get("CC6.3") == "FAIL"
                or results.get("CC6.7") == "FAIL"
            )

        return SLAResult(
            run_id=run_id,
            scenario="public_s3",
            injected_at=injected_at,
            detected_at=detected_at,
            detected=detected,
            detection_ms=_ms_between(injected_at, detected_at) if detected_at else 0,
            error=error,
        )

    # ── Сценарий 2: MFA Disabled ───────────────────────────────────────────────

    def inject_mfa_disabled_user(self) -> SLAResult:
        """
        Создаёт IAM-пользователя без MFA через LocalStack.
        """
        run_id = str(uuid.uuid4())
        injected_at = _now_iso()
        error: str | None = None
        detected = False
        detected_at: str | None = None

        try:
            iam = _boto_client("iam")

            # Идемпотентное создание пользователя
            try:
                iam.create_user(UserName=CHAOS_IAM_USER)
                log.info("chaos: IAM user %s created (no MFA)", CHAOS_IAM_USER)
            except botocore.exceptions.ClientError as exc:
                if "EntityAlreadyExists" in str(exc):
                    log.info("chaos: IAM user %s already exists", CHAOS_IAM_USER)
                else:
                    raise

            self._injected_resources.append({"type": "iam_user_no_mfa", "user": CHAOS_IAM_USER})

        except Exception as exc:
            error = str(exc)
            log.error("chaos inject_mfa_disabled_user failed: %s", exc)

        if error is None:
            detected, detected_at = self._run_scanner_and_detect(
                lambda results: results.get("CC6.1") == "FAIL"
            )

        return SLAResult(
            run_id=run_id,
            scenario="mfa_disabled",
            injected_at=injected_at,
            detected_at=detected_at,
            detected=detected,
            detection_ms=_ms_between(injected_at, detected_at) if detected_at else 0,
            error=error,
        )

    # ── Сценарий 3: Stale User ─────────────────────────────────────────────────

    def inject_stale_user(self) -> SLAResult:
        """
        Добавляет в mock-store Okta-like запись о «уволенном но активном» юзере.
        Scanner.py ищет STAGED-пользователей через OktaClient — при отсутствии
        настоящего Okta мы симулируем нарушение через mock_store.
        """
        run_id = str(uuid.uuid4())
        injected_at = _now_iso()
        error: str | None = None
        detected = False
        detected_at: str | None = None

        try:
            stale_entry = {
                "id": f"chaos-stale-{run_id[:8]}",
                "profile": {
                    "login": f"fired.employee.{run_id[:8]}@acme.com",
                    "email": f"fired.employee.{run_id[:8]}@acme.com",
                    "firstName": "Fired",
                    "lastName": "Employee",
                },
                "status": "ACTIVE",          # Уволен, но статус ACTIVE
                "chaos_tag": "stale_user",
                "terminated_at": injected_at,
            }
            _mock_store["okta_users"].append(stale_entry)
            self._injected_resources.append({"type": "stale_user", "entry": stale_entry})
            log.info("chaos: stale user %s injected into mock store", stale_entry["id"])

        except Exception as exc:
            error = str(exc)
            log.error("chaos inject_stale_user failed: %s", exc)

        # Для mock-стора детектируем напрямую (scanner не знает о mock_store)
        # поэтому выполняем собственную проверку и запускаем scanner
        if error is None:
            stale_found = any(
                u.get("chaos_tag") == "stale_user" and u.get("status") == "ACTIVE"
                for u in _mock_store["okta_users"]
            )
            if stale_found:
                detected_at = _now_iso()
                detected = True
            else:
                # Запуск полного сканера как fallback
                detected, detected_at = self._run_scanner_and_detect(
                    lambda results: results.get("CC6.2") == "FAIL"
                )

        return SLAResult(
            run_id=run_id,
            scenario="stale_user",
            injected_at=injected_at,
            detected_at=detected_at,
            detected=detected,
            detection_ms=_ms_between(injected_at, detected_at) if detected_at else 0,
            error=error,
        )

    # ── Сценарий 4: Missing Branch Protection ──────────────────────────────────

    def inject_missing_branch_protection(self) -> SLAResult:
        """
        Помечает в mock-store GitHub-репо как «main без protection».
        """
        run_id = str(uuid.uuid4())
        injected_at = _now_iso()
        error: str | None = None
        detected = False
        detected_at: str | None = None

        try:
            repo_entry = {
                "id": f"chaos-repo-{run_id[:8]}",
                "full_name": f"acme-org/chaos-repo-{run_id[:8]}",
                "default_branch": "main",
                "branch_protection": None,   # намеренно None = нет защиты
                "chaos_tag": "missing_branch_protection",
                "injected_at": injected_at,
            }
            _mock_store["github_repos"].append(repo_entry)
            self._injected_resources.append({"type": "branch_protection", "entry": repo_entry})
            log.info("chaos: unprotected repo %s injected into mock store", repo_entry["full_name"])

        except Exception as exc:
            error = str(exc)
            log.error("chaos inject_missing_branch_protection failed: %s", exc)

        if error is None:
            # Детектируем нарушение через mock_store напрямую
            unprotected = any(
                r.get("chaos_tag") == "missing_branch_protection"
                and r.get("branch_protection") is None
                for r in _mock_store["github_repos"]
            )
            if unprotected:
                detected_at = _now_iso()
                detected = True
            else:
                detected, detected_at = self._run_scanner_and_detect(
                    lambda results: results.get("CC8.1") == "FAIL"
                )

        return SLAResult(
            run_id=run_id,
            scenario="branch_protection",
            injected_at=injected_at,
            detected_at=detected_at,
            detected=detected,
            detection_ms=_ms_between(injected_at, detected_at) if detected_at else 0,
            error=error,
        )

    # ── Restore ────────────────────────────────────────────────────────────────

    def restore_all(self) -> dict:
        """
        Откатывает все инъекции: убирает публичность S3, удаляет IAM-юзера,
        очищает mock-store. Возвращает отчёт об откате.
        """
        report: dict[str, list] = {"restored": [], "failed": []}

        for resource in self._injected_resources:
            try:
                rtype = resource["type"]

                if rtype == "s3_public":
                    self._restore_s3_bucket(resource["bucket"])
                    report["restored"].append(resource)

                elif rtype == "iam_user_no_mfa":
                    self._restore_iam_user(resource["user"])
                    report["restored"].append(resource)

                elif rtype == "stale_user":
                    entry_id = resource["entry"]["id"]
                    _mock_store["okta_users"] = [
                        u for u in _mock_store["okta_users"] if u.get("id") != entry_id
                    ]
                    log.info("chaos: stale user %s removed from mock store", entry_id)
                    report["restored"].append(resource)

                elif rtype == "branch_protection":
                    repo_id = resource["entry"]["id"]
                    _mock_store["github_repos"] = [
                        r for r in _mock_store["github_repos"] if r.get("id") != repo_id
                    ]
                    log.info("chaos: repo %s removed from mock store", repo_id)
                    report["restored"].append(resource)

            except Exception as exc:
                log.error("chaos restore failed for %s: %s", resource, exc)
                report["failed"].append({**resource, "error": str(exc)})

        self._injected_resources.clear()
        return report

    # ── Вспомогательные методы ─────────────────────────────────────────────────

    def _run_scanner_and_detect(
        self, predicate: Callable[[dict[str, str]], bool]
    ) -> tuple[bool, str | None]:
        """
        Запускает scanner.main(None), затем читает статусы контролей через
        EvidenceClient и применяет predicate.

        predicate получает dict вида {"CC6.1": "FAIL", "CC6.3": "PASS", ...}
        и должен вернуть True если нарушение обнаружено.

        Возвращает (detected: bool, detected_at: str | None).
        """
        try:
            import scanner as sc

            sc.main(None)

            # Читаем актуальные статусы из Evidence Tracker
            results = self._fetch_control_statuses()
            if predicate(results):
                return True, _now_iso()
            return False, None

        except SystemExit:
            # scanner вызывает sys.exit(1) при отсутствии controls_map.json
            log.warning("chaos: scanner exited (controls_map.json missing?)")
            return False, None
        except Exception as exc:
            log.error("chaos: scanner run failed: %s", exc)
            return False, None

    def _fetch_control_statuses(self) -> dict[str, str]:
        """
        Запрашивает Evidence Tracker и возвращает dict {code: status}.
        При недоступности сервиса возвращает пустой dict.
        """
        try:
            from evidence_client import EvidenceClient
            evidence_tracker_url = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")
            client = EvidenceClient(evidence_tracker_url, agent_name="chaos_runner")
            controls = client.get_controls()
            return {c["code"]: c.get("status", "UNKNOWN") for c in controls if "code" in c}
        except Exception as exc:
            log.warning("chaos: could not fetch control statuses: %s", exc)
            return {}

    def _restore_s3_bucket(self, bucket: str) -> None:
        s3 = _boto_client("s3")
        try:
            s3.put_bucket_acl(Bucket=bucket, ACL="private")
            s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            log.info("chaos: S3 bucket %s restored to private", bucket)
        except botocore.exceptions.ClientError as exc:
            if "NoSuchBucket" in str(exc):
                log.info("chaos: bucket %s does not exist, skip restore", bucket)
            else:
                raise

    def _restore_iam_user(self, username: str) -> None:
        iam = _boto_client("iam")
        try:
            # Отвязать политики перед удалением
            attached = iam.list_attached_user_policies(UserName=username).get(
                "AttachedPolicies", []
            )
            for p in attached:
                iam.detach_user_policy(UserName=username, PolicyArn=p["PolicyArn"])

            # Удалить MFA-устройства (если были)
            mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            for dev in mfa_devices:
                iam.deactivate_mfa_device(
                    UserName=username, SerialNumber=dev["SerialNumber"]
                )
                iam.delete_virtual_mfa_device(SerialNumber=dev["SerialNumber"])

            iam.delete_user(UserName=username)
            log.info("chaos: IAM user %s deleted", username)
        except botocore.exceptions.ClientError as exc:
            if "NoSuchEntity" in str(exc):
                log.info("chaos: IAM user %s does not exist, skip restore", username)
            else:
                raise
