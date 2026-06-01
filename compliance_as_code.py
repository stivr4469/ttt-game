"""
compliance_as_code.py — движок Compliance-as-Code.

Загружает YAML-декларации контролей, выполняет проверки через boto3/LocalStack,
управляет очередью ремедиаций с approval workflow.
"""

import os
import subprocess
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
import boto3
import botocore.exceptions
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------

AWS_ENDPOINT_URL: str = os.getenv("AWS_ENDPOINT_URL", os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566"))
AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID", "test")
AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "test")
AWS_DEFAULT_REGION: str = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

_REQUIRED_FIELDS = {"control_id", "name", "framework", "severity", "check", "remediation", "sla_hours"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_CHECK_TYPES = {"aws_iam", "aws_s3", "aws_cloudtrail", "mock", "script"}
_VALID_REMEDIATION_TYPES = {"script", "manual"}
_VALID_REMEDIATION_STATUSES = {"pending_approval", "executed", "skipped", "not_needed", "failed"}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CaCControl:
    control_id: str
    name: str
    framework: str
    severity: str          # critical | high | medium | low
    check: dict            # type, condition, target, [mock_result, mock_detail]
    remediation: dict      # type, command, requires_approval, approver_role
    sla_hours: int
    tags: list[str] = field(default_factory=list)


@dataclass
class CaCCheckResult:
    control_id: str
    passed: bool
    detail: str
    checked_at: str
    remediation_triggered: bool
    remediation_status: str  # pending_approval | executed | skipped | not_needed | failed

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "passed": self.passed,
            "detail": self.detail,
            "checked_at": self.checked_at,
            "remediation_triggered": self.remediation_triggered,
            "remediation_status": self.remediation_status,
        }


# ---------------------------------------------------------------------------
# Вспомогательные функции для boto3
# ---------------------------------------------------------------------------

def _boto3_client(service: str) -> Any:
    return boto3.client(
        service,
        endpoint_url=AWS_ENDPOINT_URL,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_DEFAULT_REGION,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Движок
# ---------------------------------------------------------------------------

class ComplianceAsCodeEngine:
    """Движок Compliance-as-Code: загрузка YAML, проверки, ремедиации."""

    def __init__(self, controls_dir: str = "cac_controls/") -> None:
        self._controls_dir = Path(controls_dir)
        self._controls: dict[str, CaCControl] = {}
        # control_id → pending approval record
        self._pending_approvals: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Загрузка контролей
    # ------------------------------------------------------------------

    def load_controls(self, directory: str | None = None) -> list[CaCControl]:
        """Загрузить все YAML-контроли из директории."""
        target = Path(directory) if directory else self._controls_dir
        if not target.exists():
            log.warning("CaC controls directory not found: %s", target)
            return []

        loaded: list[CaCControl] = []
        for yaml_file in sorted(target.glob("*.yaml")):
            try:
                with open(yaml_file, encoding="utf-8") as fh:
                    raw = yaml.safe_load(fh)
                if not isinstance(raw, dict):
                    log.warning("Skipping %s: не является dict", yaml_file.name)
                    continue
                errors = self.validate_yaml(raw)
                if errors:
                    log.warning("Validation errors in %s: %s", yaml_file.name, errors)
                    continue
                control = self.load_control_from_dict(raw)
                self._controls[control.control_id] = control
                loaded.append(control)
                log.debug("Loaded control: %s", control.control_id)
            except yaml.YAMLError as exc:
                log.error("YAML parse error in %s: %s", yaml_file.name, exc)
            except Exception as exc:
                log.error("Failed to load %s: %s", yaml_file.name, exc)

        log.info("Loaded %d CaC controls from %s", len(loaded), target)
        return loaded

    def load_control_from_dict(self, data: dict) -> CaCControl:
        """Создать CaCControl из словаря (уже провалидированного)."""
        return CaCControl(
            control_id=str(data["control_id"]),
            name=str(data["name"]),
            framework=str(data["framework"]),
            severity=str(data["severity"]).lower(),
            check=dict(data["check"]),
            remediation=dict(data["remediation"]),
            sla_hours=int(data["sla_hours"]),
            tags=list(data.get("tags") or []),
        )

    def validate_yaml(self, data: dict) -> list[str]:
        """Проверить структуру YAML-декларации. Возвращает список ошибок."""
        errors: list[str] = []

        # Обязательные поля
        for f in _REQUIRED_FIELDS:
            if f not in data:
                errors.append(f"Отсутствует обязательное поле: {f}")

        if errors:
            return errors  # не продолжаем, остальные проверки упадут

        # Severity
        severity = str(data.get("severity", "")).lower()
        if severity not in _VALID_SEVERITIES:
            errors.append(f"Недопустимое severity '{severity}'. Допустимые: {_VALID_SEVERITIES}")

        # sla_hours
        try:
            sla = int(data["sla_hours"])
            if sla <= 0:
                errors.append("sla_hours должен быть положительным числом")
        except (ValueError, TypeError):
            errors.append("sla_hours должен быть целым числом")

        # check
        check = data.get("check")
        if not isinstance(check, dict):
            errors.append("check должен быть словарём")
        else:
            check_type = check.get("type", "")
            if check_type not in _VALID_CHECK_TYPES:
                errors.append(f"Недопустимый check.type '{check_type}'. Допустимые: {_VALID_CHECK_TYPES}")
            if not check.get("target"):
                errors.append("check.target обязателен")

        # remediation
        rem = data.get("remediation")
        if not isinstance(rem, dict):
            errors.append("remediation должен быть словарём")
        else:
            rem_type = rem.get("type", "")
            if rem_type not in _VALID_REMEDIATION_TYPES:
                errors.append(f"Недопустимый remediation.type '{rem_type}'. Допустимые: {_VALID_REMEDIATION_TYPES}")
            if rem_type == "script" and not rem.get("command"):
                errors.append("remediation.command обязателен для type=script")
            if "requires_approval" not in rem:
                errors.append("remediation.requires_approval обязателен")

        return errors

    # ------------------------------------------------------------------
    # Геттеры
    # ------------------------------------------------------------------

    def get_control(self, control_id: str) -> CaCControl | None:
        """Вернуть контроль по ID (lazy load при необходимости)."""
        if not self._controls:
            self.load_controls()
        return self._controls.get(control_id)

    def all_controls(self) -> list[CaCControl]:
        """Список всех загруженных контролей."""
        if not self._controls:
            self.load_controls()
        return list(self._controls.values())

    # ------------------------------------------------------------------
    # Проверки
    # ------------------------------------------------------------------

    def run_check(self, control: CaCControl) -> CaCCheckResult:
        """Запустить одну проверку контроля."""
        check_type = control.check.get("type", "")
        try:
            if check_type == "mock":
                return self._check_mock(control)
            elif check_type == "aws_iam":
                return self._check_aws_iam(control)
            elif check_type == "aws_s3":
                return self._check_aws_s3(control)
            elif check_type == "aws_cloudtrail":
                return self._check_aws_cloudtrail(control)
            elif check_type == "script":
                return CaCCheckResult(
                    control_id=control.control_id,
                    passed=False,
                    detail="check.type=script нельзя использовать как проверку, только как remediation",
                    checked_at=_now_iso(),
                    remediation_triggered=False,
                    remediation_status="not_needed",
                )
            else:
                return CaCCheckResult(
                    control_id=control.control_id,
                    passed=False,
                    detail=f"Неизвестный check.type: {check_type}",
                    checked_at=_now_iso(),
                    remediation_triggered=False,
                    remediation_status="not_needed",
                )
        except Exception as exc:
            log.exception("Ошибка при проверке %s", control.control_id)
            return CaCCheckResult(
                control_id=control.control_id,
                passed=False,
                detail=f"Исключение при проверке: {exc}",
                checked_at=_now_iso(),
                remediation_triggered=False,
                remediation_status="not_needed",
            )

    def run_all(self) -> list[CaCCheckResult]:
        """Запустить проверки всех загруженных контролей."""
        controls = self.all_controls()
        return [self.run_check(c) for c in controls]

    # ------------------------------------------------------------------
    # Конкретные check-хендлеры
    # ------------------------------------------------------------------

    def _check_mock(self, control: CaCControl) -> CaCCheckResult:
        """Mock-проверка: возвращает configurable результат из YAML."""
        mock_result = bool(control.check.get("mock_result", True))
        mock_detail = str(control.check.get("mock_detail", "Mock check"))
        return CaCCheckResult(
            control_id=control.control_id,
            passed=mock_result,
            detail=mock_detail,
            checked_at=_now_iso(),
            remediation_triggered=False,
            remediation_status="not_needed",
        )

    def _check_aws_iam(self, control: CaCControl) -> CaCCheckResult:
        """Проверка IAM через boto3/LocalStack."""
        condition = control.check.get("condition", "")
        target = control.check.get("target", "")

        try:
            iam = _boto3_client("iam")

            if "mfa_enabled" in condition and target == "all_users":
                return self._iam_check_mfa(control, iam)
            elif "admin_count" in condition:
                return self._iam_check_admin_count(control, iam, condition)
            else:
                return CaCCheckResult(
                    control_id=control.control_id,
                    passed=False,
                    detail=f"Неизвестное IAM condition: {condition}",
                    checked_at=_now_iso(),
                    remediation_triggered=False,
                    remediation_status="not_needed",
                )
        except botocore.exceptions.ClientError as exc:
            err_msg = exc.response["Error"].get("Message", str(exc))
            return CaCCheckResult(
                control_id=control.control_id,
                passed=False,
                detail=f"AWS IAM API ошибка: {err_msg}",
                checked_at=_now_iso(),
                remediation_triggered=False,
                remediation_status="not_needed",
            )
        except botocore.exceptions.EndpointConnectionError:
            return CaCCheckResult(
                control_id=control.control_id,
                passed=False,
                detail=f"Нет подключения к AWS endpoint: {AWS_ENDPOINT_URL}",
                checked_at=_now_iso(),
                remediation_triggered=False,
                remediation_status="not_needed",
            )

    def _iam_check_mfa(self, control: CaCControl, iam: Any) -> CaCCheckResult:
        """Проверить наличие MFA у всех IAM-пользователей."""
        users_resp = iam.list_users()
        users = users_resp.get("Users", [])

        if not users:
            return CaCCheckResult(
                control_id=control.control_id,
                passed=True,
                detail="Нет IAM-пользователей для проверки MFA",
                checked_at=_now_iso(),
                remediation_triggered=False,
                remediation_status="not_needed",
            )

        users_without_mfa: list[str] = []
        for user in users:
            username = user["UserName"]
            mfa_resp = iam.list_mfa_devices(UserName=username)
            if not mfa_resp.get("MFADevices"):
                users_without_mfa.append(username)

        passed = len(users_without_mfa) == 0
        detail = (
            "Все IAM-пользователи имеют MFA"
            if passed
            else f"Пользователи без MFA ({len(users_without_mfa)}): {', '.join(users_without_mfa)}"
        )
        return CaCCheckResult(
            control_id=control.control_id,
            passed=passed,
            detail=detail,
            checked_at=_now_iso(),
            remediation_triggered=False,
            remediation_status="not_needed",
        )

    def _iam_check_admin_count(self, control: CaCControl, iam: Any, condition: str) -> CaCCheckResult:
        """Проверить количество пользователей с AdministratorAccess."""
        try:
            max_admins = int(condition.split("<=")[1].strip()) if "<=" in condition else 2
        except (IndexError, ValueError):
            max_admins = 2

        # Найти пользователей с AdministratorAccess политикой
        admin_users: list[str] = []
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    attached = iam.list_attached_user_policies(UserName=username)
                    for policy in attached.get("AttachedPolicies", []):
                        if "Administrator" in policy.get("PolicyName", ""):
                            admin_users.append(username)
                            break
        except Exception as exc:
            return CaCCheckResult(
                control_id=control.control_id,
                passed=False,
                detail=f"Ошибка при проверке admin-пользователей: {exc}",
                checked_at=_now_iso(),
                remediation_triggered=False,
                remediation_status="not_needed",
            )

        passed = len(admin_users) <= max_admins
        detail = (
            f"Admin-пользователей: {len(admin_users)} (лимит: {max_admins})"
            if passed
            else f"Превышен лимит admin-пользователей: {len(admin_users)} > {max_admins}: {', '.join(admin_users)}"
        )
        return CaCCheckResult(
            control_id=control.control_id,
            passed=passed,
            detail=detail,
            checked_at=_now_iso(),
            remediation_triggered=False,
            remediation_status="not_needed",
        )

    def _check_aws_s3(self, control: CaCControl) -> CaCCheckResult:
        """Проверка S3 шифрования через boto3/LocalStack."""
        condition = control.check.get("condition", "")
        try:
            s3 = _boto3_client("s3")
            buckets_resp = s3.list_buckets()
            buckets = buckets_resp.get("Buckets", [])

            if not buckets:
                return CaCCheckResult(
                    control_id=control.control_id,
                    passed=True,
                    detail="Нет S3 бакетов для проверки",
                    checked_at=_now_iso(),
                    remediation_triggered=False,
                    remediation_status="not_needed",
                )

            unencrypted: list[str] = []
            for bucket in buckets:
                name = bucket["Name"]
                try:
                    s3.get_bucket_encryption(Bucket=name)
                except botocore.exceptions.ClientError as exc:
                    err_code = exc.response["Error"]["Code"]
                    if err_code == "ServerSideEncryptionConfigurationNotFoundError":
                        unencrypted.append(name)
                    # Другие ошибки игнорируем (NoSuchBucket и т.д.)

            passed = len(unencrypted) == 0
            detail = (
                f"Все {len(buckets)} бакетов имеют шифрование at-rest"
                if passed
                else f"Бакеты без шифрования ({len(unencrypted)}): {', '.join(unencrypted)}"
            )
            return CaCCheckResult(
                control_id=control.control_id,
                passed=passed,
                detail=detail,
                checked_at=_now_iso(),
                remediation_triggered=False,
                remediation_status="not_needed",
            )
        except botocore.exceptions.EndpointConnectionError:
            return CaCCheckResult(
                control_id=control.control_id,
                passed=False,
                detail=f"Нет подключения к AWS endpoint: {AWS_ENDPOINT_URL}",
                checked_at=_now_iso(),
                remediation_triggered=False,
                remediation_status="not_needed",
            )

    def _check_aws_cloudtrail(self, control: CaCControl) -> CaCCheckResult:
        """Проверка CloudTrail через boto3/LocalStack."""
        try:
            ct = _boto3_client("cloudtrail")
            trails_resp = ct.describe_trails(includeShadowTrails=False)
            trails = trails_resp.get("trailList", [])

            if not trails:
                return CaCCheckResult(
                    control_id=control.control_id,
                    passed=False,
                    detail="CloudTrail: нет трейлов — логирование не настроено",
                    checked_at=_now_iso(),
                    remediation_triggered=False,
                    remediation_status="not_needed",
                )

            # Проверить что хотя бы один трейл активен (logging enabled)
            active_trails: list[str] = []
            for trail in trails:
                trail_name = trail.get("Name", "unknown")
                try:
                    status = ct.get_trail_status(Name=trail_name)
                    if status.get("IsLogging"):
                        active_trails.append(trail_name)
                except Exception:
                    pass

            passed = len(active_trails) > 0
            detail = (
                f"CloudTrail активен: {', '.join(active_trails)}"
                if passed
                else f"CloudTrail трейлы найдены ({len(trails)}), но ни один не активен"
            )
            return CaCCheckResult(
                control_id=control.control_id,
                passed=passed,
                detail=detail,
                checked_at=_now_iso(),
                remediation_triggered=False,
                remediation_status="not_needed",
            )
        except botocore.exceptions.EndpointConnectionError:
            return CaCCheckResult(
                control_id=control.control_id,
                passed=False,
                detail=f"Нет подключения к AWS endpoint: {AWS_ENDPOINT_URL}",
                checked_at=_now_iso(),
                remediation_triggered=False,
                remediation_status="not_needed",
            )

    # ------------------------------------------------------------------
    # Ремедиация
    # ------------------------------------------------------------------

    def trigger_remediation(self, control: CaCControl, approved_by: str) -> dict:
        """
        Запустить ремедиацию для контроля.

        - requires_approval=false → выполнить сразу через subprocess
        - requires_approval=true  → добавить в _pending_approvals
        """
        rem = control.remediation
        rem_type = rem.get("type", "manual")

        if rem_type != "script":
            return {
                "control_id": control.control_id,
                "status": "skipped",
                "detail": f"Тип ремедиации '{rem_type}' не поддерживает автоматическое выполнение",
            }

        requires_approval = bool(rem.get("requires_approval", True))

        if requires_approval:
            # Добавить в очередь ожидания (команду не раскрываем — только метаданные)
            pending_record = {
                "control_id": control.control_id,
                "control_name": control.name,
                "approver_role": rem.get("approver_role", "admin"),
                "requested_by": approved_by,
                "requested_at": _now_iso(),
                "status": "pending_approval",
            }
            self._pending_approvals[control.control_id] = pending_record
            log.info("Ремедиация %s добавлена в очередь ожидания approve", control.control_id)
            return {
                "control_id": control.control_id,
                "status": "pending_approval",
                "detail": f"Ремедиация ожидает подтверждения роли '{rem.get('approver_role', 'admin')}'",
                "requested_by": approved_by,
            }

        # Выполнить без approve
        return self._execute_remediation_command(control, triggered_by=approved_by)

    def approve_remediation(self, control_id: str, approver: str) -> dict:
        """Подтвердить pending ремедиацию и выполнить команду."""
        pending = self._pending_approvals.get(control_id)
        if not pending:
            return {
                "control_id": control_id,
                "status": "not_found",
                "detail": "Нет ожидающей ремедиации для этого контроля",
            }

        control = self.get_control(control_id)
        if not control:
            return {
                "control_id": control_id,
                "status": "error",
                "detail": "Контроль не найден в реестре",
            }

        # Удалить из pending до выполнения
        del self._pending_approvals[control_id]

        result = self._execute_remediation_command(control, triggered_by=approver)
        result["approved_by"] = approver
        return result

    def _execute_remediation_command(self, control: CaCControl, triggered_by: str) -> dict:
        """Выполнить команду ремедиации через изолированную песочницу (cac_sandbox)."""
        command = control.remediation.get("command", "")
        if not command:
            return {
                "control_id": control.control_id,
                "status": "error",
                "detail": "Команда ремедиации не задана",
            }

        log.info("Выполнение ремедиации %s: %s (triggered_by=%s)", control.control_id, command, triggered_by)
        try:
            from cac_sandbox import run_command
            import asyncio

            loop = asyncio.new_event_loop()
            try:
                sandbox_result = loop.run_until_complete(run_command(command, dry_run=False))
            finally:
                loop.close()

            success = sandbox_result.success and sandbox_result.exit_code == 0
            status = "executed" if success else "failed"
            detail = sandbox_result.stdout.strip() or sandbox_result.stderr.strip() or "Команда выполнена без вывода"
            log.info("Ремедиация %s: %s (exit_code=%d, duration=%dms)",
                     control.control_id, status, sandbox_result.exit_code, sandbox_result.duration_ms)
            return {
                "control_id": control.control_id,
                "status": status,
                "exit_code": sandbox_result.exit_code,
                "stdout": sandbox_result.stdout.strip(),
                "stderr": sandbox_result.stderr.strip(),
                "detail": detail,
                "triggered_by": triggered_by,
                "executed_at": _now_iso(),
            }
        except Exception as exc:
            log.error("Ремедиация %s: ошибка выполнения: %s", control.control_id, exc, exc_info=True)
            return {
                "control_id": control.control_id,
                "status": "failed",
                "detail": f"Ошибка выполнения: {exc}",
                "triggered_by": triggered_by,
                "executed_at": _now_iso(),
            }

    def get_pending_approvals(self) -> list[dict]:
        """Список ожидающих подтверждения ремедиаций."""
        return list(self._pending_approvals.values())

    # ------------------------------------------------------------------
    # Вспомогательные
    # ------------------------------------------------------------------

    def add_control_from_yaml_bytes(self, content: bytes, filename: str) -> tuple[CaCControl | None, list[str]]:
        """
        Разобрать YAML из bytes, провалидировать и добавить в реестр.
        Возвращает (control, errors). Если errors непустой — контроль не добавлен.
        """
        try:
            raw = yaml.safe_load(content.decode("utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            return None, [f"Ошибка парсинга YAML: {exc}"]

        if not isinstance(raw, dict):
            return None, ["YAML должен быть словарём (mapping)"]

        errors = self.validate_yaml(raw)
        if errors:
            return None, errors

        control = self.load_control_from_dict(raw)
        self._controls[control.control_id] = control

        # Сохранить на диск — sanitize filename для предотвращения path traversal
        safe_control_id = "".join(c if c.isalnum() or c in "_-." else "_" for c in control.control_id)
        safe_filename = "".join(c if c.isalnum() or c in "_-." else "_" for c in Path(filename).name)
        dest = self._controls_dir / f"{safe_control_id.lower()}_{safe_filename}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)

        return control, []

    def validate_all_files(self) -> dict[str, list[str]]:
        """
        Проверить синтаксис всех YAML-файлов в директории.
        Возвращает {filename: [errors]} — пустой список = файл валидный.
        """
        results: dict[str, list[str]] = {}
        if not self._controls_dir.exists():
            return results

        for yaml_file in sorted(self._controls_dir.glob("*.yaml")):
            try:
                with open(yaml_file, encoding="utf-8") as fh:
                    raw = yaml.safe_load(fh)
                if not isinstance(raw, dict):
                    results[yaml_file.name] = ["Не является YAML-словарём"]
                else:
                    results[yaml_file.name] = self.validate_yaml(raw)
            except yaml.YAMLError as exc:
                results[yaml_file.name] = [f"YAML parse error: {exc}"]
            except Exception as exc:
                results[yaml_file.name] = [f"Ошибка чтения: {exc}"]

        return results
