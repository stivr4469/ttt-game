"""
compliance_engine.py — Детерминированный движок соответствия.

Единственный авторитет в определении статуса контролей.
НЕ использует AI внутри себя — только детерминированная логика на основе evidence.

Архитектура:
  ComplianceEngine  ← единственный источник истины (authority)
  AIAdvisor         ← рекомендации (advisory, отдельный модуль)

Разделение строгое: deterministic path и advisory path полностью независимы.

Поддерживаемые фреймворки:
  - SOC 2: жёстко заданные _REQUIRED_EVIDENCE_TYPES (33 контрола)
  - Остальные (GDPR, NIST CSF, ISO 27001 и др.): загружаются через FrameworkLibrary;
    evaluate_control возвращает PASS при наличии любого PASS evidence, иначе NEEDS_REVIEW.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from log_config import get_logger

log = get_logger(__name__)

# ── Статусы вердикта контроля ──────────────────────────────────────────────────

class VerdictStatus(str, Enum):
    PASS         = "PASS"          # достаточно PASS-evidence, нет FAIL
    FAIL         = "FAIL"          # есть хотя бы одно FAIL-evidence
    NEEDS_REVIEW = "NEEDS_REVIEW"  # нет FAIL, но evidence недостаточно для PASS
    OUT_OF_SCOPE = "OUT_OF_SCOPE"  # контрол исключён scope-правилом тенанта


# ── Минимальный вес evidence для PASS ─────────────────────────────────────────

# Сколько уникальных типов evidence нужно для PASS по каждому контролу.
# Данные получены из спецификаций AICPA TSC и требований к evidence collection.
_REQUIRED_EVIDENCE_TYPES: dict[str, list[str]] = {
    "CC1.1": ["policy_document", "training_completion", "ethics_attestation"],
    "CC1.2": ["board_minutes", "audit_committee_charter", "ciso_report"],
    "CC1.3": ["org_chart", "role_definitions", "reporting_structure"],
    "CC1.4": ["training_completion", "competency_assessment", "job_descriptions"],
    "CC1.5": ["disciplinary_policy", "accountability_matrix", "incident_report"],
    "CC2.1": ["information_policy", "data_classification", "access_records"],
    "CC2.2": ["communication_records", "policy_acknowledgements", "training_completion"],
    "CC2.3": ["external_privacy_policy", "breach_notification_procedure", "vendor_dpa"],
    "CC3.1": ["risk_appetite_statement", "risk_register", "board_approval"],
    "CC3.2": ["risk_assessment_report", "risk_register", "remediation_tickets"],
    "CC3.3": ["fraud_risk_assessment", "whistleblower_policy", "monitoring_evidence"],
    "CC3.4": ["change_impact_assessment", "risk_reassessment", "control_update"],
    "CC4.1": ["monitoring_dashboard", "control_test_results", "audit_report"],
    "CC4.2": ["deficiency_report", "remediation_evidence", "management_response"],
    "CC5.1": ["control_inventory", "risk_mapping", "implementation_evidence"],
    "CC5.2": ["security_policy", "technical_standards", "config_evidence"],
    "CC5.3": ["change_management_policy", "pr_review_evidence", "deployment_log"],
    "CC6.1": ["access_review", "mfa_evidence", "access_provisioning_log"],
    "CC6.2": ["authentication_config", "mfa_enforcement", "login_audit"],
    "CC6.3": ["role_definitions", "rbac_config", "access_matrix"],
    "CC6.4": ["physical_access_log", "badge_audit", "facility_policy"],
    "CC6.5": ["offboarding_checklist", "access_revocation_log", "hr_notification"],
    "CC6.6": ["firewall_config", "network_diagram", "vpn_config"],
    "CC6.7": ["dlp_config", "transfer_policy", "encryption_evidence"],
    "CC6.8": ["antivirus_config", "scan_results", "edr_evidence"],
    "CC7.1": ["baseline_config", "config_management_policy", "deviation_report"],
    "CC7.2": ["siem_alerts", "monitoring_config", "alert_review"],
    "CC7.3": ["incident_classification", "security_events_log", "escalation_evidence"],
    "CC7.4": ["incident_response_plan", "incident_report", "post_mortem"],
    "CC7.5": ["root_cause_analysis", "remediation_evidence", "lessons_learned"],
    "CC8.1": ["change_log", "change_approval", "test_evidence"],
    "CC9.1": ["bcp_document", "rto_rpo_evidence", "bcp_test_results"],
    "CC9.2": ["vendor_assessments", "vendor_contracts", "dpa_evidence"],
    "A1.1":  ["availability_policy", "sla_evidence", "capacity_plan"],
    "A1.2":  ["capacity_monitoring", "performance_metrics", "scaling_evidence"],
    "A1.3":  ["recovery_test_results", "backup_verification", "rto_evidence"],
    "PI1.1": ["processing_integrity_policy", "data_validation_evidence", "audit_log"],
    "C1.1":  ["data_classification_policy", "confidentiality_labeling", "access_controls"],
    "C1.2":  ["retention_policy", "deletion_evidence", "data_disposal_log"],
    "P1.1":  ["privacy_notice", "consent_records", "data_subject_requests"],
}

# Веса контролей для расчёта compliance score (по критичности TSC)
_CONTROL_WEIGHTS: dict[str, float] = {
    "CC6.1": 3.0,   # Управление доступом — критично
    "CC6.2": 3.0,   # Аутентификация — критично
    "CC7.4": 3.0,   # Incident Response — критично
    "CC3.2": 2.5,   # Risk Identification
    "CC5.3": 2.5,   # Change Management
    "CC6.3": 2.0,   # Roles and Responsibilities
    "CC6.5": 2.0,   # Access Revocation
    "CC6.8": 2.0,   # Malware Prevention
    "CC7.2": 2.0,   # System Monitoring
    "CC8.1": 2.0,   # Change Management
    # Все остальные контроли — вес 1.0 (см. _get_weight)
}


# ── Dataclass вердикта ──────────────────────────────────────────────────────────

@dataclass
class ControlVerdict:
    """
    Детерминированный вердикт по контролу.

    Поле ai_suggestion заполняется ТОЛЬКО извне (через AIAdvisor),
    ComplianceEngine его никогда не устанавливает.
    """
    control_id:       str
    status:           VerdictStatus
    confidence:       float                  # 0.0–1.0
    reasons:          list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    ai_suggestion:    Optional[str] = None   # advisory — заполняется AIAdvisor

    def to_dict(self) -> dict:
        return {
            "control_id":       self.control_id,
            "status":           self.status.value,
            "confidence":       self.confidence,
            "reasons":          self.reasons,
            "missing_evidence": self.missing_evidence,
            "ai_suggestion":    self.ai_suggestion,
        }


# ── Scope rules ────────────────────────────────────────────────────────────────

@dataclass
class ScopeRuleDTO:
    """Lightweight representation of a ScopeRule used by ComplianceEngine."""
    control_pattern: str    # Python regex
    action: str             # "exclude" | "include_only"
    priority: int = 0
    reason: str = ""

    def matches(self, control_id: str) -> bool:
        try:
            return bool(re.search(self.control_pattern, control_id))
        except re.error:
            return False


class ScopeChecker:
    """
    Determines whether a control is in scope given a list of ScopeRuleDTOs.

    Algorithm:
      1. Sort rules by priority DESC.
      2. "exclude" rules: first matching exclude rule → OUT_OF_SCOPE.
      3. "include_only" rules: if any include_only rules exist, control must
         match at least one — otherwise OUT_OF_SCOPE.
      4. No rule matches → in scope.
    """

    def __init__(self, rules: list[ScopeRuleDTO]):
        self._exclude = sorted(
            [r for r in rules if r.action == "exclude"],
            key=lambda r: r.priority, reverse=True,
        )
        self._include_only = sorted(
            [r for r in rules if r.action == "include_only"],
            key=lambda r: r.priority, reverse=True,
        )

    def is_in_scope(self, control_id: str) -> tuple[bool, str]:
        """Return (in_scope, reason). reason is empty when in_scope=True."""
        for rule in self._exclude:
            if rule.matches(control_id):
                return False, rule.reason or f"Excluded by pattern {rule.control_pattern!r}"

        if self._include_only:
            for rule in self._include_only:
                if rule.matches(control_id):
                    return True, ""
            return False, "Not matched by any include_only rule"

        return True, ""

    @classmethod
    def from_db_rows(cls, rows: list) -> "ScopeChecker":
        """
        Build from SQLAlchemy ScopeRule ORM rows (or any objects with
        .control_pattern / .action / .priority / .reason attributes).
        """
        dtos = [
            ScopeRuleDTO(
                control_pattern=r.control_pattern,
                action=r.action,
                priority=r.priority,
                reason=r.reason or "",
            )
            for r in rows
            if r.is_active
        ]
        return cls(dtos)


# ── Детерминированный движок ────────────────────────────────────────────────────

class ComplianceEngine:
    """
    Единственный авторитет в определении статуса контролей SOC 2.

    Правила оценки (строго детерминированные, без AI):
      1. Если хотя бы одно evidence имеет статус FAIL → вердикт FAIL.
      2. Если все required evidence types присутствуют среди PASS-evidence → PASS.
      3. Если нет FAIL, но evidence недостаточно → NEEDS_REVIEW.

    ComplianceEngine НИКОГДА не вызывает AI.
    """

    # ── Оценка контролей ───────────────────────────────────────────────────────

    def evaluate_control(
        self,
        control_id: str,
        evidence_list: list[dict],
        framework_id: str = "soc2",
        scope_checker: Optional["ScopeChecker"] = None,
    ) -> ControlVerdict:
        """
        Детерминированная оценка контроля на основе списка evidence.

        Args:
            control_id:     код контроля ("CC6.1", "CC7.4", "ID.AM-1" ...)
            evidence_list:  список dict с ключами:
                              - status: "PASS" | "FAIL" | "PENDING" (обязательно)
                              - evidence_type: тип evidence (опционально)
                              - title: заголовок (опционально)
                              - source: источник (опционально)
            framework_id:   идентификатор фреймворка (default "soc2").
                            Для не-SOC2 фреймворков required_evidence_types не определены,
                            поэтому оценка использует упрощённую логику (есть PASS → PASS).
            scope_checker:  если передан, сначала проверяется скоп контроля.
                            Контроли вне скопа получают статус OUT_OF_SCOPE без оценки.

        Returns:
            ControlVerdict с детерминированным статусом.
        """
        if scope_checker is not None:
            in_scope, oos_reason = scope_checker.is_in_scope(control_id)
            if not in_scope:
                log.debug("Контрол %s → OUT_OF_SCOPE (%s)", control_id, oos_reason)
                return ControlVerdict(
                    control_id=control_id,
                    status=VerdictStatus.OUT_OF_SCOPE,
                    confidence=1.0,
                    reasons=[oos_reason],
                    missing_evidence=[],
                )

        reasons: list[str] = []
        missing: list[str] = []

        # ── Шаг 1: проверяем FAIL evidence ────────────────────────────────────
        fail_items = [
            ev for ev in evidence_list
            if str(ev.get("status", "")).upper() == "FAIL"
        ]
        if fail_items:
            for ev in fail_items:
                title  = ev.get("title", ev.get("id", "unknown"))
                source = ev.get("source", "")
                reasons.append(
                    f"FAIL evidence: '{title}'"
                    + (f" (source: {source})" if source else "")
                )
            log.info(
                "Контрол %s → FAIL (%d fail-evidence)",
                control_id, len(fail_items),
            )
            return ControlVerdict(
                control_id=control_id,
                status=VerdictStatus.FAIL,
                confidence=1.0,  # FAIL всегда детерминирован
                reasons=reasons,
                missing_evidence=[],
            )

        # ── Шаг 2: проверяем наличие необходимых типов evidence ───────────────
        required_types = self.get_required_evidence_types(control_id)
        present_types: set[str] = set()

        pass_items = [
            ev for ev in evidence_list
            if str(ev.get("status", "")).upper() in ("PASS", "APPROVED")
        ]

        for ev in pass_items:
            ev_type = ev.get("evidence_type", ev.get("type", ""))
            if ev_type:
                present_types.add(str(ev_type).lower())

        # Проверяем покрытие (case-insensitive)
        required_lower = [t.lower() for t in required_types]
        for req in required_lower:
            if req not in present_types:
                missing.append(req)

        # ── Шаг 3: вычисляем confidence и статус ──────────────────────────────
        if not required_types:
            # Нет спецификации — если есть хотя бы одно PASS evidence, считаем PASS
            if pass_items:
                reasons.append(f"Найдено {len(pass_items)} PASS evidence (специфических требований нет)")
                return ControlVerdict(
                    control_id=control_id,
                    status=VerdictStatus.PASS,
                    confidence=0.7,
                    reasons=reasons,
                    missing_evidence=[],
                )
            else:
                reasons.append("Нет PASS evidence и нет FAIL evidence")
                return ControlVerdict(
                    control_id=control_id,
                    status=VerdictStatus.NEEDS_REVIEW,
                    confidence=0.5,
                    reasons=reasons,
                    missing_evidence=[],
                )

        if not missing:
            # Все required types покрыты
            confidence = self._calculate_confidence(
                required_count=len(required_types),
                present_count=len(present_types),
                total_pass=len(pass_items),
            )
            reasons.append(
                f"Все {len(required_types)} требуемых типов evidence присутствуют"
            )
            if len(pass_items) > len(required_types):
                reasons.append(
                    f"Дополнительно присутствует {len(pass_items) - len(required_types)} "
                    f"evidence сверх минимума"
                )
            log.info("Контрол %s → PASS (confidence=%.2f)", control_id, confidence)
            return ControlVerdict(
                control_id=control_id,
                status=VerdictStatus.PASS,
                confidence=confidence,
                reasons=reasons,
                missing_evidence=[],
            )
        else:
            # Есть missing — NEEDS_REVIEW
            coverage = (len(required_types) - len(missing)) / len(required_types)
            confidence = round(coverage * 0.8, 2)  # max 0.8 при неполном coverage
            reasons.append(
                f"Отсутствуют {len(missing)} из {len(required_types)} required evidence types"
            )
            if pass_items:
                reasons.append(f"Найдено {len(pass_items)} PASS evidence")
            log.info(
                "Контрол %s → NEEDS_REVIEW (missing=%d, confidence=%.2f)",
                control_id, len(missing), confidence,
            )
            return ControlVerdict(
                control_id=control_id,
                status=VerdictStatus.NEEDS_REVIEW,
                confidence=confidence,
                reasons=reasons,
                missing_evidence=missing,
            )

    def evaluate_framework(
        self,
        framework_id: str,
        evidence_dict: dict[str, list[dict]],
        scope_checker: Optional["ScopeChecker"] = None,
    ) -> list[ControlVerdict]:
        """
        Оценивает все assessable контроли указанного фреймворка.

        Загружает список контролей через FrameworkLibrary, затем вызывает
        evaluate_control для каждого контроля с соответствующим evidence.

        Args:
            framework_id:   идентификатор фреймворка из FRAMEWORK_CATALOG
                            ("nist-csf-2.0", "gdpr", "iso27001-2022" ...)
            evidence_dict:  словарь {ref_id: [evidence_list]}.
                            Контроли без evidence получают пустой список.
            scope_checker:  если передан, контроли вне скопа получают
                            статус OUT_OF_SCOPE и не оцениваются по evidence.

        Returns:
            Список ControlVerdict по всем assessable контролям фреймворка
            (включая OUT_OF_SCOPE).

        Raises:
            ValueError: если framework_id не найден в FrameworkLibrary.
        """
        from framework_library import get_library

        library  = get_library()
        controls = library.get_controls(framework_id, assessable_only=True)

        verdicts: list[ControlVerdict] = []
        for ctrl in controls:
            ev_list = evidence_dict.get(ctrl.ref_id, [])
            verdict = self.evaluate_control(
                ctrl.ref_id, ev_list,
                framework_id=framework_id,
                scope_checker=scope_checker,
            )
            verdicts.append(verdict)

        log.info(
            "evaluate_framework %s: %d controls — PASS=%d FAIL=%d NEEDS_REVIEW=%d",
            framework_id,
            len(verdicts),
            sum(1 for v in verdicts if v.status == VerdictStatus.PASS),
            sum(1 for v in verdicts if v.status == VerdictStatus.FAIL),
            sum(1 for v in verdicts if v.status == VerdictStatus.NEEDS_REVIEW),
        )
        return verdicts

    def get_required_evidence_types(self, control_id: str) -> list[str]:
        """
        Возвращает список required evidence types для контроля.

        Args:
            control_id: код контроля ("CC6.1")

        Returns:
            Список строк — типы evidence. Пустой список если контроль неизвестен
            или относится к не-SOC2 фреймворку.
        """
        return list(_REQUIRED_EVIDENCE_TYPES.get(control_id, []))

    # ── Расчёт compliance score ────────────────────────────────────────────────

    def calculate_compliance_score(
        self, verdicts: list[ControlVerdict]
    ) -> float:
        """
        Вычисляет compliance score 0–100 на основе взвешенных вердиктов.

        Алгоритм:
          score = Σ(weight_i * score_i) / Σ(weight_i) * 100
          где score_i = 1.0 (PASS), 0.5 (NEEDS_REVIEW), 0.0 (FAIL)

        Args:
            verdicts: список ControlVerdict

        Returns:
            Float от 0.0 до 100.0 включительно.
        """
        if not verdicts:
            return 0.0

        # Числовые значения статусов (OUT_OF_SCOPE исключается из расчёта)
        status_scores = {
            VerdictStatus.PASS:         1.0,
            VerdictStatus.NEEDS_REVIEW: 0.5,
            VerdictStatus.FAIL:         0.0,
        }

        total_weight = 0.0
        weighted_sum = 0.0

        for verdict in verdicts:
            if verdict.status == VerdictStatus.OUT_OF_SCOPE:
                continue
            weight = self._get_weight(verdict.control_id)
            score  = status_scores.get(verdict.status, 0.0)
            weighted_sum += weight * score
            total_weight  += weight

        if total_weight == 0.0:
            return 0.0

        raw_score = (weighted_sum / total_weight) * 100.0
        return round(min(max(raw_score, 0.0), 100.0), 1)

    def calculate_compliance_score_from_evidences(
        self,
        controls_evidences: dict[str, list[dict]],
    ) -> float:
        """
        Удобный метод: принимает словарь {control_id: [evidence...]},
        вычисляет вердикты и возвращает итоговый score.

        Args:
            controls_evidences: словарь {control_id: evidence_list}

        Returns:
            Float 0.0–100.0
        """
        verdicts = [
            self.evaluate_control(control_id, ev_list)
            for control_id, ev_list in controls_evidences.items()
        ]
        return self.calculate_compliance_score(verdicts)

    def find_missing_evidence_controls(
        self,
        controls_evidences: dict[str, list[dict]],
    ) -> list[dict]:
        """
        Находит контроли с недостаточными доказательствами.

        Args:
            controls_evidences: словарь {control_id: evidence_list}

        Returns:
            Список dict: {control_id, status, missing_evidence, confidence}
            только для контролей со статусом NEEDS_REVIEW или FAIL.
        """
        result: list[dict] = []
        for control_id, ev_list in controls_evidences.items():
            verdict = self.evaluate_control(control_id, ev_list)
            if verdict.status != VerdictStatus.PASS:
                result.append({
                    "control_id":       control_id,
                    "status":           verdict.status.value,
                    "missing_evidence": verdict.missing_evidence,
                    "confidence":       verdict.confidence,
                    "reasons":          verdict.reasons,
                })
        return result

    # ── Вспомогательные ────────────────────────────────────────────────────────

    def _get_weight(self, control_id: str) -> float:
        """Возвращает вес контроля для scoring (по умолчанию 1.0)."""
        return _CONTROL_WEIGHTS.get(control_id, 1.0)

    def _calculate_confidence(
        self,
        required_count: int,
        present_count:  int,
        total_pass:     int,
    ) -> float:
        """
        Вычисляет confidence для PASS-вердикта.

        Логика:
          - base 0.8 если покрытие == 100%
          - +0.1 если есть дополнительные (сверх required) evidence
          - +0.1 если total_pass >= required_count * 2 (избыточное покрытие)
        """
        if required_count == 0:
            return 0.8

        coverage = present_count / required_count
        base = min(coverage * 0.8, 0.8)

        bonus = 0.0
        if present_count > required_count:
            bonus += 0.1
        if total_pass >= required_count * 2:
            bonus += 0.1

        return round(min(base + bonus, 1.0), 2)


# ── Singleton ──────────────────────────────────────────────────────────────────

_engine_instance: Optional[ComplianceEngine] = None


def get_compliance_engine() -> ComplianceEngine:
    """Thread-safe singleton ComplianceEngine."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ComplianceEngine()
    return _engine_instance
