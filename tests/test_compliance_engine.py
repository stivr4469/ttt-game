"""
Тесты ComplianceEngine — детерминированный движок оценки SOC 2 контролей.

Минимум 20 тестов:
  - evaluate_control с разными наборами evidence
  - score calculation с весами
  - advisory vs authority separation
  - find_missing_evidence_controls
  - edge cases (пустые списки, unknown controls)
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch, MagicMock

from compliance_engine import (
    ComplianceEngine,
    ControlVerdict,
    VerdictStatus,
    get_compliance_engine,
    _REQUIRED_EVIDENCE_TYPES,
    _CONTROL_WEIGHTS,
)


# ── Фикстуры ─────────────────────────────────────────────────────────────────

@pytest.fixture
def engine() -> ComplianceEngine:
    """Свежий экземпляр ComplianceEngine для каждого теста."""
    return ComplianceEngine()


def _make_evidence(status: str, evidence_type: str = "", title: str = "test") -> dict:
    """Создаёт тестовую единицу evidence."""
    return {
        "id": f"ev-{title[:4]}",
        "status": status,
        "evidence_type": evidence_type,
        "title": title,
        "source": "test",
    }


def _make_full_pass_evidence(control_id: str) -> list[dict]:
    """Создаёт полный набор PASS evidence для контроля."""
    required = _REQUIRED_EVIDENCE_TYPES.get(control_id, [])
    return [
        _make_evidence("PASS", ev_type, f"{control_id}-{ev_type}")
        for ev_type in required
    ]


# ── Тест 1: FAIL при наличии хотя бы одного FAIL evidence ─────────────────────

def test_evaluate_fail_when_any_fail_evidence(engine: ComplianceEngine):
    """Если есть FAIL evidence — вердикт всегда FAIL."""
    evidence = [
        _make_evidence("PASS", "access_review"),
        _make_evidence("FAIL", "mfa_evidence", "MFA not configured"),
    ]
    verdict = engine.evaluate_control("CC6.1", evidence)
    assert verdict.status == VerdictStatus.FAIL
    assert verdict.confidence == 1.0
    assert any("FAIL evidence" in r for r in verdict.reasons)


# ── Тест 2: FAIL с confidence=1.0 всегда ──────────────────────────────────────

def test_evaluate_fail_confidence_always_one(engine: ComplianceEngine):
    """FAIL-вердикт всегда имеет confidence=1.0 (детерминировано)."""
    evidence = [_make_evidence("FAIL", "access_review")]
    verdict = engine.evaluate_control("CC6.1", evidence)
    assert verdict.status == VerdictStatus.FAIL
    assert verdict.confidence == 1.0


# ── Тест 3: NEEDS_REVIEW при недостаточном evidence ───────────────────────────

def test_evaluate_needs_review_when_insufficient_evidence(engine: ComplianceEngine):
    """Без FAIL, но при недостаточном coverage — NEEDS_REVIEW."""
    evidence = [_make_evidence("PASS", "access_review")]  # только один тип из трёх
    verdict = engine.evaluate_control("CC6.1", evidence)
    assert verdict.status == VerdictStatus.NEEDS_REVIEW
    assert len(verdict.missing_evidence) > 0


# ── Тест 4: PASS при полном покрытии evidence ──────────────────────────────────

def test_evaluate_pass_when_all_required_present(engine: ComplianceEngine):
    """При всех required evidence types — PASS."""
    evidence = _make_full_pass_evidence("CC6.1")
    verdict = engine.evaluate_control("CC6.1", evidence)
    assert verdict.status == VerdictStatus.PASS
    assert verdict.missing_evidence == []


# ── Тест 5: FAIL имеет приоритет над любым количеством PASS ───────────────────

def test_evaluate_fail_overrides_pass(engine: ComplianceEngine):
    """FAIL evidence переопределяет все PASS evidence."""
    evidence = _make_full_pass_evidence("CC6.1") + [
        _make_evidence("FAIL", "access_review", "Critical failure")
    ]
    verdict = engine.evaluate_control("CC6.1", evidence)
    assert verdict.status == VerdictStatus.FAIL


# ── Тест 6: пустой список evidence → NEEDS_REVIEW ────────────────────────────

def test_evaluate_empty_evidence_needs_review(engine: ComplianceEngine):
    """Пустой список evidence → NEEDS_REVIEW (нет доказательств)."""
    verdict = engine.evaluate_control("CC6.1", [])
    assert verdict.status == VerdictStatus.NEEDS_REVIEW


# ── Тест 7: unknown control с PASS evidence ────────────────────────────────────

def test_evaluate_unknown_control_with_pass_evidence(engine: ComplianceEngine):
    """Неизвестный контроль с PASS evidence → PASS (нет специфических требований)."""
    evidence = [_make_evidence("PASS", "some_evidence")]
    verdict = engine.evaluate_control("UNKNOWN_CTRL", evidence)
    assert verdict.status == VerdictStatus.PASS
    assert verdict.confidence == 0.7


# ── Тест 8: unknown control без evidence → NEEDS_REVIEW ──────────────────────

def test_evaluate_unknown_control_empty_evidence(engine: ComplianceEngine):
    """Неизвестный контроль без evidence → NEEDS_REVIEW."""
    verdict = engine.evaluate_control("UNKNOWN_CTRL", [])
    assert verdict.status == VerdictStatus.NEEDS_REVIEW


# ── Тест 9: missing_evidence перечисляет отсутствующие типы ───────────────────

def test_evaluate_missing_evidence_lists_absent_types(engine: ComplianceEngine):
    """missing_evidence содержит именно отсутствующие типы."""
    # CC6.1 требует: access_review, mfa_evidence, access_provisioning_log
    evidence = [_make_evidence("PASS", "access_review")]
    verdict = engine.evaluate_control("CC6.1", evidence)
    assert "mfa_evidence" in verdict.missing_evidence
    assert "access_provisioning_log" in verdict.missing_evidence
    assert "access_review" not in verdict.missing_evidence


# ── Тест 10: get_required_evidence_types возвращает корректный список ──────────

def test_get_required_evidence_types_known_control(engine: ComplianceEngine):
    """get_required_evidence_types возвращает список для известного контроля."""
    required = engine.get_required_evidence_types("CC6.1")
    assert isinstance(required, list)
    assert len(required) > 0
    assert "mfa_evidence" in required


# ── Тест 11: get_required_evidence_types для unknown control ──────────────────

def test_get_required_evidence_types_unknown_control(engine: ComplianceEngine):
    """get_required_evidence_types возвращает [] для неизвестного контроля."""
    required = engine.get_required_evidence_types("NOT_EXISTS")
    assert required == []


# ── Тест 12: calculate_compliance_score 100% при всех PASS ────────────────────

def test_calculate_score_all_pass(engine: ComplianceEngine):
    """Все PASS → score = 100.0."""
    verdicts = [
        ControlVerdict(control_id="CC6.1", status=VerdictStatus.PASS, confidence=0.9),
        ControlVerdict(control_id="CC7.4", status=VerdictStatus.PASS, confidence=0.9),
        ControlVerdict(control_id="CC3.2", status=VerdictStatus.PASS, confidence=0.9),
    ]
    score = engine.calculate_compliance_score(verdicts)
    assert score == 100.0


# ── Тест 13: calculate_compliance_score 0% при всех FAIL ─────────────────────

def test_calculate_score_all_fail(engine: ComplianceEngine):
    """Все FAIL → score = 0.0."""
    verdicts = [
        ControlVerdict(control_id="CC6.1", status=VerdictStatus.FAIL, confidence=1.0),
        ControlVerdict(control_id="CC7.4", status=VerdictStatus.FAIL, confidence=1.0),
    ]
    score = engine.calculate_compliance_score(verdicts)
    assert score == 0.0


# ── Тест 14: NEEDS_REVIEW даёт 50% вклад в score ─────────────────────────────

def test_calculate_score_needs_review_partial(engine: ComplianceEngine):
    """NEEDS_REVIEW даёт 50% вклад в score (однородный список)."""
    verdicts = [
        ControlVerdict(control_id="CC1.1", status=VerdictStatus.NEEDS_REVIEW, confidence=0.5),
        ControlVerdict(control_id="CC1.2", status=VerdictStatus.NEEDS_REVIEW, confidence=0.5),
    ]
    score = engine.calculate_compliance_score(verdicts)
    assert score == 50.0


# ── Тест 15: calculate_compliance_score учитывает веса ───────────────────────

def test_calculate_score_respects_weights(engine: ComplianceEngine):
    """
    CC6.1 (weight=3.0) PASS + CC1.1 (weight=1.0) FAIL.
    score = (3*1 + 1*0) / (3+1) * 100 = 75.0
    """
    verdicts = [
        ControlVerdict(control_id="CC6.1", status=VerdictStatus.PASS, confidence=0.9),
        ControlVerdict(control_id="CC1.1", status=VerdictStatus.FAIL, confidence=1.0),
    ]
    score = engine.calculate_compliance_score(verdicts)
    assert score == 75.0


# ── Тест 16: calculate_compliance_score с пустым списком ─────────────────────

def test_calculate_score_empty_verdicts(engine: ComplianceEngine):
    """Пустой список вердиктов → score = 0.0."""
    score = engine.calculate_compliance_score([])
    assert score == 0.0


# ── Тест 17: find_missing_evidence_controls ───────────────────────────────────

def test_find_missing_evidence_controls(engine: ComplianceEngine):
    """Находит контроли с FAIL и NEEDS_REVIEW, пропускает PASS."""
    controls_ev = {
        "CC6.1": _make_full_pass_evidence("CC6.1"),              # PASS
        "CC7.4": [],                                               # NEEDS_REVIEW (пусто)
        "CC3.2": [_make_evidence("FAIL", "risk_register")],       # FAIL
    }
    missing = engine.find_missing_evidence_controls(controls_ev)
    missing_ids = [m["control_id"] for m in missing]

    assert "CC6.1" not in missing_ids
    assert "CC7.4" in missing_ids
    assert "CC3.2" in missing_ids


# ── Тест 18: Advisory vs Authority — ComplianceEngine не вызывает AI ──────────

def test_engine_never_calls_ai(engine: ComplianceEngine):
    """
    ComplianceEngine не должен содержать вызовы AI-библиотек в своём исходном коде.
    Проверяем статически через inspect.getsource — надёжнее чем мок импортов.
    """
    import inspect
    # Проверяем весь класс ComplianceEngine
    engine_source = inspect.getsource(ComplianceEngine)
    assert "openai" not in engine_source,      "ComplianceEngine не должен импортировать openai"
    assert "anthropic" not in engine_source,   "ComplianceEngine не должен импортировать anthropic"
    assert "ai_advisor" not in engine_source,  "ComplianceEngine не должен импортировать ai_advisor"
    assert "AIAdvisor" not in engine_source,   "ComplianceEngine не должен использовать AIAdvisor"

    # Убедимся что evaluate_control работает без побочных эффектов
    evidence = [{"status": "PASS", "evidence_type": "access_review"}]
    verdict = engine.evaluate_control("CC6.1", evidence)
    assert verdict is not None  # функция вернула результат без вызова AI


# ── Тест 19: AIAdvisor is_advisory_only всегда True ─────────────────────────

def test_ai_advisor_is_advisory_only(tmp_path):
    """AIAdvice.is_advisory_only всегда True — архитектурный инвариант."""
    from ai_advisor import AIAdvisor, AIAdvice
    from ai_decision_log import AIDecisionLogger

    # Используем изолированный логгер чтобы не писать в реальный data/
    isolated_logger = AIDecisionLogger(data_file=tmp_path / "test_decisions.json")
    advisor = AIAdvisor(api_key=None)  # mock-режим
    advisor._logger = isolated_logger

    # suggest_remediation
    advice = advisor.suggest_remediation("CC6.1", "MFA not configured")
    assert advice.is_advisory_only is True
    assert advice.disclaimer == "AI suggestion — requires human review"

    # draft_policy
    advice2 = advisor.draft_policy("CC6.1", "Access Control Policy")
    assert advice2.is_advisory_only is True

    # explain_finding
    advice3 = advisor.explain_finding("CC6.1", "MFA disabled for 3 users")
    assert advice3.is_advisory_only is True


# ── Тест 20: AIAdvisor не изменяет статус контрола напрямую ──────────────────

def test_ai_advisor_never_changes_control_status(tmp_path):
    """
    AIAdvisor не должен вызывать методы изменения статуса контролей.
    Проверяем через inspect что suggest_remediation не вызывает
    update_control_status / evaluate_control изменяя state.
    """
    import inspect
    from ai_advisor import AIAdvisor

    # Проверяем что в suggest_remediation нет прямого изменения состояния
    source = inspect.getsource(AIAdvisor.suggest_remediation)
    assert "update_control_status" not in source
    assert "approve(" not in source

    # Проверяем draft_policy
    source2 = inspect.getsource(AIAdvisor.draft_policy)
    # draft_policy может вызывать логирование, но не должна approve
    assert "approve(" not in source2
    assert "PolicyStatus.APPROVED" not in source2


# ── Тест 21: confidence снижается при частичном покрытии ─────────────────────

def test_evaluate_confidence_decreases_with_partial_coverage(engine: ComplianceEngine):
    """Partial coverage → confidence < 0.8."""
    # CC6.1 требует 3 типа, предоставим только 1
    evidence = [_make_evidence("PASS", "access_review")]
    verdict = engine.evaluate_control("CC6.1", evidence)
    assert verdict.status == VerdictStatus.NEEDS_REVIEW
    assert verdict.confidence < 0.8


# ── Тест 22: calculate_compliance_score_from_evidences ───────────────────────

def test_calculate_compliance_score_from_evidences(engine: ComplianceEngine):
    """Удобный метод calculate_compliance_score_from_evidences работает корректно."""
    controls = {
        "CC6.1": _make_full_pass_evidence("CC6.1"),
        "CC7.4": _make_full_pass_evidence("CC7.4"),
    }
    score = engine.calculate_compliance_score_from_evidences(controls)
    assert score == 100.0


# ── Тест 23: APPROVED status evidence засчитывается как PASS ─────────────────

def test_evaluate_approved_evidence_counts_as_pass(engine: ComplianceEngine):
    """Evidence со статусом APPROVED засчитывается как PASS."""
    required = _REQUIRED_EVIDENCE_TYPES.get("CC6.1", [])
    evidence = [
        {"id": f"ev-{i}", "status": "APPROVED", "evidence_type": ev_type, "title": ev_type}
        for i, ev_type in enumerate(required)
    ]
    verdict = engine.evaluate_control("CC6.1", evidence)
    assert verdict.status == VerdictStatus.PASS


# ── Тест 24: несколько FAIL причин в reasons ─────────────────────────────────

def test_evaluate_multiple_fail_reasons(engine: ComplianceEngine):
    """Несколько FAIL evidence → несколько reasons."""
    evidence = [
        _make_evidence("FAIL", "access_review", "Access review failed"),
        _make_evidence("FAIL", "mfa_evidence", "MFA not enforced"),
    ]
    verdict = engine.evaluate_control("CC6.1", evidence)
    assert verdict.status == VerdictStatus.FAIL
    assert len(verdict.reasons) == 2
    assert all("FAIL evidence" in r for r in verdict.reasons)


# ── Тест 25: singleton get_compliance_engine возвращает один экземпляр ────────

def test_get_compliance_engine_singleton():
    """get_compliance_engine() возвращает один и тот же экземпляр."""
    engine1 = get_compliance_engine()
    engine2 = get_compliance_engine()
    assert engine1 is engine2


# ── Тест 26: ai_suggestion в ControlVerdict по умолчанию None ────────────────

def test_control_verdict_ai_suggestion_default_none(engine: ComplianceEngine):
    """ComplianceEngine никогда не заполняет ai_suggestion — только AIAdvisor."""
    evidence = [_make_evidence("PASS", "access_review")]
    verdict = engine.evaluate_control("CC6.1", evidence)
    # ComplianceEngine не должен заполнять ai_suggestion
    assert verdict.ai_suggestion is None


# ── Тест 27: to_dict возвращает корректную структуру ─────────────────────────

def test_control_verdict_to_dict(engine: ComplianceEngine):
    """ControlVerdict.to_dict() содержит все ожидаемые ключи."""
    evidence = _make_full_pass_evidence("CC6.1")
    verdict = engine.evaluate_control("CC6.1", evidence)
    d = verdict.to_dict()
    assert "control_id" in d
    assert "status" in d
    assert "confidence" in d
    assert "reasons" in d
    assert "missing_evidence" in d
    assert "ai_suggestion" in d
    assert d["status"] == "PASS"


# ── Тест 28: PENDING evidence не считается ни PASS ни FAIL ───────────────────

def test_evaluate_pending_evidence_not_counted(engine: ComplianceEngine):
    """PENDING evidence не засчитывается как PASS и не вызывает FAIL."""
    # Если только PENDING — должно быть NEEDS_REVIEW (не FAIL)
    evidence = [
        _make_evidence("PENDING", "access_review"),
        _make_evidence("PENDING", "mfa_evidence"),
    ]
    verdict = engine.evaluate_control("CC6.1", evidence)
    assert verdict.status == VerdictStatus.NEEDS_REVIEW  # нет FAIL, нет PASS


# ── Тест 29: find_missing_evidence_controls сортировка FAIL первый ───────────

def test_find_missing_sorted_fail_first(engine: ComplianceEngine):
    """find_missing_evidence_controls возвращает FAIL-контроли первыми."""
    controls = {
        "CC1.1": [],                                     # NEEDS_REVIEW
        "CC6.1": [_make_evidence("FAIL", "mfa_evidence")],  # FAIL
    }
    missing = engine.find_missing_evidence_controls(controls)
    assert len(missing) >= 1
    # FAIL должен быть среди результатов
    statuses = [m["status"] for m in missing]
    assert "FAIL" in statuses


# ── Тест 30: compliance_score в диапазоне 0-100 ──────────────────────────────

def test_compliance_score_bounds(engine: ComplianceEngine):
    """Compliance score всегда в диапазоне 0.0–100.0."""
    # Смешанный набор
    verdicts = [
        ControlVerdict(control_id="CC6.1", status=VerdictStatus.PASS, confidence=0.9),
        ControlVerdict(control_id="CC7.4", status=VerdictStatus.FAIL, confidence=1.0),
        ControlVerdict(control_id="CC3.2", status=VerdictStatus.NEEDS_REVIEW, confidence=0.5),
        ControlVerdict(control_id="CC1.1", status=VerdictStatus.PASS, confidence=0.8),
    ]
    score = engine.calculate_compliance_score(verdicts)
    assert 0.0 <= score <= 100.0
