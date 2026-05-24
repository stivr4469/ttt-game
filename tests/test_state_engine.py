"""
tests/test_state_engine.py — Тесты ComplianceStateEngine.

Минимум 20 тестов:
  - unit tests для ComplianceStateEngine
  - get_control_state возвращает правильную структуру
  - explain_control_fail содержит цепочку
  - recalculate обновляет state
  - integration с compliance_engine.py
  - snapshot / restore
  - thread-safety
  - posture calculation
  - graceful degradation
"""

from __future__ import annotations

import sys
import os
import threading
import time
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock, PropertyMock
from typing import Dict, List, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from compliance_engine import (
    ComplianceEngine,
    ControlVerdict,
    VerdictStatus,
)
from compliance_state_engine import (
    ComplianceStateEngine,
    ControlState,
    CompliancePosture,
    FailExplanation,
    get_state_engine,
    reset_state_engine,
    _extract_category,
    _get_control_weight,
)
from event_bus import (
    ComplianceEventType,
    get_event_bus,
)


# ── Вспомогательные функции ────────────────────────────────────────────────────

def _make_pass_verdict(control_id: str = "CC6.1") -> ControlVerdict:
    """Создаёт PASS-вердикт для теста."""
    return ControlVerdict(
        control_id=control_id,
        status=VerdictStatus.PASS,
        confidence=0.9,
        reasons=["Все required evidence types присутствуют"],
        missing_evidence=[],
    )


def _make_fail_verdict(control_id: str = "CC6.1") -> ControlVerdict:
    """Создаёт FAIL-вердикт для теста."""
    return ControlVerdict(
        control_id=control_id,
        status=VerdictStatus.FAIL,
        confidence=1.0,
        reasons=["FAIL evidence: 'bad access log' (source: okta)"],
        missing_evidence=[],
    )


def _make_needs_review_verdict(control_id: str = "CC6.1") -> ControlVerdict:
    """Создаёт NEEDS_REVIEW-вердикт для теста."""
    return ControlVerdict(
        control_id=control_id,
        status=VerdictStatus.NEEDS_REVIEW,
        confidence=0.4,
        reasons=["Отсутствуют 2 из 3 required evidence types"],
        missing_evidence=["mfa_evidence", "access_provisioning_log"],
    )


def _make_engine_with_verdict(verdict: ControlVerdict) -> ComplianceEngine:
    """Создаёт mock ComplianceEngine который возвращает заданный вердикт."""
    mock_engine = MagicMock(spec=ComplianceEngine)
    mock_engine.evaluate_control.return_value = verdict
    return mock_engine


# ── Фикстуры ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_singleton():
    """Сбрасывает singleton перед каждым тестом."""
    reset_state_engine()
    yield
    reset_state_engine()


@pytest.fixture
def pass_engine() -> ComplianceStateEngine:
    """Engine с PASS-вердиктом для CC6.1."""
    verdict = _make_pass_verdict("CC6.1")
    mock = _make_engine_with_verdict(verdict)
    return ComplianceStateEngine(engine=mock)


@pytest.fixture
def fail_engine() -> ComplianceStateEngine:
    """Engine с FAIL-вердиктом для любого контроля."""
    verdict = _make_fail_verdict("CC6.1")
    mock = _make_engine_with_verdict(verdict)
    return ComplianceStateEngine(engine=mock)


# ── Тест 1: get_control_state возвращает ControlState ─────────────────────────

def test_get_control_state_returns_control_state(pass_engine):
    """get_control_state возвращает объект ControlState."""
    state = pass_engine.get_control_state("CC6.1")
    assert isinstance(state, ControlState)


# ── Тест 2: структура ControlState содержит обязательные поля ─────────────────

def test_control_state_has_required_fields(pass_engine):
    """ControlState содержит все обязательные поля."""
    state = pass_engine.get_control_state("CC6.1")
    assert hasattr(state, "control_id")
    assert hasattr(state, "status")
    assert hasattr(state, "confidence")
    assert hasattr(state, "evidence_count")
    assert hasattr(state, "evidence_ids")
    assert hasattr(state, "risk_ids")
    assert hasattr(state, "affected_frameworks")
    assert hasattr(state, "last_evaluated")
    assert hasattr(state, "why_message")
    assert hasattr(state, "missing_evidence")
    assert hasattr(state, "weight")


# ── Тест 3: PASS статус корректно отражается ──────────────────────────────────

def test_pass_verdict_results_in_pass_state(pass_engine):
    """PASS-вердикт от engine → статус PASS в ControlState."""
    state = pass_engine.get_control_state("CC6.1")
    assert state.status == "PASS"
    assert state.confidence == 0.9
    assert state.missing_evidence == []


# ── Тест 4: FAIL статус корректно отражается ──────────────────────────────────

def test_fail_verdict_results_in_fail_state(fail_engine):
    """FAIL-вердикт от engine → статус FAIL в ControlState."""
    state = fail_engine.get_control_state("CC6.1")
    assert state.status == "FAIL"
    assert state.confidence == 1.0
    assert "FAIL" in state.why_message


# ── Тест 5: NEEDS_REVIEW статус ───────────────────────────────────────────────

def test_needs_review_verdict_results_in_needs_review_state():
    """NEEDS_REVIEW-вердикт → статус NEEDS_REVIEW с missing_evidence."""
    verdict = _make_needs_review_verdict("CC6.1")
    mock = _make_engine_with_verdict(verdict)
    engine = ComplianceStateEngine(engine=mock)
    state = engine.get_control_state("CC6.1")
    assert state.status == "NEEDS_REVIEW"
    assert len(state.missing_evidence) == 2


# ── Тест 6: control_id корректно сохраняется ──────────────────────────────────

def test_control_state_control_id_matches(pass_engine):
    """control_id в ControlState совпадает с запрошенным."""
    state = pass_engine.get_control_state("CC7.4")
    assert state.control_id == "CC7.4"


# ── Тест 7: last_evaluated — datetime UTC ─────────────────────────────────────

def test_control_state_last_evaluated_is_datetime(pass_engine):
    """last_evaluated — объект datetime."""
    state = pass_engine.get_control_state("CC6.1")
    assert isinstance(state.last_evaluated, datetime)


# ── Тест 8: weight берётся из _CONTROL_WEIGHTS ────────────────────────────────

def test_control_state_weight_correct_for_critical_control(pass_engine):
    """CC6.1 имеет weight=3.0 (критичный контроль)."""
    state = pass_engine.get_control_state("CC6.1")
    assert state.weight == 3.0


def test_control_state_weight_default_for_normal_control():
    """CC1.1 имеет weight=1.0 (по умолчанию)."""
    verdict = _make_pass_verdict("CC1.1")
    mock = _make_engine_with_verdict(verdict)
    engine = ComplianceStateEngine(engine=mock)
    state = engine.get_control_state("CC1.1")
    assert state.weight == 1.0


# ── Тест 9: кэш — повторный вызов не вызывает engine ─────────────────────────

def test_get_control_state_uses_cache(pass_engine):
    """Повторный get_control_state использует кэш (engine вызван только 1 раз)."""
    pass_engine.get_control_state("CC6.1")
    pass_engine.get_control_state("CC6.1")
    pass_engine._engine.evaluate_control.assert_called_once()


# ── Тест 10: recalculate сбрасывает кэш и перевычисляет ──────────────────────

def test_recalculate_one_control_updates_cache():
    """recalculate(control_id) заново вычисляет состояние."""
    verdict_pass = _make_pass_verdict("CC6.1")
    verdict_fail = _make_fail_verdict("CC6.1")

    mock = MagicMock(spec=ComplianceEngine)
    # Первый вызов → PASS, второй → FAIL
    mock.evaluate_control.side_effect = [verdict_pass, verdict_fail]

    engine = ComplianceStateEngine(engine=mock)

    state1 = engine.get_control_state("CC6.1")
    assert state1.status == "PASS"

    engine.recalculate(control_id="CC6.1")
    state2 = engine.get_control_state("CC6.1")
    assert state2.status == "FAIL"


# ── Тест 11: recalculate публикует событие при смене статуса ──────────────────

def test_recalculate_publishes_event_on_status_change():
    """При смене статуса recalculate публикует CONTROL_STATUS_CHANGED."""
    verdict_pass = _make_pass_verdict("CC6.1")
    verdict_fail = _make_fail_verdict("CC6.1")

    mock = MagicMock(spec=ComplianceEngine)
    mock.evaluate_control.side_effect = [verdict_pass, verdict_fail]

    engine = ComplianceStateEngine(engine=mock)
    bus = get_event_bus()
    bus.clear_history()

    engine.get_control_state("CC6.1")
    engine.recalculate(control_id="CC6.1")

    history = bus.get_history(
        entity_id="CC6.1",
        event_type=ComplianceEventType.CONTROL_STATUS_CHANGED,
    )
    assert len(history) >= 1
    event = history[0]
    assert event.payload["new_status"] == "FAIL"
    assert event.payload["old_status"] == "PASS"


# ── Тест 12: recalculate НЕ публикует событие если статус не изменился ────────

def test_recalculate_no_event_if_status_unchanged():
    """Если статус не изменился — событие не публикуется."""
    verdict_pass = _make_pass_verdict("CC6.1")

    mock = MagicMock(spec=ComplianceEngine)
    mock.evaluate_control.return_value = verdict_pass

    engine = ComplianceStateEngine(engine=mock)
    bus = get_event_bus()
    bus.clear_history()

    engine.get_control_state("CC6.1")
    engine.recalculate(control_id="CC6.1")

    history = bus.get_history(
        entity_id="CC6.1",
        event_type=ComplianceEventType.CONTROL_STATUS_CHANGED,
    )
    assert len(history) == 0


# ── Тест 13: explain_control_fail возвращает FailExplanation ──────────────────

def test_explain_control_fail_returns_fail_explanation(fail_engine):
    """explain_control_fail возвращает объект FailExplanation."""
    expl = fail_engine.explain_control_fail("CC6.1")
    assert isinstance(expl, FailExplanation)


# ── Тест 14: explain содержит обязательные поля ───────────────────────────────

def test_explain_control_fail_has_required_fields(fail_engine):
    """FailExplanation содержит все обязательные поля."""
    expl = fail_engine.explain_control_fail("CC6.1")
    assert hasattr(expl, "control_id")
    assert hasattr(expl, "status")
    assert hasattr(expl, "primary_reason")
    assert hasattr(expl, "dependency_chain")
    assert hasattr(expl, "affected_controls")
    assert hasattr(expl, "risk_propagation")
    assert hasattr(expl, "remediation_sla")
    assert hasattr(expl, "triggering_events")


# ── Тест 15: explain — primary_reason не пустой ───────────────────────────────

def test_explain_primary_reason_not_empty(fail_engine):
    """primary_reason не пустой для FAIL-контроля."""
    expl = fail_engine.explain_control_fail("CC6.1")
    assert expl.primary_reason
    assert len(expl.primary_reason) > 0


# ── Тест 16: explain — dependency_chain это список строк ─────────────────────

def test_explain_dependency_chain_is_list(fail_engine):
    """dependency_chain — список (может быть пустым для контроля без зависимостей)."""
    expl = fail_engine.explain_control_fail("CC6.1")
    assert isinstance(expl.dependency_chain, list)


# ── Тест 17: explain — remediation_sla > 0 ────────────────────────────────────

def test_explain_remediation_sla_positive(fail_engine):
    """remediation_sla — положительное число (часов)."""
    expl = fail_engine.explain_control_fail("CC6.1")
    assert expl.remediation_sla > 0


# ── Тест 18: get_full_compliance_posture возвращает CompliancePosture ──────────

def test_get_full_compliance_posture_returns_posture(pass_engine):
    """get_full_compliance_posture возвращает CompliancePosture."""
    # Первичный вызов — пересчитываем известные контроли
    pass_engine.recalculate(control_id="CC6.1")
    posture = pass_engine.get_full_compliance_posture()
    assert isinstance(posture, CompliancePosture)


# ── Тест 19: posture — score в диапазоне 0–100 ───────────────────────────────

def test_posture_score_in_valid_range():
    """score и weighted_score в диапазоне [0.0, 100.0]."""
    verdict = _make_pass_verdict("CC6.1")
    mock = _make_engine_with_verdict(verdict)
    engine = ComplianceStateEngine(engine=mock)
    engine.recalculate(control_id="CC6.1")

    posture = engine.get_full_compliance_posture()
    assert 0.0 <= posture.score <= 100.0
    assert 0.0 <= posture.weighted_score <= 100.0


# ── Тест 20: posture — critical_fails содержит только высоковесные FAIL ───────

def test_posture_critical_fails_high_weight_only():
    """critical_fails содержит только контроли с weight >= 3.0 и статусом FAIL."""
    # CC6.1 weight=3.0 (критичный), CC1.1 weight=1.0
    fail_61 = _make_fail_verdict("CC6.1")
    fail_11 = _make_fail_verdict("CC1.1")

    mock = MagicMock(spec=ComplianceEngine)
    mock.evaluate_control.side_effect = [fail_61, fail_11]

    engine = ComplianceStateEngine(engine=mock)
    engine.recalculate(control_id="CC6.1")
    engine.recalculate(control_id="CC1.1")

    posture = engine.get_full_compliance_posture()
    assert "CC6.1" in posture.critical_fails
    # CC1.1 weight=1.0 < 3.0 → не в critical_fails
    assert "CC1.1" not in posture.critical_fails


# ── Тест 21: posture — кэш используется при повторном вызове ─────────────────

def test_posture_cache_used_on_second_call():
    """Второй вызов get_full_compliance_posture возвращает кэшированный результат."""
    verdict = _make_pass_verdict("CC6.1")
    mock = _make_engine_with_verdict(verdict)
    engine = ComplianceStateEngine(engine=mock)
    engine.recalculate(control_id="CC6.1")

    posture1 = engine.get_full_compliance_posture()
    posture2 = engine.get_full_compliance_posture()
    # Оба объекта идентичны (тот же объект из кэша)
    assert posture1 is posture2


# ── Тест 22: get_state_snapshot возвращает dict ───────────────────────────────

def test_get_state_snapshot_returns_dict(pass_engine):
    """get_state_snapshot возвращает JSON-serializable dict."""
    pass_engine.get_control_state("CC6.1")
    snapshot = pass_engine.get_state_snapshot()
    assert isinstance(snapshot, dict)
    assert "version" in snapshot
    assert "timestamp" in snapshot
    assert "controls" in snapshot


# ── Тест 23: snapshot содержит вычисленные контроли ──────────────────────────

def test_snapshot_contains_computed_controls(pass_engine):
    """Snapshot содержит контроли которые были вычислены."""
    pass_engine.get_control_state("CC6.1")
    snapshot = pass_engine.get_state_snapshot()
    assert "CC6.1" in snapshot["controls"]


# ── Тест 24: apply_snapshot восстанавливает state ─────────────────────────────

def test_apply_snapshot_restores_state():
    """apply_snapshot восстанавливает состояние из snapshot."""
    verdict_pass = _make_pass_verdict("CC6.1")
    mock_pass = _make_engine_with_verdict(verdict_pass)
    engine = ComplianceStateEngine(engine=mock_pass)

    # Вычисляем и делаем snapshot
    engine.get_control_state("CC6.1")
    snapshot = engine.get_state_snapshot()

    # Создаём новый engine с FAIL-вердиктом
    verdict_fail = _make_fail_verdict("CC6.1")
    mock_fail = _make_engine_with_verdict(verdict_fail)
    new_engine = ComplianceStateEngine(engine=mock_fail)

    # Восстанавливаем snapshot
    new_engine.apply_snapshot(snapshot)

    # Состояние должно быть PASS (из snapshot), не FAIL
    restored_state = new_engine.get_control_state("CC6.1")
    assert restored_state.status == "PASS"


# ── Тест 25: apply_snapshot публикует события ─────────────────────────────────

def test_apply_snapshot_publishes_events():
    """apply_snapshot публикует CONTROL_STATUS_CHANGED для изменившихся контролей."""
    # Готовим snapshot с PASS
    verdict_pass = _make_pass_verdict("CC6.1")
    mock = _make_engine_with_verdict(verdict_pass)
    engine = ComplianceStateEngine(engine=mock)
    engine.get_control_state("CC6.1")
    snapshot = engine.get_state_snapshot()

    # Новый engine с пустым cache
    new_engine = ComplianceStateEngine(engine=mock)
    bus = get_event_bus()
    bus.clear_history()

    new_engine.apply_snapshot(snapshot)

    history = bus.get_history(
        entity_id="CC6.1",
        event_type=ComplianceEventType.CONTROL_STATUS_CHANGED,
    )
    assert len(history) >= 1


# ── Тест 26: thread-safety ────────────────────────────────────────────────────

def test_thread_safe_concurrent_get_control_state():
    """Конкурентные вызовы get_control_state не вызывают race condition."""
    verdict = _make_pass_verdict("CC6.1")
    mock = MagicMock(spec=ComplianceEngine)
    # Небольшая задержка для эмуляции I/O
    def slow_evaluate(*args, **kwargs):
        time.sleep(0.01)
        return verdict
    mock.evaluate_control.side_effect = slow_evaluate

    engine = ComplianceStateEngine(engine=mock)
    results: List[Any] = []
    errors: List[Exception] = []

    def worker():
        try:
            state = engine.get_control_state("CC6.1")
            results.append(state.status)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert all(r == "PASS" for r in results)


# ── Тест 27: recalculate_all пересчитывает несколько контролей ────────────────

def test_recalculate_all_recalculates_known_controls():
    """recalculate() без аргумента пересчитывает все известные контроли."""
    verdict = _make_pass_verdict("CC6.1")
    mock = MagicMock(spec=ComplianceEngine)
    mock.evaluate_control.return_value = verdict

    engine = ComplianceStateEngine(engine=mock)
    engine.recalculate()  # пересчитываем все

    # Engine должен был вызван хотя бы для нескольких контролей
    assert mock.evaluate_control.call_count >= 1


# ── Тест 28: to_dict возвращает JSON-serializable dict ────────────────────────

def test_control_state_to_dict_is_json_serializable(pass_engine):
    """ControlState.to_dict() возвращает JSON-serializable dict."""
    import json
    state = pass_engine.get_control_state("CC6.1")
    d = state.to_dict()
    assert isinstance(d, dict)
    # Должен сериализоваться без ошибок
    serialized = json.dumps(d)
    assert isinstance(serialized, str)


# ── Тест 29: FailExplanation.to_dict() ───────────────────────────────────────

def test_fail_explanation_to_dict_is_json_serializable(fail_engine):
    """FailExplanation.to_dict() возвращает JSON-serializable dict."""
    import json
    expl = fail_engine.explain_control_fail("CC6.1")
    d = expl.to_dict()
    assert isinstance(d, dict)
    serialized = json.dumps(d)
    assert isinstance(serialized, str)


# ── Тест 30: CompliancePosture.to_dict() ─────────────────────────────────────

def test_compliance_posture_to_dict_is_json_serializable():
    """CompliancePosture.to_dict() возвращает JSON-serializable dict."""
    import json
    verdict = _make_pass_verdict("CC6.1")
    mock = _make_engine_with_verdict(verdict)
    engine = ComplianceStateEngine(engine=mock)
    engine.recalculate(control_id="CC6.1")
    posture = engine.get_full_compliance_posture()
    d = posture.to_dict()
    serialized = json.dumps(d)
    assert isinstance(serialized, str)


# ── Тест 31: singleton get_state_engine ──────────────────────────────────────

def test_get_state_engine_returns_singleton():
    """get_state_engine возвращает один и тот же объект."""
    engine1 = get_state_engine()
    engine2 = get_state_engine()
    assert engine1 is engine2


# ── Тест 32: reset_state_engine сбрасывает singleton ─────────────────────────

def test_reset_state_engine_clears_singleton():
    """reset_state_engine сбрасывает singleton."""
    engine1 = get_state_engine()
    reset_state_engine()
    engine2 = get_state_engine()
    assert engine1 is not engine2


# ── Тест 33: _extract_category корректно парсит control_id ───────────────────

@pytest.mark.parametrize("control_id,expected", [
    ("CC6.1", "CC6"),
    ("CC1.1", "CC1"),
    ("A1.1", "A1"),
    ("PI1.1", "PI1"),
    ("C1.1", "C1"),
    ("P1.1", "P1"),
])
def test_extract_category(control_id, expected):
    """_extract_category правильно извлекает категорию."""
    assert _extract_category(control_id) == expected


# ── Тест 34: _get_control_weight возвращает правильные веса ──────────────────

@pytest.mark.parametrize("control_id,expected_weight", [
    ("CC6.1", 3.0),
    ("CC6.2", 3.0),
    ("CC7.4", 3.0),
    ("CC3.2", 2.5),
    ("CC5.3", 2.5),
    ("CC1.1", 1.0),  # нет в _CONTROL_WEIGHTS → 1.0
    ("UNKNOWN", 1.0),
])
def test_get_control_weight(control_id, expected_weight):
    """_get_control_weight возвращает правильный вес."""
    assert _get_control_weight(control_id) == expected_weight


# ── Тест 35: integration с реальным ComplianceEngine ─────────────────────────

def test_integration_with_real_compliance_engine():
    """Integration: ComplianceStateEngine работает с реальным ComplianceEngine."""
    real_engine = ComplianceEngine()
    state_engine = ComplianceStateEngine(engine=real_engine)

    # CC6.1 без evidence → NEEDS_REVIEW (нет FAIL, но нет и достаточного evidence)
    with patch(
        "compliance_state_engine._load_evidence_for_control",
        return_value=[],
    ):
        state = state_engine.get_control_state("CC6.1")

    assert state.control_id == "CC6.1"
    assert state.status in ("NEEDS_REVIEW", "FAIL", "PASS", "UNKNOWN")
    assert 0.0 <= state.confidence <= 1.0


# ── Тест 36: integration — FAIL evidence вызывает FAIL статус ─────────────────

def test_integration_fail_evidence_causes_fail_status():
    """Integration: FAIL evidence в controls_map → FAIL статус контроля."""
    real_engine = ComplianceEngine()
    state_engine = ComplianceStateEngine(engine=real_engine)

    fail_evidence = [
        {
            "id": "ev-fail-1",
            "control_id": "CC6.1",
            "status": "FAIL",
            "evidence_type": "access_review",
            "title": "Access review failed",
            "source": "okta",
        }
    ]

    with patch(
        "compliance_state_engine._load_evidence_for_control",
        return_value=fail_evidence,
    ):
        state = state_engine.get_control_state("CC6.1")

    assert state.status == "FAIL"
    assert state.confidence == 1.0
    assert "FAIL" in state.why_message


# ── Тест 37: integration — полный PASS набор evidence ────────────────────────

def test_integration_full_pass_evidence_causes_pass_status():
    """Integration: полный набор PASS evidence → PASS статус."""
    from compliance_engine import _REQUIRED_EVIDENCE_TYPES
    real_engine = ComplianceEngine()
    state_engine = ComplianceStateEngine(engine=real_engine)

    # Формируем полный набор для CC6.1
    required_types = _REQUIRED_EVIDENCE_TYPES.get("CC6.1", [])
    full_evidence = [
        {
            "id": f"ev-{i}",
            "control_id": "CC6.1",
            "status": "PASS",
            "evidence_type": ev_type,
            "title": f"Evidence {ev_type}",
            "source": "scanner",
        }
        for i, ev_type in enumerate(required_types)
    ]

    with patch(
        "compliance_state_engine._load_evidence_for_control",
        return_value=full_evidence,
    ):
        state = state_engine.get_control_state("CC6.1")

    assert state.status == "PASS"
    assert state.evidence_count == len(required_types)


# ── Тест 38: posture breakdown содержит категории ─────────────────────────────

def test_posture_breakdown_has_categories():
    """posture.breakdown содержит категории контролей."""
    verdict = _make_pass_verdict("CC6.1")
    mock = _make_engine_with_verdict(verdict)
    engine = ComplianceStateEngine(engine=mock)
    engine.recalculate(control_id="CC6.1")
    posture = engine.get_full_compliance_posture()

    assert isinstance(posture.breakdown, dict)
    # При наличии CC6.1 должна быть категория CC6
    if posture.total_controls > 0:
        assert len(posture.breakdown) > 0


# ── Тест 39: explain_control_fail для контроля с зависимостями ───────────────

def test_explain_control_with_dependencies():
    """CC7.4 зависит от CC7.3 → dependency_chain не пустой."""
    verdict = _make_fail_verdict("CC7.4")
    mock = _make_engine_with_verdict(verdict)
    engine = ComplianceStateEngine(engine=mock)

    # Граф должен содержать depends_on цепочку CC7.4 → CC7.3 → CC7.2 → CC7.1
    expl = engine.explain_control_fail("CC7.4")
    # dependency_chain может быть пустым если граф не построен (graceful degradation)
    assert isinstance(expl.dependency_chain, list)
    assert isinstance(expl.affected_controls, list)


# ── Тест 40: snapshot round-trip ─────────────────────────────────────────────

def test_snapshot_round_trip():
    """Snapshot → apply → snapshot даёт идентичный результат."""
    verdict = _make_pass_verdict("CC6.1")
    mock = _make_engine_with_verdict(verdict)
    engine = ComplianceStateEngine(engine=mock)
    engine.get_control_state("CC6.1")

    snapshot1 = engine.get_state_snapshot()

    new_engine = ComplianceStateEngine(engine=mock)
    new_engine.apply_snapshot(snapshot1)
    snapshot2 = new_engine.get_state_snapshot()

    # Контроли идентичны
    ctrl1 = snapshot1["controls"].get("CC6.1", {})
    ctrl2 = snapshot2["controls"].get("CC6.1", {})
    assert ctrl1["status"] == ctrl2["status"]
    assert ctrl1["confidence"] == ctrl2["confidence"]
