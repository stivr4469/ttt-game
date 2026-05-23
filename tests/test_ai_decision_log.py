"""
Тесты для AIDecisionLogger — Explainability Layer.

Покрывают: создание записей, UUID, эвристику confidence,
фильтрацию, поиск по ID, статистику, FIFO-лимит.
"""

import json
import tempfile
from pathlib import Path

import pytest

from ai_decision_log import (
    AIDecisionLogger,
    AIDecisionRecord,
    DecisionType,
    _compute_confidence,
)


# ── Фикстуры ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def tmp_log(tmp_path: Path) -> AIDecisionLogger:
    """Изолированный логгер с временным файлом для каждого теста."""
    return AIDecisionLogger(data_file=tmp_path / "test_decisions.json")


def _make_record(
    logger: AIDecisionLogger,
    *,
    decision_type: DecisionType = DecisionType.GAP_ANALYSIS,
    control_id: str | None = "CC6.1",
    outcome: str = "PASS",
    model: str = "test-model",
    prompt: str = "Analyze control CC6.1 for SOC 2 compliance",
    output: str = "The control is PASS because MFA is enabled on all Okta accounts.",
    duration_ms: int = 100,
) -> AIDecisionRecord:
    return logger.record(
        decision_type=decision_type,
        model=model,
        prompt=prompt,
        output=output,
        outcome=outcome,
        control_id=control_id,
        duration_ms=duration_ms,
    )


# ── Тесты создания записей ────────────────────────────────────────────────────

def test_record_creates_entry(tmp_log: AIDecisionLogger):
    """record() добавляет ровно одну запись в хранилище."""
    assert len(tmp_log.get_all()) == 0
    _make_record(tmp_log)
    assert len(tmp_log.get_all()) == 1


def test_record_assigns_uuid(tmp_log: AIDecisionLogger):
    """Каждая запись получает уникальный UUID формата uuid4."""
    import re
    uuid4_re = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    rec1 = _make_record(tmp_log)
    rec2 = _make_record(tmp_log)

    assert uuid4_re.match(rec1.id), f"Неверный UUID: {rec1.id}"
    assert uuid4_re.match(rec2.id), f"Неверный UUID: {rec2.id}"
    assert rec1.id != rec2.id, "UUID должны быть уникальными"


def test_record_persists_to_disk(tmp_path: Path):
    """Записи сохраняются на диск и восстанавливаются при перезапуске."""
    data_file = tmp_path / "persist_test.json"

    logger1 = AIDecisionLogger(data_file=data_file)
    rec = _make_record(logger1, control_id="CC3.2", outcome="FAIL")

    # Создаём новый логгер — должен прочитать данные с диска
    logger2 = AIDecisionLogger(data_file=data_file)
    all_records = logger2.get_all()

    assert len(all_records) == 1
    assert all_records[0].id == rec.id
    assert all_records[0].control_id == "CC3.2"
    assert all_records[0].outcome == "FAIL"


# ── Тесты эвристики confidence ─────────────────────────────────────────────────

def test_confidence_high_for_detailed_output(tmp_log: AIDecisionLogger):
    """
    Детальный ответ с ссылками на стандарты, секциями и >500 слов
    должен давать высокий confidence (>= 0.9).
    """
    detailed_output = (
        "## Analysis\n"
        "This control CC6.1 meets SOC 2 AICPA requirements because MFA is enforced "
        "via Okta policies for all 120 accounts. ISO 27001 section 9.4 is also satisfied.\n\n"
        "## Evidence\n"
        "Okta audit logs confirm 100% MFA enrollment. AWS IAM uses hardware MFA for root. "
        + "Additional SOC 2 compliance detail. " * 80  # > 500 слов
    )
    rec = logger = tmp_log  # просто используем фикстуру напрямую
    confidence = _compute_confidence(detailed_output)
    assert confidence >= 0.9, f"Ожидался confidence >= 0.9, получили {confidence}"


def test_confidence_low_for_vague_output(tmp_log: AIDecisionLogger):
    """
    Расплывчатый короткий ответ со словами неуверенности
    должен давать низкий confidence (<= 0.6).
    """
    vague_output = "It might be unclear. The control could possibly be passing or not. Unsure."
    confidence = _compute_confidence(vague_output)
    assert confidence <= 0.6, f"Ожидался confidence <= 0.6, получили {confidence}"


def test_confidence_base_is_half(tmp_log: AIDecisionLogger):
    """Нейтральный ответ должен давать confidence ~0.6 (base 0.5 + нет слов неуверенности)."""
    neutral = "The control passes the audit review."
    confidence = _compute_confidence(neutral)
    assert 0.55 <= confidence <= 0.65, f"Ожидался confidence ~0.6, получили {confidence}"


# ── Тесты фильтрации ──────────────────────────────────────────────────────────

def test_get_all_returns_list(tmp_log: AIDecisionLogger):
    """get_all() без фильтров возвращает все записи."""
    _make_record(tmp_log, control_id="CC6.1")
    _make_record(tmp_log, control_id="CC3.2")
    _make_record(tmp_log, control_id="CC7.4")

    result = tmp_log.get_all()
    assert len(result) == 3
    # Порядок: от новых к старым
    assert result[0].control_id == "CC7.4"
    assert result[-1].control_id == "CC6.1"


def test_filter_by_type(tmp_log: AIDecisionLogger):
    """get_all(decision_type=...) возвращает только записи нужного типа."""
    _make_record(tmp_log, decision_type=DecisionType.GAP_ANALYSIS)
    _make_record(tmp_log, decision_type=DecisionType.POLICY_GENERATION)
    _make_record(tmp_log, decision_type=DecisionType.GAP_ANALYSIS)

    result = tmp_log.get_all(decision_type="gap_analysis")
    assert len(result) == 2
    assert all(r.decision_type == DecisionType.GAP_ANALYSIS for r in result)


def test_filter_by_control(tmp_log: AIDecisionLogger):
    """get_all(control_id=...) возвращает только записи по нужному контролу."""
    _make_record(tmp_log, control_id="CC6.1")
    _make_record(tmp_log, control_id="CC3.2")
    _make_record(tmp_log, control_id="CC6.1")

    result = tmp_log.get_all(control_id="CC6.1")
    assert len(result) == 2
    assert all(r.control_id == "CC6.1" for r in result)


# ── Тесты поиска по ID ────────────────────────────────────────────────────────

def test_get_by_id(tmp_log: AIDecisionLogger):
    """get_by_id() находит запись по UUID."""
    rec = _make_record(tmp_log, outcome="PASS")
    found = tmp_log.get_by_id(rec.id)

    assert found is not None
    assert found.id == rec.id
    assert found.outcome == "PASS"


def test_get_by_id_returns_none_for_unknown(tmp_log: AIDecisionLogger):
    """get_by_id() возвращает None для несуществующего UUID."""
    result = tmp_log.get_by_id("00000000-0000-4000-8000-000000000000")
    assert result is None


# ── Тесты статистики ──────────────────────────────────────────────────────────

def test_stats_structure(tmp_log: AIDecisionLogger):
    """get_stats() возвращает корректную структуру с нужными полями."""
    _make_record(tmp_log, decision_type=DecisionType.GAP_ANALYSIS, outcome="FAIL")
    _make_record(tmp_log, decision_type=DecisionType.POLICY_GENERATION, outcome="draft")

    stats = tmp_log.get_stats()

    assert "total" in stats
    assert "by_type" in stats
    assert "avg_confidence" in stats
    assert "avg_duration_ms" in stats
    assert "by_outcome" in stats

    assert stats["total"] == 2
    assert stats["by_type"]["gap_analysis"] == 1
    assert stats["by_type"]["policy_generation"] == 1
    assert stats["by_outcome"]["FAIL"] == 1
    assert stats["by_outcome"]["draft"] == 1
    assert 0.0 <= stats["avg_confidence"] <= 1.0


def test_stats_empty_logger(tmp_log: AIDecisionLogger):
    """get_stats() при пустом хранилище возвращает нули."""
    stats = tmp_log.get_stats()
    assert stats["total"] == 0
    assert stats["avg_confidence"] == 0.0
    assert stats["avg_duration_ms"] == 0


# ── Тест FIFO-лимита ──────────────────────────────────────────────────────────

def test_maxlen_500_fifo(tmp_path: Path):
    """
    При записи 501-й записи старейшая (первая) удаляется.
    В хранилище остаётся ровно 500 записей.
    """
    data_file = tmp_path / "fifo_test.json"
    logger = AIDecisionLogger(data_file=data_file)

    # Записываем 500 записей с маркером в первой
    first_rec = _make_record(logger, outcome="FIRST_MARKER")
    for i in range(499):
        _make_record(logger, outcome=f"record_{i}", duration_ms=i)

    assert len(logger.get_all(limit=500)) == 500

    # Добавляем 501-ю запись
    last_rec = _make_record(logger, outcome="LAST")

    all_records = logger.get_all(limit=500)
    assert len(all_records) == 500, f"Ожидалось 500 записей, получили {len(all_records)}"

    # Первая запись должна быть вытеснена
    ids = {r.id for r in all_records}
    assert first_rec.id not in ids, "Старейшая запись должна быть вытеснена FIFO"
    assert last_rec.id in ids, "Последняя запись должна присутствовать"


# ── Тест audit trail ──────────────────────────────────────────────────────────

def test_get_audit_trail_for_control(tmp_log: AIDecisionLogger):
    """get_audit_trail() возвращает упрощённый список только для нужного контроля."""
    _make_record(tmp_log, control_id="CC6.1", outcome="PASS")
    _make_record(tmp_log, control_id="CC6.1", outcome="FAIL")
    _make_record(tmp_log, control_id="CC3.2", outcome="PASS")  # другой контрол

    trail = tmp_log.get_audit_trail("CC6.1")

    assert len(trail) == 2
    for item in trail:
        assert "id" in item
        assert "date" in item
        assert "model" in item
        assert "outcome" in item
        assert "confidence" in item
        assert "decision_type" in item
        # prompt_summary и output_summary НЕ должны быть в audit trail
        assert "prompt_summary" not in item
        assert "output_summary" not in item
