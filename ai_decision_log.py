"""
AI Decision Log — Explainability Layer для SOC 2 compliance sandbox.

Логирует каждый AI-вызов с полным decision trace, чтобы аудитор мог ответить
на вопрос "Почему AI решил что этот контроль PASS?".

Хранение: data/ai_decisions.json, FIFO-очередь максимум 500 записей.
"""

from __future__ import annotations

import json
import re
import uuid
from collections import deque
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from log_config import get_logger

log = get_logger(__name__)

# ── Глобальный синглтон ───────────────────────────────────────────────────────
# Используем единственный экземпляр через get_decision_logger(),
# чтобы policy_agent, gap_analysis_agent и роутер делили одну deque и
# не создавали race condition при параллельной записи в один файл.
_GLOBAL_LOGGER_INSTANCE: "AIDecisionLogger | None" = None


def get_decision_logger() -> "AIDecisionLogger":
    """Возвращает глобальный синглтон AIDecisionLogger."""
    global _GLOBAL_LOGGER_INSTANCE
    if _GLOBAL_LOGGER_INSTANCE is None:
        _GLOBAL_LOGGER_INSTANCE = AIDecisionLogger()
    return _GLOBAL_LOGGER_INSTANCE


# ── Константы ─────────────────────────────────────────────────────────────────

_DATA_DIR = Path(__file__).parent / "data"
_DECISIONS_FILE = _DATA_DIR / "ai_decisions.json"
_MAX_RECORDS = 500

# Слова неуверенности, снижающие confidence
_UNCERTAINTY_WORDS = frozenset(
    {"unclear", "unsure", "might", "maybe", "possibly", "uncertain",
     "not sure", "could be", "perhaps", "i'm not", "may not"}
)

# Паттерн для обнаружения ссылок на стандарты и контроли (CC6.1, SOC2, AICPA …)
_CONTROL_REF_PATTERN = re.compile(
    r"\b(CC\d+\.\d+|SOC\s*2|AICPA|ISO\s*27001|NIST|TSC|GDPR|PCI\s*DSS)\b",
    re.IGNORECASE,
)


# ── Enums и Dataclasses ───────────────────────────────────────────────────────

class DecisionType(str, Enum):
    POLICY_GENERATION  = "policy_generation"
    GAP_ANALYSIS       = "gap_analysis"
    CONTROL_ASSESSMENT = "control_assessment"
    RISK_SCORING       = "risk_scoring"
    VENDOR_ASSESSMENT  = "vendor_assessment"


@dataclass
class AIDecisionRecord:
    id: str                        # uuid4
    decision_type: DecisionType
    control_id: Optional[str]      # CC6.1 или None
    model: str                     # "claude-haiku-4-5" / "qwen2.5:7b"
    prompt_summary: str            # первые 500 символов промпта (не полный)
    evidence_used: list[str]       # список ID evidence которые были переданы
    output_summary: str            # первые 300 символов ответа
    reasoning: str                 # извлечённый reasoning (если есть CoT)
    confidence: float              # 0.0–1.0, вычисляется эвристически
    outcome: str                   # "PASS" / "FAIL" / "draft" / "risk_level:high"
    duration_ms: int
    created_by: str                # "ai:model_name"
    created_at: str
    metadata: dict = field(default_factory=dict)


# ── Эвристика уверенности ──────────────────────────────────────────────────────

def _compute_confidence(output: str) -> float:
    """
    Вычисляет confidence 0.0–1.0 по ответу LLM.

    Алгоритм:
      base = 0.5
      +0.2 — длина ответа > 500 слов
      +0.2 — наличие ссылок на стандарты/контроли (CC6.1, SOC 2 …)
      +0.1 — отсутствие слов неуверенности
      +0.1 — наличие структурированных секций (##)
    """
    base = 0.5
    words = output.split()

    if len(words) > 500:
        base += 0.2

    if _CONTROL_REF_PATTERN.search(output):
        base += 0.2

    output_lower = output.lower()
    has_uncertainty = any(w in output_lower for w in _UNCERTAINTY_WORDS)
    if not has_uncertainty:
        base += 0.1

    if re.search(r"^##\s+\S", output, re.MULTILINE):
        base += 0.1

    return min(round(base, 2), 1.0)


def _extract_reasoning(output: str) -> str:
    """
    Извлекает блок reasoning из ответа LLM.

    Ищет секции "reasoning:", "rationale:", "because:", "analysis:"
    или первые 3 предложения если явного блока нет.
    """
    # Ищем явный блок reasoning
    reasoning_re = re.compile(
        r"(?:reasoning|rationale|analysis|because)[:\s]+(.{20,500})",
        re.IGNORECASE | re.DOTALL,
    )
    m = reasoning_re.search(output[:2000])
    if m:
        snippet = m.group(1).strip()
        # Обрезаем до первого двойного переноса строки или 400 символов
        end = snippet.find("\n\n")
        return snippet[: end if end > 0 else 400]

    # Fallback: первые 3 предложения
    sentences = re.split(r"(?<=[.!?])\s+", output.strip())
    return " ".join(sentences[:3])[:400]


# ── Ontology context builder ──────────────────────────────────────────────────

def _build_ontology_context(control_id: str) -> dict:
    """
    Строит словарь ontology context для вставки в metadata AI-решения.

    Включает risk_weight, evidence_types, frameworks и sla_hours контроля.
    При недоступности онтологии возвращает минимальный словарь с флагом.

    Args:
        control_id: строка вида "CC6.1"

    Returns:
        Словарь с семантическими данными контроля или {"available": False} при ошибке.
    """
    try:
        from compliance_ontology import get_ontology_engine
        engine = get_ontology_engine()
        ctrl = engine.get_control(control_id)
        if ctrl is None:
            return {"available": False, "reason": "control_not_found"}
        return {
            "available": True,
            "risk_weight": ctrl.risk_weight,
            "evidence_types": list(ctrl.evidence_types),
            "requires": list(ctrl.requires),
            "sla_hours": ctrl.sla_hours,
            "auto_remediable": ctrl.auto_remediable,
            "owner_role": ctrl.owner_role,
            "audit_frequency": ctrl.audit_frequency,
            "frameworks": {
                "iso27001": list(ctrl.iso27001),
                "nist": list(ctrl.nist),
                "cis": list(ctrl.cis),
            },
        }
    except Exception as exc:
        log.debug("Не удалось загрузить ontology context для %s: %s", control_id, exc)
        return {"available": False, "reason": str(exc)}


# ── Хранилище ──────────────────────────────────────────────────────────────────

class AIDecisionLogger:
    """
    Логгер AI-решений с хранением в data/ai_decisions.json.

    FIFO-очередь: при превышении _MAX_RECORDS старейшие записи удаляются.
    Thread-safety: запись блокирующая (достаточно для single-process FastAPI).
    """

    def __init__(self, data_file: Path = _DECISIONS_FILE):
        self._file = data_file
        self._data_dir = data_file.parent
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._records: deque[AIDecisionRecord] = deque(
            self._load_from_disk(), maxlen=_MAX_RECORDS
        )

    # ── Персистентность ───────────────────────────────────────────────────────

    def _load_from_disk(self) -> list[AIDecisionRecord]:
        if not self._file.exists():
            return []
        try:
            with open(self._file, "r", encoding="utf-8") as fh:
                raw: list[dict] = json.load(fh)
            records = []
            for item in raw:
                try:
                    item["decision_type"] = DecisionType(item["decision_type"])
                    records.append(AIDecisionRecord(**item))
                except (KeyError, ValueError, TypeError) as exc:
                    log.warning("Пропущена повреждённая запись ai_decisions: %s", exc)
            return records
        except Exception as exc:
            log.error("Не удалось прочитать %s: %s", self._file, exc)
            return []

    def _save_to_disk(self) -> None:
        try:
            data = []
            for rec in self._records:
                d = asdict(rec)
                d["decision_type"] = rec.decision_type.value
                data.append(d)
            with open(self._file, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
        except Exception as exc:
            log.error("Не удалось сохранить ai_decisions.json: %s", exc)

    # ── Основной публичный метод ───────────────────────────────────────────────

    def record(
        self,
        decision_type: DecisionType,
        model: str,
        prompt: str,
        output: str,
        outcome: str,
        control_id: Optional[str] = None,
        evidence_used: Optional[list[str]] = None,
        duration_ms: int = 0,
        metadata: Optional[dict] = None,
    ) -> AIDecisionRecord:
        """
        Записывает AI-решение и сохраняет на диск.

        Автоматически обогащает metadata ontology context (если control_id задан):
        risk_weight, required evidence_types, frameworks, sla_hours —
        для обеспечения полноты audit trail и AI reasoning explainability.

        Args:
            decision_type: тип операции (POLICY_GENERATION, GAP_ANALYSIS …)
            model: имя модели ("claude-haiku-4-5-20251001", "qwen2.5:7b" …)
            prompt: исходный промпт — сохраняется только [:500] (безопасность)
            output: ответ LLM — сохраняется только [:300] в summary
            outcome: итог ("PASS", "FAIL", "draft", "risk_level:high" …)
            control_id: код контроля ("CC6.1") или None
            evidence_used: список ID evidence, переданных в контекст
            duration_ms: время вызова в миллисекундах
            metadata: произвольные доп. поля

        Returns:
            AIDecisionRecord с заполненными полями и ontology context в metadata
        """
        # Обогащаем metadata данными из онтологии (если control_id задан)
        enriched_metadata = dict(metadata or {})
        if control_id:
            enriched_metadata["ontology_context"] = _build_ontology_context(control_id)

        rec = AIDecisionRecord(
            id=str(uuid.uuid4()),
            decision_type=decision_type,
            control_id=control_id,
            model=model,
            prompt_summary=prompt[:500],
            evidence_used=evidence_used or [],
            output_summary=output[:300],
            reasoning=_extract_reasoning(output),
            confidence=_compute_confidence(output),
            outcome=outcome,
            duration_ms=duration_ms,
            created_by=f"ai:{model}",
            created_at=datetime.now(timezone.utc).isoformat(),
            metadata=enriched_metadata,
        )
        # deque с maxlen автоматически удаляет старейшие при превышении лимита
        self._records.append(rec)
        self._save_to_disk()
        log.info(
            "AI decision logged: type=%s control=%s outcome=%s confidence=%.2f id=%s",
            decision_type.value, control_id, outcome, rec.confidence, rec.id,
        )
        return rec

    # ── Запросы ───────────────────────────────────────────────────────────────

    def get_all(
        self,
        decision_type: Optional[str] = None,
        control_id: Optional[str] = None,
        limit: int = 50,
    ) -> list[AIDecisionRecord]:
        """
        Возвращает записи в порядке от новых к старым с опциональной фильтрацией.

        Args:
            decision_type: фильтр по типу (строка, например "gap_analysis")
            control_id: фильтр по коду контроля ("CC6.1")
            limit: максимальное количество записей (по умолчанию 50)
        """
        records = list(reversed(self._records))

        if decision_type:
            records = [r for r in records if r.decision_type.value == decision_type]
        if control_id:
            records = [r for r in records if r.control_id == control_id]

        return records[:limit]

    def get_by_id(self, decision_id: str) -> Optional[AIDecisionRecord]:
        """Возвращает одну запись по UUID или None если не найдена."""
        for rec in self._records:
            if rec.id == decision_id:
                return rec
        return None

    def get_for_control(self, control_id: str) -> list[AIDecisionRecord]:
        """Все решения по конкретному контролу, от новых к старым."""
        return [r for r in reversed(self._records) if r.control_id == control_id]

    def get_stats(self) -> dict:
        """
        Агрегированная статистика по всем записям.

        Returns:
            dict с полями: total, by_type, avg_confidence, avg_duration_ms, by_outcome
        """
        records = list(self._records)
        total = len(records)

        if total == 0:
            return {
                "total": 0,
                "by_type": {},
                "avg_confidence": 0.0,
                "avg_duration_ms": 0,
                "by_outcome": {},
            }

        by_type: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        total_confidence = 0.0
        total_duration = 0

        for rec in records:
            by_type[rec.decision_type.value] = by_type.get(rec.decision_type.value, 0) + 1
            by_outcome[rec.outcome] = by_outcome.get(rec.outcome, 0) + 1
            total_confidence += rec.confidence
            total_duration += rec.duration_ms

        return {
            "total": total,
            "by_type": by_type,
            "avg_confidence": round(total_confidence / total, 3),
            "avg_duration_ms": round(total_duration / total),
            "by_outcome": by_outcome,
        }

    def get_audit_trail(self, control_id: str) -> list[dict]:
        """
        Упрощённый audit trail для аудитора — только ключевые поля.

        Returns:
            Список dict: date, model, outcome, confidence, decision_type, id
        """
        records = self.get_for_control(control_id)
        return [
            {
                "id": r.id,
                "date": r.created_at,
                "model": r.model,
                "decision_type": r.decision_type.value,
                "outcome": r.outcome,
                "confidence": r.confidence,
            }
            for r in records
        ]
