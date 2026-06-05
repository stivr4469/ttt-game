"""
compliance_engine_routes.py — FastAPI роуты для ComplianceEngine.

Предоставляет REST API для:
  - Детерминированной оценки контролей
  - Расчёта compliance score
  - Поиска контролей с недостаточными доказательствами

Все эндпоинты используют ComplianceEngine (authority path).
AI-советы опциональны и явно помечены как advisory.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from auth import require_auth
from pydantic import BaseModel

from compliance_engine import (
    ComplianceEngine,
    ControlVerdict,
    VerdictStatus,
    get_compliance_engine,
)
from log_config import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/engine", tags=["compliance-engine"])


# ── Pydantic-схемы ─────────────────────────────────────────────────────────────

class EvidenceItem(BaseModel):
    """Единица evidence для оценки контроля."""
    id:            Optional[str] = None
    status:        str           = "PENDING"  # "PASS" | "FAIL" | "PENDING"
    evidence_type: Optional[str] = None
    title:         Optional[str] = None
    source:        Optional[str] = None


class EvaluateRequest(BaseModel):
    """Тело запроса для POST /evaluate/{control_id}."""
    evidence: list[EvidenceItem] = []


class VerdictResponse(BaseModel):
    """Ответ оценки контроля."""
    control_id:       str
    status:           str
    confidence:       float
    reasons:          list[str]
    missing_evidence: list[str]
    ai_suggestion:    Optional[str] = None
    evaluated_at:     str


class ScoreResponse(BaseModel):
    """Ответ расчёта compliance score."""
    score:          float
    total_controls: int
    pass_count:     int
    fail_count:     int
    needs_review:   int
    calculated_at:  str


class MissingEvidenceItem(BaseModel):
    """Контроль с недостаточными доказательствами."""
    control_id:       str
    status:           str
    missing_evidence: list[str]
    confidence:       float
    reasons:          list[str]


class MissingEvidenceResponse(BaseModel):
    """Ответ поиска контролей с недостаточными доказательствами."""
    items:         list[MissingEvidenceItem]
    total:         int
    generated_at:  str


# ── Хелпер: загрузка evidence из Evidence Tracker ─────────────────────────────

def _load_evidence_for_control(control_id: str) -> list[dict]:
    """
    Загружает evidence для контроля из Evidence Tracker.
    При ошибке — возвращает пустой список (не блокирует оценку).
    """
    import os
    try:
        from evidence_client import EvidenceClient
        url = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")
        client = EvidenceClient(url, agent_name="compliance_engine")
        return client.get_evidence(control_id=control_id, limit=50)
    except Exception as exc:
        log.warning("Не удалось загрузить evidence для %s: %s", control_id, exc)
        return []


def _load_all_controls_evidence() -> dict[str, list[dict]]:
    """
    Загружает evidence для всех известных контролей.
    Возвращает словарь {control_id: [evidence...]}.
    """
    import os
    from compliance_engine import _REQUIRED_EVIDENCE_TYPES
    try:
        from evidence_client import EvidenceClient
        url = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")
        client = EvidenceClient(url, agent_name="compliance_engine")
        all_controls = client.get_controls()
    except Exception as exc:
        log.warning("Не удалось загрузить controls из Evidence Tracker: %s", exc)
        all_controls = []

    result: dict[str, list[dict]] = {}
    for ctrl in all_controls:
        ctrl_id = str(ctrl.get("id", ""))
        ctrl_code = ctrl.get("code", ctrl_id)
        ev_list = _load_evidence_for_control(ctrl_id)
        result[ctrl_code] = ev_list

    # Добавляем контроли из known mapping, если они не пришли из Evidence Tracker
    for code in _REQUIRED_EVIDENCE_TYPES:
        if code not in result:
            result[code] = []

    return result


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── GET /evaluate/{control_id} ─────────────────────────────────────────────────

@router.get(
    "/evaluate/{control_id}",
    response_model=VerdictResponse,
    summary="Детерминированная оценка контроля",
    description=(
        "Оценивает контроль на основе evidence из Evidence Tracker. "
        "Результат детерминирован — AI не участвует."
    ),
)
def evaluate_control(
    control_id: str,
    include_ai_suggestion: bool = Query(
        False,
        description="Включить AI-совет в ответ (advisory, не влияет на статус)",
    ),
) -> VerdictResponse:
    """
    Загружает evidence для контроля и возвращает детерминированный вердикт.

    Параметр include_ai_suggestion=true добавляет AI-рекомендацию (помечена
    как advisory — не влияет на статус контроля).
    """
    engine = get_compliance_engine()
    evidence = _load_evidence_for_control(control_id)

    verdict = engine.evaluate_control(control_id, evidence)

    # Добавляем AI-совет только если явно запрошено и есть проблемы
    ai_suggestion = None
    if include_ai_suggestion and verdict.status != VerdictStatus.PASS:
        try:
            from ai_advisor import get_ai_advisor
            advisor = get_ai_advisor()
            gap_desc = "; ".join(verdict.missing_evidence[:3]) or "; ".join(verdict.reasons[:2])
            advice = advisor.suggest_remediation(
                control_id=control_id,
                gap_description=gap_desc,
                evidence_ids=[str(ev.get("id", "")) for ev in evidence[:5]],
            )
            ai_suggestion = advice.suggestion
        except Exception as exc:
            log.warning("Не удалось получить AI-совет для %s: %s", control_id, exc)

    log.info(
        "GET /engine/evaluate/%s → %s (confidence=%.2f, evidence=%d)",
        control_id, verdict.status.value, verdict.confidence, len(evidence),
    )

    return VerdictResponse(
        control_id=verdict.control_id,
        status=verdict.status.value,
        confidence=verdict.confidence,
        reasons=verdict.reasons,
        missing_evidence=verdict.missing_evidence,
        ai_suggestion=ai_suggestion,
        evaluated_at=_now_iso(),
    )


# ── POST /evaluate/{control_id} ────────────────────────────────────────────────

@router.post(
    "/evaluate/{control_id}",
    response_model=VerdictResponse,
    summary="Оценка контроля с переданным evidence",
    description="Оценивает контроль на основе evidence из тела запроса (для тестирования).",
)
def evaluate_control_with_evidence(
    control_id: str,
    body: EvaluateRequest,
    _: dict = Depends(require_auth),
) -> VerdictResponse:
    """
    Оценивает контроль на основе evidence из тела запроса.
    Используется для тестирования и интеграции без Evidence Tracker.
    """
    engine = get_compliance_engine()
    evidence = [ev.model_dump() for ev in body.evidence]
    verdict = engine.evaluate_control(control_id, evidence)

    log.info(
        "POST /engine/evaluate/%s → %s (evidence=%d из request body)",
        control_id, verdict.status.value, len(evidence),
    )

    return VerdictResponse(
        control_id=verdict.control_id,
        status=verdict.status.value,
        confidence=verdict.confidence,
        reasons=verdict.reasons,
        missing_evidence=verdict.missing_evidence,
        ai_suggestion=None,  # POST-эндпоинт не добавляет AI-советов
        evaluated_at=_now_iso(),
    )


# ── GET /score ─────────────────────────────────────────────────────────────────

@router.get(
    "/score",
    response_model=ScoreResponse,
    summary="Общий compliance score",
    description=(
        "Вычисляет взвешенный compliance score 0–100 на основе всех контролей. "
        "Детерминированный расчёт без AI."
    ),
)
def get_compliance_score() -> ScoreResponse:
    """
    Загружает все контроли с evidence и вычисляет compliance score.

    Score = Σ(weight_i * score_i) / Σ(weight_i) * 100
    где score_i: PASS=1.0, NEEDS_REVIEW=0.5, FAIL=0.0
    """
    engine = get_compliance_engine()
    controls_evidences = _load_all_controls_evidence()

    if not controls_evidences:
        return ScoreResponse(
            score=0.0,
            total_controls=0,
            pass_count=0,
            fail_count=0,
            needs_review=0,
            calculated_at=_now_iso(),
        )

    verdicts = [
        engine.evaluate_control(ctrl_id, ev_list)
        for ctrl_id, ev_list in controls_evidences.items()
    ]

    score = engine.calculate_compliance_score(verdicts)

    # Статистика по статусам
    pass_count    = sum(1 for v in verdicts if v.status == VerdictStatus.PASS)
    fail_count    = sum(1 for v in verdicts if v.status == VerdictStatus.FAIL)
    review_count  = sum(1 for v in verdicts if v.status == VerdictStatus.NEEDS_REVIEW)

    log.info(
        "GET /engine/score → %.1f (pass=%d fail=%d review=%d total=%d)",
        score, pass_count, fail_count, review_count, len(verdicts),
    )

    return ScoreResponse(
        score=score,
        total_controls=len(verdicts),
        pass_count=pass_count,
        fail_count=fail_count,
        needs_review=review_count,
        calculated_at=_now_iso(),
    )


# ── GET /missing-evidence ──────────────────────────────────────────────────────

@router.get(
    "/missing-evidence",
    response_model=MissingEvidenceResponse,
    summary="Контроли с недостаточными доказательствами",
    description=(
        "Возвращает список контролей, которым не хватает evidence для PASS. "
        "Включает FAIL и NEEDS_REVIEW контроли."
    ),
)
def get_missing_evidence(
    status_filter: Optional[str] = Query(
        None,
        description="Фильтр по статусу: 'FAIL' | 'NEEDS_REVIEW' | None (все)",
    ),
) -> MissingEvidenceResponse:
    """
    Находит все контроли с недостаточными доказательствами.

    Полезно для:
    - Приоритизации сбора evidence
    - Планирования remediation
    - Подготовки к аудиту
    """
    engine = get_compliance_engine()
    controls_evidences = _load_all_controls_evidence()

    missing_items = engine.find_missing_evidence_controls(controls_evidences)

    # Применяем фильтр по статусу
    if status_filter and status_filter.upper() in ("FAIL", "NEEDS_REVIEW"):
        filter_val = status_filter.upper()
        missing_items = [
            item for item in missing_items
            if item["status"] == filter_val
        ]

    # Сортируем: FAIL первыми, потом NEEDS_REVIEW
    priority_order = {"FAIL": 0, "NEEDS_REVIEW": 1}
    missing_items.sort(key=lambda x: priority_order.get(x["status"], 9))

    items = [
        MissingEvidenceItem(
            control_id=item["control_id"],
            status=item["status"],
            missing_evidence=item["missing_evidence"],
            confidence=item["confidence"],
            reasons=item["reasons"],
        )
        for item in missing_items
    ]

    log.info(
        "GET /engine/missing-evidence → %d контролей с проблемами",
        len(items),
    )

    return MissingEvidenceResponse(
        items=items,
        total=len(items),
        generated_at=_now_iso(),
    )


# ── GET /required-evidence/{control_id} ───────────────────────────────────────

@router.get(
    "/required-evidence/{control_id}",
    summary="Required evidence types для контроля",
    description="Возвращает список типов evidence, необходимых для PASS этого контроля.",
)
def get_required_evidence(control_id: str) -> dict:
    """Список required evidence types для контроля (для planning purposes)."""
    engine = get_compliance_engine()
    required = engine.get_required_evidence_types(control_id)

    if not required and control_id not in []:
        # Не выбрасываем 404 — контроль может быть unknown (вернём пустой список)
        log.info("GET /engine/required-evidence/%s → unknown control (empty list)", control_id)

    return {
        "control_id":     control_id,
        "required_types": required,
        "count":          len(required),
    }
