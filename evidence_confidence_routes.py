"""
Evidence Confidence Scoring — FastAPI роутер.

Endpoints:
  GET /api/evidence-confidence/score/{evidence_id}     — скор одной записи
  GET /api/evidence-confidence/control/{control_id}    — агрегат по контролу
  GET /api/evidence-confidence/report                  — полный отчёт всех контролов
  GET /api/evidence-confidence/low-confidence          — ?threshold=50 — проблемные записи
  GET /api/evidence-confidence/summary                 — сводная статистика

Graceful degradation: при недоступности Evidence Tracker возвращает пустые данные,
не бросает 500.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Query

from auth import require_auth
from evidence_client import EvidenceClient, EvidenceClientError
from evidence_confidence import EvidenceConfidenceScorer
from log_config import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/evidence-confidence", tags=["evidence-confidence"])

# ── Зависимости ───────────────────────────────────────────────────────────────

_EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")

# Синглтон — EvidenceConfidenceScorer не хранит состояния, создавать один экземпляр на весь процесс
_scorer = EvidenceConfidenceScorer()


def _get_client() -> EvidenceClient:
    return EvidenceClient(_EVIDENCE_TRACKER_URL, agent_name="evidence_confidence")


def _get_scorer() -> EvidenceConfidenceScorer:
    return _scorer


def _fetch_all_evidence(client: EvidenceClient) -> list[dict]:
    """
    Получает все evidence. При ошибке соединения логирует и возвращает [].
    Graceful degradation — не бросает 500.
    """
    try:
        return client.get_evidence(limit=500)
    except EvidenceClientError as exc:
        log.warning("Evidence Tracker недоступен", extra={"error": str(exc)})
        return []
    except Exception as exc:
        log.error("Неожиданная ошибка при получении evidence", extra={"error": str(exc)})
        return []


def _fetch_evidence_by_control(client: EvidenceClient, control_id: str) -> list[dict]:
    """Возвращает evidence для конкретного контрола. При ошибке — []."""
    try:
        return client.get_evidence(control_id=control_id, limit=500)
    except EvidenceClientError as exc:
        log.warning(
            "Evidence Tracker недоступен для контрола",
            extra={"control_id": control_id, "error": str(exc)},
        )
        return []
    except Exception as exc:
        log.error(
            "Неожиданная ошибка при получении evidence по контролу",
            extra={"control_id": control_id, "error": str(exc)},
        )
        return []


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/score/{evidence_id}")
async def get_evidence_score(
    evidence_id: str,
    user: dict = Depends(require_auth),
    client: EvidenceClient = Depends(_get_client),
    scorer: EvidenceConfidenceScorer = Depends(_get_scorer),
):
    """
    Вычисляет confidence score для одной записи evidence по её ID.

    Если Evidence Tracker недоступен или запись не найдена — 404.
    """
    all_ev = _fetch_all_evidence(client)

    # Ищем запись по ID
    target = next(
        (ev for ev in all_ev if str(ev.get("id", "")) == evidence_id),
        None,
    )
    if target is None:
        raise HTTPException(
            status_code=404,
            detail=f"Evidence {evidence_id!r} not found or tracker unavailable",
        )

    score = scorer.score_evidence(target)
    return scorer.score_to_dict(score)


@router.get("/control/{control_id}")
async def get_control_confidence(
    control_id: str,
    user: dict = Depends(require_auth),
    client: EvidenceClient = Depends(_get_client),
    scorer: EvidenceConfidenceScorer = Depends(_get_scorer),
):
    """
    Агрегированный confidence score по всему evidence для одного контрола.

    При недоступности трекера возвращает агрегат с нулевым evidence_count.
    """
    evidence_list = _fetch_evidence_by_control(client, control_id)
    return scorer.score_control(control_id, evidence_list)


@router.get("/report")
async def get_confidence_report(
    user: dict = Depends(require_auth),
    client: EvidenceClient = Depends(_get_client),
    scorer: EvidenceConfidenceScorer = Depends(_get_scorer),
):
    """
    Полный отчёт confidence по всем контролам и всему evidence.

    При недоступности трекера возвращает пустой отчёт (не 500).
    """
    all_ev = _fetch_all_evidence(client)
    return scorer.get_confidence_report(all_ev)


@router.get("/low-confidence")
async def get_low_confidence_evidence(
    threshold: int = Query(default=50, ge=0, le=100, description="Верхний порог confidence (0-100)"),
    user: dict = Depends(require_auth),
    client: EvidenceClient = Depends(_get_client),
    scorer: EvidenceConfidenceScorer = Depends(_get_scorer),
):
    """
    Список evidence с confidence ниже порога (по умолчанию < 50).

    Возвращает отсортированный список: самые проблемные первыми.
    """
    all_ev = _fetch_all_evidence(client)
    scores = scorer.score_bulk(all_ev)

    low = [
        scorer.score_to_dict(s)
        for s in scores
        if s.confidence < threshold
    ]
    low.sort(key=lambda x: x["confidence"])

    return {
        "threshold": threshold,
        "total_found": len(low),
        "items": low,
    }


@router.get("/summary")
async def get_confidence_summary(
    user: dict = Depends(require_auth),
    client: EvidenceClient = Depends(_get_client),
    scorer: EvidenceConfidenceScorer = Depends(_get_scorer),
):
    """
    Сводная статистика по всему evidence:
    - avg_confidence
    - stale_count (> 48 ч)
    - по уровням доверия к источнику
    - распределение по confidence-диапазонам
    - количество tampered/no_hash записей
    """
    all_ev = _fetch_all_evidence(client)
    scores = scorer.score_bulk(all_ev)

    if not scores:
        return {
            "total_evidence": 0,
            "avg_confidence": 0,
            "stale_count": 0,
            "manual_upload_count": 0,
            "tampered_count": 0,
            "no_hash_count": 0,
            "source_trust_breakdown": {"high": 0, "medium": 0, "low": 0},
            "confidence_ranges": {
                "critical_0_34":    0,
                "review_35_59":     0,
                "acceptable_60_100": 0,
            },
            "tracker_available": False,
        }

    confidences = [s.confidence for s in scores]
    avg_conf = int(round(sum(confidences) / len(confidences)))

    source_breakdown = {"high": 0, "medium": 0, "low": 0}
    for s in scores:
        source_breakdown[s.source_trust.value] = (
            source_breakdown.get(s.source_trust.value, 0) + 1
        )

    return {
        "total_evidence": len(scores),
        "avg_confidence": avg_conf,
        "stale_count": sum(1 for s in scores if "stale_evidence" in s.flags),
        "manual_upload_count": sum(1 for s in scores if "manual_upload" in s.flags),
        "tampered_count": sum(1 for s in scores if "tampered_evidence" in s.flags),
        "no_hash_count": sum(1 for s in scores if "no_hash" in s.flags),
        "source_trust_breakdown": source_breakdown,
        "confidence_ranges": {
            "critical_0_34":     sum(1 for c in confidences if c < 35),
            "review_35_59":      sum(1 for c in confidences if 35 <= c < 60),
            "acceptable_60_100": sum(1 for c in confidences if c >= 60),
        },
        "tracker_available": bool(all_ev),
    }
