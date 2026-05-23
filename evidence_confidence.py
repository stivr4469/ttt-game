"""
Evidence Confidence Scoring — вероятностная модель доверия к единицам evidence.

Заменяет бинарную модель "есть/нет" на многофакторный скор 0–100.
Факторы: свежесть, целостность (хеш), источник, полнота содержимого.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from log_config import get_logger

log = get_logger(__name__)

# ── Пороги рекомендаций ────────────────────────────────────────────────────────
_THRESHOLD_ACCEPTABLE = 60   # >= 60 → acceptable
_THRESHOLD_REVIEW     = 35   # 35–59 → review_needed
# < 35 → critical

# ── Источники с известным уровнем доверия ────────────────────────────────────
_HIGH_TRUST_SOURCES   = frozenset({"aws", "github", "okta", "scanner"})
_MEDIUM_TRUST_SOURCES = frozenset({"hr_agent", "mdm_agent", "script"})
_LOW_TRUST_SOURCES    = frozenset({"manual", "upload", "user"})

# ── Веса компонентов (сумма максимумов = 104, нормализуем через min(sum, 100)) ─
_MAX_FRESHNESS    = 40
_MAX_INTEGRITY    = 30
_MAX_SOURCE_TRUST = 22
_MAX_COMPLETENESS = 12


class IntegrityStatus(str, Enum):
    VERIFIED   = "verified"    # SHA-хеш совпадает
    UNVERIFIED = "unverified"  # хеша нет или формат неизвестен
    TAMPERED   = "tampered"    # хеш не совпадает (флаг hash_mismatch)


class SourceTrust(str, Enum):
    HIGH   = "high"    # API-интеграция (AWS, Okta, GitHub)
    MEDIUM = "medium"  # скрипт/агент
    LOW    = "low"     # ручная загрузка


@dataclass
class EvidenceScore:
    evidence_id: str
    control_id: str
    confidence: int                # 0–100 итоговый балл (integer)
    freshness_hours: float         # часов с момента сбора
    integrity: IntegrityStatus
    source_trust: SourceTrust
    score_breakdown: dict          # {"freshness": 35, "integrity": 30, "source_trust": 22, "completeness": 12}
    scored_at: str                 # ISO UTC метка скоринга
    flags: list[str] = field(default_factory=list)   # ["stale_evidence", "no_hash", "manual_upload"]


# ── Вспомогательные функции ───────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(ts: str) -> Optional[datetime]:
    """
    Разбирает ISO-строку со временем. Поддерживает форматы:
    - "2025-05-20T12:00:00+00:00"
    - "2025-05-20T12:00:00Z"
    - "2025-05-20T12:00:00"
    - "2025-05-20T12:00:00.123456"
    """
    if not ts:
        return None
    # Python 3.11+ fromisoformat поддерживает суффикс 'Z', но для совместимости нормализуем
    normalized = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        pass
    # Наивная дата без timezone — трактуем как UTC
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ── Основной класс ────────────────────────────────────────────────────────────

class EvidenceConfidenceScorer:
    """
    Вероятностная модель доверия к единицам SOC2 evidence.

    Каждая запись evidence оценивается по четырём факторам:
    1. Свежесть (0–40 pts) — насколько недавно собрано evidence
    2. Целостность (0–30 pts) — наличие и корректность SHA-хеша
    3. Доверие к источнику (0–22 pts) — тип источника (API vs ручная загрузка)
    4. Полнота (0–12 pts) — длина контента, наличие метаданных

    Итоговый confidence = min(сумма, 100), целое число.
    """

    # ── Публичный API ──────────────────────────────────────────────────────────

    def score_evidence(self, evidence: dict) -> EvidenceScore:
        """
        Вычисляет EvidenceScore для одной записи evidence.

        evidence — dict из EvidenceClient.get_evidence():
          обязательные поля: id, control_id, source, collected_at
          опциональные: content, hash, metadata, hash_mismatch
        """
        evidence_id = str(evidence.get("id", "unknown"))
        control_id  = str(evidence.get("control_id", "unknown"))
        flags: list[str] = []

        # Компоненты скора
        freshness_pts, hours_ago = self._compute_freshness_score(
            evidence.get("collected_at", ""), flags
        )
        integrity_pts, integrity_status = self._compute_integrity_score(evidence, flags)
        source_trust_pts, source_trust = self._compute_source_trust_score(
            evidence.get("source", ""), flags
        )
        completeness_pts = self._compute_completeness_score(evidence)

        total = min(
            freshness_pts + integrity_pts + source_trust_pts + completeness_pts,
            100,
        )

        log.debug(
            "Evidence scored",
            extra={
                "evidence_id": evidence_id,
                "confidence": total,
                "flags": flags,
            },
        )

        return EvidenceScore(
            evidence_id=evidence_id,
            control_id=control_id,
            confidence=int(total),
            freshness_hours=round(hours_ago, 2),
            integrity=integrity_status,
            source_trust=source_trust,
            score_breakdown={
                "freshness":    freshness_pts,
                "integrity":    integrity_pts,
                "source_trust": source_trust_pts,
                "completeness": completeness_pts,
            },
            scored_at=_now_iso(),
            flags=flags,
        )

    def score_bulk(self, evidence_list: list[dict]) -> list[EvidenceScore]:
        """Вычисляет скор для списка evidence записей."""
        return [self.score_evidence(ev) for ev in evidence_list]

    def score_control(self, control_id: str, evidence_list: list[dict]) -> dict:
        """
        Агрегированный скор по одному контролу.

        Возвращает:
        {
          "control_id": "...",
          "overall_confidence": 78,    # простое среднее по всему evidence контрола
          "evidence_count": 5,
          "min_confidence": 45,
          "stale_count": 1,            # evidence с флагом stale_evidence
          "unverified_count": 2,       # unverified + tampered
          "recommendation": "acceptable" | "review_needed" | "critical"
        }
        """
        scores = self.score_bulk(evidence_list)
        return self._aggregate_scores(control_id, scores)

    def get_confidence_report(self, evidence_list: list[dict]) -> dict:
        """
        Полный отчёт: скор каждого evidence + агрегат по контролам.

        Скоринг выполняется один раз; агрегаты строятся из уже готовых EvidenceScore
        без повторного вызова score_bulk.

        Возвращает:
        {
          "scored_at": "...",
          "total_evidence": N,
          "controls": [ score_control(ctrl_id, ...) for each ctrl ],
          "evidence_scores": [ EvidenceScore serialized for each ev ],
          "summary": { "avg_confidence": ..., "stale_count": ..., ... }
        }
        """
        scores = self.score_bulk(evidence_list)

        # Агрегируем по control_id из уже готовых EvidenceScore (без повторного скоринга)
        by_control_scores: dict[str, list[EvidenceScore]] = {}
        for s in scores:
            by_control_scores.setdefault(s.control_id, []).append(s)

        control_aggregates = [
            self._aggregate_scores(cid, ctrl_scores)
            for cid, ctrl_scores in by_control_scores.items()
        ]

        # Сводная статистика
        all_conf       = [s.confidence for s in scores]
        avg_conf       = int(round(sum(all_conf) / len(all_conf))) if all_conf else 0
        stale_total    = sum(1 for s in scores if "stale_evidence" in s.flags)
        manual_total   = sum(1 for s in scores if "manual_upload" in s.flags)
        tampered_total = sum(1 for s in scores if "tampered_evidence" in s.flags)

        return {
            "scored_at": _now_iso(),
            "total_evidence": len(scores),
            "controls": control_aggregates,
            "evidence_scores": [self.score_to_dict(s) for s in scores],
            "summary": {
                "avg_confidence":        avg_conf,
                "stale_count":           stale_total,
                "manual_upload_count":   manual_total,
                "tampered_count":        tampered_total,
                "low_confidence_count":  sum(1 for c in all_conf if c < _THRESHOLD_REVIEW),
            },
        }

    # ── Приватные методы вычисления ────────────────────────────────────────────

    def _compute_freshness_score(
        self, collected_at: str, flags: list[str]
    ) -> tuple[int, float]:
        """
        Возвращает (score, hours_ago).

        < 1h  → 40 pts
        < 4h  → 35 pts
        < 24h → 25 pts
        < 48h → 15 pts
        < 7d  → 5 pts
        >= 7d → 0 pts + flag "stale_evidence"
        Нет метки → 0 pts + flag "stale_evidence"
        """
        if not collected_at:
            flags.append("stale_evidence")
            return 0, -1.0   # -1.0 означает "возраст неизвестен"

        dt = _parse_iso(collected_at)
        if dt is None:
            log.warning("Не удалось распознать collected_at", extra={"value": collected_at})
            flags.append("stale_evidence")
            return 0, -1.0   # -1.0 означает "возраст неизвестен"

        now = datetime.now(timezone.utc)
        # Если dt наивная — добавляем UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        delta_seconds = (now - dt).total_seconds()
        hours_ago = delta_seconds / 3600.0

        if hours_ago < 0:
            # evidence из будущего — считаем как very fresh
            return _MAX_FRESHNESS, 0.0

        if hours_ago < 1:
            return 40, hours_ago
        if hours_ago < 4:
            return 35, hours_ago
        if hours_ago < 24:
            return 25, hours_ago
        if hours_ago < 48:
            return 15, hours_ago
        if hours_ago < 168:   # 7 * 24
            return 5, hours_ago

        flags.append("stale_evidence")
        return 0, hours_ago

    def _compute_integrity_score(
        self, evidence: dict, flags: list[str]
    ) -> tuple[int, IntegrityStatus]:
        """
        has hash field and hash starts with "sha256:" → verified → 30 pts
        has hash but format unknown                   → unverified → 15 pts
        no hash                                       → unverified → 10 pts + flag "no_hash"
        hash_mismatch flag present                    → tampered → 0 pts + flag "tampered_evidence"
        """
        # Приоритет: явный сигнал о подмене
        if evidence.get("hash_mismatch"):
            flags.append("tampered_evidence")
            return 0, IntegrityStatus.TAMPERED

        hash_value = evidence.get("hash") or evidence.get("sha256") or ""

        if not hash_value:
            flags.append("no_hash")
            return 10, IntegrityStatus.UNVERIFIED

        if str(hash_value).startswith("sha256:"):
            return 30, IntegrityStatus.VERIFIED

        # Хеш есть, но формат неизвестен
        return 15, IntegrityStatus.UNVERIFIED

    def _compute_source_trust_score(
        self, source: str, flags: list[str]
    ) -> tuple[int, SourceTrust]:
        """
        source in HIGH_TRUST_SOURCES   → high → 22 pts
        source in MEDIUM_TRUST_SOURCES → medium → 14 pts
        source in LOW_TRUST_SOURCES    → low → 6 pts + flag "manual_upload"
        unknown                        → medium → 10 pts
        """
        normalized = source.strip().lower()

        if normalized in _HIGH_TRUST_SOURCES:
            return 22, SourceTrust.HIGH

        if normalized in _MEDIUM_TRUST_SOURCES:
            return 14, SourceTrust.MEDIUM

        if normalized in _LOW_TRUST_SOURCES:
            flags.append("manual_upload")
            return 6, SourceTrust.LOW

        # Неизвестный источник — medium с пониженным баллом
        log.debug("Неизвестный источник evidence", extra={"source": source})
        return 10, SourceTrust.MEDIUM

    def _compute_completeness_score(self, evidence: dict) -> int:
        """
        content length > 100 chars → 8 pts
        has metadata field         → 4 pts
        total max 12 pts
        """
        pts = 0
        content = evidence.get("content") or ""
        if len(str(content)) > 100:
            pts += 8

        if evidence.get("metadata") is not None:
            pts += 4

        return min(pts, _MAX_COMPLETENESS)

    # ── Вспомогательные методы ─────────────────────────────────────────────────

    def _aggregate_scores(self, control_id: str, scores: list[EvidenceScore]) -> dict:
        """
        Строит агрегат по контролу из уже готовых EvidenceScore.
        Вызывается как из score_control, так и из get_confidence_report (без повторного скоринга).
        """
        if not scores:
            return {
                "control_id": control_id,
                "overall_confidence": 0,
                "evidence_count": 0,
                "min_confidence": 0,
                "stale_count": 0,
                "unverified_count": 0,
                "recommendation": "critical",
            }

        confidences      = [s.confidence for s in scores]
        overall          = int(round(sum(confidences) / len(confidences)))
        min_conf         = min(confidences)
        stale_count      = sum(1 for s in scores if "stale_evidence" in s.flags)
        unverified_count = sum(
            1 for s in scores
            if s.integrity in (IntegrityStatus.UNVERIFIED, IntegrityStatus.TAMPERED)
        )

        return {
            "control_id": control_id,
            "overall_confidence": overall,
            "evidence_count": len(scores),
            "min_confidence": min_conf,
            "stale_count": stale_count,
            "unverified_count": unverified_count,
            "recommendation": self._recommendation(overall),
        }

    @staticmethod
    def _recommendation(overall_confidence: int) -> str:
        """Переводит числовой confidence в текстовую рекомендацию."""
        if overall_confidence >= _THRESHOLD_ACCEPTABLE:
            return "acceptable"
        if overall_confidence >= _THRESHOLD_REVIEW:
            return "review_needed"
        return "critical"

    @staticmethod
    def score_to_dict(score: EvidenceScore) -> dict:
        """Сериализует EvidenceScore в dict для API-ответов. JSON-безопасный."""
        # freshness_hours = -1.0 означает "неизвестно"; для API заменяем на null
        freshness: float | None = score.freshness_hours if score.freshness_hours >= 0 else None
        return {
            "evidence_id":     score.evidence_id,
            "control_id":      score.control_id,
            "confidence":      score.confidence,
            "freshness_hours": freshness,
            "integrity":       score.integrity.value,
            "source_trust":    score.source_trust.value,
            "score_breakdown": score.score_breakdown,
            "scored_at":       score.scored_at,
            "flags":           score.flags,
        }
