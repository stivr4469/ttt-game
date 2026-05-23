"""
Тесты для EvidenceConfidenceScorer — полное покрытие всех факторов.
"""
from __future__ import annotations

import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from evidence_confidence import (
    EvidenceConfidenceScorer,
    EvidenceScore,
    IntegrityStatus,
    SourceTrust,
)

# ── Хелперы ───────────────────────────────────────────────────────────────────

def _iso(hours_ago: float = 0) -> str:
    """Возвращает ISO-строку: текущее время минус hours_ago часов."""
    dt = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return dt.isoformat()


def _make_evidence(
    *,
    ev_id: str = "ev-001",
    control_id: str = "ctrl-001",
    collected_at: str | None = None,
    source: str = "aws",
    content: str = "x" * 200,
    hash_val: str | None = "sha256:abcdef1234567890",
    hash_mismatch: bool = False,
    metadata: dict | None = None,
    hours_ago: float = 2.0,
) -> dict:
    ev: dict = {
        "id": ev_id,
        "control_id": control_id,
        "collected_at": collected_at if collected_at is not None else _iso(hours_ago),
        "source": source,
        "content": content,
    }
    if hash_val is not None:
        ev["hash"] = hash_val
    if hash_mismatch:
        ev["hash_mismatch"] = True
    if metadata is not None:
        ev["metadata"] = metadata
    return ev


@pytest.fixture
def scorer() -> EvidenceConfidenceScorer:
    return EvidenceConfidenceScorer()


# ── 1. Свежее evidence → высокий скор ─────────────────────────────────────────

class TestFreshEvidence:
    def test_fresh_evidence_high_score(self, scorer: EvidenceConfidenceScorer):
        """Evidence собранное 30 минут назад должно получать freshness=40."""
        ev = _make_evidence(hours_ago=0.5, source="aws",
                            hash_val="sha256:abc123", metadata={"env": "prod"})
        score = scorer.score_evidence(ev)

        assert score.score_breakdown["freshness"] == 40
        # Полный набор: 40 + 30 + 22 + 12 = 104, ограничено до 100
        assert score.confidence == 100

    def test_evidence_under_4h_gets_35_freshness(self, scorer):
        ev = _make_evidence(hours_ago=2.0)
        score = scorer.score_evidence(ev)
        assert score.score_breakdown["freshness"] == 35

    def test_evidence_under_24h_gets_25_freshness(self, scorer):
        ev = _make_evidence(hours_ago=10.0)
        score = scorer.score_evidence(ev)
        assert score.score_breakdown["freshness"] == 25

    def test_evidence_under_48h_gets_15_freshness(self, scorer):
        ev = _make_evidence(hours_ago=36.0)
        score = scorer.score_evidence(ev)
        assert score.score_breakdown["freshness"] == 15

    def test_evidence_under_7d_gets_5_freshness(self, scorer):
        ev = _make_evidence(hours_ago=96.0)  # 4 дня
        score = scorer.score_evidence(ev)
        assert score.score_breakdown["freshness"] == 5

    def test_stale_evidence_low_score(self, scorer: EvidenceConfidenceScorer):
        """Evidence старше 7 дней → freshness=0, флаг stale_evidence."""
        ev = _make_evidence(hours_ago=200.0)  # > 7 дней
        score = scorer.score_evidence(ev)

        assert score.score_breakdown["freshness"] == 0
        assert "stale_evidence" in score.flags
        assert score.freshness_hours > 0


# ── 2. Целостность хеша ────────────────────────────────────────────────────────

class TestIntegrity:
    def test_verified_hash_integrity_high(self, scorer: EvidenceConfidenceScorer):
        """Хеш в формате sha256:... → integrity=verified, 30 pts."""
        ev = _make_evidence(hash_val="sha256:deadbeef1234")
        score = scorer.score_evidence(ev)

        assert score.integrity == IntegrityStatus.VERIFIED
        assert score.score_breakdown["integrity"] == 30

    def test_no_hash_unverified(self, scorer: EvidenceConfidenceScorer):
        """Отсутствие хеша → integrity=unverified, 10 pts, flag no_hash."""
        ev = _make_evidence(hash_val=None)
        score = scorer.score_evidence(ev)

        assert score.integrity == IntegrityStatus.UNVERIFIED
        assert score.score_breakdown["integrity"] == 10
        assert "no_hash" in score.flags

    def test_unknown_hash_format_unverified(self, scorer):
        """Хеш без префикса sha256: → unverified, 15 pts."""
        ev = _make_evidence(hash_val="md5:aabbcc112233")
        score = scorer.score_evidence(ev)

        assert score.integrity == IntegrityStatus.UNVERIFIED
        assert score.score_breakdown["integrity"] == 15
        assert "no_hash" not in score.flags

    def test_hash_mismatch_tampered(self, scorer):
        """hash_mismatch=True → tampered, 0 pts, flag tampered_evidence."""
        ev = _make_evidence(hash_val="sha256:abc", hash_mismatch=True)
        score = scorer.score_evidence(ev)

        assert score.integrity == IntegrityStatus.TAMPERED
        assert score.score_breakdown["integrity"] == 0
        assert "tampered_evidence" in score.flags


# ── 3. Источник evidence ──────────────────────────────────────────────────────

class TestSourceTrust:
    def test_aws_source_high_trust(self, scorer: EvidenceConfidenceScorer):
        """Источник 'aws' → source_trust=high, 22 pts."""
        ev = _make_evidence(source="aws")
        score = scorer.score_evidence(ev)

        assert score.source_trust == SourceTrust.HIGH
        assert score.score_breakdown["source_trust"] == 22

    @pytest.mark.parametrize("src", ["github", "okta", "scanner"])
    def test_known_high_trust_sources(self, scorer, src):
        ev = _make_evidence(source=src)
        score = scorer.score_evidence(ev)
        assert score.source_trust == SourceTrust.HIGH
        assert score.score_breakdown["source_trust"] == 22

    def test_manual_source_low_trust(self, scorer: EvidenceConfidenceScorer):
        """Источник 'manual' → source_trust=low, 6 pts, flag manual_upload."""
        ev = _make_evidence(source="manual")
        score = scorer.score_evidence(ev)

        assert score.source_trust == SourceTrust.LOW
        assert score.score_breakdown["source_trust"] == 6
        assert "manual_upload" in score.flags

    @pytest.mark.parametrize("src", ["upload", "user"])
    def test_other_low_trust_sources(self, scorer, src):
        ev = _make_evidence(source=src)
        score = scorer.score_evidence(ev)
        assert score.source_trust == SourceTrust.LOW

    @pytest.mark.parametrize("src", ["hr_agent", "mdm_agent", "script"])
    def test_medium_trust_sources(self, scorer, src):
        ev = _make_evidence(source=src)
        score = scorer.score_evidence(ev)
        assert score.source_trust == SourceTrust.MEDIUM
        assert score.score_breakdown["source_trust"] == 14

    def test_unknown_source_medium_fallback(self, scorer):
        """Неизвестный источник → medium с 10 pts (не 14 как известные medium-источники)."""
        ev = _make_evidence(source="some_unknown_tool")
        score = scorer.score_evidence(ev)
        assert score.source_trust == SourceTrust.MEDIUM
        assert score.score_breakdown["source_trust"] == 10


# ── 4. Флаги ──────────────────────────────────────────────────────────────────

class TestFlags:
    def test_flags_stale_evidence(self, scorer: EvidenceConfidenceScorer):
        """Evidence > 7 дней → флаг stale_evidence."""
        ev = _make_evidence(hours_ago=200.0)
        score = scorer.score_evidence(ev)
        assert "stale_evidence" in score.flags

    def test_flags_manual_upload(self, scorer: EvidenceConfidenceScorer):
        """Источник 'manual' → флаг manual_upload."""
        ev = _make_evidence(source="manual")
        score = scorer.score_evidence(ev)
        assert "manual_upload" in score.flags

    def test_no_flags_for_clean_evidence(self, scorer):
        """Чистое evidence без проблем — пустой список флагов."""
        ev = _make_evidence(
            hours_ago=1.0,
            source="aws",
            hash_val="sha256:clean",
            hash_mismatch=False,
        )
        score = scorer.score_evidence(ev)
        assert score.flags == []

    def test_multiple_flags_accumulated(self, scorer):
        """Несколько проблем → несколько флагов одновременно."""
        ev = _make_evidence(
            hours_ago=200.0,      # stale
            source="manual",      # manual_upload
            hash_val=None,        # no_hash
        )
        score = scorer.score_evidence(ev)
        assert "stale_evidence" in score.flags
        assert "manual_upload" in score.flags
        assert "no_hash" in score.flags


# ── 5. Агрегация по контролу ──────────────────────────────────────────────────

class TestControlAggregation:
    def test_score_control_aggregation(self, scorer: EvidenceConfidenceScorer):
        """score_control возвращает правильные агрегаты."""
        evidence_list = [
            _make_evidence(ev_id="ev-1", hours_ago=1.0,   source="aws",    hash_val="sha256:a"),
            _make_evidence(ev_id="ev-2", hours_ago=50.0,  source="manual", hash_val=None),
            _make_evidence(ev_id="ev-3", hours_ago=200.0, source="github", hash_val="sha256:b"),
        ]
        result = scorer.score_control("ctrl-test", evidence_list)

        assert result["control_id"] == "ctrl-test"
        assert result["evidence_count"] == 3
        # ev-3 > 7 дней → stale
        assert result["stale_count"] == 1
        # ev-2 no hash, ev-3 sha256 → unverified: ev-2 (no_hash→unverified), ev-3 (sha256 → verified)
        # ev-1 sha256 → verified, ev-2 no hash → unverified
        assert result["unverified_count"] == 1
        assert 0 <= result["overall_confidence"] <= 100
        assert 0 <= result["min_confidence"] <= result["overall_confidence"]

    def test_overall_confidence_weighted(self, scorer: EvidenceConfidenceScorer):
        """overall_confidence — среднее по всем evidence (не только extremes)."""
        evidence_list = [
            _make_evidence(ev_id="ev-a", hours_ago=0.5, source="aws",    hash_val="sha256:x", metadata={"k": "v"}),
            _make_evidence(ev_id="ev-b", hours_ago=200.0, source="manual", hash_val=None),
        ]
        result = scorer.score_control("ctrl-weighted", evidence_list)

        scores = scorer.score_bulk(evidence_list)
        expected_avg = int(round(sum(s.confidence for s in scores) / len(scores)))
        assert result["overall_confidence"] == expected_avg

    def test_empty_evidence_list_returns_critical(self, scorer):
        """Пустой список evidence → recommendation=critical, count=0."""
        result = scorer.score_control("ctrl-empty", [])
        assert result["evidence_count"] == 0
        assert result["overall_confidence"] == 0
        assert result["recommendation"] == "critical"

    def test_recommendation_critical_when_low_confidence(self, scorer: EvidenceConfidenceScorer):
        """Низкий confidence → recommendation=critical."""
        # Максимально плохое evidence: стale + tampered + manual
        ev = {
            "id": "ev-bad",
            "control_id": "ctrl-bad",
            "collected_at": _iso(500.0),      # > 7 дней
            "source": "manual",
            "content": "x",                   # < 100 символов → completeness минимум
            "hash_mismatch": True,
        }
        result = scorer.score_control("ctrl-bad", [ev])
        # freshness=0, integrity=0 (tampered), source=6, completeness=0 → total=6
        assert result["overall_confidence"] < 35
        assert result["recommendation"] == "critical"

    def test_recommendation_acceptable_when_high_confidence(self, scorer):
        """Высокий confidence → recommendation=acceptable."""
        ev = _make_evidence(
            hours_ago=0.5,
            source="aws",
            hash_val="sha256:good",
            metadata={"env": "prod"},
        )
        result = scorer.score_control("ctrl-good", [ev])
        assert result["overall_confidence"] >= 60
        assert result["recommendation"] == "acceptable"


# ── 6. Bulk scoring ──────────────────────────────────────────────────────────

class TestBulkScore:
    def test_bulk_score_returns_list(self, scorer: EvidenceConfidenceScorer):
        """score_bulk возвращает список EvidenceScore той же длины что вход."""
        evidence_list = [
            _make_evidence(ev_id=f"ev-{i}", hours_ago=float(i * 5))
            for i in range(5)
        ]
        results = scorer.score_bulk(evidence_list)

        assert isinstance(results, list)
        assert len(results) == 5
        assert all(isinstance(r, EvidenceScore) for r in results)

    def test_bulk_empty_list(self, scorer):
        assert scorer.score_bulk([]) == []

    def test_bulk_preserves_evidence_id(self, scorer):
        evidence_list = [_make_evidence(ev_id="ev-unique-99")]
        results = scorer.score_bulk(evidence_list)
        assert results[0].evidence_id == "ev-unique-99"


# ── 7. Confidence report ──────────────────────────────────────────────────────

class TestConfidenceReport:
    def test_report_structure(self, scorer):
        """get_confidence_report возвращает все ожидаемые ключи."""
        evidence_list = [
            _make_evidence(ev_id="ev-r1", control_id="ctrl-A"),
            _make_evidence(ev_id="ev-r2", control_id="ctrl-A"),
            _make_evidence(ev_id="ev-r3", control_id="ctrl-B"),
        ]
        report = scorer.get_confidence_report(evidence_list)

        assert "scored_at" in report
        assert "total_evidence" in report
        assert "controls" in report
        assert "evidence_scores" in report
        assert "summary" in report
        assert report["total_evidence"] == 3
        # Два уникальных контрола
        assert len(report["controls"]) == 2

    def test_report_empty_evidence(self, scorer):
        """Пустой список → отчёт с нулями."""
        report = scorer.get_confidence_report([])
        assert report["total_evidence"] == 0
        assert report["controls"] == []
        assert report["summary"]["avg_confidence"] == 0


# ── 8. Граничные случаи ───────────────────────────────────────────────────────

class TestEdgeCases:
    def test_confidence_is_integer(self, scorer):
        """confidence всегда целое число, не float."""
        ev = _make_evidence(hours_ago=5.0)
        score = scorer.score_evidence(ev)
        assert isinstance(score.confidence, int)

    def test_confidence_capped_at_100(self, scorer):
        """Сумма всех факторов не превышает 100."""
        ev = _make_evidence(
            hours_ago=0.1,
            source="aws",
            hash_val="sha256:perfect",
            metadata={"key": "val"},
        )
        score = scorer.score_evidence(ev)
        assert score.confidence <= 100

    def test_confidence_not_negative(self, scorer):
        """confidence никогда не отрицательный."""
        ev = {
            "id": "ev-neg",
            "control_id": "ctrl-neg",
            "collected_at": _iso(9999.0),
            "source": "manual",
            "content": "",
            "hash_mismatch": True,
        }
        score = scorer.score_evidence(ev)
        assert score.confidence >= 0

    def test_missing_collected_at_gives_stale(self, scorer):
        """Отсутствие collected_at → флаг stale_evidence, freshness=0, freshness_hours=-1."""
        ev = {
            "id": "ev-nocollect",
            "control_id": "ctrl-x",
            "source": "aws",
            "content": "some content here that is long enough to score",
        }
        score = scorer.score_evidence(ev)
        assert "stale_evidence" in score.flags
        assert score.score_breakdown["freshness"] == 0
        # -1.0 — sentinel для "возраст неизвестен", JSON-безопасное значение
        assert score.freshness_hours == -1.0

    def test_score_to_dict_freshness_unknown_is_null(self, scorer):
        """score_to_dict: freshness_hours=-1.0 → None (JSON null)."""
        ev = {
            "id": "ev-null-fresh",
            "control_id": "ctrl-x",
            "source": "aws",
            "content": "some content",
        }
        score = scorer.score_evidence(ev)
        d = scorer.score_to_dict(score)
        assert d["freshness_hours"] is None
