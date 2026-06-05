"""
Time-Machine Audit Engine — реконструкция compliance-состояния на произвольную дату.

Алгоритм реконструкции статуса контроля:
  - Берём все evidence с collected_at <= target_date
  - Группируем по control_id
  - Если есть evidence со status=FAIL за последние 7 дней от target_date → FAIL
  - Иначе если есть evidence со status=PASS → PASS
  - Иначе → UNKNOWN
"""

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from evidence_client import EvidenceClient, EvidenceClientError
from log_config import get_logger

log = get_logger(__name__)

# Окно «свежего» FAIL: если есть FAIL-evidence за последние N дней от target_date
_FAIL_WINDOW_DAYS = 7

# Максимум evidence в одном запросе к tracker
_EVIDENCE_FETCH_LIMIT = 1000


def _parse_dt(value: str | None) -> datetime | None:
    """
    Разбирает ISO-8601 строку в timezone-aware datetime.
    Поддерживает форматы: с 'Z', с '+00:00', без timezone (считается UTC).
    """
    if not value:
        return None
    try:
        # Нормализуем 'Z' → '+00:00'
        normalized = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        # Если timezone не указан — считаем UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        log.warning("Не удалось разобрать дату", extra={"value": value})
        return None


def _parse_target_date(date_str: str) -> datetime:
    """
    Преобразует строку даты "YYYY-MM-DD" в конец этого дня (23:59:59 UTC).
    Принимает также полный ISO-8601 datetime.
    Raises ValueError при невалидном формате.
    """
    try:
        if "T" in date_str or " " in date_str:
            normalized = date_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        # Только дата "YYYY-MM-DD" → конец дня
        d = datetime.fromisoformat(date_str)
        return d.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(
            f"Неверный формат даты: '{date_str}'. "
            "Ожидается ISO 8601, например: 2026-01-14 или 2026-01-14T15:00:00Z"
        ) from exc


# ── Доменные объекты ────────────────────────────────────────────────────────────

@dataclass
class ControlSnapshot:
    control_id: str
    status: str           # "PASS" | "FAIL" | "UNKNOWN"
    evidence_count: int
    last_evidence_at: str | None
    evidence_items: list[dict] = field(default_factory=list)


@dataclass
class ComplianceSnapshot:
    snapshot_date: str    # запрошенная дата
    generated_at: str     # момент генерации снапшота
    controls: list[ControlSnapshot] = field(default_factory=list)
    pass_count: int = 0
    fail_count: int = 0
    pass_rate: float = 0.0
    integrity_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Сериализует снапшот в dict, пригодный для JSON-ответа."""
        return {
            "snapshot_date": self.snapshot_date,
            "generated_at": self.generated_at,
            "controls": [asdict(c) for c in self.controls],
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "unknown_count": len(self.controls) - self.pass_count - self.fail_count,
            "total_controls": len(self.controls),
            "pass_rate": self.pass_rate,
            "integrity_hash": self.integrity_hash,
        }


# ── Движок ─────────────────────────────────────────────────────────────────────

class TimeMachineEngine:
    """
    Реконструирует compliance-состояние на произвольную дату.

    Использует EvidenceClient для получения evidence из Evidence Tracker.
    При недоступности трекера — graceful degradation (пустые контроли).
    """

    def __init__(self, evidence_client: EvidenceClient | None = None) -> None:
        base_url = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")
        self._client = evidence_client or EvidenceClient(
            base_url=base_url,
            agent_name="time_machine",
        )

    # ── Публичный API ───────────────────────────────────────────────────────────

    def get_snapshot(self, target_date: str) -> ComplianceSnapshot:
        """
        Реконструирует полное compliance-состояние на указанную дату.

        target_date: строка ISO 8601, например "2026-01-14"
        Возвращает ComplianceSnapshot (никогда не бросает 404 — при отсутствии
        evidence возвращает снапшот с пустыми контролями UNKNOWN).
        """
        cutoff = _parse_target_date(target_date)
        evidence_all = self._fetch_evidence_safe()

        # Фильтруем: только evidence до cutoff
        filtered = [e for e in evidence_all if self._collected_before(e, cutoff)]

        # Группируем по control_id
        by_control: dict[str, list[dict]] = {}
        for ev in filtered:
            cid = ev.get("control_id") or ev.get("control", {}).get("id", "unknown")
            by_control.setdefault(cid, []).append(ev)

        controls: list[ControlSnapshot] = []
        for control_id, items in sorted(by_control.items()):
            snap = self._reconstruct_control(control_id, items, cutoff)
            controls.append(snap)

        pass_count = sum(1 for c in controls if c.status == "PASS")
        fail_count = sum(1 for c in controls if c.status == "FAIL")
        total = len(controls)
        pass_rate = round(pass_count / total * 100, 1) if total > 0 else 0.0

        snapshot = ComplianceSnapshot(
            snapshot_date=target_date,
            generated_at=datetime.now(timezone.utc).isoformat(),
            controls=controls,
            pass_count=pass_count,
            fail_count=fail_count,
            pass_rate=pass_rate,
        )
        snapshot.integrity_hash = self._compute_integrity_hash(snapshot)

        log.info(
            "Снапшот реконструирован",
            extra={
                "target_date": target_date,
                "total_controls": total,
                "pass": pass_count,
                "fail": fail_count,
            },
        )
        return snapshot

    def get_timeline(self, control_id: str, days: int = 90) -> list[dict]:
        """
        Возвращает историю изменений статуса контроля за последние N дней.

        Результат: список событий изменения статуса, отсортированных по дате.
        Каждое событие: {"date": "...", "status": "PASS|FAIL|UNKNOWN", "evidence_count": N}
        """
        if days <= 0:
            raise ValueError("days должен быть положительным числом")
        if days > 3650:
            raise ValueError("days не может превышать 3650 (10 лет)")

        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=days)

        evidence_all = self._fetch_evidence_safe(control_id=control_id)
        evidence_for_ctrl = [
            e for e in evidence_all
            if (e.get("control_id") or e.get("control", {}).get("id")) == control_id
        ]

        if not evidence_for_ctrl:
            return []

        # Собираем уникальные даты (по дням) из collected_at
        dates_seen: set[str] = set()
        for ev in evidence_for_ctrl:
            dt = _parse_dt(ev.get("collected_at") or ev.get("created_at"))
            if dt and dt >= start_dt:
                dates_seen.add(dt.date().isoformat())

        timeline: list[dict] = []
        for date_str in sorted(dates_seen):
            cutoff = _parse_target_date(date_str)
            items_up_to = [
                e for e in evidence_for_ctrl
                if self._collected_before(e, cutoff)
            ]
            if not items_up_to:
                continue
            snap = self._reconstruct_control(control_id, items_up_to, cutoff)
            timeline.append({
                "date": date_str,
                "status": snap.status,
                "evidence_count": snap.evidence_count,
            })

        return timeline

    def compare_snapshots(self, date_from: str, date_to: str) -> dict:
        """
        Сравнивает compliance-состояние между двумя датами.

        Возвращает:
          new_pass   — контроли, которые стали PASS (были не-PASS)
          new_fail   — контроли, которые стали FAIL (были не-FAIL)
          unchanged  — контроли без изменений
          improved   — контроли, статус которых улучшился (FAIL → PASS/UNKNOWN)
          degraded   — контроли, статус которых ухудшился (PASS → FAIL/UNKNOWN)

        Оптимизация: единый fetch для обоих снапшотов.
        """
        # Единственный запрос к трекеру — затем реконструируем оба снапшота локально
        evidence_all = self._fetch_evidence_safe()
        snap_from = self._build_snapshot_from_evidence(date_from, evidence_all)
        snap_to = self._build_snapshot_from_evidence(date_to, evidence_all)

        from_map = {c.control_id: c.status for c in snap_from.controls}
        to_map = {c.control_id: c.status for c in snap_to.controls}

        all_controls = sorted(set(from_map) | set(to_map))

        new_pass: list[dict] = []
        new_fail: list[dict] = []
        unchanged: list[dict] = []
        improved: list[dict] = []
        degraded: list[dict] = []

        for cid in all_controls:
            s_from = from_map.get(cid, "UNKNOWN")
            s_to = to_map.get(cid, "UNKNOWN")
            entry = {"control_id": cid, "from": s_from, "to": s_to}

            if s_from == s_to:
                unchanged.append(entry)
            else:
                if s_to == "PASS":
                    new_pass.append(entry)
                if s_to == "FAIL":
                    new_fail.append(entry)
                if s_from == "FAIL" and s_to in ("PASS", "UNKNOWN"):
                    improved.append(entry)
                if s_from == "PASS" and s_to in ("FAIL", "UNKNOWN"):
                    degraded.append(entry)

        return {
            "date_from": date_from,
            "date_to": date_to,
            "pass_rate_from": snap_from.pass_rate,
            "pass_rate_to": snap_to.pass_rate,
            "pass_rate_delta": round(snap_to.pass_rate - snap_from.pass_rate, 1),
            "new_pass": new_pass,
            "new_fail": new_fail,
            "improved": improved,
            "degraded": degraded,
            "unchanged": unchanged,
            "total_changed": len(new_pass) + len(new_fail),
        }

    def get_drift_events(self, days: int = 30) -> list[dict]:
        """
        Возвращает события compliance-дрейфа за последние N дней.

        Дрейф = переход контроля между статусами (PASS→FAIL или FAIL→PASS).
        Сортировка: сначала деградации (PASS→FAIL), потом улучшения.
        """
        if days <= 0:
            raise ValueError("days должен быть положительным числом")
        if days > 3650:
            raise ValueError("days не может превышать 3650")

        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=days)

        evidence_all = self._fetch_evidence_safe()

        # Собираем уникальные дни, когда есть evidence в диапазоне
        dates_with_evidence: set[str] = set()
        for ev in evidence_all:
            dt = _parse_dt(ev.get("collected_at") or ev.get("created_at"))
            if dt and start_dt <= dt <= end_dt:
                dates_with_evidence.add(dt.date().isoformat())

        if not dates_with_evidence:
            return []

        sorted_dates = sorted(dates_with_evidence)

        # Единственный fetch — реконструируем снапшоты локально без повторных запросов
        snapshots: list[ComplianceSnapshot] = [
            self._build_snapshot_from_evidence(d, evidence_all)
            for d in sorted_dates
        ]

        # Детектируем переходы между соседними снапшотами
        drift_events: list[dict] = []
        for i in range(1, len(snapshots)):
            prev = snapshots[i - 1]
            curr = snapshots[i]
            prev_map = {c.control_id: c.status for c in prev.controls}
            curr_map = {c.control_id: c.status for c in curr.controls}

            for cid in set(prev_map) | set(curr_map):
                s_prev = prev_map.get(cid, "UNKNOWN")
                s_curr = curr_map.get(cid, "UNKNOWN")
                if s_prev == s_curr:
                    continue
                # Только значимые переходы (игнорируем появление из UNKNOWN)
                if s_prev == "UNKNOWN":
                    continue
                drift_type = "degradation" if s_curr == "FAIL" else "improvement"
                drift_events.append({
                    "date": sorted_dates[i],
                    "control_id": cid,
                    "from_status": s_prev,
                    "to_status": s_curr,
                    "drift_type": drift_type,
                })

        # Сортируем: деградации первыми, внутри группы — по дате возрастающей
        drift_events.sort(
            key=lambda e: (0 if e["drift_type"] == "degradation" else 1, e["date"])
        )

        log.info(
            "События дрейфа вычислены",
            extra={"days": days, "events_count": len(drift_events)},
        )
        return drift_events

    def get_available_dates(self) -> list[str]:
        """
        Возвращает список дат (YYYY-MM-DD), когда есть хотя бы одно evidence.
        Используется UI-календарём для навигации.
        """
        evidence_all = self._fetch_evidence_safe()
        dates: set[str] = set()
        for ev in evidence_all:
            dt = _parse_dt(ev.get("collected_at") or ev.get("created_at"))
            if dt:
                dates.add(dt.date().isoformat())
        return sorted(dates)

    # ── Внутренние методы ───────────────────────────────────────────────────────

    def _build_snapshot_from_evidence(
        self,
        target_date: str,
        evidence_all: list[dict],
    ) -> ComplianceSnapshot:
        """
        Реконструирует снапшот из уже загруженного списка evidence (без сетевого запроса).
        Используется внутри compare_snapshots и get_drift_events для экономии запросов.
        """
        cutoff = _parse_target_date(target_date)
        filtered = [e for e in evidence_all if self._collected_before(e, cutoff)]

        by_control: dict[str, list[dict]] = {}
        for ev in filtered:
            cid = ev.get("control_id") or ev.get("control", {}).get("id", "unknown")
            by_control.setdefault(cid, []).append(ev)

        controls: list[ControlSnapshot] = [
            self._reconstruct_control(cid, items, cutoff)
            for cid, items in sorted(by_control.items())
        ]

        pass_count = sum(1 for c in controls if c.status == "PASS")
        fail_count = sum(1 for c in controls if c.status == "FAIL")
        total = len(controls)
        pass_rate = round(pass_count / total * 100, 1) if total > 0 else 0.0

        snapshot = ComplianceSnapshot(
            snapshot_date=target_date,
            generated_at=datetime.now(timezone.utc).isoformat(),
            controls=controls,
            pass_count=pass_count,
            fail_count=fail_count,
            pass_rate=pass_rate,
        )
        snapshot.integrity_hash = self._compute_integrity_hash(snapshot)
        return snapshot

    def _fetch_evidence_safe(
        self,
        control_id: str | None = None,
    ) -> list[dict]:
        """
        Получает evidence из трекера.
        При ошибке подключения — возвращает пустой список (graceful degradation).
        """
        try:
            return self._client.get_evidence(
                control_id=control_id,
                limit=_EVIDENCE_FETCH_LIMIT,
            )
        except EvidenceClientError as exc:
            log.warning(
                "Evidence Tracker недоступен, Time Machine вернёт пустой снапшот",
                extra={"error": str(exc)},
            )
            return []

    @staticmethod
    def _collected_before(evidence: dict, cutoff: datetime) -> bool:
        """Возвращает True если evidence был собран до (включительно) cutoff."""
        raw = evidence.get("collected_at") or evidence.get("created_at")
        dt = _parse_dt(raw)
        if dt is None:
            # Evidence без даты — включаем (консервативный подход)
            return True
        return dt <= cutoff

    @staticmethod
    def _reconstruct_control(
        control_id: str,
        items: list[dict],
        cutoff: datetime,
    ) -> ControlSnapshot:
        """
        Реконструирует статус одного контроля на дату cutoff.

        Логика:
          1. Если есть FAIL-evidence за последние _FAIL_WINDOW_DAYS от cutoff → FAIL
          2. Иначе если есть PASS-evidence → PASS
          3. Иначе → UNKNOWN
        """
        if not items:
            return ControlSnapshot(
                control_id=control_id,
                status="UNKNOWN",
                evidence_count=0,
                last_evidence_at=None,
            )

        fail_window_start = cutoff - timedelta(days=_FAIL_WINDOW_DAYS)

        # Сортируем по дате (свежее первым) для определения last_evidence_at
        dated: list[tuple[datetime | None, dict]] = []
        for ev in items:
            raw = ev.get("collected_at") or ev.get("created_at")
            dated.append((_parse_dt(raw), ev))
        dated.sort(key=lambda x: x[0] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)

        last_evidence_at: str | None = None
        if dated[0][0] is not None:
            last_evidence_at = dated[0][0].isoformat()

        # Проверяем наличие свежего FAIL
        has_recent_fail = any(
            ev.get("status") == "FAIL"
            and dt is not None
            and dt >= fail_window_start
            for dt, ev in dated
        )

        has_pass = any(ev.get("status") == "PASS" for _, ev in dated)

        if has_recent_fail:
            status = "FAIL"
        elif has_pass:
            status = "PASS"
        else:
            status = "UNKNOWN"

        return ControlSnapshot(
            control_id=control_id,
            status=status,
            evidence_count=len(items),
            last_evidence_at=last_evidence_at,
            evidence_items=[ev for _, ev in dated[:5]],  # топ-5 самых свежих
        )

    @staticmethod
    def _compute_integrity_hash(snapshot: ComplianceSnapshot) -> str:
        """
        Вычисляет SHA-256 от JSON-сериализации снапшота (без поля integrity_hash).
        Обеспечивает tamper-detection для audit trail.
        """
        payload = {
            "snapshot_date": snapshot.snapshot_date,
            "generated_at": snapshot.generated_at,
            "controls": [
                {
                    "control_id": c.control_id,
                    "status": c.status,
                    "evidence_count": c.evidence_count,
                    "last_evidence_at": c.last_evidence_at,
                }
                for c in sorted(snapshot.controls, key=lambda ctrl: ctrl.control_id)
            ],
            "pass_count": snapshot.pass_count,
            "fail_count": snapshot.fail_count,
            "pass_rate": snapshot.pass_rate,
        }
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode()).hexdigest()
