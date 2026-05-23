"""
compliance_ontology.py — Ontology Layer для SOC 2 compliance sandbox.

Загружает machine-readable семантику из YAML-файлов ontology/*.yaml
и предоставляет query engine для AI reasoning над контролями.

Архитектура:
  - OntologyLoader    — читает все YAML, кэширует в памяти
  - ControlOntology   — frozen dataclass с полной семантикой контроля
  - OntologyQueryEngine — методы запросов: get_control, find_by_category, etc.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from log_config import get_logger

log = get_logger(__name__)

# ── Путь к директории с YAML-файлами ──────────────────────────────────────────

_ONTOLOGY_DIR = Path(__file__).parent / "ontology"

# Блокировка для thread-safe ленивой загрузки
_LOADER_LOCK = threading.Lock()


# ── Frozen dataclass — полная семантика одного контроля ───────────────────────

@dataclass(frozen=True)
class ControlOntology:
    """
    Неизменяемая семантическая запись для одного SOC 2 контроля.

    Все коллекции хранятся как tuple для полной иммутабельности.
    """

    # Идентификация
    id: str                              # "CC6.1"
    title: str                           # человекочитаемый заголовок
    category: str                        # "logical_access", "governance", etc.
    description: str                     # подробное описание назначения

    # Требования: что должно быть задействовано для выполнения контроля
    requires: tuple[str, ...]            # ("MFA", "RBAC", "PasswordPolicy")

    # Типы доказательств, необходимых для аудита
    evidence_types: tuple[str, ...]      # ("aws_iam_scan", "okta_mfa_check")

    # Веса и SLA
    risk_weight: float                   # 0.0–1.0, выше = критичнее
    sla_hours: int                       # SLA на устранение в часах

    # Маппинг на фреймворки
    iso27001: tuple[str, ...]            # ("A.9.4.2", "A.9.4.3")
    nist: tuple[str, ...]                # ("IA-2", "IA-5")
    cis: tuple[str, ...]                 # ("4.1", "4.4")

    # Метаданные автоматизации
    auto_remediable: bool                # можно ли устранить автоматически
    owner_role: str                      # "security_team", "ciso", etc.
    audit_frequency: str                 # "continuous", "annual", "quarterly"

    # Шаги устранения
    remediation_steps: tuple[str, ...]   # последовательность действий

    def __post_init__(self) -> None:
        """Валидация инварианта: risk_weight должен быть в диапазоне [0.0, 1.0]."""
        if not (0.0 <= self.risk_weight <= 1.0):
            raise ValueError(
                f"Контроль {self.id}: risk_weight={self.risk_weight} вне диапазона [0.0, 1.0]"
            )


# ── Загрузчик YAML ─────────────────────────────────────────────────────────────

class OntologyLoader:
    """
    Загружает все YAML-файлы из ontology/ и кэширует результат.

    Кэш инициализируется один раз при первом обращении.
    Повторные вызовы load() возвращают кэш без I/O.
    """

    def __init__(self, ontology_dir: Path = _ONTOLOGY_DIR) -> None:
        self._dir = ontology_dir
        # Словарь: id контроля → ControlOntology
        self._cache: dict[str, ControlOntology] | None = None

    def load(self) -> dict[str, ControlOntology]:
        """
        Загрузить (или вернуть из кэша) все контроли из YAML.

        Returns:
            Словарь {control_id: ControlOntology} для всех загруженных контролей.

        Raises:
            FileNotFoundError: если директория ontology/ не существует.
        """
        if self._cache is not None:
            return self._cache

        if not self._dir.exists():
            raise FileNotFoundError(
                f"Директория онтологий не найдена: {self._dir}"
            )

        result: dict[str, ControlOntology] = {}
        yaml_files = sorted(self._dir.glob("*.yaml"))

        if not yaml_files:
            log.warning("В директории %s не найдено YAML-файлов", self._dir)

        for yaml_path in yaml_files:
            try:
                parsed = self._parse_yaml_file(yaml_path)
                result.update(parsed)
                log.debug("Загружено %d контролей из %s", len(parsed), yaml_path.name)
            except Exception as exc:
                log.error("Ошибка при загрузке %s: %s", yaml_path.name, exc)
                raise

        self._cache = result
        log.info("Онтология загружена: %d контролей из %d файлов", len(result), len(yaml_files))
        return self._cache

    def reload(self) -> dict[str, ControlOntology]:
        """Сбросить кэш и перезагрузить все YAML-файлы."""
        self._cache = None
        return self.load()

    def _parse_yaml_file(self, path: Path) -> dict[str, ControlOntology]:
        """Парсит один YAML-файл и возвращает словарь {id: ControlOntology}."""
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)

        if not isinstance(raw, dict) or "controls" not in raw:
            raise ValueError(f"YAML файл {path.name} должен содержать ключ 'controls'")

        result: dict[str, ControlOntology] = {}
        for item in raw["controls"]:
            try:
                ontology = self._build_ontology(item, path.name)
                result[ontology.id] = ontology
            except Exception as exc:
                raise ValueError(
                    f"Ошибка при разборе контроля в {path.name}: {exc}"
                ) from exc
        return result

    def _build_ontology(self, item: dict, source_file: str) -> ControlOntology:
        """Создаёт ControlOntology из сырого словаря YAML."""
        control_id = item.get("id")
        if not control_id:
            raise ValueError(f"Контроль без 'id' в {source_file}")

        frameworks = item.get("frameworks", {})

        return ControlOntology(
            id=control_id,
            title=item.get("title", ""),
            category=item.get("category", "unknown"),
            description=str(item.get("description", "")).strip(),
            requires=tuple(item.get("requires", [])),
            evidence_types=tuple(item.get("evidence_types", [])),
            risk_weight=float(item.get("risk_weight", 0.5)),
            sla_hours=int(item.get("sla_hours", 168)),
            iso27001=tuple(frameworks.get("iso27001", [])),
            nist=tuple(frameworks.get("nist", [])),
            cis=tuple(frameworks.get("cis", [])),
            auto_remediable=bool(item.get("auto_remediable", False)),
            owner_role=item.get("owner_role", "security_team"),
            audit_frequency=item.get("audit_frequency", "annual"),
            remediation_steps=tuple(item.get("remediation_steps", [])),
        )


# ── Query Engine ───────────────────────────────────────────────────────────────

class OntologyQueryEngine:
    """
    Движок запросов к семантике SOC 2 контролей.

    Предоставляет методы для получения, поиска и объяснения контролей.
    Использует OntologyLoader для ленивой загрузки данных.
    """

    def __init__(self, loader: OntologyLoader | None = None) -> None:
        self._loader = loader or OntologyLoader()

    def _controls(self) -> dict[str, ControlOntology]:
        """Возвращает словарь всех контролей (с кэшированием)."""
        return self._loader.load()

    # ── Базовые lookup-методы ──────────────────────────────────────────────

    def get_control(self, control_id: str) -> Optional[ControlOntology]:
        """
        Получить контроль по ID.

        Args:
            control_id: строка вида "CC6.1"

        Returns:
            ControlOntology или None если не найден.
        """
        return self._controls().get(control_id)

    def get_all(self) -> list[ControlOntology]:
        """Вернуть все контроли в алфавитном порядке по ID."""
        return sorted(self._controls().values(), key=lambda c: c.id)

    def get_required_evidence(self, control_id: str) -> tuple[str, ...]:
        """
        Возвращает список типов доказательств, необходимых для контроля.

        Args:
            control_id: строка вида "CC6.1"

        Returns:
            Tuple типов evidence или пустой tuple если контроль не найден.
        """
        ctrl = self.get_control(control_id)
        return ctrl.evidence_types if ctrl else ()

    def get_dependencies(self, control_id: str) -> tuple[str, ...]:
        """
        Возвращает список политик/процессов, требуемых для выполнения контроля.

        Args:
            control_id: строка вида "CC6.1"

        Returns:
            Tuple требований (MFA, RBAC, …) или пустой tuple.
        """
        ctrl = self.get_control(control_id)
        return ctrl.requires if ctrl else ()

    def get_risk_weight(self, control_id: str) -> float:
        """
        Возвращает risk_weight контроля.

        Args:
            control_id: строка вида "CC6.1"

        Returns:
            float [0.0, 1.0] или 0.0 если контроль не найден.
        """
        ctrl = self.get_control(control_id)
        return ctrl.risk_weight if ctrl else 0.0

    def get_remediation_sla(self, control_id: str) -> int:
        """
        Возвращает SLA на устранение нарушения в часах.

        Args:
            control_id: строка вида "CC6.1"

        Returns:
            int (часы) или 168 (1 неделя) по умолчанию если не найден.
        """
        ctrl = self.get_control(control_id)
        return ctrl.sla_hours if ctrl else 168

    # ── Поиск и фильтрация ─────────────────────────────────────────────────

    def find_by_category(self, category: str) -> list[ControlOntology]:
        """
        Найти все контроли по категории.

        Args:
            category: строка, например "logical_access", "governance"

        Returns:
            Список контролей (отсортированный по ID).
        """
        cat_lower = category.lower()
        return sorted(
            [c for c in self._controls().values() if c.category.lower() == cat_lower],
            key=lambda c: c.id,
        )

    def find_auto_remediable(self) -> list[ControlOntology]:
        """Вернуть все контроли, которые можно устранить автоматически."""
        return sorted(
            [c for c in self._controls().values() if c.auto_remediable],
            key=lambda c: c.id,
        )

    def find_by_risk_weight_threshold(self, min_weight: float) -> list[ControlOntology]:
        """
        Найти контроли с risk_weight >= порогового значения.

        Args:
            min_weight: минимальный вес риска [0.0, 1.0]

        Returns:
            Список контролей, отсортированный по risk_weight DESC.
        """
        return sorted(
            [c for c in self._controls().values() if c.risk_weight >= min_weight],
            key=lambda c: c.risk_weight,
            reverse=True,
        )

    def find_by_owner(self, owner_role: str) -> list[ControlOntology]:
        """Найти все контроли по owner_role."""
        return sorted(
            [c for c in self._controls().values() if c.owner_role == owner_role],
            key=lambda c: c.id,
        )

    def find_by_audit_frequency(self, frequency: str) -> list[ControlOntology]:
        """Найти все контроли по частоте аудита (continuous, annual, quarterly, etc.)."""
        return sorted(
            [c for c in self._controls().values() if c.audit_frequency == frequency],
            key=lambda c: c.id,
        )

    def find_by_framework_control(self, framework: str, control_ref: str) -> list[ControlOntology]:
        """
        Найти SOC 2 контроли, покрывающие указанный ID фреймворка.

        Args:
            framework: "iso27001", "nist" или "cis"
            control_ref: строка, например "A.9.4.2", "IA-2", "4.1"

        Returns:
            Список сопоставленных SOC 2 контролей.
        """
        framework_lower = framework.lower()
        ref_upper = control_ref.upper()
        result: list[ControlOntology] = []

        for ctrl in self._controls().values():
            if framework_lower == "iso27001":
                mapped = [x.upper() for x in ctrl.iso27001]
            elif framework_lower == "nist":
                mapped = [x.upper() for x in ctrl.nist]
            elif framework_lower == "cis":
                mapped = [x.upper() for x in ctrl.cis]
            else:
                continue

            if ref_upper in mapped:
                result.append(ctrl)

        return sorted(result, key=lambda c: c.id)

    # ── Объяснение контроля ────────────────────────────────────────────────

    def explain_control(self, control_id: str) -> str:
        """
        Генерирует человекочитаемое объяснение контроля.

        Возвращает полное текстовое описание для аудиторов и AI reasoning,
        включая маппинги на фреймворки, требуемые evidence и шаги устранения.

        Args:
            control_id: строка вида "CC6.1"

        Returns:
            Строка с мультистрочным объяснением или сообщение "не найден".
        """
        ctrl = self.get_control(control_id)
        if ctrl is None:
            return f"Контроль {control_id!r} не найден в онтологии."

        lines: list[str] = [
            f"=== {ctrl.id}: {ctrl.title} ===",
            f"Категория:    {ctrl.category}",
            f"Риск-вес:     {ctrl.risk_weight:.2f}  |  SLA: {ctrl.sla_hours}h  |  Частота аудита: {ctrl.audit_frequency}",
            f"Владелец:     {ctrl.owner_role}",
            f"Авто-fix:     {'Да' if ctrl.auto_remediable else 'Нет'}",
            "",
            "Описание:",
            f"  {ctrl.description}",
            "",
        ]

        if ctrl.requires:
            lines.append("Требования:")
            for req in ctrl.requires:
                lines.append(f"  • {req}")
            lines.append("")

        if ctrl.evidence_types:
            lines.append("Типы доказательств:")
            for ev in ctrl.evidence_types:
                lines.append(f"  • {ev}")
            lines.append("")

        # Маппинги на фреймворки
        fw_parts: list[str] = []
        if ctrl.iso27001:
            fw_parts.append(f"ISO 27001: {', '.join(ctrl.iso27001)}")
        if ctrl.nist:
            fw_parts.append(f"NIST 800-53: {', '.join(ctrl.nist)}")
        if ctrl.cis:
            fw_parts.append(f"CIS v8: {', '.join(ctrl.cis)}")
        if fw_parts:
            lines.append("Маппинги фреймворков:")
            for part in fw_parts:
                lines.append(f"  {part}")
            lines.append("")

        if ctrl.remediation_steps:
            lines.append("Шаги устранения:")
            for i, step in enumerate(ctrl.remediation_steps, 1):
                lines.append(f"  {i}. {step}")

        return "\n".join(lines)

    def get_all_categories(self) -> list[str]:
        """Возвращает уникальный отсортированный список всех категорий."""
        return sorted({c.category for c in self._controls().values()})

    def count(self) -> int:
        """Возвращает общее количество загруженных контролей."""
        return len(self._controls())

    def get_continuous_controls(self) -> list[ControlOntology]:
        """
        Возвращает контроли, требующие непрерывного мониторинга.

        Используется для настройки automated compliance scanning —
        эти контроли должны проверяться каждый день или в режиме real-time.

        Returns:
            Список контролей с audit_frequency="continuous", отсортированный
            по risk_weight DESC.
        """
        return sorted(
            [c for c in self._controls().values() if c.audit_frequency == "continuous"],
            key=lambda c: c.risk_weight,
            reverse=True,
        )

    def get_high_risk_summary(self, threshold: float = 0.8) -> dict:
        """
        Возвращает сводку высокорискованных контролей для AI reasoning.

        Формирует dict, пригодный для передачи в LLM-промпт как контекст:
        наиболее критичные контроли, их SLA и типы требуемых доказательств.

        Args:
            threshold: минимальный risk_weight для включения (по умолчанию 0.8)

        Returns:
            Словарь {control_id: {title, risk_weight, sla_hours, evidence_types}}
        """
        result: dict = {}
        for ctrl in self._controls().values():
            if ctrl.risk_weight >= threshold:
                result[ctrl.id] = {
                    "title": ctrl.title,
                    "risk_weight": ctrl.risk_weight,
                    "sla_hours": ctrl.sla_hours,
                    "evidence_types": list(ctrl.evidence_types),
                    "auto_remediable": ctrl.auto_remediable,
                    "category": ctrl.category,
                }
        return dict(sorted(result.items(), key=lambda kv: kv[1]["risk_weight"], reverse=True))


# ── Thread-safe singleton ───────────────────────────────────────────────────────

_engine_instance: Optional[OntologyQueryEngine] = None


def get_ontology_engine() -> OntologyQueryEngine:
    """
    Получить singleton OntologyQueryEngine (thread-safe ленивая инициализация).

    OntologyQueryEngine безопасен для чтения из множества потоков.
    Lock используется только при первом создании.
    """
    global _engine_instance
    if _engine_instance is None:
        with _LOADER_LOCK:
            if _engine_instance is None:  # double-checked locking
                _engine_instance = OntologyQueryEngine()
    return _engine_instance
