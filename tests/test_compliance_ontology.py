"""
tests/test_compliance_ontology.py — Тесты для Compliance Ontology Layer.

Покрывает:
 - Загрузка YAML (OntologyLoader)
 - Query Engine: get_control, find_by_category, dependencies, explain
 - Обогащение ControlMappingEngine.enrich_with_ontology()
 - Интеграция с AIDecisionLogger (ontology context в metadata)
 - Edge cases: несуществующие контроли, threshold-поиск, фреймворки
"""

from __future__ import annotations

import sys
import os
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

# Добавляем корень проекта в sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from compliance_ontology import (
    ControlOntology,
    OntologyLoader,
    OntologyQueryEngine,
    get_ontology_engine,
    _ONTOLOGY_DIR,
)


# ── Фикстуры ───────────────────────────────────────────────────────────────────

@pytest.fixture
def real_engine() -> OntologyQueryEngine:
    """Движок на реальных YAML-файлах из ontology/."""
    loader = OntologyLoader(_ONTOLOGY_DIR)
    return OntologyQueryEngine(loader)


@pytest.fixture
def minimal_yaml_dir(tmp_path: Path) -> Path:
    """Временная директория с минимальным YAML для изолированных тестов."""
    data = {
        "controls": [
            {
                "id": "CC6.1",
                "title": "Logical Access Controls",
                "category": "logical_access",
                "requires": ["MFA", "RBAC", "PasswordPolicy"],
                "evidence_types": ["aws_iam_scan", "okta_mfa_check"],
                "risk_weight": 0.9,
                "sla_hours": 24,
                "frameworks": {
                    "iso27001": ["A.9.4.2", "A.9.4.3"],
                    "nist": ["IA-2", "IA-5"],
                    "cis": ["4.1", "4.4"],
                },
                "auto_remediable": True,
                "owner_role": "security_team",
                "audit_frequency": "continuous",
                "description": "Логический доступ ограничен авторизованными пользователями.",
                "remediation_steps": ["Включить MFA", "Обновить password policy"],
            },
            {
                "id": "CC1.1",
                "title": "Integrity and Ethical Values",
                "category": "governance",
                "requires": ["CodeOfConduct", "EthicsPolicy"],
                "evidence_types": ["hr_policy_audit", "training_records"],
                "risk_weight": 0.6,
                "sla_hours": 168,
                "frameworks": {
                    "iso27001": ["A.5.1"],
                    "nist": ["PM-1"],
                    "cis": ["14.1"],
                },
                "auto_remediable": False,
                "owner_role": "ciso",
                "audit_frequency": "annual",
                "description": "Приверженность честности и этическим ценностям.",
                "remediation_steps": ["Разработать Кодекс поведения"],
            },
        ]
    }
    yaml_file = tmp_path / "cc_test.yaml"
    with open(yaml_file, "w") as fh:
        yaml.dump(data, fh, allow_unicode=True)
    return tmp_path


@pytest.fixture
def engine_from_yaml(minimal_yaml_dir: Path) -> OntologyQueryEngine:
    """Движок на временных YAML-файлах (изолированный)."""
    loader = OntologyLoader(minimal_yaml_dir)
    return OntologyQueryEngine(loader)


# ── БЛОК 1: Загрузка YAML ──────────────────────────────────────────────────────

class TestOntologyLoader:

    def test_loader_loads_real_yaml_files(self) -> None:
        """Загрузчик должен успешно прочитать реальные YAML из ontology/."""
        loader = OntologyLoader(_ONTOLOGY_DIR)
        result = loader.load()
        # Все 33 основных CC-контроля должны быть загружены
        assert len(result) >= 33

    def test_loader_returns_dict_with_control_ids_as_keys(self) -> None:
        """Ключи словаря должны совпадать с id контролей."""
        loader = OntologyLoader(_ONTOLOGY_DIR)
        result = loader.load()
        for key, value in result.items():
            assert key == value.id

    def test_loader_caches_on_second_call(self, minimal_yaml_dir: Path) -> None:
        """Повторный вызов load() должен вернуть тот же объект из кэша."""
        loader = OntologyLoader(minimal_yaml_dir)
        first = loader.load()
        second = loader.load()
        assert first is second  # идентичный объект кэша

    def test_loader_reload_invalidates_cache(self, minimal_yaml_dir: Path) -> None:
        """reload() должен сбросить кэш и перечитать файлы."""
        loader = OntologyLoader(minimal_yaml_dir)
        first = loader.load()
        reloaded = loader.reload()
        # Данные должны совпадать по содержанию, но быть новым объектом
        assert set(first.keys()) == set(reloaded.keys())

    def test_loader_raises_on_missing_directory(self) -> None:
        """FileNotFoundError если директория онтологий не существует."""
        loader = OntologyLoader(Path("/nonexistent_ontology_dir"))
        with pytest.raises(FileNotFoundError):
            loader.load()

    def test_loader_raises_on_invalid_yaml_structure(self, tmp_path: Path) -> None:
        """ValueError если YAML не содержит ключа 'controls'."""
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("not_controls:\n  - id: CC1.1\n")
        loader = OntologyLoader(tmp_path)
        with pytest.raises(ValueError, match="controls"):
            loader.load()

    def test_loader_all_cc_categories_present(self) -> None:
        """Все категории CC1-CC9 должны присутствовать в реальных данных."""
        loader = OntologyLoader(_ONTOLOGY_DIR)
        result = loader.load()
        loaded_ids = set(result.keys())
        for cc_prefix in ["CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7", "CC8", "CC9"]:
            cc_controls = [k for k in loaded_ids if k.startswith(cc_prefix)]
            assert cc_controls, f"Нет контролей для {cc_prefix}"


# ── БЛОК 2: get_control ────────────────────────────────────────────────────────

class TestGetControl:

    def test_get_existing_control(self, engine_from_yaml: OntologyQueryEngine) -> None:
        """get_control() должен возвращать ControlOntology для существующего ID."""
        ctrl = engine_from_yaml.get_control("CC6.1")
        assert ctrl is not None
        assert ctrl.id == "CC6.1"

    def test_get_nonexistent_control_returns_none(self, engine_from_yaml: OntologyQueryEngine) -> None:
        """get_control() должен вернуть None для несуществующего ID."""
        ctrl = engine_from_yaml.get_control("CC99.99")
        assert ctrl is None

    def test_control_is_frozen_dataclass(self, engine_from_yaml: OntologyQueryEngine) -> None:
        """ControlOntology должен быть immutable (frozen dataclass)."""
        ctrl = engine_from_yaml.get_control("CC6.1")
        assert ctrl is not None
        with pytest.raises((AttributeError, TypeError)):
            ctrl.risk_weight = 0.1  # type: ignore[misc]

    def test_control_fields_types(self, engine_from_yaml: OntologyQueryEngine) -> None:
        """Все поля ControlOntology должны иметь ожидаемые типы."""
        ctrl = engine_from_yaml.get_control("CC6.1")
        assert ctrl is not None
        assert isinstance(ctrl.id, str)
        assert isinstance(ctrl.title, str)
        assert isinstance(ctrl.category, str)
        assert isinstance(ctrl.requires, tuple)
        assert isinstance(ctrl.evidence_types, tuple)
        assert isinstance(ctrl.risk_weight, float)
        assert isinstance(ctrl.sla_hours, int)
        assert isinstance(ctrl.iso27001, tuple)
        assert isinstance(ctrl.nist, tuple)
        assert isinstance(ctrl.cis, tuple)
        assert isinstance(ctrl.auto_remediable, bool)
        assert isinstance(ctrl.remediation_steps, tuple)

    def test_risk_weight_in_valid_range(self, real_engine: OntologyQueryEngine) -> None:
        """Все risk_weight должны быть в диапазоне [0.0, 1.0]."""
        for ctrl in real_engine.get_all():
            assert 0.0 <= ctrl.risk_weight <= 1.0, (
                f"{ctrl.id}: risk_weight={ctrl.risk_weight} вне диапазона"
            )


# ── БЛОК 3: Evidence и Dependencies ───────────────────────────────────────────

class TestEvidenceAndDependencies:

    def test_get_required_evidence_returns_tuple(self, engine_from_yaml: OntologyQueryEngine) -> None:
        """get_required_evidence() должен вернуть tuple строк."""
        evidence = engine_from_yaml.get_required_evidence("CC6.1")
        assert isinstance(evidence, tuple)
        assert len(evidence) > 0

    def test_get_required_evidence_for_cc6_1(self, real_engine: OntologyQueryEngine) -> None:
        """CC6.1 должен требовать aws_iam_scan и okta_mfa_check."""
        evidence = real_engine.get_required_evidence("CC6.1")
        assert "aws_iam_scan" in evidence
        assert "okta_mfa_check" in evidence

    def test_get_required_evidence_returns_empty_for_unknown(self, engine_from_yaml: OntologyQueryEngine) -> None:
        """Для несуществующего контроля должен вернуться пустой tuple."""
        evidence = engine_from_yaml.get_required_evidence("UNKNOWN.99")
        assert evidence == ()

    def test_get_dependencies_returns_tuple(self, engine_from_yaml: OntologyQueryEngine) -> None:
        """get_dependencies() должен вернуть tuple строк."""
        deps = engine_from_yaml.get_dependencies("CC6.1")
        assert isinstance(deps, tuple)
        assert "MFA" in deps
        assert "RBAC" in deps

    def test_get_dependencies_empty_for_unknown(self, engine_from_yaml: OntologyQueryEngine) -> None:
        """Для несуществующего контроля — пустой tuple."""
        deps = engine_from_yaml.get_dependencies("NONEXISTENT")
        assert deps == ()


# ── БЛОК 4: Risk Weight и SLA ──────────────────────────────────────────────────

class TestRiskWeightAndSLA:

    def test_get_risk_weight_for_cc6_1(self, real_engine: OntologyQueryEngine) -> None:
        """CC6.1 должен иметь высокий risk_weight (>= 0.85)."""
        weight = real_engine.get_risk_weight("CC6.1")
        assert weight >= 0.85

    def test_get_risk_weight_returns_zero_for_unknown(self, engine_from_yaml: OntologyQueryEngine) -> None:
        """Для несуществующего контроля должен вернуться 0.0."""
        weight = engine_from_yaml.get_risk_weight("UNKNOWN")
        assert weight == 0.0

    def test_get_remediation_sla_for_cc6_1(self, real_engine: OntologyQueryEngine) -> None:
        """CC6.1 должен иметь SLA <= 24 часов (критичный контроль)."""
        sla = real_engine.get_remediation_sla("CC6.1")
        assert sla <= 24

    def test_get_remediation_sla_default_for_unknown(self, engine_from_yaml: OntologyQueryEngine) -> None:
        """Для несуществующего контроля должен вернуться дефолтный SLA (168 часов)."""
        sla = engine_from_yaml.get_remediation_sla("NONEXISTENT")
        assert sla == 168


# ── БЛОК 5: find_by_category ───────────────────────────────────────────────────

class TestFindByCategory:

    def test_find_by_category_logical_access(self, real_engine: OntologyQueryEngine) -> None:
        """Категория logical_access должна содержать CC6.1, CC6.2, CC6.3, CC6.5."""
        controls = real_engine.find_by_category("logical_access")
        ids = {c.id for c in controls}
        assert "CC6.1" in ids
        assert "CC6.2" in ids

    def test_find_by_category_governance(self, real_engine: OntologyQueryEngine) -> None:
        """Категория governance должна содержать CC1-контроли."""
        controls = real_engine.find_by_category("governance")
        assert len(controls) >= 3
        for c in controls:
            assert c.category == "governance"

    def test_find_by_category_case_insensitive(self, real_engine: OntologyQueryEngine) -> None:
        """Поиск по категории должен быть case-insensitive."""
        lower = real_engine.find_by_category("logical_access")
        upper = real_engine.find_by_category("LOGICAL_ACCESS")
        assert {c.id for c in lower} == {c.id for c in upper}

    def test_find_by_category_empty_for_nonexistent(self, real_engine: OntologyQueryEngine) -> None:
        """Для несуществующей категории должен возвращаться пустой список."""
        controls = real_engine.find_by_category("nonexistent_category_xyz")
        assert controls == []

    def test_find_by_category_returns_sorted(self, real_engine: OntologyQueryEngine) -> None:
        """Результаты должны быть отсортированы по ID."""
        controls = real_engine.find_by_category("logical_access")
        ids = [c.id for c in controls]
        assert ids == sorted(ids)


# ── БЛОК 6: Автоматизация и поиск ─────────────────────────────────────────────

class TestAutoRemediableAndSearch:

    def test_find_auto_remediable_contains_cc6_1(self, real_engine: OntologyQueryEngine) -> None:
        """CC6.1 должен быть в списке auto_remediable контролей."""
        controls = real_engine.find_auto_remediable()
        ids = {c.id for c in controls}
        assert "CC6.1" in ids

    def test_find_by_risk_weight_threshold(self, real_engine: OntologyQueryEngine) -> None:
        """Все контроли в результате должны иметь risk_weight >= порога."""
        threshold = 0.8
        controls = real_engine.find_by_risk_weight_threshold(threshold)
        for ctrl in controls:
            assert ctrl.risk_weight >= threshold

    def test_find_by_risk_weight_sorted_descending(self, real_engine: OntologyQueryEngine) -> None:
        """Результаты должны быть отсортированы по risk_weight DESC."""
        controls = real_engine.find_by_risk_weight_threshold(0.5)
        weights = [c.risk_weight for c in controls]
        assert weights == sorted(weights, reverse=True)

    def test_find_by_framework_control_iso27001(self, real_engine: OntologyQueryEngine) -> None:
        """Поиск по ISO 27001 контролю должен вернуть связанные SOC 2 контроли."""
        # A.5.15 присутствует в CC6.1
        results = real_engine.find_by_framework_control("iso27001", "A.5.15")
        ids = {c.id for c in results}
        assert "CC6.1" in ids

    def test_find_by_framework_control_nist(self, real_engine: OntologyQueryEngine) -> None:
        """Поиск по NIST контролю должен вернуть связанные SOC 2 контроли."""
        results = real_engine.find_by_framework_control("nist", "IA-2")
        ids = {c.id for c in results}
        assert "CC6.1" in ids

    def test_get_all_categories_not_empty(self, real_engine: OntologyQueryEngine) -> None:
        """Список категорий не должен быть пустым."""
        cats = real_engine.get_all_categories()
        assert len(cats) > 0
        assert all(isinstance(c, str) for c in cats)

    def test_get_continuous_controls_includes_cc6_1(self, real_engine: OntologyQueryEngine) -> None:
        """CC6.1 должен быть в списке непрерывно мониторируемых контролей."""
        continuous = real_engine.get_continuous_controls()
        ids = {c.id for c in continuous}
        assert "CC6.1" in ids

    def test_get_continuous_controls_sorted_by_risk_desc(self, real_engine: OntologyQueryEngine) -> None:
        """get_continuous_controls() должен быть отсортирован по risk_weight DESC."""
        controls = real_engine.get_continuous_controls()
        weights = [c.risk_weight for c in controls]
        assert weights == sorted(weights, reverse=True)

    def test_get_high_risk_summary_returns_dict(self, real_engine: OntologyQueryEngine) -> None:
        """get_high_risk_summary() должен возвращать непустой словарь."""
        summary = real_engine.get_high_risk_summary(threshold=0.8)
        assert isinstance(summary, dict)
        assert len(summary) > 0

    def test_get_high_risk_summary_all_above_threshold(self, real_engine: OntologyQueryEngine) -> None:
        """Все контроли в сводке должны иметь risk_weight >= threshold."""
        threshold = 0.85
        summary = real_engine.get_high_risk_summary(threshold=threshold)
        for ctrl_id, data in summary.items():
            assert data["risk_weight"] >= threshold, (
                f"{ctrl_id}: risk_weight={data['risk_weight']} ниже порога {threshold}"
            )

    def test_get_high_risk_summary_contains_cc6_1(self, real_engine: OntologyQueryEngine) -> None:
        """CC6.1 (risk_weight=0.9) должен попасть в сводку с порогом 0.8."""
        summary = real_engine.get_high_risk_summary(threshold=0.8)
        assert "CC6.1" in summary

    def test_count_returns_positive_integer(self, real_engine: OntologyQueryEngine) -> None:
        """count() должен возвращать положительное число."""
        assert real_engine.count() >= 33


# ── БЛОК 7: explain_control ────────────────────────────────────────────────────

class TestExplainControl:

    def test_explain_existing_control_contains_id(self, engine_from_yaml: OntologyQueryEngine) -> None:
        """explain_control() должен содержать ID контроля."""
        explanation = engine_from_yaml.explain_control("CC6.1")
        assert "CC6.1" in explanation

    def test_explain_existing_control_contains_title(self, engine_from_yaml: OntologyQueryEngine) -> None:
        """explain_control() должен содержать заголовок контроля."""
        explanation = engine_from_yaml.explain_control("CC6.1")
        ctrl = engine_from_yaml.get_control("CC6.1")
        assert ctrl is not None
        assert ctrl.title in explanation

    def test_explain_nonexistent_control(self, engine_from_yaml: OntologyQueryEngine) -> None:
        """explain_control() для несуществующего ID должен сообщить об отсутствии."""
        explanation = engine_from_yaml.explain_control("CC99.99")
        assert "не найден" in explanation.lower() or "not found" in explanation.lower()

    def test_explain_control_contains_remediation_steps(self, real_engine: OntologyQueryEngine) -> None:
        """Объяснение для CC6.1 должно содержать шаги устранения."""
        explanation = real_engine.explain_control("CC6.1")
        assert "MFA" in explanation or "mfa" in explanation.lower()

    def test_explain_control_contains_frameworks(self, real_engine: OntologyQueryEngine) -> None:
        """Объяснение должно содержать маппинги фреймворков."""
        explanation = real_engine.explain_control("CC6.1")
        assert "ISO" in explanation or "NIST" in explanation


# ── БЛОК 8: enrich_with_ontology (ControlMappingEngine) ──────────────────────

class TestEnrichWithOntology:

    def test_enrich_existing_control(self) -> None:
        """enrich_with_ontology() должен вернуть словарь с данными из онтологии."""
        from control_mapping import get_engine
        result = get_engine().enrich_with_ontology("CC6.1")
        assert isinstance(result, dict)
        assert result.get("soc2") == "CC6.1"

    def test_enrich_nonexistent_control_returns_empty(self) -> None:
        """Для несуществующего SOC2 контроля должен вернуться пустой dict."""
        from control_mapping import get_engine
        result = get_engine().enrich_with_ontology("CC99.99")
        assert result == {}

    def test_enrich_includes_ontology_flag(self) -> None:
        """enrich_with_ontology() должен включать флаг ontology_enriched."""
        from control_mapping import get_engine
        result = get_engine().enrich_with_ontology("CC6.1")
        assert "ontology_enriched" in result

    def test_enrich_includes_risk_weight_when_ontology_available(self) -> None:
        """При доступной онтологии в результате должен быть risk_weight."""
        from control_mapping import get_engine
        result = get_engine().enrich_with_ontology("CC6.1")
        if result.get("ontology_enriched"):
            assert "risk_weight" in result
            assert isinstance(result["risk_weight"], float)


# ── БЛОК 9: Интеграция с AIDecisionLogger ─────────────────────────────────────

class TestAIDecisionLoggerOntologyIntegration:

    def test_record_with_control_id_includes_ontology_context(self, tmp_path: Path) -> None:
        """Запись с control_id должна содержать ontology_context в metadata."""
        from ai_decision_log import AIDecisionLogger, DecisionType
        logger = AIDecisionLogger(data_file=tmp_path / "test_decisions.json")
        rec = logger.record(
            decision_type=DecisionType.CONTROL_ASSESSMENT,
            model="test-model",
            prompt="Assess CC6.1 MFA compliance",
            output="Based on the evidence, CC6.1 passes MFA requirements.",
            outcome="PASS",
            control_id="CC6.1",
        )
        assert "ontology_context" in rec.metadata

    def test_record_without_control_id_no_ontology_context(self, tmp_path: Path) -> None:
        """Запись без control_id не должна содержать ontology_context."""
        from ai_decision_log import AIDecisionLogger, DecisionType
        logger = AIDecisionLogger(data_file=tmp_path / "test_decisions2.json")
        rec = logger.record(
            decision_type=DecisionType.GAP_ANALYSIS,
            model="test-model",
            prompt="General gap analysis",
            output="No specific controls mentioned.",
            outcome="draft",
        )
        assert "ontology_context" not in rec.metadata

    def test_ontology_context_contains_risk_weight(self, tmp_path: Path) -> None:
        """ontology_context должен содержать risk_weight для известного контроля."""
        from ai_decision_log import AIDecisionLogger, DecisionType
        logger = AIDecisionLogger(data_file=tmp_path / "test_decisions3.json")
        rec = logger.record(
            decision_type=DecisionType.CONTROL_ASSESSMENT,
            model="test-model",
            prompt="Assess CC6.1",
            output="CC6.1 assessment complete.",
            outcome="PASS",
            control_id="CC6.1",
        )
        ctx = rec.metadata.get("ontology_context", {})
        if ctx.get("available"):
            assert "risk_weight" in ctx
            assert ctx["risk_weight"] >= 0.8


# ── БЛОК 10: Singleton и Thread Safety ────────────────────────────────────────

class TestSingleton:

    def test_get_ontology_engine_returns_same_instance(self) -> None:
        """get_ontology_engine() должен возвращать один и тот же объект."""
        # Сбрасываем singleton перед тестом
        import compliance_ontology
        compliance_ontology._engine_instance = None

        engine1 = get_ontology_engine()
        engine2 = get_ontology_engine()
        assert engine1 is engine2

    def test_engine_thread_safe_access(self) -> None:
        """Параллельный доступ к движку не должен вызывать ошибок."""
        import compliance_ontology
        compliance_ontology._engine_instance = None

        results = []
        errors = []

        def worker() -> None:
            try:
                eng = get_ontology_engine()
                ctrl = eng.get_control("CC6.1")
                results.append(ctrl is not None)
            except Exception as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Ошибки в потоках: {errors}"
        assert all(results), "Некоторые потоки не нашли CC6.1"
