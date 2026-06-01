"""
Тесты для AssetManager — P5 Asset-centric compliance.

Покрытие:
  - CRUD операции над активами
  - Валидация входных данных
  - Compliance posture расчёт
  - Sync из MDM inventory
  - Sync из Scanner
  - Non-compliant search
  - Risk mappings
  - Статистика
  - Backward compat (JSON store без БД)

Все тесты изолированы: используют in-memory _JsonStore с временными файлами.
"""

import json
import sys
import os
import time
from pathlib import Path

import pytest

# Добавляем корень проекта в sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from asset_manager import (
    ASSET_TYPES,
    COMPLIANCE_STATUSES,
    CRITICALITY_ORDER,
    ENVIRONMENTS,
    EXPOSURE_LEVELS,
    AssetManager,
    _MemStore,
    get_asset_manager,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_store() -> _MemStore:
    """Создаёт изолированный in-memory store для каждого теста."""
    return _MemStore()


@pytest.fixture
def manager(tmp_store: _MemStore) -> AssetManager:
    """Создаёт AssetManager с изолированным in-memory store."""
    return AssetManager(store=tmp_store)


@pytest.fixture
def device_data() -> dict:
    """Базовые данные для Device-актива."""
    return {
        "asset_type": "device",
        "name": "alice-macbook-pro",
        "owner_id": "alice@acme.com",
        "environment": "prod",
        "criticality": "high",
        "tags": {"os": "macOS 14.5"},
        "metadata": {"device_id": "MAC-001", "hostname": "alice-macbook-pro"},
    }


@pytest.fixture
def cloud_data() -> dict:
    """Базовые данные для CloudAccount-актива."""
    return {
        "asset_type": "cloud_account",
        "name": "AWS Production",
        "owner_id": "infra@acme.com",
        "environment": "prod",
        "criticality": "critical",
        "tags": {"provider": "aws"},
        "metadata": {"account_id": "123456789", "region": "us-east-1"},
    }


@pytest.fixture
def registered_device(manager: AssetManager, device_data: dict) -> dict:
    """Заранее зарегистрированный device-актив."""
    return manager.register_asset(device_data)


# ── CRUD тесты ────────────────────────────────────────────────────────────────

class TestRegisterAsset:
    """Тесты создания активов."""

    def test_register_returns_asset_with_id(self, manager: AssetManager, device_data: dict):
        """register_asset должен вернуть актив с назначенным id."""
        asset = manager.register_asset(device_data)
        assert "id" in asset
        assert len(asset["id"]) == 36  # UUID4

    def test_register_stores_all_fields(self, manager: AssetManager, device_data: dict):
        """Все переданные поля должны сохраняться."""
        asset = manager.register_asset(device_data)
        assert asset["asset_type"] == "device"
        assert asset["name"] == "alice-macbook-pro"
        assert asset["owner_id"] == "alice@acme.com"
        assert asset["environment"] == "prod"
        assert asset["criticality"] == "high"

    def test_register_adds_timestamps(self, manager: AssetManager, device_data: dict):
        """created_at и updated_at должны быть добавлены автоматически."""
        asset = manager.register_asset(device_data)
        assert "created_at" in asset
        assert "updated_at" in asset

    def test_register_invalid_type_raises(self, manager: AssetManager):
        """Недопустимый asset_type должен вызывать ValueError."""
        with pytest.raises(ValueError, match="Недопустимый тип"):
            manager.register_asset({"asset_type": "invalid_type", "name": "test"})

    def test_register_invalid_criticality_raises(self, manager: AssetManager):
        """Недопустимая criticality должна вызывать ValueError."""
        with pytest.raises(ValueError, match="Недопустимый уровень критичности"):
            manager.register_asset({
                "asset_type": "device",
                "name": "test",
                "criticality": "ultra-critical",
            })

    def test_register_with_explicit_id(self, manager: AssetManager, device_data: dict):
        """Явно переданный id должен сохраняться."""
        device_data["id"] = "custom-id-123"
        asset = manager.register_asset(device_data)
        assert asset["id"] == "custom-id-123"

    def test_register_all_asset_types(self, manager: AssetManager):
        """Должны регистрироваться все допустимые типы активов."""
        for asset_type in ASSET_TYPES:
            asset = manager.register_asset({"asset_type": asset_type, "name": f"test-{asset_type}"})
            assert asset["asset_type"] == asset_type


class TestGetAsset:
    """Тесты получения актива."""

    def test_get_existing_asset(self, manager: AssetManager, registered_device: dict):
        """Существующий актив должен возвращаться по ID."""
        found = manager.get_asset(registered_device["id"])
        assert found is not None
        assert found["id"] == registered_device["id"]

    def test_get_nonexistent_returns_none(self, manager: AssetManager):
        """Несуществующий актив должен возвращать None."""
        result = manager.get_asset("nonexistent-id")
        assert result is None


class TestListAssets:
    """Тесты листинга и фильтрации."""

    def test_list_returns_all(self, manager: AssetManager, device_data: dict, cloud_data: dict):
        """list_assets без фильтров возвращает все активы."""
        manager.register_asset(device_data)
        manager.register_asset(cloud_data)
        assets = manager.list_assets()
        assert len(assets) == 2

    def test_filter_by_type(self, manager: AssetManager, device_data: dict, cloud_data: dict):
        """Фильтр по типу возвращает только нужные активы."""
        manager.register_asset(device_data)
        manager.register_asset(cloud_data)
        devices = manager.list_assets(asset_type="device")
        assert len(devices) == 1
        assert devices[0]["asset_type"] == "device"

    def test_filter_by_criticality(self, manager: AssetManager, device_data: dict, cloud_data: dict):
        """Фильтр по критичности работает корректно."""
        manager.register_asset(device_data)   # criticality=high
        manager.register_asset(cloud_data)    # criticality=critical
        critical = manager.list_assets(criticality="critical")
        assert len(critical) == 1
        assert critical[0]["criticality"] == "critical"

    def test_list_sorted_by_criticality(self, manager: AssetManager):
        """Список отсортирован: critical раньше low."""
        manager.register_asset({"asset_type": "device", "name": "low-device", "criticality": "low"})
        manager.register_asset({"asset_type": "device", "name": "critical-device", "criticality": "critical"})
        assets = manager.list_assets()
        assert assets[0]["criticality"] == "critical"
        assert assets[1]["criticality"] == "low"


class TestUpdateAsset:
    """Тесты обновления активов."""

    def test_update_name(self, manager: AssetManager, registered_device: dict):
        """Обновление имени должно работать."""
        updated = manager.update_asset(registered_device["id"], {"name": "new-name"})
        assert updated["name"] == "new-name"

    def test_update_preserves_id(self, manager: AssetManager, registered_device: dict):
        """ID должен оставаться неизменным после обновления."""
        original_id = registered_device["id"]
        updated = manager.update_asset(original_id, {"name": "updated"})
        assert updated["id"] == original_id

    def test_update_nonexistent_returns_none(self, manager: AssetManager):
        """Обновление несуществующего актива возвращает None."""
        result = manager.update_asset("fake-id", {"name": "x"})
        assert result is None

    def test_update_sets_updated_at(self, manager: AssetManager, registered_device: dict):
        """updated_at должен присутствовать в обновлённом активе."""
        time.sleep(0.01)
        updated = manager.update_asset(registered_device["id"], {"name": "newer"})
        # updated_at может быть тем же секундным значением, но поле должно существовать
        assert "updated_at" in updated


class TestDeleteAsset:
    """Тесты удаления активов."""

    def test_delete_existing(self, manager: AssetManager, registered_device: dict):
        """Удаление существующего актива возвращает True."""
        result = manager.delete_asset(registered_device["id"])
        assert result is True
        assert manager.get_asset(registered_device["id"]) is None

    def test_delete_nonexistent_returns_false(self, manager: AssetManager):
        """Удаление несуществующего актива возвращает False."""
        result = manager.delete_asset("nonexistent")
        assert result is False

    def test_delete_removes_control_mappings(self, manager: AssetManager, registered_device: dict):
        """Удаление актива должно убрать его control-маппинги."""
        asset_id = registered_device["id"]
        manager.update_compliance_status(asset_id, "CC6.6", "PASS")
        manager.delete_asset(asset_id)
        controls = manager.get_controls_for_asset(asset_id)
        assert controls == []


# ── Compliance posture тесты ──────────────────────────────────────────────────

class TestCompliancePosture:
    """Тесты расчёта compliance posture."""

    def test_posture_empty_controls(self, manager: AssetManager, registered_device: dict):
        """Актив без маппингов имеет UNKNOWN статус."""
        posture = manager.get_asset_compliance_posture(registered_device["id"])
        assert posture["total_controls"] == 0
        assert posture["overall_status"] == "UNKNOWN"

    def test_posture_all_pass(self, manager: AssetManager, registered_device: dict):
        """100% PASS → overall_status PASS, compliance_pct 100."""
        asset_id = registered_device["id"]
        manager.update_compliance_status(asset_id, "CC6.6", "PASS")
        manager.update_compliance_status(asset_id, "CC6.8", "PASS")
        posture = manager.get_asset_compliance_posture(asset_id)
        assert posture["overall_status"] == "PASS"
        assert posture["compliance_pct"] == 100.0

    def test_posture_with_fail(self, manager: AssetManager, registered_device: dict):
        """Любой FAIL → overall_status FAIL."""
        asset_id = registered_device["id"]
        manager.update_compliance_status(asset_id, "CC6.6", "PASS")
        manager.update_compliance_status(asset_id, "CC6.8", "FAIL")
        posture = manager.get_asset_compliance_posture(asset_id)
        assert posture["overall_status"] == "FAIL"
        assert posture["fail_count"] == 1

    def test_posture_compliance_pct_calculation(self, manager: AssetManager, registered_device: dict):
        """compliance_pct = PASS / total * 100."""
        asset_id = registered_device["id"]
        manager.update_compliance_status(asset_id, "CC6.1", "PASS")
        manager.update_compliance_status(asset_id, "CC6.2", "PASS")
        manager.update_compliance_status(asset_id, "CC6.3", "FAIL")
        manager.update_compliance_status(asset_id, "CC6.4", "UNKNOWN")
        posture = manager.get_asset_compliance_posture(asset_id)
        assert posture["pass_count"] == 2
        assert posture["fail_count"] == 1
        assert posture["total_controls"] == 4
        assert posture["compliance_pct"] == 50.0

    def test_posture_nonexistent_asset(self, manager: AssetManager):
        """Несуществующий актив возвращает error в posture."""
        posture = manager.get_asset_compliance_posture("bad-id")
        assert "error" in posture

    def test_posture_upsert_same_control(self, manager: AssetManager, registered_device: dict):
        """Повторное обновление того же контроля не дублирует запись."""
        asset_id = registered_device["id"]
        manager.update_compliance_status(asset_id, "CC6.6", "PASS")
        manager.update_compliance_status(asset_id, "CC6.6", "FAIL")  # upsert
        posture = manager.get_asset_compliance_posture(asset_id)
        assert posture["total_controls"] == 1
        assert posture["fail_count"] == 1


# ── Non-compliant search тесты ────────────────────────────────────────────────

class TestNonCompliantSearch:
    """Тесты поиска non-compliant активов."""

    def test_no_non_compliant_initially(self, manager: AssetManager, registered_device: dict):
        """Без FAIL маппингов — пустой список."""
        manager.update_compliance_status(registered_device["id"], "CC6.6", "PASS")
        result = manager.find_non_compliant_assets()
        assert result == []

    def test_find_fail_assets(self, manager: AssetManager, registered_device: dict):
        """Актив с FAIL маппингом должен быть найден."""
        asset_id = registered_device["id"]
        manager.update_compliance_status(asset_id, "CC6.6", "FAIL")
        result = manager.find_non_compliant_assets()
        assert len(result) == 1
        assert result[0]["control_id"] == "CC6.6"
        assert result[0]["asset"]["id"] == asset_id

    def test_filter_by_control_id(self, manager: AssetManager, registered_device: dict):
        """Фильтр по control_id работает."""
        asset_id = registered_device["id"]
        manager.update_compliance_status(asset_id, "CC6.6", "FAIL")
        manager.update_compliance_status(asset_id, "CC6.8", "FAIL")

        result = manager.find_non_compliant_assets(control_id="CC6.6")
        assert len(result) == 1
        assert result[0]["control_id"] == "CC6.6"

    def test_partial_not_in_non_compliant(self, manager: AssetManager, registered_device: dict):
        """PARTIAL статус НЕ попадает в non-compliant список."""
        asset_id = registered_device["id"]
        manager.update_compliance_status(asset_id, "CC6.6", "PARTIAL")
        result = manager.find_non_compliant_assets()
        assert result == []

    def test_sorted_by_criticality(self, manager: AssetManager):
        """Non-compliant отсортированы: critical сначала."""
        low = manager.register_asset({"asset_type": "device", "name": "low", "criticality": "low"})
        critical = manager.register_asset({"asset_type": "device", "name": "critical", "criticality": "critical"})
        manager.update_compliance_status(low["id"], "CC6.6", "FAIL")
        manager.update_compliance_status(critical["id"], "CC6.6", "FAIL")
        result = manager.find_non_compliant_assets()
        assert result[0]["asset"]["criticality"] == "critical"


# ── Sync тесты ────────────────────────────────────────────────────────────────

class TestSyncFromMDM:
    """Тесты синхронизации из MDM inventory."""

    def _make_mdm_file(self, tmp_path: Path, devices: list) -> Path:
        """Создаёт временный MDM inventory файл."""
        path = tmp_path / "mdm_inventory.json"
        data = {
            "organization": "Acme",
            "last_sync": "2026-01-01T00:00:00Z",
            "devices": devices,
        }
        path.write_text(json.dumps(data))
        return path

    def test_sync_creates_device_assets(self, manager: AssetManager, tmp_path: Path):
        """sync_from_mdm создаёт device-активы из inventory."""
        path = self._make_mdm_file(tmp_path, [
            {
                "device_id": "MAC-001",
                "hostname": "alice-laptop",
                "owner": "alice@acme.com",
                "os": "macOS 14.5",
                "device_type": "laptop",
                "filevault_enabled": True,
                "compliant": True,
            }
        ])
        result = manager.sync_from_mdm(inventory_path=path)
        assert result["created"] == 1
        assert result["updated"] == 0
        assets = manager.list_assets(asset_type="device")
        assert len(assets) == 1
        assert assets[0]["name"] == "alice-laptop"

    def test_sync_updates_existing_asset(self, manager: AssetManager, tmp_path: Path):
        """Повторный sync обновляет существующие активы."""
        device = {
            "device_id": "MAC-001",
            "hostname": "alice-laptop",
            "owner": "alice@acme.com",
            "os": "macOS 14.5",
            "device_type": "laptop",
            "filevault_enabled": True,
            "compliant": True,
        }
        path = self._make_mdm_file(tmp_path, [device])

        # Первый sync — создаёт
        manager.sync_from_mdm(inventory_path=path)

        # Меняем данные и синкаем снова
        device["hostname"] = "alice-laptop-updated"
        path.write_text(json.dumps({"organization": "Acme", "devices": [device]}))
        result = manager.sync_from_mdm(inventory_path=path)

        assert result["created"] == 0
        assert result["updated"] == 1

    def test_sync_missing_file_returns_error(self, manager: AssetManager, tmp_path: Path):
        """Отсутствующий файл возвращает error в результате."""
        result = manager.sync_from_mdm(inventory_path=tmp_path / "missing.json")
        assert "error" in result

    def test_sync_stores_metadata(self, manager: AssetManager, tmp_path: Path):
        """sync_from_mdm сохраняет device_id в metadata."""
        path = self._make_mdm_file(tmp_path, [{
            "device_id": "WIN-001",
            "hostname": "bob-workstation",
            "owner": "bob@acme.com",
            "device_type": "workstation",
            "compliant": False,
        }])
        manager.sync_from_mdm(inventory_path=path)
        assets = manager.list_assets(asset_type="device")
        assert assets[0]["metadata"]["device_id"] == "WIN-001"


class TestSyncFromScanner:
    """Тесты синхронизации из Scanner evidence."""

    def test_sync_creates_cloud_account(self, manager: AssetManager, tmp_path: Path):
        """sync_from_scanner создаёт cloud_account активы."""
        scanner_file = tmp_path / "scanner_evidence.json"
        scanner_file.write_text(json.dumps([{
            "account_id": "123456789012",
            "name": "AWS Production",
            "provider": "aws",
            "region": "us-east-1",
            "environment": "prod",
            "criticality": "critical",
        }]))
        result = manager.sync_from_scanner(evidence_file=scanner_file)
        assert result["created"] == 1
        assets = manager.list_assets(asset_type="cloud_account")
        assert len(assets) == 1

    def test_sync_no_data_returns_note(self, manager: AssetManager, tmp_path: Path):
        """Без данных scanner sync возвращает note."""
        result = manager.sync_from_scanner(evidence_file=tmp_path / "missing.json")
        assert "note" in result or result["created"] == 0


# ── Risk mapping тесты ────────────────────────────────────────────────────────

class TestRiskMappings:
    """Тесты управления risk-маппингами."""

    def test_add_risk_mapping(self, manager: AssetManager, registered_device: dict):
        """Добавление risk-маппинга работает."""
        mapping = manager.add_risk_mapping(registered_device["id"], "RISK-001", "high")
        assert mapping is not None
        assert mapping["risk_id"] == "RISK-001"
        assert mapping["exposure_level"] == "high"

    def test_add_risk_nonexistent_asset_returns_none(self, manager: AssetManager):
        """Маппинг для несуществующего актива возвращает None."""
        result = manager.add_risk_mapping("bad-id", "RISK-001", "low")
        assert result is None

    def test_invalid_exposure_level_raises(self, manager: AssetManager, registered_device: dict):
        """Недопустимый exposure_level вызывает ValueError."""
        with pytest.raises(ValueError, match="Недопустимый exposure_level"):
            manager.add_risk_mapping(registered_device["id"], "RISK-001", "ultra-high")

    def test_get_risk_mappings(self, manager: AssetManager, registered_device: dict):
        """get_risk_mappings возвращает все маппинги актива."""
        asset_id = registered_device["id"]
        manager.add_risk_mapping(asset_id, "RISK-001", "high")
        manager.add_risk_mapping(asset_id, "RISK-002", "medium")
        risks = manager.get_risk_mappings(asset_id)
        assert len(risks) == 2


# ── Stats тесты ───────────────────────────────────────────────────────────────

class TestGetStats:
    """Тесты статистики."""

    def test_empty_stats(self, manager: AssetManager):
        """Пустой менеджер возвращает нулевую статистику."""
        stats = manager.get_stats()
        assert stats["total"] == 0
        assert stats["compliance_pct"] == 0.0

    def test_stats_by_type(self, manager: AssetManager, device_data: dict, cloud_data: dict):
        """by_type правильно считает количество по типам."""
        manager.register_asset(device_data)
        manager.register_asset(cloud_data)
        stats = manager.get_stats()
        assert stats["by_type"]["device"] == 1
        assert stats["by_type"]["cloud_account"] == 1

    def test_stats_compliance_pct(self, manager: AssetManager, registered_device: dict):
        """compliance_pct рассчитывается по всем маппингам."""
        asset_id = registered_device["id"]
        manager.update_compliance_status(asset_id, "CC6.6", "PASS")
        manager.update_compliance_status(asset_id, "CC6.8", "FAIL")
        stats = manager.get_stats()
        assert stats["compliance_pct"] == 50.0


# ── Singleton тест ────────────────────────────────────────────────────────────

class TestGetAssetManager:
    """Тест singleton-паттерна get_asset_manager."""

    def test_singleton_returns_same_instance(self):
        """get_asset_manager возвращает один и тот же экземпляр."""
        m1 = get_asset_manager()
        m2 = get_asset_manager()
        assert m1 is m2


# ── Константы тесты ───────────────────────────────────────────────────────────

class TestConstants:
    """Тесты корректности констант модуля."""

    def test_all_asset_types_defined(self):
        """Все ожидаемые типы присутствуют."""
        expected = {"device", "cloud_account", "repository", "database", "employee", "vendor_service"}
        assert expected.issubset(ASSET_TYPES)

    def test_criticality_order_complete(self):
        """Все уровни критичности определены."""
        assert "critical" in CRITICALITY_ORDER
        assert "high" in CRITICALITY_ORDER
        assert "medium" in CRITICALITY_ORDER
        assert "low" in CRITICALITY_ORDER

    def test_criticality_sort_order(self):
        """critical < high < medium < low по числовому порядку."""
        assert CRITICALITY_ORDER["critical"] < CRITICALITY_ORDER["high"]
        assert CRITICALITY_ORDER["high"] < CRITICALITY_ORDER["medium"]
        assert CRITICALITY_ORDER["medium"] < CRITICALITY_ORDER["low"]

    def test_compliance_statuses_complete(self):
        """Все статусы compliance определены."""
        assert "PASS" in COMPLIANCE_STATUSES
        assert "FAIL" in COMPLIANCE_STATUSES
        assert "PARTIAL" in COMPLIANCE_STATUSES
        assert "UNKNOWN" in COMPLIANCE_STATUSES

    def test_environments_complete(self):
        """Все окружения определены."""
        assert "prod" in ENVIRONMENTS
        assert "staging" in ENVIRONMENTS
        assert "dev" in ENVIRONMENTS
