"""
asset_manager.py — Asset-centric compliance управление.

Центральный компонент P5: связывает активы организации (устройства,
cloud-аккаунты, репозитории, базы данных, сотрудников, вендор-сервисы)
с SOC2 контролями и реестром рисков.

Режимы хранения:
  DB (DATABASE_URL задан)   → SQLAlchemy ORM через AsyncSession
  JSON fallback (по умолчанию) → data/assets.json (backward compat)
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from log_config import get_logger

log = get_logger(__name__)

# ── Константы ─────────────────────────────────────────────────────────────────

# Путь к JSON-файлу для fallback-режима
_ASSETS_FILE = Path(__file__).parent / "data" / "assets.json"

# Допустимые типы активов
ASSET_TYPES = frozenset({
    "device",
    "cloud_account",
    "repository",
    "database",
    "employee",
    "vendor_service",
})

# Допустимые уровни критичности (порядок важен для сортировки)
CRITICALITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Допустимые окружения
ENVIRONMENTS = frozenset({"prod", "staging", "dev"})

# Допустимые compliance-статусы
COMPLIANCE_STATUSES = frozenset({"PASS", "FAIL", "PARTIAL", "UNKNOWN"})

# Допустимые уровни экспозиции риска
EXPOSURE_LEVELS = frozenset({"critical", "high", "medium", "low"})

# Имя файла MDM инвентаря (совместимость с mdm_agent.py)
MDM_INVENTORY_FILE = Path(__file__).parent / "mdm_device_inventory.json"


# ── Вспомогательные функции ───────────────────────────────────────────────────

def _new_uuid() -> str:
    """Генерирует новый UUID4 как строку."""
    return str(uuid.uuid4())


def _utcnow_iso() -> str:
    """Текущее время UTC в ISO 8601 формате."""
    return datetime.now(timezone.utc).isoformat()


def _validate_asset_type(asset_type: str) -> None:
    """Проверяет допустимость типа актива."""
    if asset_type not in ASSET_TYPES:
        raise ValueError(
            f"Недопустимый тип актива '{asset_type}'. "
            f"Допустимые: {sorted(ASSET_TYPES)}"
        )


def _validate_criticality(criticality: str) -> None:
    """Проверяет допустимость уровня критичности."""
    if criticality not in CRITICALITY_ORDER:
        raise ValueError(
            f"Недопустимый уровень критичности '{criticality}'. "
            f"Допустимые: {list(CRITICALITY_ORDER)}"
        )


def _validate_status(status: str) -> None:
    """Проверяет допустимость compliance-статуса."""
    if status not in COMPLIANCE_STATUSES:
        raise ValueError(
            f"Недопустимый статус '{status}'. "
            f"Допустимые: {sorted(COMPLIANCE_STATUSES)}"
        )


# ── JSON storage layer ────────────────────────────────────────────────────────

class _JsonStore:
    """
    In-memory + JSON-файл хранилище для fallback-режима без БД.

    Структура data/assets.json:
      {
        "assets": { "<asset_id>": { ...asset fields... } },
        "control_mappings": [ { asset_id, control_id, status, ... } ],
        "risk_mappings": [ { asset_id, risk_id, exposure_level } ]
      }
    """

    def __init__(self, path: Path = _ASSETS_FILE) -> None:
        self._path = path
        self._data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        """Читает JSON из файла или возвращает пустую структуру."""
        if self._path.exists():
            try:
                with open(self._path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("Не удалось прочитать %s: %s. Начинаем с пустого.", self._path, exc)
        return {"assets": {}, "control_mappings": [], "risk_mappings": []}

    def _save(self) -> None:
        """Сохраняет текущее состояние в JSON-файл."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2, ensure_ascii=False, default=str)

    # ── Assets ────────────────────────────────────────────────────────────────

    def put_asset(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        """Создаёт или обновляет актив."""
        self._data["assets"][asset["id"]] = asset
        self._save()
        return asset

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Возвращает актив по ID или None."""
        return self._data["assets"].get(asset_id)

    def list_assets(
        self,
        asset_type: Optional[str] = None,
        criticality: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Возвращает отфильтрованный список активов."""
        items = list(self._data["assets"].values())
        if asset_type:
            items = [a for a in items if a.get("asset_type") == asset_type]
        if criticality:
            items = [a for a in items if a.get("criticality") == criticality]
        if environment:
            items = [a for a in items if a.get("environment") == environment]
        # Сортировка: сначала по критичности, затем по имени
        items.sort(key=lambda a: (
            CRITICALITY_ORDER.get(a.get("criticality", "low"), 99),
            a.get("name", ""),
        ))
        return items

    def delete_asset(self, asset_id: str) -> bool:
        """Удаляет актив и все его маппинги."""
        if asset_id not in self._data["assets"]:
            return False
        del self._data["assets"][asset_id]
        # Удаляем связанные маппинги
        self._data["control_mappings"] = [
            m for m in self._data["control_mappings"] if m["asset_id"] != asset_id
        ]
        self._data["risk_mappings"] = [
            m for m in self._data["risk_mappings"] if m["asset_id"] != asset_id
        ]
        self._save()
        return True

    # ── Control mappings ─────────────────────────────────────────────────────

    def upsert_control_mapping(
        self,
        asset_id: str,
        control_id: str,
        status: str,
        evidence_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Создаёт или обновляет маппинг актив ↔ контроль."""
        # Ищем существующий маппинг
        for mapping in self._data["control_mappings"]:
            if mapping["asset_id"] == asset_id and mapping["control_id"] == control_id:
                mapping["compliance_status"] = status
                mapping["last_checked"] = _utcnow_iso()
                if evidence_ids is not None:
                    mapping["evidence_ids"] = evidence_ids
                self._save()
                return mapping

        # Создаём новый маппинг
        new_mapping: Dict[str, Any] = {
            "id": len(self._data["control_mappings"]) + 1,
            "asset_id": asset_id,
            "control_id": control_id,
            "compliance_status": status,
            "last_checked": _utcnow_iso(),
            "evidence_ids": evidence_ids or [],
        }
        self._data["control_mappings"].append(new_mapping)
        self._save()
        return new_mapping

    def get_control_mappings(self, asset_id: str) -> List[Dict[str, Any]]:
        """Возвращает все маппинги для данного актива."""
        return [
            m for m in self._data["control_mappings"]
            if m["asset_id"] == asset_id
        ]

    def get_assets_by_control(
        self,
        control_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Возвращает маппинги для данного контроля (опционально фильтр по статусу)."""
        mappings = [
            m for m in self._data["control_mappings"]
            if m["control_id"] == control_id
        ]
        if status:
            mappings = [m for m in mappings if m["compliance_status"] == status]
        return mappings

    def list_all_control_mappings(self) -> List[Dict[str, Any]]:
        """Возвращает все control-маппинги."""
        return list(self._data["control_mappings"])

    # ── Risk mappings ─────────────────────────────────────────────────────────

    def upsert_risk_mapping(
        self,
        asset_id: str,
        risk_id: str,
        exposure_level: str,
    ) -> Dict[str, Any]:
        """Создаёт или обновляет маппинг актив ↔ риск."""
        for mapping in self._data["risk_mappings"]:
            if mapping["asset_id"] == asset_id and mapping["risk_id"] == risk_id:
                mapping["exposure_level"] = exposure_level
                self._save()
                return mapping

        new_mapping: Dict[str, Any] = {
            "id": len(self._data["risk_mappings"]) + 1,
            "asset_id": asset_id,
            "risk_id": risk_id,
            "exposure_level": exposure_level,
        }
        self._data["risk_mappings"].append(new_mapping)
        self._save()
        return new_mapping

    def get_risk_mappings(self, asset_id: str) -> List[Dict[str, Any]]:
        """Возвращает все маппинги рисков для данного актива."""
        return [
            m for m in self._data["risk_mappings"]
            if m["asset_id"] == asset_id
        ]

    def list_all_risk_mappings(self) -> List[Dict[str, Any]]:
        """Возвращает все risk-маппинги."""
        return list(self._data["risk_mappings"])


# ── AssetManager ──────────────────────────────────────────────────────────────

class AssetManager:
    """
    Менеджер активов для asset-centric compliance.

    Поддерживает два режима хранения:
      - JSON fallback (по умолчанию): data/assets.json
      - DB (если DATABASE_URL задан): через AsyncSession (реализуется в роутере)

    Основные возможности:
      - CRUD операции над активами
      - Управление compliance-маппингами актив ↔ контроль
      - Управление risk-маппингами актив ↔ риск
      - Синхронизация с MDM (mdm_device_inventory.json)
      - Синхронизация со Scanner (парсинг evidence с source=SCANNER)
      - Поиск non-compliant активов
      - Расчёт compliance posture для актива
    """

    def __init__(self, store: Optional[_JsonStore] = None) -> None:
        # Используем переданный store или создаём новый JSON-store
        self._store = store or _JsonStore()

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def register_asset(self, asset_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Регистрирует новый актив в системе.

        Args:
            asset_data: словарь с полями актива. Обязательные поля:
              - asset_type: тип актива
              - name: название

        Returns:
            Созданный актив с назначенным id.

        Raises:
            ValueError: если тип актива или критичность недопустимы.
        """
        asset_type = asset_data.get("asset_type", "")
        criticality = asset_data.get("criticality", "medium")
        environment = asset_data.get("environment", "prod")

        _validate_asset_type(asset_type)
        _validate_criticality(criticality)
        if environment not in ENVIRONMENTS:
            environment = "prod"

        # Генерируем ID если не передан (поддержка внешних ID для sync)
        asset_id = asset_data.get("id") or _new_uuid()

        asset: Dict[str, Any] = {
            "id": asset_id,
            "asset_type": asset_type,
            "name": asset_data.get("name", ""),
            "owner_id": asset_data.get("owner_id") or asset_data.get("owner"),
            "environment": environment,
            "criticality": criticality,
            "tags": asset_data.get("tags") or {},
            "metadata": asset_data.get("metadata") or {},
            "created_at": asset_data.get("created_at") or _utcnow_iso(),
            "updated_at": _utcnow_iso(),
        }

        log.info(
            "Регистрация актива %s (%s) type=%s",
            asset_id,
            asset["name"],
            asset_type,
        )
        return self._store.put_asset(asset)

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """
        Возвращает актив по ID.

        Returns:
            Словарь актива или None если не найден.
        """
        return self._store.get_asset(asset_id)

    def list_assets(
        self,
        asset_type: Optional[str] = None,
        criticality: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Возвращает список активов с опциональной фильтрацией.

        Args:
            asset_type:  фильтр по типу (device, cloud_account, etc.)
            criticality: фильтр по критичности (critical, high, medium, low)
            environment: фильтр по окружению (prod, staging, dev)
        """
        return self._store.list_assets(
            asset_type=asset_type,
            criticality=criticality,
            environment=environment,
        )

    def update_asset(self, asset_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Обновляет поля существующего актива.

        Returns:
            Обновлённый актив или None если актив не найден.
        """
        existing = self._store.get_asset(asset_id)
        if not existing:
            return None

        # Защита иммутабельных полей
        update_data.pop("id", None)
        update_data.pop("created_at", None)

        # Валидируем изменяемые поля
        if "asset_type" in update_data:
            _validate_asset_type(update_data["asset_type"])
        if "criticality" in update_data:
            _validate_criticality(update_data["criticality"])

        existing.update(update_data)
        existing["updated_at"] = _utcnow_iso()
        return self._store.put_asset(existing)

    def delete_asset(self, asset_id: str) -> bool:
        """
        Удаляет актив и все связанные маппинги.

        Returns:
            True если удалён, False если не найден.
        """
        return self._store.delete_asset(asset_id)

    # ── Compliance mappings ───────────────────────────────────────────────────

    def update_compliance_status(
        self,
        asset_id: str,
        control_id: str,
        status: str,
        evidence_ids: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Обновляет compliance-статус для пары актив ↔ контроль.

        Args:
            asset_id:    ID актива
            control_id:  ID контроля (например "CC6.6")
            status:      PASS / FAIL / PARTIAL / UNKNOWN
            evidence_ids: список ID доказательств

        Returns:
            Обновлённый маппинг или None если актив не найден.

        Raises:
            ValueError: недопустимый статус.
        """
        _validate_status(status)

        if not self._store.get_asset(asset_id):
            log.warning("Актив не найден: %s", asset_id)
            return None

        mapping = self._store.upsert_control_mapping(
            asset_id=asset_id,
            control_id=control_id,
            status=status,
            evidence_ids=evidence_ids,
        )
        log.info(
            "Compliance статус обновлён asset=%s control=%s status=%s",
            asset_id, control_id, status,
        )
        return mapping

    def get_asset_compliance_posture(self, asset_id: str) -> Dict[str, Any]:
        """
        Рассчитывает compliance posture для актива.

        Returns:
            Словарь:
              asset_id:          str
              total_controls:    int
              pass_count:        int
              fail_count:        int
              partial_count:     int
              unknown_count:     int
              compliance_pct:    float  — % контролей со статусом PASS
              overall_status:    str    — PASS / FAIL / PARTIAL / UNKNOWN
              controls:          list   — детальный список маппингов
        """
        asset = self._store.get_asset(asset_id)
        if not asset:
            return {
                "asset_id": asset_id,
                "error": "Asset not found",
                "total_controls": 0,
                "compliance_pct": 0.0,
                "overall_status": "UNKNOWN",
                "controls": [],
            }

        mappings = self._store.get_control_mappings(asset_id)
        total = len(mappings)

        if total == 0:
            return {
                "asset_id": asset_id,
                "asset_name": asset.get("name"),
                "total_controls": 0,
                "pass_count": 0,
                "fail_count": 0,
                "partial_count": 0,
                "unknown_count": 0,
                "compliance_pct": 0.0,
                "overall_status": "UNKNOWN",
                "controls": [],
            }

        pass_count = sum(1 for m in mappings if m["compliance_status"] == "PASS")
        fail_count = sum(1 for m in mappings if m["compliance_status"] == "FAIL")
        partial_count = sum(1 for m in mappings if m["compliance_status"] == "PARTIAL")
        unknown_count = sum(1 for m in mappings if m["compliance_status"] == "UNKNOWN")

        compliance_pct = round(pass_count / total * 100, 1) if total > 0 else 0.0

        # Определяем общий статус
        if fail_count > 0:
            overall_status = "FAIL"
        elif unknown_count == total:
            overall_status = "UNKNOWN"
        elif pass_count == total:
            overall_status = "PASS"
        else:
            overall_status = "PARTIAL"

        return {
            "asset_id": asset_id,
            "asset_name": asset.get("name"),
            "asset_type": asset.get("asset_type"),
            "criticality": asset.get("criticality"),
            "total_controls": total,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "partial_count": partial_count,
            "unknown_count": unknown_count,
            "compliance_pct": compliance_pct,
            "overall_status": overall_status,
            "controls": sorted(mappings, key=lambda m: m.get("control_id", "")),
        }

    def get_controls_for_asset(self, asset_id: str) -> List[Dict[str, Any]]:
        """
        Возвращает список контролей, применимых к данному активу.

        Returns:
            Список маппингов с control_id и compliance_status.
        """
        return self._store.get_control_mappings(asset_id)

    def add_risk_mapping(
        self,
        asset_id: str,
        risk_id: str,
        exposure_level: str = "medium",
    ) -> Optional[Dict[str, Any]]:
        """
        Добавляет или обновляет маппинг актив ↔ риск.

        Args:
            asset_id:       ID актива
            risk_id:        ID риска (например "RISK-001")
            exposure_level: critical / high / medium / low

        Returns:
            Маппинг или None если актив не найден.
        """
        if exposure_level not in EXPOSURE_LEVELS:
            raise ValueError(
                f"Недопустимый exposure_level '{exposure_level}'. "
                f"Допустимые: {sorted(EXPOSURE_LEVELS)}"
            )
        if not self._store.get_asset(asset_id):
            return None
        return self._store.upsert_risk_mapping(asset_id, risk_id, exposure_level)

    def get_risk_mappings(self, asset_id: str) -> List[Dict[str, Any]]:
        """Возвращает все риск-маппинги для актива."""
        return self._store.get_risk_mappings(asset_id)

    # ── Non-compliant search ──────────────────────────────────────────────────

    def find_non_compliant_assets(
        self,
        control_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Ищет активы с FAIL статусом.

        Args:
            control_id: если задан — фильтрует только по данному контролю.

        Returns:
            Список словарей: {asset, control_id, mapping}.
        """
        all_mappings = self._store.list_all_control_mappings()

        # Фильтр по статусу FAIL
        fail_mappings = [
            m for m in all_mappings
            if m.get("compliance_status") == "FAIL"
        ]

        # Опциональный фильтр по control_id
        if control_id:
            fail_mappings = [m for m in fail_mappings if m.get("control_id") == control_id]

        # Обогащаем маппинги данными об активе
        result: List[Dict[str, Any]] = []
        seen_pairs: set = set()

        for mapping in fail_mappings:
            pair = (mapping["asset_id"], mapping["control_id"])
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            asset = self._store.get_asset(mapping["asset_id"])
            if asset:
                result.append({
                    "asset": asset,
                    "control_id": mapping["control_id"],
                    "compliance_status": mapping["compliance_status"],
                    "last_checked": mapping.get("last_checked"),
                    "evidence_ids": mapping.get("evidence_ids", []),
                })

        # Сортируем по критичности актива
        result.sort(key=lambda r: (
            CRITICALITY_ORDER.get(r["asset"].get("criticality", "low"), 99),
            r["control_id"],
        ))
        return result

    # ── Sync from MDM ─────────────────────────────────────────────────────────

    def sync_from_mdm(self, inventory_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Синхронизирует активы типа 'device' из mdm_device_inventory.json.

        Логика:
          - Читает inventory-файл
          - Для каждого устройства: создаёт новый актив или обновляет существующий
          - Совпадение по device_id в metadata

        Returns:
            Словарь: {created, updated, total}
        """
        path = inventory_path or MDM_INVENTORY_FILE

        if not path.exists():
            log.warning("MDM inventory файл не найден: %s", path)
            return {"created": 0, "updated": 0, "total": 0, "error": "file not found"}

        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            log.error("Ошибка чтения MDM inventory: %s", exc)
            return {"created": 0, "updated": 0, "total": 0, "error": str(exc)}

        devices = data.get("devices", [])
        created = 0
        updated = 0

        for device in devices:
            device_id = device.get("device_id")
            if not device_id:
                continue

            # Критичность: серверы критические, ноутбуки высокие
            device_type = device.get("device_type", "laptop")
            criticality = "critical" if device_type == "server" else "high"

            # Ищем существующий актив по device_id в metadata
            existing = self._find_asset_by_metadata("device_id", device_id)

            asset_data: Dict[str, Any] = {
                "asset_type": "device",
                "name": device.get("hostname", device_id),
                "owner_id": device.get("owner"),
                "environment": "prod",
                "criticality": criticality,
                "tags": {
                    "os": device.get("os", ""),
                    "device_type": device_type,
                    "edr": device.get("edr_name", ""),
                    "compliant": str(device.get("compliant", False)),
                },
                "metadata": {
                    "device_id": device_id,
                    "hostname": device.get("hostname"),
                    "os": device.get("os"),
                    "device_type": device_type,
                    "filevault_enabled": device.get("filevault_enabled"),
                    "screen_lock_minutes": device.get("screen_lock_minutes"),
                    "edr_installed": device.get("edr_installed"),
                    "edr_name": device.get("edr_name"),
                    "os_up_to_date": device.get("os_up_to_date"),
                    "last_check_in": device.get("last_check_in"),
                    "mdm_compliant": device.get("compliant"),
                },
            }

            if existing:
                self.update_asset(existing["id"], asset_data)
                updated += 1
            else:
                self.register_asset(asset_data)
                created += 1

        total = created + updated
        log.info(
            "MDM sync завершён: created=%d updated=%d total=%d",
            created, updated, total,
        )
        return {"created": created, "updated": updated, "total": total}

    # ── Sync from Scanner ─────────────────────────────────────────────────────

    def sync_from_scanner(self, evidence_file: Optional[Path] = None) -> Dict[str, Any]:
        """
        Синхронизирует cloud_account активы из evidence с source=SCANNER.

        Читает JSON-файл evidence (если есть) и создаёт/обновляет
        cloud_account активы на основе найденных AWS-ресурсов.

        Returns:
            Словарь: {created, updated, total}
        """
        # Пробуем загрузить данные из известных источников scanner
        scanner_data = self._load_scanner_data(evidence_file)
        if not scanner_data:
            return {"created": 0, "updated": 0, "total": 0, "note": "no scanner data"}

        created = 0
        updated = 0

        for account_info in scanner_data:
            account_id = account_info.get("account_id") or account_info.get("resource_id")
            if not account_id:
                continue

            existing = self._find_asset_by_metadata("account_id", account_id)

            asset_data: Dict[str, Any] = {
                "asset_type": "cloud_account",
                "name": account_info.get("name") or f"AWS {account_id}",
                "owner_id": account_info.get("owner"),
                "environment": account_info.get("environment", "prod"),
                "criticality": account_info.get("criticality", "critical"),
                "tags": {
                    "provider": account_info.get("provider", "aws"),
                    "region": account_info.get("region", ""),
                    "source": "scanner",
                },
                "metadata": {
                    "account_id": account_id,
                    "region": account_info.get("region"),
                    "provider": account_info.get("provider", "aws"),
                    "services": account_info.get("services", []),
                    "last_scan": account_info.get("last_scan") or _utcnow_iso(),
                },
            }

            if existing:
                self.update_asset(existing["id"], asset_data)
                updated += 1
            else:
                self.register_asset(asset_data)
                created += 1

        total = created + updated
        log.info(
            "Scanner sync завершён: created=%d updated=%d total=%d",
            created, updated, total,
        )
        return {"created": created, "updated": updated, "total": total}

    def _load_scanner_data(self, evidence_file: Optional[Path]) -> List[Dict[str, Any]]:
        """
        Загружает данные сканера из JSON-файла или возвращает дефолтный
        cloud account на основе переменных окружения AWS.
        """
        # Если передан явный файл — используем его
        if evidence_file and evidence_file.exists():
            try:
                with open(evidence_file, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    return data if isinstance(data, list) else [data]
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("Ошибка чтения scanner evidence: %s", exc)

        # Иначе создаём запись по переменным окружения (если AWS настроен)
        region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        key_id = os.getenv("AWS_ACCESS_KEY_ID", "")

        if key_id and key_id != "test":
            return [{
                "account_id": key_id[:12],
                "name": f"AWS {region}",
                "provider": "aws",
                "region": region,
                "environment": "prod",
                "criticality": "critical",
                "last_scan": _utcnow_iso(),
            }]

        # Нет данных — возвращаем пустой список
        return []

    # ── Statistics ────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """
        Возвращает статистику по всем активам.

        Returns:
            Словарь:
              total:              общее количество активов
              by_type:            {asset_type: count}
              by_criticality:     {criticality: count}
              by_environment:     {environment: count}
              compliance_summary: {status: count} по всем маппингам
              compliance_pct:     float — % PASS среди всех маппингов
        """
        all_assets = self._store.list_assets()
        all_mappings = self._store.list_all_control_mappings()

        by_type: Dict[str, int] = {}
        by_criticality: Dict[str, int] = {}
        by_environment: Dict[str, int] = {}

        for asset in all_assets:
            by_type[asset.get("asset_type", "unknown")] = (
                by_type.get(asset.get("asset_type", "unknown"), 0) + 1
            )
            by_criticality[asset.get("criticality", "unknown")] = (
                by_criticality.get(asset.get("criticality", "unknown"), 0) + 1
            )
            by_environment[asset.get("environment", "unknown")] = (
                by_environment.get(asset.get("environment", "unknown"), 0) + 1
            )

        compliance_summary: Dict[str, int] = {
            "PASS": 0, "FAIL": 0, "PARTIAL": 0, "UNKNOWN": 0,
        }
        for m in all_mappings:
            status = m.get("compliance_status", "UNKNOWN")
            compliance_summary[status] = compliance_summary.get(status, 0) + 1

        total_mappings = len(all_mappings)
        compliance_pct = (
            round(compliance_summary["PASS"] / total_mappings * 100, 1)
            if total_mappings > 0
            else 0.0
        )

        return {
            "total": len(all_assets),
            "by_type": by_type,
            "by_criticality": by_criticality,
            "by_environment": by_environment,
            "total_control_mappings": total_mappings,
            "compliance_summary": compliance_summary,
            "compliance_pct": compliance_pct,
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _find_asset_by_metadata(
        self,
        meta_key: str,
        meta_value: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Ищет актив по полю в metadata.

        Используется для sync-операций чтобы избежать дублирования.
        """
        for asset in self._store.list_assets():
            meta = asset.get("metadata") or {}
            if str(meta.get(meta_key, "")) == str(meta_value):
                return asset
        return None


# ── Singleton instance ────────────────────────────────────────────────────────

# Глобальный экземпляр для использования в роутерах
# (без БД — JSON fallback автоматически)
_default_manager: Optional[AssetManager] = None


def get_asset_manager() -> AssetManager:
    """
    Возвращает глобальный экземпляр AssetManager.
    Инициализируется один раз при первом вызове.
    """
    global _default_manager
    if _default_manager is None:
        _default_manager = AssetManager()
        log.info("AssetManager инициализирован (JSON store: %s)", _ASSETS_FILE)
    return _default_manager
