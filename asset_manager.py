"""
asset_manager.py — Asset-centric compliance управление.

Центральный компонент P5: связывает активы организации (устройства,
cloud-аккаунты, репозитории, базы данных, сотрудников, вендор-сервисы)
с SOC2 контролями и реестром рисков.

Хранение: SQLAlchemy ORM через AsyncSession (AsyncSessionLocal из database.py).
Таблица: asset_record (модель AssetRecord из models.py).
Дополнительные поля (environment, tags, metadata, control_mappings,
risk_mappings) хранятся в колонке extra как JSON.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import select

from database import AsyncSessionLocal
from log_config import get_logger
from models import AssetRecord

log = get_logger(__name__)

# ── Константы ─────────────────────────────────────────────────────────────────

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


def _run_async(coro):
    """
    Запускает async-корутину из синхронного контекста.
    Паттерн взят из vendor_risk_agent.py.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


# ── Преобразование ORM → dict ─────────────────────────────────────────────────

def _record_to_dict(record: AssetRecord) -> Dict[str, Any]:
    """Конвертирует ORM-запись AssetRecord в словарь актива."""
    extra = record.extra or {}
    return {
        "id": record.id,
        "asset_type": record.asset_type,
        "name": record.name,
        "owner_id": record.owner or extra.get("owner_id"),
        "environment": extra.get("environment", "prod"),
        "criticality": record.criticality,
        "tags": extra.get("tags") or {},
        "metadata": extra.get("metadata") or {},
        "created_at": record.created_at.isoformat() if record.created_at else _utcnow_iso(),
        "updated_at": extra.get("updated_at", _utcnow_iso()),
    }


def _dict_to_record_fields(asset: Dict[str, Any]) -> Dict[str, Any]:
    """
    Возвращает kwargs для создания/обновления AssetRecord из словаря актива.
    Поля, которых нет в AssetRecord напрямую, идут в extra.
    """
    extra = {
        "environment": asset.get("environment", "prod"),
        "tags": asset.get("tags") or {},
        "metadata": asset.get("metadata") or {},
        "owner_id": asset.get("owner_id"),
        "updated_at": asset.get("updated_at", _utcnow_iso()),
        # control_mappings и risk_mappings хранятся отдельными ключами в extra
        "control_mappings": asset.get("_control_mappings", []),
        "risk_mappings": asset.get("_risk_mappings", []),
    }
    return {
        "id": asset["id"],
        "name": asset.get("name", ""),
        "asset_type": asset.get("asset_type", ""),
        "owner": asset.get("owner_id"),
        "criticality": asset.get("criticality", "medium"),
        "classification": "internal",
        "status": "active",
        "extra": extra,
    }


# ── In-memory storage layer (test use only) ───────────────────────────────────

class _MemStore:
    """In-memory drop-in replacement for _DbStore used in unit tests."""

    def __init__(self, path=None) -> None:  # path kwarg kept for old fixture compat
        self._assets: Dict[str, Dict[str, Any]] = {}
        self._cmaps: Dict[str, List[Dict[str, Any]]] = {}   # asset_id → mappings
        self._rmaps: Dict[str, List[Dict[str, Any]]] = {}   # asset_id → mappings

    def put_asset(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        stored = {k: v for k, v in asset.items() if not k.startswith("_")}
        self._assets[stored["id"]] = stored
        return dict(stored)

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        a = self._assets.get(asset_id)
        return dict(a) if a else None

    def list_assets(
        self,
        asset_type: Optional[str] = None,
        criticality: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        items = [dict(a) for a in self._assets.values()]
        if asset_type:
            items = [a for a in items if a.get("asset_type") == asset_type]
        if criticality:
            items = [a for a in items if a.get("criticality") == criticality]
        if environment:
            items = [a for a in items if a.get("environment") == environment]
        items.sort(key=lambda a: (
            CRITICALITY_ORDER.get(a.get("criticality", "low"), 99),
            a.get("name", ""),
        ))
        return items

    def delete_asset(self, asset_id: str) -> bool:
        if asset_id not in self._assets:
            return False
        del self._assets[asset_id]
        self._cmaps.pop(asset_id, None)
        self._rmaps.pop(asset_id, None)
        return True

    def upsert_control_mapping(
        self,
        asset_id: str,
        control_id: str,
        status: str,
        evidence_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if asset_id not in self._assets:
            return {}
        mappings = self._cmaps.setdefault(asset_id, [])
        for m in mappings:
            if m["control_id"] == control_id:
                m["compliance_status"] = status
                m["last_checked"] = _utcnow_iso()
                if evidence_ids is not None:
                    m["evidence_ids"] = evidence_ids
                return m
        mapping: Dict[str, Any] = {
            "id": len(mappings) + 1,
            "asset_id": asset_id,
            "control_id": control_id,
            "compliance_status": status,
            "last_checked": _utcnow_iso(),
            "evidence_ids": evidence_ids or [],
        }
        mappings.append(mapping)
        return mapping

    def get_control_mappings(self, asset_id: str) -> List[Dict[str, Any]]:
        return list(self._cmaps.get(asset_id, []))

    def get_assets_by_control(
        self, control_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        result = []
        for mappings in self._cmaps.values():
            for m in mappings:
                if m["control_id"] == control_id:
                    if status is None or m["compliance_status"] == status:
                        result.append(m)
        return result

    def list_all_control_mappings(self) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for mappings in self._cmaps.values():
            result.extend(mappings)
        return result

    def upsert_risk_mapping(
        self, asset_id: str, risk_id: str, exposure_level: str
    ) -> Dict[str, Any]:
        if asset_id not in self._assets:
            return {}
        mappings = self._rmaps.setdefault(asset_id, [])
        for m in mappings:
            if m["risk_id"] == risk_id:
                m["exposure_level"] = exposure_level
                return m
        mapping: Dict[str, Any] = {
            "id": len(mappings) + 1,
            "asset_id": asset_id,
            "risk_id": risk_id,
            "exposure_level": exposure_level,
        }
        mappings.append(mapping)
        return mapping

    def get_risk_mappings(self, asset_id: str) -> List[Dict[str, Any]]:
        return list(self._rmaps.get(asset_id, []))

    def list_all_risk_mappings(self) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for mappings in self._rmaps.values():
            result.extend(mappings)
        return result


# ── DB storage layer ──────────────────────────────────────────────────────────

class _DbStore:
    """
    DB-backed хранилище активов через AssetRecord ORM.

    Структура extra JSON:
      {
        "environment": "prod",
        "tags": { ... },
        "metadata": { ... },
        "owner_id": "...",
        "updated_at": "...",
        "control_mappings": [ { asset_id, control_id, compliance_status, ... } ],
        "risk_mappings":    [ { asset_id, risk_id, exposure_level } ]
      }
    """

    # ── Assets ────────────────────────────────────────────────────────────────

    async def _put_asset_async(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        """Создаёт или обновляет актив в БД (upsert)."""
        fields = _dict_to_record_fields(asset)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(AssetRecord).where(AssetRecord.id == fields["id"])
            )
            record = result.scalar_one_or_none()
            if record is None:
                record = AssetRecord(**fields)
                session.add(record)
            else:
                for k, v in fields.items():
                    if k != "id":
                        setattr(record, k, v)
            await session.commit()
            await session.refresh(record)
        return _record_to_dict(record)

    def put_asset(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        return _run_async(self._put_asset_async(asset))

    async def _get_asset_async(self, asset_id: str) -> Optional[Dict[str, Any]]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(AssetRecord).where(AssetRecord.id == asset_id)
            )
            record = result.scalar_one_or_none()
            return _record_to_dict(record) if record else None

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        return _run_async(self._get_asset_async(asset_id))

    async def _list_assets_async(
        self,
        asset_type: Optional[str] = None,
        criticality: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        async with AsyncSessionLocal() as session:
            stmt = select(AssetRecord)
            if asset_type:
                stmt = stmt.where(AssetRecord.asset_type == asset_type)
            if criticality:
                stmt = stmt.where(AssetRecord.criticality == criticality)
            result = await session.execute(stmt)
            records = result.scalars().all()

        items = [_record_to_dict(r) for r in records]

        # Фильтр по environment (хранится в extra)
        if environment:
            items = [a for a in items if a.get("environment") == environment]

        # Сортировка: сначала по критичности, затем по имени
        items.sort(key=lambda a: (
            CRITICALITY_ORDER.get(a.get("criticality", "low"), 99),
            a.get("name", ""),
        ))
        return items

    def list_assets(
        self,
        asset_type: Optional[str] = None,
        criticality: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        return _run_async(self._list_assets_async(asset_type, criticality, environment))

    async def _delete_asset_async(self, asset_id: str) -> bool:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(AssetRecord).where(AssetRecord.id == asset_id)
            )
            record = result.scalar_one_or_none()
            if not record:
                return False
            await session.delete(record)
            await session.commit()
        return True

    def delete_asset(self, asset_id: str) -> bool:
        return _run_async(self._delete_asset_async(asset_id))

    # ── Control mappings ─────────────────────────────────────────────────────
    # Маппинги хранятся в extra["control_mappings"] записи актива

    def _get_asset_extra(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Возвращает extra словарь актива или None."""
        asset = self.get_asset(asset_id)
        if not asset:
            return None
        return asset

    def upsert_control_mapping(
        self,
        asset_id: str,
        control_id: str,
        status: str,
        evidence_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Создаёт или обновляет маппинг актив ↔ контроль в extra."""
        asset = self.get_asset(asset_id)
        if not asset:
            return {}

        # Читаем текущие маппинги из extra
        fields = _dict_to_record_fields(asset)
        extra = fields["extra"]
        mappings: List[Dict[str, Any]] = extra.get("control_mappings", [])

        # Ищем существующий
        found = None
        for m in mappings:
            if m["asset_id"] == asset_id and m["control_id"] == control_id:
                found = m
                break

        if found:
            found["compliance_status"] = status
            found["last_checked"] = _utcnow_iso()
            if evidence_ids is not None:
                found["evidence_ids"] = evidence_ids
            result_mapping = found
        else:
            result_mapping = {
                "id": len(mappings) + 1,
                "asset_id": asset_id,
                "control_id": control_id,
                "compliance_status": status,
                "last_checked": _utcnow_iso(),
                "evidence_ids": evidence_ids or [],
            }
            mappings.append(result_mapping)

        extra["control_mappings"] = mappings
        # Сохраняем обратно
        asset["_control_mappings"] = mappings
        asset["_risk_mappings"] = extra.get("risk_mappings", [])
        self.put_asset(asset)
        return result_mapping

    def get_control_mappings(self, asset_id: str) -> List[Dict[str, Any]]:
        asset = self.get_asset(asset_id)
        if not asset:
            return []
        fields = _dict_to_record_fields(asset)
        return fields["extra"].get("control_mappings", [])

    def get_assets_by_control(
        self,
        control_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        all_mappings = self.list_all_control_mappings()
        mappings = [m for m in all_mappings if m["control_id"] == control_id]
        if status:
            mappings = [m for m in mappings if m["compliance_status"] == status]
        return mappings

    def list_all_control_mappings(self) -> List[Dict[str, Any]]:
        all_assets = self.list_assets()
        result = []
        for asset in all_assets:
            fields = _dict_to_record_fields(asset)
            result.extend(fields["extra"].get("control_mappings", []))
        return result

    # ── Risk mappings ─────────────────────────────────────────────────────────

    def upsert_risk_mapping(
        self,
        asset_id: str,
        risk_id: str,
        exposure_level: str,
    ) -> Dict[str, Any]:
        """Создаёт или обновляет маппинг актив ↔ риск в extra."""
        asset = self.get_asset(asset_id)
        if not asset:
            return {}

        fields = _dict_to_record_fields(asset)
        extra = fields["extra"]
        mappings: List[Dict[str, Any]] = extra.get("risk_mappings", [])

        found = None
        for m in mappings:
            if m["asset_id"] == asset_id and m["risk_id"] == risk_id:
                found = m
                break

        if found:
            found["exposure_level"] = exposure_level
            result_mapping = found
        else:
            result_mapping = {
                "id": len(mappings) + 1,
                "asset_id": asset_id,
                "risk_id": risk_id,
                "exposure_level": exposure_level,
            }
            mappings.append(result_mapping)

        extra["risk_mappings"] = mappings
        asset["_control_mappings"] = extra.get("control_mappings", [])
        asset["_risk_mappings"] = mappings
        self.put_asset(asset)
        return result_mapping

    def get_risk_mappings(self, asset_id: str) -> List[Dict[str, Any]]:
        asset = self.get_asset(asset_id)
        if not asset:
            return []
        fields = _dict_to_record_fields(asset)
        return fields["extra"].get("risk_mappings", [])

    def list_all_risk_mappings(self) -> List[Dict[str, Any]]:
        all_assets = self.list_assets()
        result = []
        for asset in all_assets:
            fields = _dict_to_record_fields(asset)
            result.extend(fields["extra"].get("risk_mappings", []))
        return result


# ── AssetManager ──────────────────────────────────────────────────────────────

class AssetManager:
    """
    Менеджер активов для asset-centric compliance.

    Хранение: SQLAlchemy ORM через AsyncSessionLocal (таблица asset_record).
    Маппинги контролей и рисков хранятся в колонке extra (JSON).

    Основные возможности:
      - CRUD операции над активами
      - Управление compliance-маппингами актив ↔ контроль
      - Управление risk-маппингами актив ↔ риск
      - Синхронизация с MDM (mdm_device_inventory.json)
      - Синхронизация со Scanner (парсинг evidence с source=SCANNER)
      - Поиск non-compliant активов
      - Расчёт compliance posture для актива
    """

    def __init__(self, store: Optional[_DbStore] = None) -> None:
        self._store = store or _DbStore()

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def register_asset(self, asset_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Регистрирует новый актив в системе (INSERT в asset_record).

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
        Возвращает актив по ID (SELECT из asset_record).

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
        Возвращает список активов с опциональной фильтрацией (SELECT из asset_record).

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
        Обновляет поля существующего актива (UPDATE asset_record).

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
        Удаляет актив и все связанные маппинги (DELETE из asset_record).

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
        Ищет активы с FAIL статусом (SELECT asset_record, фильтр в Python).

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

            # Ищем существующий актив по device_id в metadata (DB-запрос)
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
        Возвращает статистику по всем активам (агрегация по asset_record).

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
        Ищет актив по полю в metadata (SELECT + фильтр в Python).

        Используется для sync-операций чтобы избежать дублирования.
        Для SQLite: фильтрует в памяти (нет встроенного JSON-извлечения в ORM).
        Для PostgreSQL: можно заменить на jsonb-запрос при необходимости.
        """
        for asset in self._store.list_assets():
            meta = asset.get("metadata") or {}
            if str(meta.get(meta_key, "")) == str(meta_value):
                return asset
        return None


# ── Singleton instance ────────────────────────────────────────────────────────

# Глобальный экземпляр для использования в роутерах
_default_manager: Optional[AssetManager] = None


def get_asset_manager() -> AssetManager:
    """
    Возвращает глобальный экземпляр AssetManager.
    Инициализируется один раз при первом вызове.
    Использует DB-хранилище (AsyncSessionLocal → asset_record).
    """
    global _default_manager
    if _default_manager is None:
        _default_manager = AssetManager()
        log.info("AssetManager инициализирован (DB store: asset_record)")
    return _default_manager
