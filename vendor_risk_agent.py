"""
Vendor Risk Management Agent — полный pipeline управления рисками вендоров.

Реализует:
- CRUD вендоров (хранение в data/vendors.json)
- Оценку SOC2 отчётов через AI (OpenRouter / Anthropic) с graceful fallback
- Расчёт Risk Score по формуле: criticality + DPA-статус + AI-оценка + давность ревью
- Историю assessments (data/vendor_assessments.json)
- Trust Center subprocessors
- Предупреждения об истекающих DPA

SOC2 контрол для Vendor Risk: CC9.2
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from sqlalchemy import select

from database import AsyncSessionLocal
from log_config import get_logger
from evidence_client import EvidenceClient
import models as _models

load_dotenv()

log = get_logger(__name__)

SOC2_VENDOR_CONTROL = "CC9.2"

# ── Пути к файлам данных ──────────────────────────────────────────────────────
_DATA_DIR = Path(__file__).parent / "data"
_VENDORS_FILE = _DATA_DIR / "vendors.json"          # Legacy: vendors now stored in DB
_ASSESSMENTS_FILE = _DATA_DIR / "vendor_assessments.json"  # Legacy: assessments now stored in DB (fallback only)

# ── LLM-настройки (тот же паттерн что в gap_analysis_agent.py) ───────────────
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku")
_RATE_LIMIT_BACKOFF = [10, 30, 60, 120]

# ── Константы ─────────────────────────────────────────────────────────────────
VALID_CATEGORIES = frozenset({"cloud", "saas", "infrastructure", "hr", "security"})
VALID_CRITICALITIES = frozenset({"critical", "high", "medium", "low"})
VALID_STATUSES = frozenset({"approved", "under_review", "rejected", "expired"})
VALID_RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})
VALID_RECOMMENDATIONS = frozenset({"approve", "conditional", "reject"})

# Веса для расчёта Risk Score (0-100)
_CRITICALITY_WEIGHT = {"critical": 40, "high": 30, "medium": 20, "low": 10}
_RISK_LEVEL_WEIGHT = {"critical": 40, "high": 30, "medium": 20, "low": 10}


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class Vendor:
    id: str
    name: str
    category: str           # "cloud" | "saas" | "infrastructure" | "hr" | "security"
    criticality: str        # "critical" | "high" | "medium" | "low"
    soc2_report_url: str
    dpa_signed: bool
    dpa_expiry: Optional[str]        # ISO date строка или None
    subprocessors: list[str]
    last_review_date: Optional[str]  # ISO date строка или None
    next_review_date: Optional[str]  # ISO date строка или None
    risk_score: int                  # 0-100
    status: str                      # "approved" | "under_review" | "rejected" | "expired"
    notes: str
    created_at: str
    updated_at: str


@dataclass
class VendorAssessment:
    id: str
    vendor_id: str
    assessment_date: str
    exceptions_found: list[str]
    uecc_items: list[str]      # User Entity Control Considerations
    risk_level: str            # "low" | "medium" | "high" | "critical"
    recommendation: str        # "approve" | "conditional" | "reject"
    summary: str
    raw_analysis: str


# ── Вспомогательные функции ───────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_str_field(value: str, valid_set: frozenset[str], default: str, field_name: str) -> str:
    if value not in valid_set:
        log.warning(f"Неизвестное значение поля {field_name}: {value!r}, используем {default!r}")
        return default
    return value


def _load_json(path: Path, default: list) -> list:
    if not path.exists():
        return list(default)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.error(f"Ошибка чтения {path}: {exc}")
        return list(default)


def _save_json(path: Path, data: list) -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _vendor_from_dict(d: dict) -> Vendor:
    return Vendor(
        id=d["id"],
        name=d["name"],
        category=d.get("category", "saas"),
        criticality=d.get("criticality", "medium"),
        soc2_report_url=d.get("soc2_report_url", ""),
        dpa_signed=bool(d.get("dpa_signed", False)),
        dpa_expiry=d.get("dpa_expiry"),
        subprocessors=d.get("subprocessors", []),
        last_review_date=d.get("last_review_date"),
        next_review_date=d.get("next_review_date"),
        risk_score=int(d.get("risk_score", 50)),
        status=d.get("status", "under_review"),
        notes=d.get("notes", ""),
        created_at=d.get("created_at", _now_iso()),
        updated_at=d.get("updated_at", _now_iso()),
    )


def _assessment_from_dict(d: dict) -> VendorAssessment:
    return VendorAssessment(
        id=d["id"],
        vendor_id=d["vendor_id"],
        assessment_date=d.get("assessment_date", _now_iso()),
        exceptions_found=d.get("exceptions_found", []),
        uecc_items=d.get("uecc_items", []),
        risk_level=d.get("risk_level", "medium"),
        recommendation=d.get("recommendation", "conditional"),
        summary=d.get("summary", ""),
        raw_analysis=d.get("raw_analysis", ""),
    )


# ── Seed-данные ───────────────────────────────────────────────────────────────

_SEED_VENDORS: list[dict] = [
    {
        "id": "VND-001",
        "name": "Amazon Web Services",
        "category": "cloud",
        "criticality": "critical",
        "soc2_report_url": "https://aws.amazon.com/compliance/soc/",
        "dpa_signed": True,
        "dpa_expiry": (datetime.now(timezone.utc) + timedelta(days=180)).strftime("%Y-%m-%d"),
        "subprocessors": ["AWS Lambda", "AWS RDS", "AWS S3"],
        "last_review_date": (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d"),
        "next_review_date": (datetime.now(timezone.utc) + timedelta(days=275)).strftime("%Y-%m-%d"),
        "risk_score": 20,
        "status": "approved",
        "notes": "Primary cloud infrastructure provider. Annual review required.",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    },
    {
        "id": "VND-002",
        "name": "Okta",
        "category": "security",
        "criticality": "critical",
        "soc2_report_url": "https://trust.okta.com/",
        "dpa_signed": True,
        "dpa_expiry": (datetime.now(timezone.utc) + timedelta(days=15)).strftime("%Y-%m-%d"),
        "subprocessors": ["AWS", "Cloudflare"],
        "last_review_date": (datetime.now(timezone.utc) - timedelta(days=45)).strftime("%Y-%m-%d"),
        "next_review_date": (datetime.now(timezone.utc) + timedelta(days=320)).strftime("%Y-%m-%d"),
        "risk_score": 25,
        "status": "approved",
        "notes": "Identity provider. DPA renewal needed soon.",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    },
    {
        "id": "VND-003",
        "name": "GitHub",
        "category": "saas",
        "criticality": "high",
        "soc2_report_url": "https://github.com/security/compliance",
        "dpa_signed": True,
        "dpa_expiry": (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%Y-%m-%d"),
        "subprocessors": ["Microsoft Azure"],
        "last_review_date": (datetime.now(timezone.utc) - timedelta(days=120)).strftime("%Y-%m-%d"),
        "next_review_date": (datetime.now(timezone.utc) + timedelta(days=245)).strftime("%Y-%m-%d"),
        "risk_score": 30,
        "status": "approved",
        "notes": "Source code repository. Enterprise plan.",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    },
    {
        "id": "VND-004",
        "name": "Slack",
        "category": "saas",
        "criticality": "medium",
        "soc2_report_url": "https://slack.com/security",
        "dpa_signed": True,
        "dpa_expiry": (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%d"),
        "subprocessors": ["AWS", "Google Cloud"],
        "last_review_date": (datetime.now(timezone.utc) - timedelta(days=200)).strftime("%Y-%m-%d"),
        "next_review_date": (datetime.now(timezone.utc) + timedelta(days=165)).strftime("%Y-%m-%d"),
        "risk_score": 35,
        "status": "approved",
        "notes": "Internal communications. Business+ plan.",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    },
    {
        "id": "VND-005",
        "name": "Atlassian Jira",
        "category": "saas",
        "criticality": "high",
        "soc2_report_url": "https://www.atlassian.com/trust/compliance/soc2",
        "dpa_signed": True,
        "dpa_expiry": (datetime.now(timezone.utc) + timedelta(days=25)).strftime("%Y-%m-%d"),
        "subprocessors": ["AWS", "Salesforce"],
        "last_review_date": (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%d"),
        "next_review_date": (datetime.now(timezone.utc) + timedelta(days=305)).strftime("%Y-%m-%d"),
        "risk_score": 32,
        "status": "approved",
        "notes": "Project management and issue tracking.",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    },
    {
        "id": "VND-006",
        "name": "Checkr",
        "category": "hr",
        "criticality": "high",
        "soc2_report_url": "https://checkr.com/trust",
        "dpa_signed": False,
        "dpa_expiry": None,
        "subprocessors": [],
        "last_review_date": None,
        "next_review_date": (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%d"),
        "risk_score": 65,
        "status": "under_review",
        "notes": "Background check provider. DPA not yet signed — pending legal review.",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    },
]


# ── AI-анализ ─────────────────────────────────────────────────────────────────

def _build_assessment_prompt(vendor_name: str, report_text: str) -> str:
    return f"""You are a senior SOC 2 compliance auditor reviewing a vendor's SOC 2 report.

VENDOR: {vendor_name}

SOC 2 REPORT EXCERPT:
{report_text[:4000]}

Your task: analyze the SOC 2 report for exceptions, User Entity Control Considerations (UECCs), and overall risk.

IMPORTANT: Respond ONLY with a valid JSON object. No markdown, no code fences.

Required JSON structure:
{{
  "exceptions_found": [
    "Description of exception 1 (specific, e.g. 'Backup restoration testing not performed quarterly')",
    "Description of exception 2"
  ],
  "uecc_items": [
    "UECC item 1 (responsibility that falls on the user organization)",
    "UECC item 2"
  ],
  "risk_level": "low",
  "recommendation": "approve",
  "summary": "2-3 sentence summary of the vendor's security posture based on this report"
}}

Rules:
- exceptions_found: list of 0-5 specific exceptions found in the report (empty list if none)
- uecc_items: list of 0-5 User Entity Control Considerations (things the customer must do)
- risk_level: exactly one of "low", "medium", "high", "critical"
  - "low": clean report, few or no exceptions
  - "medium": minor exceptions, key controls in place
  - "high": multiple exceptions or gaps in critical controls
  - "critical": material weaknesses or fundamental control failures
- recommendation: exactly one of "approve", "conditional", "reject"
  - "approve": report is clean, vendor meets SOC 2 requirements
  - "conditional": vendor can be used with specific compensating controls
  - "reject": exceptions are too severe, vendor should not be used
- summary: concise factual summary (not a repeat of exceptions)
"""


def _parse_assessment_response(raw: str, vendor_name: str) -> dict:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])
    try:
        data = json.loads(text)
        if not isinstance(data.get("exceptions_found"), list):
            data["exceptions_found"] = []
        if not isinstance(data.get("uecc_items"), list):
            data["uecc_items"] = []
        if data.get("risk_level") not in VALID_RISK_LEVELS:
            data["risk_level"] = "medium"
        if data.get("recommendation") not in VALID_RECOMMENDATIONS:
            data["recommendation"] = "conditional"
        if not isinstance(data.get("summary"), str):
            data["summary"] = "Manual review required."
        return data
    except json.JSONDecodeError as exc:
        log.error(f"Ошибка парсинга AI ответа для {vendor_name}: {exc}")
        return {
            "exceptions_found": ["Unable to parse AI response — manual review required"],
            "uecc_items": [],
            "risk_level": "medium",
            "recommendation": "conditional",
            "summary": f"AI analysis returned unparseable response for {vendor_name}. Manual review recommended.",
        }


def _call_llm(prompt: str, vendor_name: str) -> str:
    """Отправляет запрос в OpenRouter / Anthropic с retry-логикой."""
    api_key = OPENROUTER_API_KEY or ANTHROPIC_API_KEY
    if not api_key:
        raise RuntimeError("AI ключи не настроены")

    # Используем openai-compatible API (OpenRouter)
    try:
        from openai import OpenAI, RateLimitError
    except ImportError as exc:
        raise RuntimeError(f"Пакет openai не установлен: {exc}") from exc

    base_url = "https://openrouter.ai/api/v1" if OPENROUTER_API_KEY else "https://api.anthropic.com/v1"
    client = OpenAI(
        base_url=base_url,
        api_key=api_key,
        default_headers={
            "HTTP-Referer": "compliance-sandbox",
            "X-Title": "Vendor Risk Management",
        },
    )

    for attempt, wait in enumerate(_RATE_LIMIT_BACKOFF):
        try:
            response = client.chat.completions.create(
                model=OPENROUTER_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
            )
            return response.choices[0].message.content
        except RateLimitError:
            if attempt == len(_RATE_LIMIT_BACKOFF) - 1:
                raise
            log.warning(
                f"Rate limit при анализе {vendor_name} (попытка {attempt + 1}), ждём {wait}с"
            )
            time.sleep(wait)

    raise RuntimeError("Все попытки LLM исчерпаны")


def _mock_assessment(vendor_name: str) -> dict:
    """Возвращает mock-оценку когда AI недоступен."""
    return {
        "exceptions_found": ["AI analysis not available — API key not configured"],
        "uecc_items": [
            "Customer must implement access controls as described in vendor documentation",
            "Customer must retain logs for minimum 1 year",
        ],
        "risk_level": "medium",
        "recommendation": "conditional",
        "summary": (
            f"Mock assessment for {vendor_name}. "
            "Configure OPENROUTER_API_KEY or ANTHROPIC_API_KEY to enable AI analysis."
        ),
    }


# ── DB helpers для Vendor ─────────────────────────────────────────────────────

def _vendor_dict_to_db(d: dict) -> _models.Vendor:
    """Преобразует dict вендора в ORM-модель Vendor."""
    extra = {k: v for k, v in d.items() if k not in ("id", "name", "status", "dpa_signed", "last_review_date")}
    return _models.Vendor(
        id=d["id"],
        name=d["name"],
        tier=d.get("criticality", "medium"),
        status=d.get("status", "under_review"),
        dpa_signed=bool(d.get("dpa_signed", False)),
        last_review_date=d.get("last_review_date"),
        data=extra,
    )


def _db_vendor_to_dict(row: _models.Vendor) -> dict:
    """Преобразует ORM-запись Vendor обратно в dict (совместимость с _vendor_from_dict)."""
    d: dict = {"id": row.id, "name": row.name, "status": row.status,
               "dpa_signed": row.dpa_signed, "last_review_date": row.last_review_date,
               "criticality": row.tier}
    if row.data:
        d.update(row.data)
    return d


def _assessment_db_to_dict(row: "_models.VendorAssessment") -> dict:
    return {
        "id": row.id,
        "vendor_id": row.vendor_id,
        "assessment_date": row.assessment_date,
        "risk_level": row.risk_level,
        "recommendation": row.recommendation,
        "summary": row.summary,
        "raw_analysis": row.raw_analysis,
        "exceptions_found": row.exceptions_found or [],
        "uecc_items": row.uecc_items or [],
    }


def _run_async(coro):
    """Запускает async корутину из синхронного контекста."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


async def _db_load_vendors_async() -> list[dict]:
    """Загружает всех вендоров из БД."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(_models.Vendor))
        rows = result.scalars().all()
        return [_db_vendor_to_dict(r) for r in rows]


async def _db_save_vendor_async(vendor_dict: dict) -> None:
    """Создаёт или обновляет вендора в БД (upsert по id)."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(_models.Vendor).where(_models.Vendor.id == vendor_dict["id"])
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            session.add(_vendor_dict_to_db(vendor_dict))
        else:
            extra = {k: v for k, v in vendor_dict.items()
                     if k not in ("id", "name", "status", "dpa_signed", "last_review_date")}
            existing.name = vendor_dict["name"]
            existing.tier = vendor_dict.get("criticality", "medium")
            existing.status = vendor_dict.get("status", "under_review")
            existing.dpa_signed = bool(vendor_dict.get("dpa_signed", False))
            existing.last_review_date = vendor_dict.get("last_review_date")
            existing.data = extra
        await session.commit()


async def _db_delete_vendor_async(vendor_id: str) -> bool:
    """Удаляет вендора из БД. Возвращает True если удалён."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(_models.Vendor).where(_models.Vendor.id == vendor_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        await session.delete(row)
        await session.commit()
        return True


async def _db_vendor_count_async() -> int:
    """Возвращает количество вендоров в БД."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(_models.Vendor))
        return len(result.scalars().all())


async def _db_load_assessments_async(vendor_id: str | None = None) -> list[dict]:
    """Загружает assessments из БД (все или для конкретного vendor_id)."""
    async with AsyncSessionLocal() as session:
        stmt = select(_models.VendorAssessment)
        if vendor_id:
            stmt = stmt.where(_models.VendorAssessment.vendor_id == vendor_id)
        rows = (await session.execute(stmt)).scalars().all()
        return [_assessment_db_to_dict(r) for r in rows]


async def _db_save_assessment_async(a: dict) -> None:
    """Upsert одного assessment по id."""
    async with AsyncSessionLocal() as session:
        existing = await session.get(_models.VendorAssessment, a["id"])
        if existing is None:
            session.add(_models.VendorAssessment(
                id=a["id"],
                vendor_id=a["vendor_id"],
                assessment_date=a.get("assessment_date", ""),
                risk_level=a.get("risk_level"),
                recommendation=a.get("recommendation"),
                summary=a.get("summary"),
                raw_analysis=a.get("raw_analysis"),
                exceptions_found=a.get("exceptions_found"),
                uecc_items=a.get("uecc_items"),
            ))
        else:
            existing.assessment_date = a.get("assessment_date", existing.assessment_date)
            existing.risk_level = a.get("risk_level", existing.risk_level)
            existing.recommendation = a.get("recommendation", existing.recommendation)
            existing.summary = a.get("summary", existing.summary)
            existing.raw_analysis = a.get("raw_analysis", existing.raw_analysis)
            existing.exceptions_found = a.get("exceptions_found", existing.exceptions_found)
            existing.uecc_items = a.get("uecc_items", existing.uecc_items)
        await session.commit()


# ── Основной агент ────────────────────────────────────────────────────────────

class VendorRiskAgent:
    """
    Полный pipeline управления рисками вендоров.

    Хранение:
    - data/vendors.json — реестр вендоров
    - data/vendor_assessments.json — история оценок
    """

    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._ensure_seed()

    # ── Seed ──────────────────────────────────────────────────────────────────

    def _ensure_seed(self) -> None:
        """Заполняет БД seed-данными если таблица vendor пуста."""
        count = _run_async(_db_vendor_count_async())
        if count > 0:
            return

        seeded: list[dict] = []
        for raw in _SEED_VENDORS:
            v = _vendor_from_dict(raw)
            v.risk_score = self._calculate_risk_score(v, None)
            d = asdict(v)
            seeded.append(d)
            _run_async(_db_save_vendor_async(d))

        log.info(f"Seed: создано {len(seeded)} вендоров в БД")

    # ── Внутренние helpers ────────────────────────────────────────────────────

    def _load_vendors(self) -> list[dict]:
        return _run_async(_db_load_vendors_async())

    def load_vendors(self) -> list[Vendor]:
        return [_vendor_from_dict(d) for d in self._load_vendors()]

    def _save_vendors(self, vendors: list[dict]) -> None:
        for vendor_dict in vendors:
            _run_async(_db_save_vendor_async(vendor_dict))

    def _load_assessments(self) -> list[dict]:
        try:
            return _run_async(_db_load_assessments_async())
        except Exception:
            return _load_json(_ASSESSMENTS_FILE, [])   # fallback

    def _save_assessments(self, assessments: list[dict]) -> None:
        for a in assessments:
            try:
                _run_async(_db_save_assessment_async(a))
            except Exception as exc:
                log.warning("DB save assessment failed, skipping: %s", exc)

    def _next_vendor_id(self, vendors: list[dict]) -> str:
        max_num = 0
        for v in vendors:
            vid = v.get("id", "")
            if vid.startswith("VND-"):
                try:
                    num = int(vid.split("-")[1])
                    if num > max_num:
                        max_num = num
                except (ValueError, IndexError):
                    pass
        return f"VND-{str(max_num + 1).zfill(3)}"

    # ── Risk Score формула ────────────────────────────────────────────────────

    def _calculate_risk_score(
        self, vendor: Vendor, assessment: Optional[VendorAssessment]
    ) -> int:
        """
        Формула (0-100):
        - criticality_weight: critical=40, high=30, medium=20, low=10
        - dpa_status: нет DPA или истёк/не подписан → +20, подписан → +0
        - assessment_risk: из последней оценки (0-40 по уровню риска)
        - days_since_review: >365 дней без ревью → +10, >180 → +5, <= 180 → +0
        Нормализуем до 0-100.
        """
        score = 0

        # 1. Criticality (0-40)
        score += _CRITICALITY_WEIGHT.get(vendor.criticality, 20)

        # 2. DPA status (0-20)
        dpa_penalty = 0
        if not vendor.dpa_signed:
            dpa_penalty = 20
        elif vendor.dpa_expiry:
            try:
                expiry = datetime.strptime(vendor.dpa_expiry, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 0:
                    dpa_penalty = 20  # истёк
                elif days_left <= 30:
                    dpa_penalty = 10  # истекает скоро
            except ValueError:
                dpa_penalty = 5
        score += dpa_penalty

        # 3. Assessment risk (0-40)
        if assessment:
            score += _RISK_LEVEL_WEIGHT.get(assessment.risk_level, 20)

        # 4. Days since last review (0-10)
        if vendor.last_review_date:
            try:
                last_review = datetime.strptime(vendor.last_review_date, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
                days_since = (datetime.now(timezone.utc) - last_review).days
                if days_since > 365:
                    score += 10
                elif days_since > 180:
                    score += 5
            except ValueError:
                score += 5
        else:
            score += 10  # никогда не проверялся

        # Нормализуем: максимум теоретически 110 (40+20+40+10), кладём cap на 100
        return min(score, 100)

    # ── CRUD вендоров ─────────────────────────────────────────────────────────

    def create_vendor(self, data: dict) -> Vendor:
        """Создаёт нового вендора."""
        vendors = self._load_vendors()
        new_id = self._next_vendor_id(vendors)
        now = _now_iso()

        category = _validate_str_field(
            data.get("category", "saas"), VALID_CATEGORIES, "saas", "category"
        )
        criticality = _validate_str_field(
            data.get("criticality", "medium"), VALID_CRITICALITIES, "medium", "criticality"
        )
        status = _validate_str_field(
            data.get("status", "under_review"), VALID_STATUSES, "under_review", "status"
        )

        vendor_dict: dict = {
            "id": new_id,
            "name": str(data.get("name", "Unknown Vendor")).strip(),
            "category": category,
            "criticality": criticality,
            "soc2_report_url": str(data.get("soc2_report_url", "")),
            "dpa_signed": bool(data.get("dpa_signed", False)),
            "dpa_expiry": data.get("dpa_expiry"),
            "subprocessors": list(data.get("subprocessors", [])),
            "last_review_date": data.get("last_review_date"),
            "next_review_date": data.get("next_review_date"),
            "risk_score": 50,  # будет пересчитан ниже
            "status": status,
            "notes": str(data.get("notes", "")),
            "created_at": now,
            "updated_at": now,
        }

        vendor = _vendor_from_dict(vendor_dict)
        vendor.risk_score = self._calculate_risk_score(vendor, None)
        vendor_dict["risk_score"] = vendor.risk_score

        vendors.append(vendor_dict)
        self._save_vendors(vendors)
        log.info(f"Вендор создан: {vendor.name} ({new_id})")
        return vendor

    def get_all_vendors(
        self,
        category: Optional[str] = None,
        status: Optional[str] = None,
        criticality: Optional[str] = None,
    ) -> list[Vendor]:
        """Возвращает список вендоров с опциональной фильтрацией."""
        vendors = self._load_vendors()
        if category:
            vendors = [v for v in vendors if v.get("category") == category]
        if status:
            vendors = [v for v in vendors if v.get("status") == status]
        if criticality:
            vendors = [v for v in vendors if v.get("criticality") == criticality]
        return [_vendor_from_dict(v) for v in vendors]

    def get_vendor(self, vendor_id: str) -> Optional[Vendor]:
        """Возвращает вендора по ID или None."""
        vendors = self._load_vendors()
        for v in vendors:
            if v.get("id") == vendor_id:
                return _vendor_from_dict(v)
        return None

    def update_vendor(self, vendor_id: str, data: dict) -> Optional[Vendor]:
        """Обновляет поля вендора, пересчитывает risk_score."""
        vendors = self._load_vendors()
        for v in vendors:
            if v.get("id") != vendor_id:
                continue

            # Разрешённые поля для обновления
            updatable = [
                "name", "category", "criticality", "soc2_report_url",
                "dpa_signed", "dpa_expiry", "subprocessors",
                "last_review_date", "next_review_date", "status", "notes",
            ]
            for key in updatable:
                if key in data:
                    v[key] = data[key]

            v["updated_at"] = _now_iso()

            # Пересчитываем score
            vendor_obj = _vendor_from_dict(v)
            latest_assessment = self._get_latest_assessment(vendor_id)
            vendor_obj.risk_score = self._calculate_risk_score(vendor_obj, latest_assessment)
            v["risk_score"] = vendor_obj.risk_score

            self._save_vendors(vendors)
            log.info(f"Вендор обновлён: {v.get('name')} ({vendor_id})")
            return vendor_obj

        return None

    def delete_vendor(self, vendor_id: str) -> bool:
        """Удаляет вендора. Возвращает True если удалён."""
        deleted = _run_async(_db_delete_vendor_async(vendor_id))
        if deleted:
            log.info(f"Вендор удалён: {vendor_id}")
        return deleted

    # ── Assessments ───────────────────────────────────────────────────────────

    def run_assessment(self, vendor_id: str, report_text: str) -> VendorAssessment:
        """
        Запускает AI-оценку SOC2 отчёта вендора.
        При отсутствии AI-ключей — возвращает mock-assessment (не бросает исключений).
        """
        vendor = self.get_vendor(vendor_id)
        if vendor is None:
            raise ValueError(f"Вендор {vendor_id} не найден")

        api_key = OPENROUTER_API_KEY or ANTHROPIC_API_KEY
        if api_key:
            try:
                prompt = _build_assessment_prompt(vendor.name, report_text)
                raw = _call_llm(prompt, vendor.name)
                parsed = _parse_assessment_response(raw, vendor.name)
                log.info(
                    f"AI-оценка выполнена для {vendor.name}",
                    extra={"risk_level": parsed["risk_level"]},
                )
            except Exception as exc:
                log.warning(
                    f"AI-оценка не удалась для {vendor.name}: {exc} — используем mock"
                )
                parsed = _mock_assessment(vendor.name)
        else:
            log.info(f"AI ключи не настроены — mock-оценка для {vendor.name}")
            parsed = _mock_assessment(vendor.name)

        now = _now_iso()
        assessment_dict: dict = {
            "id": str(uuid.uuid4()),
            "vendor_id": vendor_id,
            "assessment_date": now,
            "exceptions_found": parsed["exceptions_found"],
            "uecc_items": parsed["uecc_items"],
            "risk_level": parsed["risk_level"],
            "recommendation": parsed["recommendation"],
            "summary": parsed["summary"],
            "raw_analysis": report_text[:2000],  # храним обрезанный текст
        }

        # Сохраняем assessment
        assessments = self._load_assessments()
        assessments.append(assessment_dict)
        self._save_assessments(assessments)

        # Пересчитываем risk_score вендора
        assessment_obj = _assessment_from_dict(assessment_dict)
        self._refresh_vendor_score(vendor_id, assessment_obj)

        log.info(
            f"Assessment сохранён: {assessment_dict['id']}",
            extra={"vendor": vendor.name, "risk_level": parsed["risk_level"]},
        )
        return assessment_obj

    def get_assessments(self, vendor_id: str) -> list[VendorAssessment]:
        """Возвращает историю оценок вендора (от новых к старым)."""
        assessments = self._load_assessments()
        vendor_assessments = [
            _assessment_from_dict(a) for a in assessments if a.get("vendor_id") == vendor_id
        ]
        # Сортировка: новые сначала
        vendor_assessments.sort(key=lambda a: a.assessment_date, reverse=True)
        return vendor_assessments

    def _get_latest_assessment(self, vendor_id: str) -> Optional[VendorAssessment]:
        """Возвращает самую свежую оценку вендора."""
        vendor_assessments = self.get_assessments(vendor_id)
        return vendor_assessments[0] if vendor_assessments else None

    def _refresh_vendor_score(self, vendor_id: str, assessment: VendorAssessment) -> None:
        """Обновляет risk_score вендора после новой оценки."""
        vendors = self._load_vendors()
        for v in vendors:
            if v.get("id") == vendor_id:
                vendor_obj = _vendor_from_dict(v)
                new_score = self._calculate_risk_score(vendor_obj, assessment)
                v["risk_score"] = new_score
                v["last_review_date"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                v["updated_at"] = _now_iso()
                self._save_vendors(vendors)
                break

    # ── Аналитика и Trust Center ──────────────────────────────────────────────

    def get_risk_summary(self) -> dict:
        """Статистика: по criticality, по status, avg risk score."""
        vendors = self._load_vendors()

        by_criticality: dict[str, int] = {}
        by_status: dict[str, int] = {}
        total_score = 0
        scores_by_criticality: dict[str, list[int]] = {}

        for v in vendors:
            crit = v.get("criticality", "medium")
            stat = v.get("status", "under_review")
            score = int(v.get("risk_score", 50))

            by_criticality[crit] = by_criticality.get(crit, 0) + 1
            by_status[stat] = by_status.get(stat, 0) + 1
            total_score += score
            scores_by_criticality.setdefault(crit, []).append(score)

        avg_score = round(total_score / len(vendors), 1) if vendors else 0

        avg_by_criticality = {
            crit: round(sum(scores) / len(scores), 1)
            for crit, scores in scores_by_criticality.items()
        }

        # Высокорисковые вендоры (score > 60)
        high_risk_vendors = [
            {"id": v["id"], "name": v["name"], "risk_score": v.get("risk_score", 50)}
            for v in vendors
            if int(v.get("risk_score", 50)) > 60
        ]

        return {
            "total_vendors": len(vendors),
            "by_criticality": by_criticality,
            "by_status": by_status,
            "average_risk_score": avg_score,
            "avg_score_by_criticality": avg_by_criticality,
            "high_risk_vendors": high_risk_vendors,
        }

    def get_expiring_dpas(self, days: int = 30) -> list[Vendor]:
        """Возвращает вендоров с DPA истекающим в течение `days` дней."""
        vendors = self._load_vendors()
        result: list[Vendor] = []
        cutoff = datetime.now(timezone.utc) + timedelta(days=days)

        for v in vendors:
            dpa_expiry = v.get("dpa_expiry")
            if not dpa_expiry:
                continue
            try:
                expiry_dt = datetime.strptime(dpa_expiry, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
                # Включаем: истёкшие и истекающие в течение days
                if expiry_dt <= cutoff:
                    result.append(_vendor_from_dict(v))
            except ValueError:
                continue

        result.sort(key=lambda v: v.dpa_expiry or "")
        return result

    def get_subprocessors_list(self) -> list[dict]:
        """Список субпроцессоров всех approved вендоров для Trust Center."""
        vendors = self._load_vendors()
        result: list[dict] = []
        seen: set[str] = set()

        for v in vendors:
            if v.get("status") != "approved":
                continue
            vendor_name = v.get("name", "Unknown")
            for sp in v.get("subprocessors", []):
                if sp not in seen:
                    seen.add(sp)
                    result.append({
                        "subprocessor": sp,
                        "parent_vendor": vendor_name,
                        "parent_vendor_id": v.get("id"),
                        "category": v.get("category"),
                    })

        result.sort(key=lambda x: x["subprocessor"])
        return result

    def renew_dpa(self, vendor_id: str, new_expiry: str) -> Optional[Vendor]:
        """Обновляет дату истечения DPA вендора."""
        try:
            datetime.strptime(new_expiry, "%Y-%m-%d")
        except ValueError:
            raise ValueError(f"Неверный формат даты: {new_expiry!r}. Ожидается YYYY-MM-DD")

        return self.update_vendor(vendor_id, {"dpa_expiry": new_expiry, "dpa_signed": True})

    # ── Jira integration ──────────────────────────────────────────────────────

    def create_jira_ticket(
        self,
        vendor_id: str,
        assessment: Optional[VendorAssessment] = None,
    ) -> dict:
        """
        Создаёт Jira-тикет для вендора с высоким риском или выявленными exceptions.

        Если JIRA_URL не настроен — возвращает mock-ответ (не падает с ошибкой).
        """
        vendor = self.get_vendor(vendor_id)
        if vendor is None:
            raise ValueError(f"Вендор {vendor_id} не найден")

        # Берём последний assessment если не передан
        if assessment is None:
            assessment = self._get_latest_assessment(vendor_id)

        summary = f"[VRM] Vendor Review Required: {vendor.name} ({vendor.criticality.upper()})"

        description_parts = [
            f"Vendor: {vendor.name}",
            f"Category: {vendor.category}",
            f"Criticality: {vendor.criticality}",
            f"Current Risk Score: {vendor.risk_score}/100",
            f"Status: {vendor.status}",
        ]

        if vendor.dpa_expiry:
            description_parts.append(f"DPA Expiry: {vendor.dpa_expiry}")
        if not vendor.dpa_signed:
            description_parts.append("WARNING: DPA not signed")

        if assessment:
            description_parts.extend([
                "",
                f"Latest Assessment ({assessment.assessment_date[:10]}):",
                f"Risk Level: {assessment.risk_level}",
                f"Recommendation: {assessment.recommendation}",
                f"Summary: {assessment.summary}",
            ])
            if assessment.exceptions_found:
                description_parts.append("Exceptions found:")
                for exc in assessment.exceptions_found:
                    description_parts.append(f"  - {exc}")
            if assessment.uecc_items:
                description_parts.append("UECC items:")
                for item in assessment.uecc_items:
                    description_parts.append(f"  - {item}")

        description = "\n".join(description_parts)

        # Приоритет Jira из risk_score
        if vendor.risk_score >= 70:
            jira_priority = "Critical"
        elif vendor.risk_score >= 50:
            jira_priority = "High"
        elif vendor.risk_score >= 30:
            jira_priority = "Medium"
        else:
            jira_priority = "Low"

        jira_url = os.getenv("JIRA_URL", "")
        jira_user = os.getenv("JIRA_USER", "")
        jira_token = os.getenv("JIRA_API_TOKEN", "")
        jira_project = os.getenv("JIRA_PROJECT_KEY", "SEC")

        if not all([jira_url, jira_user, jira_token]):
            log.warning(
                "Jira не настроен (JIRA_URL/JIRA_USER/JIRA_API_TOKEN) — mock тикет",
                extra={"vendor": vendor.name},
            )
            mock_key = f"{jira_project}-MOCK-{vendor_id}"
            # Сохраняем ссылку на тикет в вендоре (даже mock)
            self.update_vendor(vendor_id, {"notes": f"{vendor.notes} | Jira: {mock_key}".strip()})
            return {
                "key": mock_key,
                "url": f"https://jira.example.com/browse/{mock_key}",
                "status": "mock",
                "summary": summary,
            }

        try:
            from jira_client import JiraClient
            jira = JiraClient(jira_url, jira_user, jira_token)
            result = jira.create_issue(
                project_key=jira_project,
                summary=summary,
                description=description,
                issue_type="Task",
                priority=jira_priority,
                labels=["soc2", "vendor-risk", "compliance", vendor.criticality],
            )
            # Сохраняем ключ тикета в notes вендора
            self.update_vendor(
                vendor_id,
                {"notes": f"{vendor.notes} | Jira: {result['key']}".strip()},
            )
            log.info(
                f"Jira тикет создан для {vendor.name}",
                extra={"key": result["key"], "priority": jira_priority},
            )
            return result
        except Exception as exc:
            log.error(f"Ошибка создания Jira тикета для {vendor.name}: {exc}")
            raise

    def analyze_vendor(self, vendor: dict) -> dict:
        """Простая классификация риска вендора без вызова AI (быстрый sync-путь)."""
        soc2 = vendor.get("soc2_certified", False)
        category = vendor.get("category", "")
        if soc2 and category in ("cloud", "security"):
            level = "LOW"
        elif soc2:
            level = "MEDIUM"
        elif category in ("cloud", "security", "infrastructure"):
            level = "HIGH"
        else:
            level = "MEDIUM"
        return {"name": vendor.get("name", ""), "risk_level": level}

    def run_assessment(self) -> list[dict]:
        """Запускает analyze_vendor для каждого вендора из load_vendors(). Ошибка одного не останавливает остальных."""
        vendors = self.load_vendors()
        results = []
        for v in vendors:
            vendor_dict = v if isinstance(v, dict) else {"name": v.name, "category": v.category, "soc2_certified": v.dpa_signed, "data_processed": []}
            try:
                result = self.analyze_vendor(vendor_dict)
                result.setdefault("name", vendor_dict.get("name", ""))
                results.append(result)
            except Exception as exc:
                log.warning(f"analyze_vendor failed for {vendor_dict.get('name')}: {exc}")
                results.append({"name": vendor_dict.get("name", ""), "risk_level": "UNKNOWN", "error": str(exc)})
        return results


def main(controls_map: dict | None = None) -> dict:
    """Entry point для оркестратора — запускает vendor risk scan и возвращает summary."""
    agent = VendorRiskAgent()
    vendors = agent.load_vendors()
    high_risk = [v for v in vendors if v.risk_score >= 70]
    return {
        "control": SOC2_VENDOR_CONTROL,
        "total_vendors": len(vendors),
        "high_risk_count": len(high_risk),
        "high_risk_vendors": [v.name for v in high_risk],
    }
