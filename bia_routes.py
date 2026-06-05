"""
FastAPI router for Business Impact Analysis (BIA) module.
Provides RTO/RPO tracking and recovery testing endpoints.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import require_admin, require_auditor, require_auth
from bia_models import BIAAsset, BIAEscalation, BIATest
from database import AsyncSessionLocal, Base, engine
from log_config import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/bia", tags=["bia"])

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"


# ── Table creation ────────────────────────────────────────────────────────────

async def _create_tables() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


try:
    asyncio.get_event_loop().run_until_complete(_create_tables())
except RuntimeError:
    pass  # Event loop already running; ui_server.py will call create_all


# ── Pydantic models ───────────────────────────────────────────────────────────

class AssetCreate(BaseModel):
    name: str
    description: Optional[str] = None
    category: str
    criticality: int = 3
    rto_hours: float
    rpo_hours: float
    mtpd_hours: Optional[float] = None
    owner: Optional[str] = None
    dependencies: Optional[str] = None


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    criticality: Optional[int] = None
    rto_hours: Optional[float] = None
    rpo_hours: Optional[float] = None
    mtpd_hours: Optional[float] = None
    owner: Optional[str] = None
    dependencies: Optional[str] = None


class TestCreate(BaseModel):
    test_type: str = "tabletop"
    test_date: Optional[datetime] = None
    actual_rto_hours: Optional[float] = None
    actual_rpo_hours: Optional[float] = None
    outcome: str  # "pass", "fail", "partial"
    notes: Optional[str] = None
    tested_by: Optional[str] = None


class EscalationTier(BaseModel):
    tier: int
    time_hours: float
    estimated_loss_usd: Optional[float] = None
    description: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_tenant_id(user: dict) -> str:
    return user.get("tenant_id") or DEFAULT_TENANT_ID


def _asset_to_dict(asset: BIAAsset) -> dict[str, Any]:
    return {
        "id": asset.id,
        "tenant_id": asset.tenant_id,
        "name": asset.name,
        "description": asset.description,
        "category": asset.category,
        "criticality": asset.criticality,
        "rto_hours": asset.rto_hours,
        "rpo_hours": asset.rpo_hours,
        "mtpd_hours": asset.mtpd_hours,
        "owner": asset.owner,
        "dependencies": asset.dependencies,
        "is_active": asset.is_active,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
    }


def _test_to_dict(test: BIATest) -> dict[str, Any]:
    return {
        "id": test.id,
        "asset_id": test.asset_id,
        "test_date": test.test_date.isoformat() if test.test_date else None,
        "actual_rto_hours": test.actual_rto_hours,
        "actual_rpo_hours": test.actual_rpo_hours,
        "test_type": test.test_type,
        "outcome": test.outcome,
        "met_rto": test.met_rto,
        "met_rpo": test.met_rpo,
        "notes": test.notes,
        "tested_by": test.tested_by,
    }


def _escalation_to_dict(esc: BIAEscalation) -> dict[str, Any]:
    return {
        "id": esc.id,
        "asset_id": esc.asset_id,
        "tier": esc.tier,
        "time_hours": esc.time_hours,
        "estimated_loss_usd": esc.estimated_loss_usd,
        "description": esc.description,
    }


async def _get_last_test(
    db: AsyncSession, asset_id: str, tenant_id: str
) -> Optional[BIATest]:
    result = await db.execute(
        select(BIATest)
        .where(BIATest.asset_id == asset_id, BIATest.tenant_id == tenant_id)
        .order_by(BIATest.test_date.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _enrich_asset(
    db: AsyncSession, asset: BIAAsset, tenant_id: str
) -> dict[str, Any]:
    """Add last_test_date, last_test_outcome, rto_status, days_since_test."""
    d = _asset_to_dict(asset)
    last_test = await _get_last_test(db, asset.id, tenant_id)
    if last_test:
        d["last_test_date"] = last_test.test_date.isoformat()
        d["last_test_outcome"] = last_test.outcome
        d["rto_status"] = "pass" if last_test.met_rto else "fail"
        now = datetime.now(timezone.utc)
        test_dt = last_test.test_date
        if test_dt.tzinfo is None:
            test_dt = test_dt.replace(tzinfo=timezone.utc)
        d["days_since_test"] = (now - test_dt).days
    else:
        d["last_test_date"] = None
        d["last_test_outcome"] = None
        d["rto_status"] = "untested"
        d["days_since_test"] = None
    return d


# ── Seed data ─────────────────────────────────────────────────────────────────

_SEED_ASSETS = [
    {
        "name": "Primary Database",
        "description": "Primary PostgreSQL production database cluster",
        "category": "infrastructure",
        "criticality": 5,
        "rto_hours": 1.0,
        "rpo_hours": 0.25,
        "mtpd_hours": 4.0,
        "owner": "Platform Engineering",
    },
    {
        "name": "Auth Service / Okta",
        "description": "Identity provider and SSO authentication service",
        "category": "application",
        "criticality": 5,
        "rto_hours": 2.0,
        "rpo_hours": 1.0,
        "mtpd_hours": 8.0,
        "owner": "Security Team",
    },
    {
        "name": "AWS Production VPC",
        "description": "Core AWS production network and compute infrastructure",
        "category": "infrastructure",
        "criticality": 5,
        "rto_hours": 4.0,
        "rpo_hours": 1.0,
        "mtpd_hours": 12.0,
        "owner": "Platform Engineering",
    },
    {
        "name": "GitHub / Code Repository",
        "description": "Source code version control and CI/CD pipelines",
        "category": "application",
        "criticality": 4,
        "rto_hours": 8.0,
        "rpo_hours": 2.0,
        "mtpd_hours": 24.0,
        "owner": "Engineering",
    },
    {
        "name": "Jira / Ticketing",
        "description": "Project management and issue tracking system",
        "category": "application",
        "criticality": 3,
        "rto_hours": 24.0,
        "rpo_hours": 4.0,
        "mtpd_hours": 48.0,
        "owner": "Engineering",
    },
    {
        "name": "Backup Storage",
        "description": "S3-based backup and disaster recovery storage",
        "category": "data",
        "criticality": 4,
        "rto_hours": 4.0,
        "rpo_hours": 0.5,
        "mtpd_hours": 24.0,
        "owner": "Platform Engineering",
    },
]

_SEED_TESTS = [
    # (asset_index, actual_rto_hours, actual_rpo_hours, test_type, outcome, days_ago)
    (0, 0.8, 0.2, "functional", "pass", 45),
    (1, 2.5, 1.2, "tabletop", "partial", 60),
    (2, 3.5, 0.8, "tabletop", "pass", 30),
    (3, 7.5, 1.5, "tabletop", "pass", 75),
    (4, 20.0, 3.5, "tabletop", "pass", 90),
    (5, 5.0, 0.6, "functional", "fail", 15),
]

_SEED_ESCALATIONS = [
    # (asset_index, tier, time_hours, estimated_loss_usd, description)
    (0, 1, 0.5, 10000, "Initial alert: DBA on-call notified, failover initiated"),
    (0, 2, 1.0, 50000, "Revenue impact begins: executive team notified"),
    (0, 3, 2.0, 200000, "Critical: customer SLA breach, incident commander engaged"),
    (1, 1, 1.0, 5000, "Auth failures detected: security team notified"),
    (1, 2, 2.0, 30000, "All logins blocked: emergency access procedures activated"),
    (2, 1, 2.0, 20000, "Infrastructure degraded: runbook escalation tier 1"),
    (2, 2, 4.0, 100000, "Partial outage: DR site activation considered"),
    (2, 3, 8.0, 500000, "Full outage: DR site activated, war room opened"),
]


async def _seed_data(tenant_id: str) -> None:
    """Seed example assets, tests, and escalations for a new tenant."""
    async with AsyncSessionLocal() as db:
        asset_ids: list[str] = []
        now = datetime.now(timezone.utc)

        for seed in _SEED_ASSETS:
            asset = BIAAsset(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                name=seed["name"],
                description=seed.get("description"),
                category=seed["category"],
                criticality=seed["criticality"],
                rto_hours=seed["rto_hours"],
                rpo_hours=seed["rpo_hours"],
                mtpd_hours=seed.get("mtpd_hours"),
                owner=seed.get("owner"),
                is_active=True,
                created_at=now,
            )
            db.add(asset)
            asset_ids.append(asset.id)

        await db.flush()

        for asset_idx, actual_rto, actual_rpo, test_type, outcome, days_ago in _SEED_TESTS:
            asset_id = asset_ids[asset_idx]
            # Look up the asset for target values
            asset_seed = _SEED_ASSETS[asset_idx]
            met_rto = actual_rto <= asset_seed["rto_hours"] if actual_rto is not None else None
            met_rpo = actual_rpo <= asset_seed["rpo_hours"] if actual_rpo is not None else None
            test = BIATest(
                id=str(uuid.uuid4()),
                asset_id=asset_id,
                tenant_id=tenant_id,
                test_date=now - timedelta(days=days_ago),
                actual_rto_hours=actual_rto,
                actual_rpo_hours=actual_rpo,
                test_type=test_type,
                outcome=outcome,
                met_rto=met_rto,
                met_rpo=met_rpo,
                notes="Seeded test record",
                tested_by="System Seed",
            )
            db.add(test)

        for asset_idx, tier, time_hours, loss_usd, description in _SEED_ESCALATIONS:
            asset_id = asset_ids[asset_idx]
            esc = BIAEscalation(
                id=str(uuid.uuid4()),
                asset_id=asset_id,
                tier=tier,
                time_hours=time_hours,
                estimated_loss_usd=float(loss_usd),
                description=description,
            )
            db.add(esc)

        await db.commit()
        log.info("BIA seed data created", extra={"tenant_id": tenant_id})


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/summary")
async def get_summary(user: dict = Depends(require_auth)) -> dict[str, Any]:
    """
    Dashboard summary: total assets, tested last 90d, RTO/RPO pass rates,
    critical untested count, avg RTO gap hours, by_category breakdown.
    Seeds 6 example assets on first call if the table is empty.
    """
    tenant_id = _get_tenant_id(user)

    async with AsyncSessionLocal() as db:
        # Check if table is empty for this tenant
        asset_count_result = await db.execute(
            select(BIAAsset).where(
                BIAAsset.tenant_id == tenant_id,
                BIAAsset.is_active.is_(True),
            )
        )
        assets = list(asset_count_result.scalars().all())

        if not assets:
            await _seed_data(tenant_id)
            # Reload
            async with AsyncSessionLocal() as db2:
                asset_count_result2 = await db2.execute(
                    select(BIAAsset).where(
                        BIAAsset.tenant_id == tenant_id,
                        BIAAsset.is_active.is_(True),
                    )
                )
                assets = list(asset_count_result2.scalars().all())

        total_assets = len(assets)
        now = datetime.now(timezone.utc)
        cutoff_90d = now - timedelta(days=90)

        tested_last_90d = 0
        rto_pass = 0
        rto_total = 0
        rpo_pass = 0
        rpo_total = 0
        critical_untested = 0
        rto_gaps: list[float] = []
        by_category: dict[str, int] = {}

        # Use the same db session (assets already loaded above)
        async with AsyncSessionLocal() as db3:
            for asset in assets:
                cat = asset.category
                by_category[cat] = by_category.get(cat, 0) + 1

                # Get most recent test in last 90d
                result = await db3.execute(
                    select(BIATest)
                    .where(
                        BIATest.asset_id == asset.id,
                        BIATest.tenant_id == tenant_id,
                        BIATest.test_date >= cutoff_90d,
                    )
                    .order_by(BIATest.test_date.desc())
                    .limit(1)
                )
                recent_test = result.scalar_one_or_none()

                if recent_test:
                    tested_last_90d += 1
                    if recent_test.met_rto is not None:
                        rto_total += 1
                        if recent_test.met_rto:
                            rto_pass += 1
                    if recent_test.met_rpo is not None:
                        rpo_total += 1
                        if recent_test.met_rpo:
                            rpo_pass += 1
                    if (
                        recent_test.actual_rto_hours is not None
                        and asset.rto_hours is not None
                    ):
                        gap = recent_test.actual_rto_hours - asset.rto_hours
                        rto_gaps.append(gap)
                else:
                    # Untested in last 90d
                    if asset.criticality >= 4:
                        critical_untested += 1

        pct_tested = round(tested_last_90d / total_assets * 100, 1) if total_assets else 0.0
        rto_pass_rate = round(rto_pass / rto_total * 100, 1) if rto_total else 0.0
        rpo_pass_rate = round(rpo_pass / rpo_total * 100, 1) if rpo_total else 0.0
        avg_rto_gap = round(sum(rto_gaps) / len(rto_gaps), 2) if rto_gaps else 0.0

        return {
            "total_assets": total_assets,
            "tested_last_90d": tested_last_90d,
            "pct_tested": pct_tested,
            "rto_pass_rate": rto_pass_rate,
            "rpo_pass_rate": rpo_pass_rate,
            "critical_untested": critical_untested,
            "avg_rto_gap_hours": avg_rto_gap,
            "by_category": by_category,
        }


@router.get("/assets")
async def list_assets(user: dict = Depends(require_auth)) -> list[dict[str, Any]]:
    """List active assets for tenant including last test info."""
    tenant_id = _get_tenant_id(user)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(BIAAsset)
            .where(
                BIAAsset.tenant_id == tenant_id,
                BIAAsset.is_active.is_(True),
            )
            .order_by(BIAAsset.criticality.desc(), BIAAsset.name)
        )
        assets = list(result.scalars().all())
        return [await _enrich_asset(db, a, tenant_id) for a in assets]


@router.post("/assets")
async def create_asset(
    body: AssetCreate,
    user: dict = Depends(require_auditor),
) -> dict[str, Any]:
    """Create a new BIA asset. Requires admin or auditor role."""
    tenant_id = _get_tenant_id(user)

    async with AsyncSessionLocal() as db:
        asset = BIAAsset(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            name=body.name,
            description=body.description,
            category=body.category,
            criticality=body.criticality,
            rto_hours=body.rto_hours,
            rpo_hours=body.rpo_hours,
            mtpd_hours=body.mtpd_hours,
            owner=body.owner,
            dependencies=body.dependencies,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(asset)
        await db.commit()

        log.info("BIA asset created", extra={"asset_id": asset.id, "name": asset.name})
        return await _enrich_asset(db, asset, tenant_id)


@router.get("/assets/{asset_id}")
async def get_asset(
    asset_id: str,
    user: dict = Depends(require_auth),
) -> dict[str, Any]:
    """Get a single asset with test history (last 10) and escalation tiers."""
    tenant_id = _get_tenant_id(user)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(BIAAsset).where(
                BIAAsset.id == asset_id,
                BIAAsset.tenant_id == tenant_id,
                BIAAsset.is_active.is_(True),
            )
        )
        asset = result.scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

        d = await _enrich_asset(db, asset, tenant_id)

        # Last 10 tests
        tests_result = await db.execute(
            select(BIATest)
            .where(BIATest.asset_id == asset_id, BIATest.tenant_id == tenant_id)
            .order_by(BIATest.test_date.desc())
            .limit(10)
        )
        d["tests"] = [_test_to_dict(t) for t in tests_result.scalars().all()]

        # Escalation tiers
        esc_result = await db.execute(
            select(BIAEscalation)
            .where(BIAEscalation.asset_id == asset_id)
            .order_by(BIAEscalation.tier)
        )
        d["escalations"] = [_escalation_to_dict(e) for e in esc_result.scalars().all()]

        return d


@router.patch("/assets/{asset_id}")
async def update_asset(
    asset_id: str,
    body: AssetUpdate,
    user: dict = Depends(require_auditor),
) -> dict[str, Any]:
    """Update a BIA asset. Requires admin or auditor role."""
    tenant_id = _get_tenant_id(user)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(BIAAsset).where(
                BIAAsset.id == asset_id,
                BIAAsset.tenant_id == tenant_id,
                BIAAsset.is_active.is_(True),
            )
        )
        asset = result.scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

        update_data = body.model_dump(exclude_none=True)
        for field, value in update_data.items():
            setattr(asset, field, value)

        await db.commit()
        log.info("BIA asset updated", extra={"asset_id": asset_id})
        return await _enrich_asset(db, asset, tenant_id)


@router.delete("/assets/{asset_id}")
async def delete_asset(
    asset_id: str,
    user: dict = Depends(require_admin),
) -> dict[str, str]:
    """Soft-delete a BIA asset. Admin only."""
    tenant_id = _get_tenant_id(user)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(BIAAsset).where(
                BIAAsset.id == asset_id,
                BIAAsset.tenant_id == tenant_id,
                BIAAsset.is_active.is_(True),
            )
        )
        asset = result.scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

        asset.is_active = False
        await db.commit()
        log.info("BIA asset deleted (soft)", extra={"asset_id": asset_id})
        return {"status": "deleted", "asset_id": asset_id}


@router.post("/assets/{asset_id}/tests")
async def record_test(
    asset_id: str,
    body: TestCreate,
    user: dict = Depends(require_auth),
) -> dict[str, Any]:
    """Record a recovery test result for an asset. Auto-calculates met_rto/met_rpo."""
    tenant_id = _get_tenant_id(user)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(BIAAsset).where(
                BIAAsset.id == asset_id,
                BIAAsset.tenant_id == tenant_id,
                BIAAsset.is_active.is_(True),
            )
        )
        asset = result.scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

        # Auto-calculate met_rto and met_rpo
        met_rto: Optional[bool] = None
        met_rpo: Optional[bool] = None
        if body.actual_rto_hours is not None:
            met_rto = body.actual_rto_hours <= asset.rto_hours
        if body.actual_rpo_hours is not None:
            met_rpo = body.actual_rpo_hours <= asset.rpo_hours

        test = BIATest(
            id=str(uuid.uuid4()),
            asset_id=asset_id,
            tenant_id=tenant_id,
            test_date=body.test_date or datetime.now(timezone.utc),
            actual_rto_hours=body.actual_rto_hours,
            actual_rpo_hours=body.actual_rpo_hours,
            test_type=body.test_type,
            outcome=body.outcome,
            met_rto=met_rto,
            met_rpo=met_rpo,
            notes=body.notes,
            tested_by=body.tested_by,
        )
        db.add(test)
        await db.commit()

        log.info(
            "BIA test recorded",
            extra={"asset_id": asset_id, "outcome": body.outcome, "met_rto": met_rto},
        )
        return _test_to_dict(test)


@router.get("/assets/{asset_id}/escalations")
async def get_escalations(
    asset_id: str,
    user: dict = Depends(require_auth),
) -> list[dict[str, Any]]:
    """Get escalation tiers for an asset."""
    tenant_id = _get_tenant_id(user)

    async with AsyncSessionLocal() as db:
        # Verify asset exists and belongs to tenant
        asset_result = await db.execute(
            select(BIAAsset).where(
                BIAAsset.id == asset_id,
                BIAAsset.tenant_id == tenant_id,
                BIAAsset.is_active.is_(True),
            )
        )
        if not asset_result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

        result = await db.execute(
            select(BIAEscalation)
            .where(BIAEscalation.asset_id == asset_id)
            .order_by(BIAEscalation.tier)
        )
        return [_escalation_to_dict(e) for e in result.scalars().all()]


@router.put("/assets/{asset_id}/escalations")
async def replace_escalations(
    asset_id: str,
    tiers: list[EscalationTier],
    user: dict = Depends(require_auditor),
) -> list[dict[str, Any]]:
    """Replace all escalation tiers for an asset. Requires admin or auditor role."""
    tenant_id = _get_tenant_id(user)

    async with AsyncSessionLocal() as db:
        # Verify asset exists and belongs to tenant
        asset_result = await db.execute(
            select(BIAAsset).where(
                BIAAsset.id == asset_id,
                BIAAsset.tenant_id == tenant_id,
                BIAAsset.is_active.is_(True),
            )
        )
        if not asset_result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

        # Delete existing tiers
        existing = await db.execute(
            select(BIAEscalation).where(BIAEscalation.asset_id == asset_id)
        )
        for esc in existing.scalars().all():
            await db.delete(esc)

        # Create new tiers
        new_tiers: list[BIAEscalation] = []
        for t in tiers:
            esc = BIAEscalation(
                id=str(uuid.uuid4()),
                asset_id=asset_id,
                tier=t.tier,
                time_hours=t.time_hours,
                estimated_loss_usd=t.estimated_loss_usd,
                description=t.description,
            )
            db.add(esc)
            new_tiers.append(esc)

        await db.commit()
        log.info(
            "BIA escalations replaced",
            extra={"asset_id": asset_id, "tier_count": len(new_tiers)},
        )
        return [_escalation_to_dict(e) for e in new_tiers]
