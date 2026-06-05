"""
SQLAlchemy ORM models for Business Impact Analysis (BIA) module.
Tables: bia_assets, bia_tests, bia_escalations
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BIAAsset(Base):
    __tablename__ = "bia_assets"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # "infrastructure", "application", "data", "people", "vendor"
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    # 1-5 (5 = most critical)
    criticality: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    # target Recovery Time Objective in hours
    rto_hours: Mapped[float] = mapped_column(Float, nullable=False)
    # target Recovery Point Objective in hours
    rpo_hours: Mapped[float] = mapped_column(Float, nullable=False)
    # Max Tolerable Period of Disruption in hours
    mtpd_hours: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # responsible team/person
    owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    # comma-separated asset names
    dependencies: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    def __repr__(self) -> str:
        return f"<BIAAsset id={self.id} name={self.name} criticality={self.criticality}>"


class BIATest(Base):
    __tablename__ = "bia_tests"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("bia_assets.id"), nullable=False, index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    test_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    actual_rto_hours: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    actual_rpo_hours: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # "tabletop", "functional", "full_scale"
    test_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="tabletop"
    )
    # "pass", "fail", "partial"
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    met_rto: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    met_rpo: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tested_by: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

    def __repr__(self) -> str:
        return f"<BIATest id={self.id} asset_id={self.asset_id} outcome={self.outcome}>"


class BIAEscalation(Base):
    __tablename__ = "bia_escalations"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("bia_assets.id"), nullable=False, index=True
    )
    # 1=first threshold, 2=second, 3=critical
    tier: Mapped[int] = mapped_column(Integer, nullable=False)
    # hours until this tier triggers
    time_hours: Mapped[float] = mapped_column(Float, nullable=False)
    estimated_loss_usd: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    def __repr__(self) -> str:
        return f"<BIAEscalation id={self.id} asset_id={self.asset_id} tier={self.tier}>"
